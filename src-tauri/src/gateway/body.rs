//! Request body transformer — applies ZCode-equivalent body mutations before
//! forwarding upstream. Ported from zcode-api `src/proxy/body-transformer.ts`.
//!
//! The upstream is always Anthropic-format, so only the Anthropic branch is
//! ported:
//!   1. clear existing `cache_control` markers on all non-system messages,
//!      then mark the last content block of the last non-system message
//!      with `{ type: "ephemeral" }` (mirrors the bundle's `zsi`+`Fsi` pair);
//!   2. inject `metadata.user_id` (device/session blob, `account_uuid` is
//!      always "" in real traffic);
//!   3. start-plan → prepend ZCode gateway system blocks (the gateway rejects
//!      requests without them with 3012) + context-prefix user turn + strip
//!      client `cache_control` from tools.

use serde_json::{json, Map, Value};

use super::identity::EnvPromptInfo;
use super::prompt;

/// Clear stale `cache_control` markers on non-system message blocks, then
/// mark the last non-system message's last block. Output-stable on an
/// already-canonical body.
fn apply_anthropic_cache_control(body: &mut Map<String, Value>) {
    let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) else {
        return;
    };
    for msg in messages.iter_mut() {
        if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
            continue;
        }
        let Some(blocks) = msg.get_mut("content").and_then(|c| c.as_array_mut()) else {
            continue;
        };
        for block in blocks.iter_mut() {
            if let Some(obj) = block.as_object_mut() {
                obj.remove("cache_control");
            }
        }
    }

    for msg in messages.iter_mut().rev() {
        if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
            continue;
        }
        match msg.get_mut("content") {
            Some(Value::String(s)) => {
                *msg.get_mut("content").unwrap() = json!([
                    { "type": "text", "text": s.clone(), "cache_control": { "type": "ephemeral" } }
                ]);
                return;
            }
            Some(Value::Array(blocks)) => {
                if let Some(last) = blocks.last_mut() {
                    if let Some(obj) = last.as_object_mut() {
                        if !obj.contains_key("cache_control") {
                            obj.insert("cache_control".into(), json!({ "type": "ephemeral" }));
                        }
                    }
                }
                return;
            }
            _ => return,
        }
    }
}

/// Inject `metadata.user_id` when not already set; preserves any existing
/// `metadata.*` fields other than `user_id`.
fn apply_anthropic_user_id(body: &mut Map<String, Value>, user_id: &str) {
    if body.get("metadata").and_then(|m| m.get("user_id")).and_then(|u| u.as_str()) == Some(user_id) {
        return;
    }
    let mut metadata = body
        .get("metadata")
        .and_then(|m| m.as_object().cloned())
        .unwrap_or_default();
    metadata.insert("user_id".into(), json!(user_id));
    body.insert("metadata".into(), Value::Object(metadata));
}

/// start-plan: prepend the official ZCode gateway system blocks and the
/// currentDate context-prefix user turn; strip client `cache_control` from
/// tools (official blocks 3 + last-message marker 1 already fill the
/// 4-breakpoint cache budget).
fn apply_start_plan_system(body: &mut Map<String, Value>, provider: Option<&str>, env: &EnvPromptInfo) {
    let model = body.get("model").and_then(|m| m.as_str()).map(str::to_string);
    let existing_system = body.get("system").cloned();
    let blocks = prompt::build_start_plan_system(existing_system.as_ref(), model.as_deref(), env, provider);
    body.insert("system".into(), Value::Array(blocks));

    if let Some(messages) = body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        if !messages.is_empty() {
            messages.insert(0, prompt::build_context_prefix_message());
        }
    }
    if let Some(tools) = body.get_mut("tools").and_then(|t| t.as_array_mut()) {
        for tool in tools.iter_mut() {
            if let Some(obj) = tool.as_object_mut() {
                obj.remove("cache_control");
            }
        }
    }
}

/// The `metadata.user_id` value the real client attaches to EVERY
/// anthropic-kind request: `{"device_id": mid, "account_uuid": "", "session_id": id}`.
pub fn build_anthropic_metadata_user_id(device_mid: Option<&str>, session_id: Option<&str>) -> String {
    let session = session_id
        .map(|s| {
            for p in ["sess_", "subagent_agent_"] {
                if let Some(rest) = s.strip_prefix(p) {
                    if !rest.is_empty() {
                        return rest.to_string();
                    }
                }
            }
            s.to_string()
        })
        .unwrap_or_default();
    let mut obj = serde_json::Map::new();
    if let Some(mid) = device_mid {
        obj.insert("device_id".into(), json!(mid));
    }
    obj.insert("account_uuid".into(), json!(""));
    obj.insert("session_id".into(), json!(session));
    Value::Object(obj).to_string()
}

/// Apply body transformations to a parsed Anthropic-format request.
pub fn transform_anthropic_body(
    body: &mut Map<String, Value>,
    start_plan: bool,
    provider: Option<&str>,
    metadata_user_id: &str,
    env: &EnvPromptInfo,
) {
    if start_plan {
        apply_start_plan_system(body, provider, env);
    }
    apply_anthropic_cache_control(body);
    apply_anthropic_user_id(body, metadata_user_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env() -> EnvPromptInfo {
        EnvPromptInfo {
            cwd: "/tmp".into(),
            platform: "win32".into(),
            shell: "bash".into(),
            os_version: "10.0.19045 x64".into(),
        }
    }

    #[test]
    fn cache_control_moves_to_last_block() {
        let mut body = json!({
            "messages": [
                { "role": "user", "content": [{ "type": "text", "text": "old", "cache_control": { "type": "ephemeral" } }] },
                { "role": "user", "content": "new" }
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        apply_anthropic_cache_control(&mut body);
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs[0]["content"][0].get("cache_control").is_none());
        let content = msgs[1]["content"].as_array().unwrap();
        assert_eq!(content[0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn metadata_user_id_shape() {
        let v = build_anthropic_metadata_user_id(Some("mid-1"), Some("sess_abc"));
        let parsed: Value = serde_json::from_str(&v).unwrap();
        assert_eq!(parsed["device_id"], "mid-1");
        assert_eq!(parsed["account_uuid"], "");
        assert_eq!(parsed["session_id"], "abc");
    }

    #[test]
    fn start_plan_injects_system_and_prefix() {
        let mut body = json!({
            "model": "glm-5.3",
            "messages": [{ "role": "user", "content": "hi" }]
        })
        .as_object()
        .unwrap()
        .clone();
        apply_start_plan_system(&mut body, Some("zai"), &env());
        let system = body["system"].as_array().unwrap();
        assert!(system.len() >= 3);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("<system-reminder>"));
    }
}
