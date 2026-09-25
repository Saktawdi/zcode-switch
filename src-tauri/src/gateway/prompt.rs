//! ZCode system-prompt assembly — a faithful port of zcode-api
//! `src/proxy/system-prompt.ts`, itself a mirror of the desktop client's
//! ContextBuilder.
//!
//! The start-plan gateway does content inspection — without the ZCode identity
//! blocks in the `system` field it rejects with 3012 "method not allowed".
//! The real client assembles EXACTLY 3 wire blocks, each with
//! `cache_control: {type:"ephemeral"}`:
//!   1. cli_prefix alone
//!   2. every other STABLE section, `\n\n`-joined
//!   3. every DYNAMIC section, `\n\n`-joined, with an explicit `"\n\n"` prefix

use chrono::{Datelike, Local};
use serde_json::{json, Value};

const ZCODE_SYSTEM_JSON: &str = include_str!("zcode_system.json");

pub fn system_data() -> &'static Value {
    static DATA: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(ZCODE_SYSTEM_JSON).expect("zcode_system.json is valid JSON"))
}

/// Bundle `p2`: OAuth provider → built-in model-provider id used in the
/// powered-by line (`zai` → "zai-api", `bigmodel` → "bigmodel-api").
pub fn provider_model_id(provider: &str) -> &'static str {
    match provider {
        "zai" => "zai-api",
        "bigmodel" => "bigmodel-api",
        _ => "zai-api",
    }
}

/// Bundle `pK` (formatLocalIsoDate): local `YYYY-MM-DD`, zero-padded.
pub fn format_local_iso_date() -> String {
    let now = Local::now();
    format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day())
}

/// Environment Info section (`T9o`/`eMi`): lines joined with `\n`; powered-by
/// line last (only when both model and provider are known).
pub fn build_environment_section(env: &super::identity::EnvPromptInfo, model: Option<&str>, provider: Option<&str>) -> String {
    let data = system_data();
    let e = &data["environment"];
    let mut lines = vec![
        e["heading"].as_str().unwrap_or_default().to_string(),
        e["invokedLine"].as_str().unwrap_or_default().to_string(),
        format!(
            "- {}: {}",
            e["cwdLabel"].as_str().unwrap_or_default(),
            env.cwd
        ),
        format!(
            "- {}: {}",
            e["gitLabel"].as_str().unwrap_or_default(),
            e["gitNo"].as_str().unwrap_or_default()
        ),
        format!(
            "- {}: {}",
            e["platformLabel"].as_str().unwrap_or_default(),
            env.platform
        ),
        format!(
            "- {}: {}",
            e["shellLabel"].as_str().unwrap_or_default(),
            env.shell
        ),
        format!(
            "- {}: {}",
            e["osVersionLabel"].as_str().unwrap_or_default(),
            env.os_version
        ),
    ];
    if let (Some(m), Some(p)) = (model.map(str::trim).filter(|m| !m.is_empty()), provider) {
        let line = e["poweredByLine"].as_str().unwrap_or_default();
        lines.push(line.replace("{provider}", provider_model_id(p)).replace("{model}", m));
    }
    lines.join("\n")
}

fn normalize_user_system(system: Option<&Value>) -> Vec<Value> {
    let mut out = vec![];
    let Some(sys) = system else { return out };
    match sys {
        Value::String(s) => {
            let text = s.trim();
            if !text.is_empty() {
                out.push(json!({ "type": "text", "text": text }));
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::String(s) => {
                        if !s.trim().is_empty() {
                            out.push(json!({ "type": "text", "text": s }));
                        }
                    }
                    Value::Object(b) => {
                        if b.get("type").and_then(|t| t.as_str()) == Some("text") {
                            if let Some(text) = b.get("text").and_then(|t| t.as_str()) {
                                // cache_control intentionally dropped — the official
                                // blocks already fill 3 of 4 cache breakpoints.
                                if !text.trim().is_empty() {
                                    out.push(json!({ "type": "text", "text": text }));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    out
}

/// Prepend the official ZCode gateway blocks to the request's `system` field
/// (3 blocks, ephemeral breakpoints, dynamic block `\n\n`-prefixed). Client
/// system blocks, if any, are preserved AFTER the official blocks.
pub fn build_start_plan_system(
    existing_system: Option<&Value>,
    model: Option<&str>,
    env: &super::identity::EnvPromptInfo,
    provider: Option<&str>,
) -> Vec<Value> {
    let data = system_data();
    let stable = data["stableSections"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join("\n\n"))
        .unwrap_or_default();
    let dynamic = [
        data["dynamicSections"]["beforeEnvironment"].as_str().unwrap_or_default().to_string(),
        build_environment_section(env, model, provider),
        data["dynamicSections"]["afterEnvironment"].as_str().unwrap_or_default().to_string(),
    ]
    .join("\n\n");
    let official = vec![
        json!({ "type": "text", "text": data["cliPrefix"].as_str().unwrap_or_default(), "cache_control": { "type": "ephemeral" } }),
        json!({ "type": "text", "text": stable, "cache_control": { "type": "ephemeral" } }),
        json!({ "type": "text", "text": format!("\n\n{dynamic}"), "cache_control": { "type": "ephemeral" } }),
    ];
    let mut out = official;
    out.extend(normalize_user_system(existing_system));
    out
}

/// The meta_user context_prefix: a leading user turn whose single text block
/// is the currentDate section wrapped in `<system-reminder>…</system-reminder>`.
pub fn build_context_prefix_message() -> Value {
    let data = system_data();
    let cp = &data["contextPrefix"];
    let current_date_section = format!(
        "{}\n{}",
        cp["currentDateHeading"].as_str().unwrap_or_default(),
        cp["currentDateLine"]
            .as_str()
            .unwrap_or_default()
            .replace("{date}", &format_local_iso_date())
    );
    let body = [
        cp["intro"].as_str().unwrap_or_default(),
        current_date_section.as_str(),
        "",
        cp["outro"].as_str().unwrap_or_default(),
    ]
    .join("\n");
    json!({
        "role": "user",
        "content": [{
            "type": "text",
            "text": format!(
                "{}{body}{}",
                data["systemReminder"]["open"].as_str().unwrap_or_default(),
                data["systemReminder"]["close"].as_str().unwrap_or_default()
            ),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_plan_system_has_three_official_blocks() {
        let env = super::super::identity::env_prompt_info();
        let blocks = build_start_plan_system(None, Some("glm-5.3"), &env, Some("zai"));
        assert!(blocks.len() >= 3);
        assert!(blocks[0]["text"].as_str().unwrap().starts_with("You are ZCode"));
        assert_eq!(blocks[0]["cache_control"]["type"], "ephemeral");
        let dyn_text = blocks[2]["text"].as_str().unwrap();
        assert!(dyn_text.starts_with("\n\n"));
        assert!(dyn_text.contains("zai-api/glm-5.3"));
    }

    #[test]
    fn context_prefix_wraps_system_reminder() {
        let msg = build_context_prefix_message();
        let text = msg["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("<system-reminder>"));
        assert!(text.ends_with("</system-reminder>"));
        assert!(text.contains(&format_local_iso_date()));
    }
}
