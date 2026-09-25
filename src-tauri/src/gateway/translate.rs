//! OpenAI → Anthropic request translator and Anthropic → OpenAI response
//! translator. Ported from zcode-api `src/translator/openai-to-anthropic.ts`.
//!
//! Both plan tiers post an Anthropic-format upstream, so only this direction
//! is needed: OpenAI clients are translated on the way up and Anthropic →
//! OpenAI on the way down; Anthropic clients speak the upstream's native
//! format (passthrough).
//!
//! The TS implementation is duck-typed over JSON; here we operate on
//! `serde_json::Value` for the same lossless-for-unknown-fields behavior.

use serde_json::{json, Map, Value};

use super::models;

/// Extract the joined text of an OpenAI message content (string or parts).
fn extract_text(msg: &Value) -> String {
    match msg.get("content") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter(|c| c.get("type").and_then(|t| t.as_str()) == Some("text"))
            .filter_map(|c| c.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

fn parse_data_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("data:")?;
    let (meta, data) = rest.split_once(',')?;
    let media = meta.strip_suffix(";base64")?;
    if media.is_empty() || data.is_empty() {
        return None;
    }
    Some((media.to_string(), data.to_string()))
}

/// Map an OpenAI `image_url` string to an Anthropic image block: `data:` URLs
/// become base64 sources, http(s) URLs become url sources, anything else
/// degrades to a text block rather than a block the upstream would reject.
fn image_url_to_anthropic_block(url: &str) -> Value {
    if let Some((media_type, data)) = parse_data_url(url) {
        return json!({
            "type": "image",
            "source": { "type": "base64", "media_type": media_type, "data": data },
        });
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        return json!({ "type": "image", "source": { "type": "url", "url": url } });
    }
    json!({ "type": "text", "text": url })
}

fn content_part_to_anthropic(part: &Value) -> Value {
    match part.get("type").and_then(|t| t.as_str()) {
        Some("text") => json!({ "type": "text", "text": part.get("text").and_then(|t| t.as_str()).unwrap_or_default() }),
        Some("image_url") => {
            let url = part
                .pointer("/image_url/url")
                .and_then(|u| u.as_str())
                .unwrap_or_default();
            if url.is_empty() {
                json!({ "type": "text", "text": "" })
            } else {
                image_url_to_anthropic_block(url)
            }
        }
        _ => json!({ "type": "text", "text": "" }),
    }
}

/// Convert OpenAI message content into the Anthropic shape: string stays
/// string, null becomes "", parts map to blocks.
fn translate_content_openai_to_anthropic(msg: &Value) -> Value {
    match msg.get("content") {
        Some(Value::String(s)) => json!(s),
        Some(Value::Null) | None => json!(""),
        Some(Value::Array(parts)) => Value::Array(parts.iter().map(content_part_to_anthropic).collect()),
        _ => json!(""),
    }
}

fn parse_tool_arguments(raw: Option<&str>) -> Value {
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return json!({});
    };
    match serde_json::from_str::<Value>(raw) {
        Ok(v @ Value::Object(_)) => v,
        _ => json!({}),
    }
}

fn tool_result_content(msg: &Value) -> Value {
    match msg.get("content") {
        Some(Value::String(s)) => json!(s),
        Some(Value::Array(parts)) => {
            if parts.iter().all(|c| c.get("type").and_then(|t| t.as_str()) == Some("text")) {
                json!(parts
                    .iter()
                    .filter_map(|c| c.get("text").and_then(|t| t.as_str()))
                    .collect::<Vec<_>>()
                    .join(""))
            } else {
                Value::Array(parts.iter().map(content_part_to_anthropic).collect())
            }
        }
        _ => json!(""),
    }
}

fn translate_message_openai_to_anthropic(msg: &Value) -> Value {
    let tool_calls = msg.get("tool_calls").and_then(|t| t.as_array());
    if msg.get("role").and_then(|r| r.as_str()) == Some("assistant")
        && tool_calls.is_some_and(|t| !t.is_empty())
    {
        let mut blocks: Vec<Value> = vec![];
        let text = extract_text(msg);
        if !text.is_empty() {
            blocks.push(json!({ "type": "text", "text": text }));
        }
        for tc in tool_calls.unwrap() {
            blocks.push(json!({
                "type": "tool_use",
                "id": tc.get("id").cloned().unwrap_or(Value::Null),
                "name": tc.pointer("/function/name").cloned().unwrap_or(Value::Null),
                "input": parse_tool_arguments(tc.pointer("/function/arguments").and_then(|a| a.as_str())),
            }));
        }
        return json!({ "role": "assistant", "content": blocks });
    }
    let role = if msg.get("role").and_then(|r| r.as_str()) == Some("assistant") {
        "assistant"
    } else {
        "user"
    };
    json!({ "role": role, "content": translate_content_openai_to_anthropic(msg) })
}

/// Coalesce consecutive `role:"tool"` messages into a single Anthropic `user`
/// message with multiple `tool_result` blocks (Anthropic's expected shape for
/// parallel tool results).
fn translate_messages_with_tool_coalescing(messages: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    let mut i = 0;
    while i < messages.len() {
        let m = &messages[i];
        if m.get("role").and_then(|r| r.as_str()) == Some("tool")
            && m.get("tool_call_id").and_then(|t| t.as_str()).is_some_and(|t| !t.is_empty())
        {
            let mut results: Vec<Value> = vec![];
            while i < messages.len() {
                let tool = &messages[i];
                let Some(tool_call_id) = tool.get("tool_call_id").and_then(|t| t.as_str()) else {
                    break;
                };
                if tool.get("role").and_then(|r| r.as_str()) != Some("tool") {
                    break;
                }
                results.push(json!({
                    "type": "tool_result",
                    "tool_use_id": tool_call_id,
                    "content": tool_result_content(tool),
                }));
                i += 1;
            }
            out.push(json!({ "role": "user", "content": results }));
            continue;
        }
        out.push(translate_message_openai_to_anthropic(m));
        i += 1;
    }
    out
}

fn translate_tool_choice(choice: &Value) -> Option<Value> {
    match choice {
        Value::String(s) => match s.as_str() {
            "auto" => Some(json!({ "type": "auto" })),
            "required" => Some(json!({ "type": "any" })),
            _ => None,
        },
        Value::Object(_) => {
            if choice.get("type").and_then(|t| t.as_str()) == Some("function") {
                Some(json!({
                    "type": "tool",
                    "name": choice.pointer("/function/name").cloned().unwrap_or(Value::Null),
                }))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn explicit_thinking_config(req: &Map<String, Value>) -> Option<Value> {
    let explicit = req.get("thinking")?;
    if !explicit.is_object() {
        return None;
    }
    match explicit.get("type").and_then(|t| t.as_str()) {
        Some("disabled") => return Some(json!({ "type": "disabled" })),
        Some("enabled") | Some("adaptive") => {}
        _ => return None,
    }
    let budget = explicit
        .get("budget_tokens")
        .or_else(|| explicit.get("budgetTokens"))
        .and_then(|b| b.as_u64());
    let mut out = Map::new();
    out.insert("type".into(), json!(explicit.get("type").and_then(|t| t.as_str()).unwrap_or("enabled")));
    if let Some(b) = budget.filter(|b| *b > 0) {
        out.insert("budget_tokens".into(), json!(b));
    }
    if explicit.get("type").and_then(|t| t.as_str()) == Some("adaptive") {
        if let Some(display) = explicit.get("display").and_then(|d| d.as_bool()) {
            out.insert("display".into(), json!(display));
        }
    }
    Some(Value::Object(out))
}

/// Non-GLM-5.3 thinking translation: explicit config wins, then
/// `reasoning_effort:"none"` → disabled, then catalog reasoning models get
/// thinking enabled with the SDK's default 1024 budget.
fn translate_thinking(req: &Map<String, Value>, model: &str) -> Option<Value> {
    if let Some(explicit) = explicit_thinking_config(req) {
        return Some(explicit);
    }
    if req.get("reasoning_effort").and_then(|r| r.as_str()) == Some("none") {
        return Some(json!({ "type": "disabled" }));
    }
    if models::is_reasoning_model(model) {
        return Some(json!({ "type": "enabled", "budget_tokens": models::GLM53_MIN_THINKING_BUDGET }));
    }
    None
}

/// GLM-5.3 family: `output_config.effort` is the only channel the Anthropic
/// upstream honors, paired with a matching `thinking.budget_tokens`.
fn translate_glm53_reasoning(req: &Map<String, Value>, model: &str) -> Value {
    if let Some(explicit) = req.get("thinking").filter(|t| t.is_object()) {
        if explicit.get("type").and_then(|t| t.as_str()) == Some("disabled") {
            return json!({ "thinking": { "type": "disabled" } });
        }
    }
    let effort = models::normalize_glm53_effort(req.get("reasoning_effort").and_then(|r| r.as_str()));
    let mut budget = models::glm53_thinking_budget(effort);
    if let Some(explicit) = req.get("thinking").filter(|t| t.is_object()) {
        if matches!(
            explicit.get("type").and_then(|t| t.as_str()),
            Some("enabled") | Some("adaptive")
        ) {
            if let Some(explicit_budget) = explicit
                .get("budget_tokens")
                .or_else(|| explicit.get("budgetTokens"))
                .and_then(|b| b.as_f64())
            {
                let floored = explicit_budget.floor() as u64;
                if explicit_budget.is_finite() && floored > 0 {
                    budget = floored;
                }
            }
        }
    }
    let model_max = models::model_def(model).map(|m| m.max_output_tokens);
    let fitted = models::clamp_glm53_budget_to_model(budget, model_max);
    json!({
        "thinking": { "type": "enabled", "budget_tokens": fitted },
        "output_config": { "effort": effort.as_str() },
    })
}

/// Post-pass mirroring the bundle's anthropic request-builder compat rules,
/// applied AFTER thinking injection:
///   - thinking enabled → temperature/top_k/top_p voided, budget defaults to
///     1024 when missing, max_tokens += budget clamped to the model ceiling;
///   - no thinking + both temperature and top_p → top_p voided.
fn apply_anthropic_thinking_compat(result: &mut Map<String, Value>) {
    let thinking_enabled = result
        .get("thinking")
        .and_then(|t| t.get("type").and_then(|ty| ty.as_str()))
        .is_some_and(|ty| ty == "enabled" || ty == "adaptive");

    if !thinking_enabled {
        if result.contains_key("temperature") && result.contains_key("top_p") {
            result.remove("top_p");
        }
        return;
    }

    let budget = match result.get_mut("thinking").and_then(|t| t.get_mut("budget_tokens")) {
        Some(b) => match b.as_f64() {
            Some(v) if v.is_finite() && v > 0.0 => v as u64,
            _ => {
                *b = json!(models::GLM53_MIN_THINKING_BUDGET);
                models::GLM53_MIN_THINKING_BUDGET
            }
        },
        None => {
            let t = result.get_mut("thinking").unwrap();
            if let Some(obj) = t.as_object_mut() {
                obj.insert("budget_tokens".into(), json!(models::GLM53_MIN_THINKING_BUDGET));
            }
            models::GLM53_MIN_THINKING_BUDGET
        }
    };

    result.remove("temperature");
    result.remove("top_k");
    result.remove("top_p");

    let model = result.get("model").and_then(|m| m.as_str()).unwrap_or_default().to_string();
    let max_tokens = result.get("max_tokens").and_then(|m| m.as_u64()).unwrap_or(0);
    let mut new_max = max_tokens.saturating_add(budget);
    if let Some(model_max) = models::model_def(&model).map(|m| m.max_output_tokens) {
        new_max = new_max.min(model_max);
    }
    result.insert("max_tokens".into(), json!(new_max));
}

/// Translate an OpenAI chat request into an Anthropic messages request.
pub fn translate_request_openai_to_anthropic(req: &Value) -> Result<Value, String> {
    let obj = req
        .as_object()
        .ok_or_else(|| "OpenAI request body must be a JSON object".to_string())?;
    let model = obj
        .get("model")
        .and_then(|m| m.as_str())
        .ok_or_else(|| "OpenAI request is missing `model`".to_string())?
        .to_string();
    let messages = obj
        .get("messages")
        .and_then(|m| m.as_array())
        .ok_or_else(|| "OpenAI request is missing `messages`".to_string())?;

    let system_parts: Vec<String> = messages
        .iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
        .map(extract_text)
        .filter(|s| !s.is_empty())
        .collect();
    let non_system: Vec<&Value> = messages
        .iter()
        .filter(|m| m.get("role").and_then(|r| r.as_str()) != Some("system"))
        .collect();
    let non_system_refs: Vec<Value> = non_system.iter().map(|m| (*m).clone()).collect();

    let mut result = Map::new();
    result.insert("model".into(), json!(model));
    result.insert(
        "messages".into(),
        json!(translate_messages_with_tool_coalescing(&non_system_refs)),
    );
    let max_tokens = obj
        .get("max_tokens")
        .and_then(|m| m.as_u64())
        .unwrap_or_else(|| models::resolve_default_max_tokens(&model));
    result.insert("max_tokens".into(), json!(max_tokens));

    if !system_parts.is_empty() {
        result.insert("system".into(), json!(system_parts.join("\n\n")));
    }
    for key in ["temperature", "top_p"] {
        if let Some(v) = obj.get(key) {
            if !v.is_null() {
                result.insert(key.into(), v.clone());
            }
        }
    }
    if let Some(stream) = obj.get("stream").and_then(|s| s.as_bool()) {
        result.insert("stream".into(), json!(stream));
    }
    if let Some(stop) = obj.get("stop").filter(|s| !s.is_null()) {
        let arr = match stop {
            Value::String(s) => vec![json!(s)],
            Value::Array(a) => a.clone(),
            _ => vec![],
        };
        if !arr.is_empty() {
            result.insert("stop_sequences".into(), Value::Array(arr));
        }
    }

    if models::is_glm53_model(&model) {
        let pair = translate_glm53_reasoning(obj, &model);
        if let Some(t) = pair.get("thinking") {
            result.insert("thinking".into(), t.clone());
        }
        if let Some(oc) = pair.get("output_config") {
            result.insert("output_config".into(), oc.clone());
        }
    } else if let Some(t) = translate_thinking(obj, &model) {
        result.insert("thinking".into(), t);
    }
    apply_anthropic_thinking_compat(&mut result);

    let tools = obj.get("tools").and_then(|t| t.as_array());
    let tool_choice_none = obj.get("tool_choice").and_then(|t| t.as_str()) == Some("none");
    if let Some(tools) = tools.filter(|t| !t.is_empty()) {
        if !tool_choice_none {
            let translated: Vec<Value> = tools
                .iter()
                .map(|tool| {
                    let mut out = Map::new();
                    out.insert("name".into(), tool.pointer("/function/name").cloned().unwrap_or(Value::Null));
                    if let Some(desc) = tool.pointer("/function/description").filter(|d| !d.is_null()) {
                        out.insert("description".into(), desc.clone());
                    }
                    if let Some(params) = tool.pointer("/function/parameters").filter(|p| !p.is_null()) {
                        out.insert("input_schema".into(), params.clone());
                    }
                    Value::Object(out)
                })
                .collect();
            result.insert("tools".into(), Value::Array(translated));
        }
    }
    if !tool_choice_none {
        if let Some(choice) = obj.get("tool_choice").filter(|c| !c.is_null()) {
            if let Some(translated) = translate_tool_choice(choice) {
                result.insert("tool_choice".into(), translated);
            }
        }
    }

    Ok(Value::Object(result))
}

// ---------------------------------------------------------------------------
// Anthropic → OpenAI response translation
// ---------------------------------------------------------------------------

/// Convert an Anthropic usage block into OpenAI's cache-inclusive usage
/// semantics: prompt = input + cache_read + cache_creation.
pub fn anthropic_usage_to_openai(usage: Option<&Value>) -> Value {
    let usage = usage.cloned().unwrap_or(Value::Null);
    let input = usage.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let output = usage.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let cache_read = usage.get("cache_read_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let cache_creation = usage.get("cache_creation_input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let prompt = input + cache_read + cache_creation;

    let mut out = Map::new();
    out.insert("prompt_tokens".into(), json!(prompt));
    out.insert("completion_tokens".into(), json!(output));
    out.insert("total_tokens".into(), json!(prompt + output));
    // Presence-preserving: an upstream explicitly reporting 0 cache reads stays
    // distinguishable from one reporting no cache breakdown at all.
    if usage.get("cache_read_input_tokens").and_then(|v| v.as_u64()).is_some() {
        out.insert("prompt_tokens_details".into(), json!({ "cached_tokens": cache_read }));
    }
    Value::Object(out)
}

pub fn map_stop_reason_to_finish_reason(stop_reason: Option<&str>) -> Option<&'static str> {
    match stop_reason {
        Some("end_turn") | Some("stop_sequence") => Some("stop"),
        Some("max_tokens") => Some("length"),
        Some("tool_use") => Some("tool_calls"),
        _ => None,
    }
}

/// Translate an Anthropic messages response into an OpenAI chat completion.
pub fn translate_response_anthropic_to_openai(resp: &Value, model: &str) -> Result<Value, String> {
    let obj = resp
        .as_object()
        .ok_or_else(|| "Anthropic response must be an object".to_string())?;
    let content = obj
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| "Anthropic response is missing `content`".to_string())?;

    let text: String = content
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("text"))
        .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
        .collect::<Vec<_>>()
        .join("");
    let reasoning: String = content
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking"))
        .filter_map(|b| b.get("thinking").and_then(|t| t.as_str()))
        .collect::<Vec<_>>()
        .join("");
    let tool_uses: Vec<&Value> = content
        .iter()
        .filter(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
        .collect();

    let mut message = Map::new();
    message.insert("role".into(), json!("assistant"));
    message.insert("content".into(), if text.is_empty() { Value::Null } else { json!(text) });
    if !reasoning.is_empty() {
        message.insert("reasoning_content".into(), json!(reasoning));
    }
    if !tool_uses.is_empty() {
        let calls: Vec<Value> = tool_uses
            .iter()
            .map(|b| {
                json!({
                    "id": b.get("id").cloned().unwrap_or(Value::Null),
                    "type": "function",
                    "function": {
                        "name": b.get("name").cloned().unwrap_or(Value::Null),
                        "arguments": serde_json::to_string(b.get("input").unwrap_or(&json!({}))).unwrap_or_default(),
                    },
                })
            })
            .collect();
        message.insert("tool_calls".into(), Value::Array(calls));
    }

    let finish_reason = map_stop_reason_to_finish_reason(obj.get("stop_reason").and_then(|s| s.as_str()));

    let out = json!({
        "id": obj.get("id").cloned().unwrap_or(json!("chatcmpl-translated")),
        "object": "chat.completion",
        "created": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "model": model,
        "choices": [{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }],
        "usage": anthropic_usage_to_openai(obj.get("usage")),
    });
    Ok(out)
}

/// Build an OpenAI-format error envelope (used for translated error paths).
pub fn openai_error_body(message: &str, error_type: &str) -> Value {
    json!({ "error": { "type": error_type, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openai_to_anthropic_basic() {
        let req = json!({
            "model": "glm-5.3",
            "messages": [
                { "role": "system", "content": "be brief" },
                { "role": "user", "content": "hello" }
            ],
            "max_tokens": 100,
            "temperature": 0.5
        });
        let out = translate_request_openai_to_anthropic(&req).unwrap();
        assert_eq!(out["system"], "be brief");
        assert_eq!(out["messages"][0]["role"], "user");
        // glm-5.3: thinking injected, temperature voided, max_tokens += 32000 budget
        assert_eq!(out["thinking"]["type"], "enabled");
        assert_eq!(out["output_config"]["effort"], "max");
        assert!(out.get("temperature").is_none());
        assert_eq!(out["max_tokens"], json!(100u64 + 32_000u64).as_u64().unwrap().min(128_000));
    }

    #[test]
    fn tool_messages_coalesce() {
        let req = json!({
            "model": "glm-4.6",
            "messages": [
                { "role": "user", "content": "run it" },
                { "role": "assistant", "tool_calls": [{ "id": "c1", "type": "function", "function": { "name": "sh", "arguments": "{\"cmd\":\"ls\"}" } }] },
                { "role": "tool", "tool_call_id": "c1", "content": "a.txt" },
                { "role": "tool", "tool_call_id": "c2", "content": "b.txt" }
            ]
        });
        let out = translate_request_openai_to_anthropic(&req).unwrap();
        let msgs = out["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[1]["content"][0]["type"], "tool_use");
        assert_eq!(msgs[2]["role"], "user");
        assert_eq!(msgs[2]["content"].as_array().unwrap().len(), 2);
        assert_eq!(out["thinking"]["budget_tokens"], json!(1024u64));
    }

    #[test]
    fn anthropic_response_to_openai() {
        let resp = json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                { "type": "thinking", "thinking": "hmm" },
                { "type": "text", "text": "hi" },
                { "type": "tool_use", "id": "t1", "name": "sh", "input": { "cmd": "ls" } }
            ],
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 3 }
        });
        let out = translate_response_anthropic_to_openai(&resp, "glm-4.6").unwrap();
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "hi");
        assert_eq!(out["choices"][0]["message"]["reasoning_content"], "hmm");
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
        assert_eq!(out["choices"][0]["message"]["tool_calls"][0]["function"]["name"], "sh");
        assert_eq!(out["usage"]["prompt_tokens"], 13);
        assert_eq!(out["usage"]["prompt_tokens_details"]["cached_tokens"], 3);
    }
}
