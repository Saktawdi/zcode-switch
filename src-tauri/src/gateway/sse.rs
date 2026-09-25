//! SSE event translator — converts an Anthropic SSE stream into OpenAI SSE
//! chunks on the fly. Ported from zcode-api `src/translator/sse-translator.ts`
//! (`anthropicSseToOpenaiSse` + `translateEvent`).
//!
//! The reverse direction (OpenAI SSE → Anthropic SSE) is never exercised:
//! both plan tiers speak Anthropic upstream, and Anthropic clients take the
//! passthrough path.

use std::collections::HashMap;

use serde_json::{json, Value};

use super::translate::{anthropic_usage_to_openai, map_stop_reason_to_finish_reason};

/// Locate the earliest SSE frame boundary (blank line in any of the three
/// line-ending styles) — a CRLF-only upstream never produces a `\n\n`
/// boundary, so a plain `find("\n\n")` would buffer forever.
fn next_frame_boundary(buf: &str) -> Option<(usize, usize)> {
    let a = buf.find("\r\n\r\n").map(|i| (i, i + 4));
    let b = buf.find("\n\n").map(|i| (i, i + 2));
    let c = buf.find("\r\r").map(|i| (i, i + 2));
    [a, b, c].into_iter().flatten().min_by_key(|(s, _)| *s)
}

pub struct ParsedSse {
    pub data: Value,
}

/// Parse a raw SSE frame into JSON payloads (event type is not needed — the
/// Anthropic stream carries `type` inside `data`).
pub fn parse_sse_chunk(raw: &str) -> Vec<ParsedSse> {
    let mut results = vec![];
    for line in raw.lines() {
        let Some(rest) = line.strip_prefix("data:") else { continue };
        // SSE spec: the colon may be followed by at most ONE space.
        let data = rest.strip_prefix(' ').unwrap_or(rest);
        if data.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(data) {
            results.push(ParsedSse { data: v });
        }
    }
    results
}

#[derive(Default)]
struct AnthropicUsage {
    input_tokens: u64,
    output_tokens: u64,
    cache_read: Option<u64>,
    cache_creation: Option<u64>,
}

impl AnthropicUsage {
    /// Fold an incremental usage report into the running snapshot. Overwrite
    /// (not accumulate) semantics: the upstream re-reports absolute totals.
    fn merge(&mut self, patch: Option<&Value>) {
        let Some(patch) = patch else { return };
        if let Some(v) = patch.get("input_tokens").and_then(|v| v.as_u64()) {
            self.input_tokens = v;
        }
        if let Some(v) = patch.get("output_tokens").and_then(|v| v.as_u64()) {
            self.output_tokens = v;
        }
        if let Some(v) = patch.get("cache_read_input_tokens").and_then(|v| v.as_u64()) {
            self.cache_read = Some(v);
        }
        if let Some(v) = patch.get("cache_creation_input_tokens").and_then(|v| v.as_u64()) {
            self.cache_creation = Some(v);
        }
    }

    fn to_value(&self) -> Value {
        let mut v = json!({
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        });
        if let Some(cr) = self.cache_read {
            v["cache_read_input_tokens"] = json!(cr);
        }
        if let Some(cc) = self.cache_creation {
            v["cache_creation_input_tokens"] = json!(cc);
        }
        v
    }
}

/// Streaming translation state.
pub struct SseTranslator {
    fallback_model: String,
    message_id: String,
    model: String,
    role_sent: bool,
    usage: AnthropicUsage,
    tool_call_index: u64,
    block_index_to_tool_call_index: HashMap<u64, u64>,
    finish_reason_sent: bool,
    buffer: String,
}

impl SseTranslator {
    pub fn new(fallback_model: &str) -> Self {
        SseTranslator {
            fallback_model: fallback_model.to_string(),
            message_id: String::new(),
            model: fallback_model.to_string(),
            role_sent: false,
            usage: AnthropicUsage::default(),
            tool_call_index: 0,
            block_index_to_tool_call_index: HashMap::new(),
            finish_reason_sent: false,
            buffer: String::new(),
        }
    }

    fn make_chunk(&self, delta: Value, finish_reason: Option<&str>, usage: Option<Value>) -> String {
        let mut chunk = json!({
            "id": if self.message_id.is_empty() { "chatcmpl-stream".to_string() } else { self.message_id.clone() },
            "object": "chat.completion.chunk",
            "created": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }],
        });
        if let Some(u) = usage {
            chunk["usage"] = u;
        }
        format!("data: {chunk}\n\n")
    }

    /// Feed raw upstream bytes (lossy-decoded text); returns translated OpenAI
    /// SSE chunks ready to forward.
    pub fn feed(&mut self, text: &str) -> Vec<String> {
        self.buffer.push_str(text);
        let mut out = vec![];
        while let Some((start, end)) = next_frame_boundary(&self.buffer) {
            let frame: String = self.buffer.drain(..end).collect();
            for parsed in parse_sse_chunk(&frame[..start]) {
                if let Some(chunk) = self.translate_event(parsed.data) {
                    out.push(chunk);
                }
            }
        }
        out
    }

    /// Flush any trailing frame (stream ended without a final blank line).
    pub fn finish(&mut self) -> Vec<String> {
        let mut out = vec![];
        let rest = std::mem::take(&mut self.buffer);
        if !rest.trim().is_empty() {
            for parsed in parse_sse_chunk(&rest) {
                if let Some(chunk) = self.translate_event(parsed.data) {
                    out.push(chunk);
                }
            }
        }
        out.push("data: [DONE]\n\n".to_string());
        out
    }

    fn translate_event(&mut self, data: Value) -> Option<String> {
        match data.get("type").and_then(|t| t.as_str())? {
            "message_start" => {
                let msg = data.get("message").cloned().unwrap_or(Value::Null);
                self.message_id = msg
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("msg_stream")
                    .to_string();
                if let Some(m) = msg.get("model").and_then(|m| m.as_str()).filter(|m| !m.is_empty()) {
                    self.model = m.to_string();
                }
                self.usage.merge(msg.get("usage"));
                if !self.role_sent {
                    self.role_sent = true;
                    return Some(self.make_chunk(json!({ "role": "assistant" }), None, None));
                }
                None
            }
            "content_block_start" => {
                let block = data.get("content_block").cloned().unwrap_or(Value::Null);
                let block_idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                if block.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    let my_index = self.tool_call_index;
                    self.tool_call_index += 1;
                    self.block_index_to_tool_call_index.insert(block_idx, my_index);
                    return Some(self.make_chunk(
                        json!({
                            "tool_calls": [{
                                "index": my_index,
                                "id": block.get("id").cloned().unwrap_or(Value::Null),
                                "type": "function",
                                "function": {
                                    "name": block.get("name").cloned().unwrap_or(Value::Null),
                                    "arguments": "",
                                },
                            }],
                        }),
                        None,
                        None,
                    ));
                }
                None
            }
            "content_block_delta" => {
                let delta = data.get("delta").cloned().unwrap_or(Value::Null);
                let block_idx = data.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                match delta.get("type").and_then(|t| t.as_str())? {
                    "text_delta" => Some(self.make_chunk(
                        json!({ "content": delta.get("text").cloned().unwrap_or(Value::Null) }),
                        None,
                        None,
                    )),
                    "thinking_delta" => Some(self.make_chunk(
                        json!({ "reasoning_content": delta.get("thinking").cloned().unwrap_or(Value::Null) }),
                        None,
                        None,
                    )),
                    "signature_delta" => None,
                    "input_json_delta" => {
                        let my_index = self.block_index_to_tool_call_index.get(&block_idx).copied()?;
                        Some(self.make_chunk(
                            json!({
                                "tool_calls": [{
                                    "index": my_index,
                                    "function": {
                                        "arguments": delta.get("partial_json").and_then(|p| p.as_str()).unwrap_or_default(),
                                    },
                                }],
                            }),
                            None,
                            None,
                        ))
                    }
                    _ => None,
                }
            }
            "message_delta" => {
                // Fold usage in *before* the stop_reason branch: this is the
                // only place the real input and cache counts ever arrive.
                self.usage.merge(data.get("usage"));
                let stop_reason = data
                    .pointer("/delta/stop_reason")
                    .and_then(|s| s.as_str())
                    .map(str::to_string);
                if let Some(reason) = stop_reason {
                    if !self.finish_reason_sent {
                        self.finish_reason_sent = true;
                        let finish = map_stop_reason_to_finish_reason(Some(&reason)).unwrap_or("stop");
                        return Some(self.make_chunk(
                            json!({}),
                            Some(finish),
                            Some(anthropic_usage_to_openai(Some(&self.usage.to_value()))),
                        ));
                    }
                }
                None
            }
            "message_stop" => {
                if self.finish_reason_sent {
                    return None;
                }
                self.finish_reason_sent = true;
                Some(self.make_chunk(
                    json!({}),
                    Some("stop"),
                    Some(anthropic_usage_to_openai(Some(&self.usage.to_value()))),
                ))
            }
            // ping / content_block_stop / unknown → no OpenAI output
            _ => None,
        }
    }
}

/// Convenience: current model for the in-flight translation (pre-message_start).
pub fn fallback_model(t: &SseTranslator) -> &str {
    &t.fallback_model
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: Vec<&str>) -> String {
        let mut t = SseTranslator::new("glm-4.6");
        let mut out = String::new();
        for c in chunks {
            for piece in t.feed(c) {
                out.push_str(&piece);
            }
        }
        for piece in t.finish() {
            out.push_str(&piece);
        }
        out
    }

    #[test]
    fn translates_full_stream() {
        let sse = vec![
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"glm-4.6\",\"usage\":{\"input_tokens\":10}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ];
        let out = run(sse);
        assert!(out.contains("\"role\": \"assistant\"") || out.contains("\"role\":\"assistant\""));
        assert!(out.contains("\"content\":\"hi\"") || out.contains("\"content\": \"hi\""));
        assert!(out.contains("\"finish_reason\":\"stop\"") || out.contains("\"finish_reason\": \"stop\""));
        assert!(out.contains("data: [DONE]"));
        // usage must be cache-inclusive
        assert!(out.contains("\"prompt_tokens\":10") || out.contains("\"prompt_tokens\": 10"));
        assert!(out.contains("\"completion_tokens\":2") || out.contains("\"completion_tokens\": 2"));
    }

    #[test]
    fn handles_crlf_frames_and_tool_calls() {
        let sse = vec![
            "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",\"model\":\"glm-4.6\"}}\r\n\r\n",
            "event: content_block_start\r\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t9\",\"name\":\"sh\"}}\r\n\r\n",
            "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"cmd\\\":\"}}\r\n\r\n",
            "event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n",
        ];
        let out = run(sse);
        assert!(out.contains("\"tool_calls\""));
        assert!(out.contains("\"name\":\"sh\"") || out.contains("\"name\": \"sh\""));
        assert!(out.contains("\"arguments\":\"{\\\"cmd\\\":\"") || out.contains("cmd\\"));
        assert!(out.contains("data: [DONE]"));
    }

    #[test]
    fn thinking_deltas_become_reasoning_content() {
        let out = run(vec![
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"aha\"}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        ]);
        assert!(out.contains("reasoning_content"));
    }
}
