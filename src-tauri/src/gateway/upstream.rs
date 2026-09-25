//! Upstream request builder — constructs the forwarded HTTP request.
//! Ported from zcode-api `src/proxy/upstream.ts` + `trace-headers.ts`.
//!
//! Both plan tiers post an Anthropic-format upstream:
//! - coding-plan → `{provider anthropic base}/v1/messages` with the dual
//!   `x-api-key` + `Authorization: Bearer` headers (bundle `ebo`);
//! - start-plan  → `https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages`
//!   with `Authorization: Bearer {jwt}`.
//!
//! The LLM User-Agent carries the `ai-sdk/anthropic/3.0.81` SDK suffix
//! (bundle `Cm`/`k0o`); control-plane fetches keep the bare `ZCode/…` UA.

use serde_json::Value;
use uuid::Uuid;

use super::identity;
use super::pool::PoolEntry;

pub const ANTHROPIC_VERSION: &str = "2023-06-01";
pub const ANTHROPIC_SDK_UA: &str = "ai-sdk/anthropic/3.0.81";

pub const DEFAULT_SOURCE_TITLE: &str = "cli";
pub const DEFAULT_REFERER_ORIGIN: &str = "https://zcode.z.ai";

/// Inbound headers that must never reach the upstream (spoofed V4 signing
/// values would either fail verification or silently disable proxy signing;
/// auth headers are regenerated per account).
const STRIP_HEADERS: &[&str] = &[
    "host",
    "authorization",
    "x-api-key",
    "anthropic-version",
    "content-length",
    "content-type",
    "connection",
    "proxy-authorization",
    "proxy-authenticate",
    "transfer-encoding",
    "accept-encoding",
    "x-request-id",
    "x-zcode-trace-id",
    "x-zcode-session-type",
    "x-query-id",
    "x-session-id",
    "x-client-ts",
    "x-client-version",
    "x-client-sig",
    "x-client-nonce",
    "x-app-id",
    "x-client-pow",
    "x-client-sign-verified",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
];

/// The only inbound header worth forwarding (anthropic-beta feature flags).
pub fn passthrough_header(inbound: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut out = vec![];
    for name in ["anthropic-beta"] {
        if let Some(v) = inbound.get(name).and_then(|v| v.to_str().ok()) {
            out.push((name.to_string(), v.to_string()));
        }
    }
    out
}

pub fn should_strip(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    STRIP_HEADERS.contains(&lower.as_str())
}

/// Trace/attribution headers mirroring the bundle's `Bdt`
/// (createModelRequestAttributionHeaders): x-request-id, x-zcode-session-type,
/// x-zcode-trace-id, plus x-query-id + x-session-id for coding-plan only
/// (start-plan never sends them).
fn trace_headers(plan: &str) -> Vec<(String, String)> {
    let mut h = vec![
        ("x-request-id".to_string(), Uuid::new_v4().to_string()),
        ("x-zcode-session-type".to_string(), "main".to_string()),
        ("x-zcode-trace-id".to_string(), Uuid::new_v4().to_string()),
    ];
    if plan != "start-plan" {
        h.push(("x-query-id".to_string(), Uuid::new_v4().to_string()));
        h.push(("x-session-id".to_string(), Uuid::new_v4().to_string()));
    }
    h
}

/// Build the complete upstream header list for one account attempt.
pub fn build_upstream_headers(
    entry: &PoolEntry,
    session_id: &str,
    inbound: &reqwest::header::HeaderMap,
    accept_encoding: &str,
) -> Vec<(String, String)> {
    let mut h: Vec<(String, String)> = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept-encoding".to_string(), accept_encoding.to_string()),
    ];
    h.extend(passthrough_header(inbound));
    // g6n LLM identity headers, then the SDK UA suffix (order: identity first
    // so the UA assignment below lands on the identity copy).
    let mut identity_headers = identity::build_llm_identity_headers(DEFAULT_SOURCE_TITLE, DEFAULT_REFERER_ORIGIN);
    for (k, v) in identity_headers.iter_mut() {
        if k == "User-Agent" {
            *v = format!("{v} {ANTHROPIC_SDK_UA}");
        }
    }
    h.extend(identity_headers);
    h.extend(trace_headers(&entry.plan));

    if entry.plan == "start-plan" {
        h.push(("authorization".to_string(), format!("Bearer {}", entry.jwt)));
    } else {
        // Bundle `ebo` (coding-plan, anthropic): x-api-key AND
        // `Authorization: Bearer {credential}` — both headers, same value.
        h.push(("x-api-key".to_string(), entry.credential.clone()));
        h.push(("authorization".to_string(), format!("Bearer {}", entry.credential)));
    }
    h.push(("anthropic-version".to_string(), ANTHROPIC_VERSION.to_string()));
    let _ = session_id;
    h
}

/// The `metadata.user_id` blob for this account's attempt.
pub fn metadata_user_id_for(entry: &PoolEntry, session_id: &str) -> String {
    super::body::build_anthropic_metadata_user_id(entry.device_mid.as_deref(), Some(session_id))
}

/// Extract (model, stream) from a request body without failing.
pub fn peek_meta(body: Option<&str>) -> (String, bool) {
    let Some(body) = body else { return ("-".to_string(), false) };
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return ("-".to_string(), false);
    };
    (
        v.get("model").and_then(|m| m.as_str()).unwrap_or("-").to_string(),
        v.get("stream").and_then(|s| s.as_bool()).unwrap_or(false),
    )
}

/// Build a JSON error response body in the Anthropic-error envelope shape.
pub fn error_body(error_type: &str, message: &str) -> Value {
    serde_json::json!({ "error": { "type": error_type, "message": message } })
}
