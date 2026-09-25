//! Provider endpoint routing — port of zcode-api
//! `src/proxy/endpoint-routing.ts` (ZCode 3.7+
//! `ProviderEndpointRoutingService`).
//!
//! The desktop client periodically fetches
//! `GET https://zcode.z.ai/api/v1/agent/configs` and rewrites provider request
//! URLs according to the returned `data.proxyEndpoint.mapping` table
//! (`from` → `to`, exact normalized-URL match). As of 2026-08 the server maps
//! the coding-plan Anthropic endpoints to `zcode.z.ai/api/v1/ultra[-zai]/…`;
//! the table is server-controlled and resolution is generic.
//!
//! Failure semantics are strictly fail-open: any fetch/parse error keeps the
//! previous snapshot and requests go to their original URL after a cooldown.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;

const DEFAULT_ORIGIN: &str = "https://zcode.z.ai";
const CONFIG_PATH: &str = "/api/v1/agent/configs";
const SUCCESS_TTL: Duration = Duration::from_secs(300);
const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_MAPPING_ENTRIES: usize = 256;

pub struct EndpointRoutingService {
    client: reqwest::Client,
    config_url: String,
    identity: Arc<dyn Fn(Option<&str>) -> Vec<(String, String)> + Send + Sync>,
    state: tokio::sync::Mutex<RoutingState>,
}

struct RoutingState {
    snapshot: Option<Snapshot>,
    retry_after: Instant,
}

struct Snapshot {
    expires_at: Instant,
    mapping: HashMap<String, String>,
}

fn normalize_path(path: &str) -> String {
    if path == "/" {
        return "/".to_string();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Routing key: `${protocol}//${hostname.toLowerCase()}:${port}${normalizedPath}`
/// (default port 443).
fn routing_key(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.split('@').next_back().unwrap_or(authority);
    let default_port = if scheme == "https" { "443" } else { "80" };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, p),
        Some(_) => (authority, default_port),
        None => (authority, default_port),
    };
    Some(format!("{scheme}://{}:{port}{}", host.to_ascii_lowercase(), normalize_path(path)))
}

fn parse_plain_https_url(value: &Value) -> Option<String> {
    let s = value.as_str()?;
    let (scheme, rest) = s.split_once("://")?;
    if scheme != "https" {
        return None;
    }
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return None;
    }
    Some(s.to_string())
}

impl EndpointRoutingService {
    /// `identity_headers` is a closure producing the control-plane (`TV`)
    /// header set, parameterized by the optional `x-api-key` credential.
    pub fn new(
        client: reqwest::Client,
        origin: Option<&str>,
        identity_headers: Arc<dyn Fn(Option<&str>) -> Vec<(String, String)> + Send + Sync>,
    ) -> Self {
        let base = origin
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .unwrap_or(DEFAULT_ORIGIN);
        EndpointRoutingService {
            client,
            config_url: format!("{}{CONFIG_PATH}", base.trim_end_matches('/')),
            identity: identity_headers,
            state: tokio::sync::Mutex::new(RoutingState {
                snapshot: None,
                retry_after: Instant::now(),
            }),
        }
    }

    /// Resolve a request URL through the mapping table. Never fails: any
    /// error resolves to the original URL (fail-open).
    pub async fn resolve(&self, url: &str, credential: Option<&str>) -> (bool, String) {
        let Some(key) = routing_key(url) else {
            return (false, url.to_string());
        };
        {
            let st = self.state.lock().await;
            if let Some(snap) = &st.snapshot {
                if snap.expires_at > Instant::now() {
                    if let Some(target) = snap.mapping.get(&key) {
                        // preserve the original query string
                        let query = url.split_once('?').map(|(_, q)| q).unwrap_or_default();
                        let out = if query.is_empty() {
                            target.clone()
                        } else if target.contains('?') {
                            format!("{target}&{query}")
                        } else {
                            format!("{target}?{query}")
                        };
                        return (true, out);
                    }
                    return (false, url.to_string());
                }
            }
            if st.retry_after > Instant::now() {
                return (false, url.to_string());
            }
        }
        self.refresh(credential).await;
        let st = self.state.lock().await;
        if let Some(snap) = &st.snapshot {
            if let Some(target) = snap.mapping.get(&key) {
                let query = url.split_once('?').map(|(_, q)| q).unwrap_or_default();
                let out = if query.is_empty() {
                    target.clone()
                } else if target.contains('?') {
                    format!("{target}&{query}")
                } else {
                    format!("{target}?{query}")
                };
                return (true, out);
            }
        }
        (false, url.to_string())
    }

    async fn refresh(&self, credential: Option<&str>) {
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in (self.identity)(credential) {
            if let (Ok(name), Ok(val)) = (reqwest::header::HeaderName::try_from(k.as_str()), reqwest::header::HeaderValue::try_from(v.as_str())) {
                headers.insert(name, val);
            }
        }
        headers.insert(
            reqwest::header::HeaderName::from_static("accept"),
            reqwest::header::HeaderValue::from_static("application/json"),
        );        let result = self
            .client
            .get(&self.config_url)
            .headers(headers)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await;
        let mapping = match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
                Ok(parsed)
                    if parsed.get("code").and_then(|c| c.as_i64()) == Some(0) =>
                {
                    parse_mapping(&parsed)
                }
                _ => None,
            },
            _ => None,
        };
        let mut st = self.state.lock().await;
        match mapping {
            Some(map) => {
                st.snapshot = Some(Snapshot {
                    expires_at: Instant::now() + SUCCESS_TTL,
                    mapping: map,
                });
                st.retry_after = Instant::now();
            }
            None => {
                st.retry_after = Instant::now() + FAILURE_COOLDOWN;
            }
        }
    }
}

fn parse_mapping(parsed: &Value) -> Option<HashMap<String, String>> {
    let entries = parsed.pointer("/data/proxyEndpoint/mapping")?.as_array()?;
    if entries.len() > MAX_MAPPING_ENTRIES {
        return None;
    }
    let mut map = HashMap::new();
    for entry in entries {
        let from = parse_plain_https_url(entry.get("from")?)?;
        let to = parse_plain_https_url(entry.get("to")?)?;
        let key = routing_key(&from)?;
        if map.contains_key(&key) {
            return None; // duplicate from → treat the whole snapshot as invalid
        }
        map.insert(key, to);
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_key_normalization() {
        assert_eq!(
            routing_key("https://api.z.ai/api/anthropic/v1/messages").as_deref(),
            Some("https://api.z.ai:443/api/anthropic/v1/messages")
        );
        assert_eq!(
            routing_key("https://API.Z.AI:443/api/anthropic/v1/messages/").as_deref(),
            Some("https://api.z.ai:443/api/anthropic/v1/messages")
        );
        assert_eq!(
            routing_key("http://example.com:8080/x").as_deref(),
            Some("http://example.com:8080/x")
        );
        assert!(routing_key("not-a-url").is_none());
    }

    #[test]
    fn mapping_parse() {
        let v: Value = serde_json::json!({
            "code": 0,
            "data": { "proxyEndpoint": { "mapping": [
                { "from": "https://api.z.ai/api/anthropic/v1/messages",
                  "to": "https://zcode.z.ai/api/v1/ultra-zai/v1/messages" }
            ]}}
        });
        let map = parse_mapping(&v).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("https://api.z.ai:443/api/anthropic/v1/messages"));
    }

    #[test]
    fn bad_mapping_is_fail_open() {
        let v: Value = serde_json::json!({
            "code": 0,
            "data": { "proxyEndpoint": { "mapping": [
                { "from": "http://insecure/x", "to": "https://ok/y" }
            ]}}
        });
        assert!(parse_mapping(&v).is_none());
    }
}
