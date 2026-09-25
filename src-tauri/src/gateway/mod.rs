//! Z·GATEWAY — embedded local API gateway, fusing zcode-api (ZCode Proxy)
//! into zcode-switch.
//!
//! Exposes the account pool as OpenAI / Anthropic compatible endpoints:
//!   - POST /v1/chat/completions  (OpenAI in, translated to the Anthropic
//!     upstream and back, streaming included)
//!   - POST /v1/messages          (Anthropic passthrough + body transforms)
//!   - GET  /v1/models            (pinned GLM catalog)
//!   - GET  /health, /gw/status
//!
//! Fusion features over the zcode-api original:
//!   - the upstream credential is not a single login but zcode-switch's whole
//!     account store (round-robin + failover with per-failure cooldowns);
//!   - every account's requests carry that account's own virtual device mid
//!     (fingerprint isolation), not one shared identity;
//!   - lifecycle is embedded in the Tauri app (settings toggle, port, key).

pub mod body;
pub mod captcha;
pub mod handler;
pub mod logs;
pub mod identity;
pub mod models;
pub mod pool;
pub mod prompt;
pub mod repair;
pub mod routing;
pub mod server;
pub mod signing;
pub mod sse;
pub mod translate;
pub mod upstream;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::store::{self, Paths};
use pool::AccountPool;

/// Default listen port. 8317 deliberately avoids clashing with the standalone
/// ZCode Proxy (8080) on machines that run both.
pub const DEFAULT_PORT: u16 = 8317;

#[derive(Debug, Clone, Serialize)]
pub struct GatewayConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub per_account_concurrency: u32,
}

impl GatewayConfig {
    pub fn from_settings(s: &store::Settings) -> Self {
        GatewayConfig {
            enabled: s.gateway_enabled(),
            host: "127.0.0.1".to_string(),
            port: s.gateway_port(),
            api_key: s.gateway_api_key(),
            per_account_concurrency: s.gateway_per_account_concurrency(),
        }
    }
}

struct GatewayRuntime {
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    ctx: Arc<handler::GatewayContext>,
    config: GatewayConfig,
}

static GATEWAY_RUNTIME: Mutex<Option<GatewayRuntime>> = Mutex::new(None);

fn runtime_cell() -> std::sync::MutexGuard<'static, Option<GatewayRuntime>> {
    GATEWAY_RUNTIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn build_context(per_account_concurrency: u32) -> handler::GatewayContext {
    let paths = Paths::detect();
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        // 两次读之间的空闲上限：上游假死（连接挂着不出字节）时兜底，
        // 保证请求日志终会落盘而不是永远悬挂。SSE 流式不受影响
        // （只限"间隔"，不限总时长）。
        .read_timeout(Duration::from_secs(300))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .expect("reqwest client builds");
    let pool = Arc::new(AccountPool::new(paths.home.clone()));
    let source_title = upstream::DEFAULT_SOURCE_TITLE;
    let referer = upstream::DEFAULT_REFERER_ORIGIN;

    let routing_client = http.clone();
    let control_mid = crate::quota::device_mid();
    let routing = routing::EndpointRoutingService::new(
        routing_client,
        Some("https://zcode.z.ai"),
        Arc::new(move |credential: Option<&str>| {
            let mut h = identity::build_control_identity_headers(source_title, referer, control_mid.as_deref());
            if let Some(cred) = credential {
                h.push(("x-api-key".into(), cred.to_string()));
            }
            h
        }),
    );

    let signing_client = http.clone();
    let signing = signing::SigningManager::new(
        signing_client,
        Some("https://zcode.z.ai"),
        identity::build_llm_identity_headers(source_title, referer),
    );
    handler::GatewayContext {
        pool,
        http,
        routing: Some(routing),
        signing: Some(signing),
        per_account_concurrency,
    }
}

/// Start the gateway server. Binds synchronously so port errors surface to
/// the caller; the serve loop runs on Tauri's async runtime.
pub async fn start(config: GatewayConfig) -> Result<(), String> {
    stop().await;
    let paths = Paths::detect();
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("端口 {addr} 监听失败：{e}"))?;

    let ctx = Arc::new(build_context(config.per_account_concurrency));
    let state = Arc::new(server::GatewayState {
        ctx: ctx.clone(),
        api_key: config
            .api_key
            .clone()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty()),
    });
    let router = server::build_router(state);

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tauri::async_runtime::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.changed().await;
            })
            .await;
    });

    // coding-plan key 自愈循环（随网关生命周期）
    {
        let home = paths.home.clone();
        let repair_rx = shutdown_tx.subscribe();
        tauri::async_runtime::spawn(async move {
            repair::run_loop(home, repair_rx).await;
        });
    }

    *runtime_cell() = Some(GatewayRuntime {
        shutdown_tx,
        ctx,
        config,
    });
    Ok(())
}

/// Stop the running gateway (no-op when not running).
pub async fn stop() {
    let runtime = runtime_cell().take();
    if let Some(rt) = runtime {
        let _ = rt.shutdown_tx.send(true);
        // Give the graceful shutdown a moment; requests in flight may finish.
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
}

/// Apply a desired config: start / stop / restart as needed. Returns whether
/// the gateway is running afterwards.
pub async fn apply(config: GatewayConfig) -> Result<bool, String> {
    if config.enabled {
        start(config).await?;
        Ok(true)
    } else {
        stop().await;
        Ok(false)
    }
}

/// True when the gateway server is currently running.
pub fn is_running() -> bool {
    runtime_cell().is_some()
}

/// Serializable status snapshot for the UI. Careful not to hold the std
/// mutex guard across awaits (the future must stay Send for Tauri commands).
pub async fn status_value() -> Value {
    let live = {
        let runtime = runtime_cell();
        runtime
            .as_ref()
            .map(|rt| (rt.config.clone(), rt.ctx.pool.clone()))
    };
    let Some((config, pool)) = live else {
        let cfg = GatewayConfig::from_settings(&store::load_settings(&Paths::detect()));
        return serde_json::json!({
            "running": false,
            "enabled": cfg.enabled,
            "port": cfg.port,
            "apiKeySet": cfg.api_key.as_deref().map(|k| !k.trim().is_empty()).unwrap_or(false),
            "perAccountConcurrency": cfg.per_account_concurrency,
        });
    };
    let accounts = pool.status().await;
    serde_json::json!({
        "running": true,
        "enabled": config.enabled,
        "host": config.host,
        "port": config.port,
        "apiKeySet": config.api_key.as_deref().map(|k| !k.trim().is_empty()).unwrap_or(false),
        "perAccountConcurrency": config.per_account_concurrency,
        "captchaPending": captcha::interactive_pending(),
        "captchaPool": { "size": captcha::pool_len(), "min": captcha::POOL_MIN, "max": captcha::POOL_MAX, "urgent": captcha::urgent() },
        "accounts": accounts,
    })
}

/// Pool-only status (works even when the server is stopped, for UI previews).
pub async fn pool_status_value() -> Value {
    let paths = Paths::detect();
    let pool = AccountPool::new(paths.home);
    let entries = pool.status().await;
    serde_json::json!({ "accounts": entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_from_settings_defaults() {
        let s = store::Settings::default();
        let cfg = GatewayConfig::from_settings(&s);
        assert!(!cfg.enabled);
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert!(cfg.api_key.is_none());
    }
}

#[cfg(test)]
mod smoke_tests {
    use super::*;
    use serde_json::json;

    /// End-to-end smoke: bind a real server on an ephemeral port and hit the
    /// routes. The account pool is empty on test machines, so chat requests
    /// must fail closed with 503 + a reason.
    #[tokio::test]
    async fn server_smoke() {
        // Isolate the account store so tests never touch real credentials
        // or the real upstream.
        let sandbox = std::env::temp_dir().join(format!("zsw-gw-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(sandbox.join("accounts")).unwrap();
        std::env::set_var("ZCODE_SWITCH_HOME", &sandbox);
        let ctx = Arc::new(build_context(3));
        let state = Arc::new(server::GatewayState { ctx, api_key: None });
        let router = server::build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let client = reqwest::Client::new();
        let health: Value = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(health["status"], "ok");

        let models = client.get(format!("http://{addr}/v1/models")).send().await.unwrap();
        assert!(models.status().is_success());
        let models_json: Value = models.json().await.unwrap();
        assert_eq!(models_json["object"], "list");
        assert!(models_json["data"].as_array().unwrap().len() >= 10);

        let chat = client
            .post(format!("http://{addr}/v1/chat/completions"))
            .json(&json!({ "model": "glm-4.6", "messages": [{ "role": "user", "content": "hi" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(chat.status().as_u16(), 503);
        let body: Value = chat.json().await.unwrap();
        assert!(body["error"]["message"].as_str().unwrap().contains("账号池"));

        // Anthropic route answers in the anthropic error envelope.
        let msg = client
            .post(format!("http://{addr}/v1/messages"))
            .header("anthropic-version", "2023-06-01")
            .json(&json!({ "model": "glm-4.6", "max_tokens": 16, "messages": [{ "role": "user", "content": "hi" }] }))
            .send()
            .await
            .unwrap();
        assert_eq!(msg.status().as_u16(), 503);
        let body: Value = msg.json().await.unwrap();
        assert!(body["error"]["type"].as_str().is_some());

        // Empty OpenAI body → 400 translation_failed.
        let bad = client
            .post(format!("http://{addr}/v1/chat/completions"))
            .body("")
            .send()
            .await
            .unwrap();
        assert_eq!(bad.status().as_u16(), 400);
    }

    /// With an API key set, requests without the key are rejected 401 before
    /// touching the pool.
    #[tokio::test]
    async fn server_requires_api_key() {
        let sandbox = std::env::temp_dir().join(format!("zsw-gw-test-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(sandbox.join("accounts")).unwrap();
        std::env::set_var("ZCODE_SWITCH_HOME", &sandbox);
        let ctx = Arc::new(build_context(3));
        let state = Arc::new(server::GatewayState { ctx, api_key: Some("sk-secret".into()) });
        let router = server::build_router(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = reqwest::Client::new();
        let denied = client.get(format!("http://{addr}/health")).send().await.unwrap();
        assert_eq!(denied.status().as_u16(), 401);
        let ok = client
            .get(format!("http://{addr}/health"))
            .header("authorization", "Bearer sk-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(ok.status().as_u16(), 200);
        let ok2 = client
            .get(format!("http://{addr}/health"))
            .header("x-api-key", "sk-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(ok2.status().as_u16(), 200);
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;
    use crate::gateway::pool::{AccountPool, PoolEntry};
    use serde_json::json;
    use std::sync::Arc as StdArc;

    fn mock_entry(messages_url: String) -> PoolEntry {
        PoolEntry {
            account_id: "mock-1".into(),
            name: "Mock Account".into(),
            provider: "zai".into(),
            plan: "coding-plan".into(),
            credential: "key.secret".into(),
            jwt: String::new(),
            device_mid: Some("11111111-2222-3333-4444-555555555555".into()),
            messages_url,
            excluded: false,
            unusable_reason: String::new(),
        }
    }

    fn pool_with_entry(entry: PoolEntry) -> StdArc<AccountPool> {
        let sandbox = std::env::temp_dir().join(format!("zsw-gw-mock-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(sandbox.join("accounts")).unwrap();
        std::env::set_var("ZCODE_SWITCH_HOME", &sandbox);
        let mut pool = AccountPool::new(sandbox.clone());
        pool.inject_snapshot_for_tests(vec![entry]);
        Arc::new(pool)
    }

    fn ctx_with(pool: StdArc<AccountPool>) -> Arc<handler::GatewayContext> {
        Arc::new(handler::GatewayContext {
            pool,
            http: reqwest::Client::new(),
            routing: None,
            signing: None,
            per_account_concurrency: 3,
        })
    }

    async fn spawn_mock() -> String {
        let app = axum::Router::new().route(
            "/v1/messages",
            axum::routing::post(|body: String| async move {
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap_or(json!({}));
                let model = parsed.get("model").cloned().unwrap_or(json!("glm-4.6"));
                // 验证网关注入的 metadata.user_id 存在（融合 body transform）
                assert!(parsed.get("metadata").and_then(|m| m.get("user_id")).is_some(), "metadata.user_id must be injected");
                if parsed.get("stream") == Some(&json!(true)) {
                    let sse = "event: message_start\n\
data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_mock\",\"model\":\"glm-4.6\",\"usage\":{\"input_tokens\":10}}}\n\n\
event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello from mock\"}}\n\n\
event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
                    axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .body(axum::body::Body::from(sse))
                        .unwrap()
                } else {
                    axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(json!({
                            "id": "msg_mock", "type": "message", "role": "assistant",
                            "content": [{ "type": "text", "text": "hello from mock" }],
                            "model": model, "stop_reason": "end_turn", "stop_sequence": null,
                            "usage": { "input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 3 }
                        }).to_string()))
                        .unwrap()
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { let _ = axum::serve(listener, app).await; });
        format!("http://{addr}")
    }

    /// OpenAI batch: request translated up, response translated back.
    #[tokio::test]
    async fn openai_batch_roundtrip() {
        let base = spawn_mock().await;
        let pool = pool_with_entry(mock_entry(format!("{base}/v1/messages")));
        let ctx = ctx_with(pool);
        let headers = reqwest::header::HeaderMap::new();
        let body = json!({
            "model": "glm-4.6",
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 100
        }).to_string();
        let resp = handler::handle_completion(&ctx, &headers, Some(body), handler::Format::OpenAi, "/v1/chat/completions").await;
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["choices"][0]["message"]["content"], "hello from mock");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 13);
        assert_eq!(out["usage"]["completion_tokens"], 5);
    }

    /// OpenAI streaming: Anthropic SSE upstream becomes OpenAI chunks.
    #[tokio::test]
    async fn openai_stream_roundtrip() {
        let base = spawn_mock().await;
        let pool = pool_with_entry(mock_entry(format!("{base}/v1/messages")));
        let ctx = ctx_with(pool);
        let headers = reqwest::header::HeaderMap::new();
        let body = json!({
            "model": "glm-4.6",
            "stream": true,
            "messages": [{ "role": "user", "content": "hi" }]
        }).to_string();
        let resp = handler::handle_completion(&ctx, &headers, Some(body), handler::Format::OpenAi, "/v1/chat/completions").await;
        assert_eq!(resp.status().as_u16(), 200);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("chat.completion.chunk"));
        assert!(text.contains("hello from mock"));
        assert!(text.contains("[DONE]"));
        assert!(text.contains("x-zswitch") || text.contains("\"usage\""));
    }

    /// Anthropic passthrough: native clients get the upstream body untouched.
    #[tokio::test]
    async fn anthropic_passthrough() {
        let base = spawn_mock().await;
        let pool = pool_with_entry(mock_entry(format!("{base}/v1/messages")));
        let ctx = ctx_with(pool);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("anthropic-version", reqwest::header::HeaderValue::from_static("2023-06-01"));
        let body = json!({
            "model": "glm-5.3",
            "max_tokens": 128,
            "messages": [{ "role": "user", "content": "hi" }]
        }).to_string();
        let resp = handler::handle_completion(&ctx, &headers, Some(body), handler::Format::Anthropic, "/v1/messages").await;
        assert_eq!(resp.status().as_u16(), 200);
        let account_header = resp
            .headers()
            .get("x-zswitch-account")
            .map(|v| v.to_str().unwrap().to_string());
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(out["type"], "message");
        assert_eq!(out["content"][0]["text"], "hello from mock");
        // account observability header rides the response
        assert_eq!(account_header.as_deref(), Some("Mock Account"));
    }
}
