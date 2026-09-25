//! HTTP server bootstrap with routing and proxy API key auth.
//! Ported from zcode-api `src/server/server.ts` onto axum.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;

use super::handler::{handle_completion, handle_list_models, Format, GatewayContext};
use super::signing::ct_eq;

pub struct GatewayState {
    pub ctx: Arc<GatewayContext>,
    pub api_key: Option<String>,
}

fn cors_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("access-control-allow-origin", "*"),
        ("access-control-allow-methods", "GET, POST, OPTIONS"),
        (
            "access-control-allow-headers",
            "Content-Type, Authorization, x-api-key, anthropic-version, anthropic-beta",
        ),
        ("access-control-max-age", "86400"),
    ]
}

async fn cors_layer(req: Request<axum::body::Body>, next: Next) -> Response {
    if req.method() == axum::http::Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        for (k, v) in cors_headers() {
            resp.headers_mut().insert(
                axum::http::HeaderName::from_static(k),
                axum::http::HeaderValue::from_static(v),
            );
        }
        return resp;
    }
    let mut resp = next.run(req).await;
    for (k, v) in cors_headers() {
        resp.headers_mut().insert(
            axum::http::HeaderName::from_static(k),
            axum::http::HeaderValue::from_static(v),
        );
    }
    resp
}

/// Constant-time proxy key check (audit parity with the TS implementation):
/// a plain `==` is a timing side channel on non-loopback deployments.
fn check_proxy_key(auth_header: &str, expected: &str) -> bool {
    let trimmed = auth_header.trim();
    let presented = trimmed.strip_prefix("Bearer ").map(str::trim).unwrap_or(trimmed);
    ct_eq(presented.as_bytes(), expected.as_bytes())
}

async fn auth_layer(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(expected) = state.api_key.clone().filter(|k| !k.is_empty()) {
        let provided = req
            .headers()
            .get("authorization")
            .or_else(|| req.headers().get("x-api-key"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        match provided {
            Some(h) if check_proxy_key(&h, &expected) => {}
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    axum::Json(json!({
                        "error": { "type": "authentication_error", "message": "Invalid or missing proxy API key" }
                    })),
                )
                    .into_response();
            }
        }
    }
    next.run(req).await
}

async fn health(State(state): State<Arc<GatewayState>>) -> Response {
    let pool = state.ctx.pool.snapshot().await;
    let usable = pool.entries.iter().filter(|e| e.unusable_reason.is_empty()).count();
    (
        StatusCode::OK,
        axum::Json(json!({
            "status": "ok",
            "service": "zcode-switch-gateway",
            "accounts": { "total": pool.entries.len(), "usable": usable },
        })),
    )
        .into_response()
}

async fn gw_status(State(state): State<Arc<GatewayState>>) -> Response {
    let pool = state.ctx.pool.status().await;
    (
        StatusCode::OK,
        axum::Json(json!({ "accounts": pool })),
    )
        .into_response()
}

async fn chat_completions(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let inbound = to_reqwest_headers(&headers);
    handle_completion(&state.ctx, &inbound, Some(body), Format::OpenAi).await
}

async fn messages(
    State(state): State<Arc<GatewayState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let inbound = to_reqwest_headers(&headers);
    handle_completion(&state.ctx, &inbound, Some(body), Format::Anthropic).await
}

fn to_reqwest_headers(headers: &axum::http::HeaderMap) -> reqwest::header::HeaderMap {
    let mut out = reqwest::header::HeaderMap::with_capacity(headers.len());
    for (k, v) in headers.iter() {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            out.insert(name, val);
        }
    }
    out
}

pub fn build_router(state: Arc<GatewayState>) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/health", get(health))
        .route("/gw/status", get(gw_status))
        .route("/v1/models", get(handle_list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/messages", post(messages))
        .layer(middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(middleware::from_fn(cors_layer))
        .with_state(state)
}
