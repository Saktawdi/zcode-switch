//! Main gateway request pipeline — translate, transform, pick an account,
//! route, sign, forward, and translate back; with cross-account failover.
//!
//! Ported from zcode-api `src/proxy/handler.ts`, extended with the fusion
//! feature: the single-credential upstream is replaced by the zcode-switch
//! account pool (round-robin + failover on 401/402/403/429/5xx/network).

use std::sync::Arc;

use axum::response::IntoResponse;
use futures_util::StreamExt;
use serde_json::Value;

use super::body::transform_anthropic_body;
use super::identity::env_prompt_info;
use super::models;
use super::pool::{AccountPool, FailureKind, PoolEntry};
use super::routing::EndpointRoutingService;
use super::signing::SigningManager;
use super::sse::SseTranslator;
use super::translate::{translate_request_openai_to_anthropic, translate_response_anthropic_to_openai};
use super::upstream;

/// The inbound protocol the client speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    OpenAi,
    Anthropic,
}

pub struct GatewayContext {
    pub pool: Arc<AccountPool>,
    pub http: reqwest::Client,
    pub routing: Option<EndpointRoutingService>,
    pub signing: Option<SigningManager>,
    /// 每账号最大并发请求数（信号量许可数，默认 3）。
    pub per_account_concurrency: u32,
}

/// Incremental UTF-8 feeder — SSE text can split multibyte characters across
/// network chunks; hold back the incomplete tail instead of lossy-crushing it.
struct Utf8Feeder {
    buf: Vec<u8>,
}

impl Utf8Feeder {
    fn new() -> Self {
        Utf8Feeder { buf: Vec::new() }
    }

    fn feed(&mut self, chunk: &[u8]) -> String {
        self.buf.extend_from_slice(chunk);
        match std::str::from_utf8(&self.buf) {
            Ok(s) => {
                let out = s.to_string();
                self.buf.clear();
                out
            }
            Err(e) => {
                let valid = e.valid_up_to();
                let out = String::from_utf8_lossy(&self.buf[..valid]).to_string();
                self.buf.drain(..valid);
                out
            }
        }
    }

    fn finish(&mut self) -> String {
        let out = String::from_utf8_lossy(&self.buf).to_string();
        self.buf.clear();
        out
    }
}

/// Headers forwarded from the upstream response to the client.
const FORWARD_RESPONSE_HEADERS: &[&str] = &[
    "content-type",
    "content-encoding",
    "cache-control",
    "x-request-id",
    "anthropic-ratelimit-requests-limit",
    "anthropic-ratelimit-requests-remaining",
    "anthropic-ratelimit-requests-reset",
    "anthropic-ratelimit-tokens-limit",
    "anthropic-ratelimit-tokens-remaining",
    "anthropic-ratelimit-tokens-reset",
];

fn hs(name: &'static str) -> reqwest::header::HeaderName {
    reqwest::header::HeaderName::from_static(name)
}

fn hv_str(value: &str) -> Option<reqwest::header::HeaderValue> {
    // Header values must stay visible-ASCII: some clients choke on obs-text
    // even though the http crate would accept it. Non-ASCII account names
    // simply omit the observability header.
    if !value.is_ascii() {
        return None;
    }
    reqwest::header::HeaderValue::try_from(value.to_string()).ok()
}

fn base_response_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(hs("content-type"), reqwest::header::HeaderValue::from_static("application/json"));
    headers
}

fn finalize_headers(
    mut headers: reqwest::header::HeaderMap,
    upstream_headers: &reqwest::header::HeaderMap,
    account: &str,
    attempts: usize,
) -> reqwest::header::HeaderMap {
    for h in FORWARD_RESPONSE_HEADERS {
        if let Some(v) = upstream_headers.get(*h) {
            headers.insert(hs(h), v.clone());
        }
    }
    if let Some(val) = hv_str(account) {
        headers.insert(hs("x-zswitch-account"), val);
    }
    headers.insert(hs("x-zswitch-attempts"), reqwest::header::HeaderValue::from(attempts as u32));
    headers
}

fn json_response(status: u16, headers: reqwest::header::HeaderMap, body: Value) -> axum::response::Response {
    let body = axum::body::Body::from(body.to_string());
    let mut builder = axum::http::Response::builder().status(status);
    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }
    builder.body(body).unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn error_response(format: Format, status: u16, error_type: &str, message: &str) -> axum::response::Response {
    let body = match format {
        Format::OpenAi => super::translate::openai_error_body(message, error_type),
        Format::Anthropic => upstream::error_body(error_type, message),
    };
    json_response(status, base_response_headers(), body)
}

/// Failover-worthy upstream statuses: 401 (invalid/expired credential), 402
/// (quota exhausted), 403 (captcha challenge / blocked), 429 (rate limit),
/// 5xx (upstream issue). 400-class client errors are never failed over.
fn failure_kind_for_status(status: u16) -> Option<FailureKind> {
    match status {
        401 => Some(FailureKind::Unauthorized),
        402 => Some(FailureKind::PaymentRequired),
        403 => Some(FailureKind::Forbidden),
        429 => Some(FailureKind::RateLimited),
        s if s >= 500 => Some(FailureKind::ServerError),
        _ => None,
    }
}

/// Max distinct accounts tried per client request.
const MAX_ATTEMPTS: usize = 3;

/// Outcome of one account attempt.
enum AttemptOutcome {
    /// A response the client should receive — stop the failover loop.
    Terminal(axum::response::Response),
    /// Account busy at the per-account concurrency limit — try the next candidate.
    Busy,
    /// Try the next candidate, optionally updating the last-error snapshot.
    Next(Option<(u16, String, String)>),
}

pub async fn handle_completion(
    ctx: &GatewayContext,
    inbound_headers: &reqwest::header::HeaderMap,
    body: Option<String>,
    format: Format,
    route: &str,
) -> axum::response::Response {
    let started = std::time::Instant::now();
    // 请求日志：attempt 过程中填充账号/状态，函数尾部落盘（内存环 + 文件）。
    let log = std::sync::Arc::new(std::sync::Mutex::new(super::logs::GatewayLogEntry {
        ts: chrono::Utc::now().timestamp_millis(),
        route: route.to_string(),
        format: match format { Format::OpenAi => "openai".into(), Format::Anthropic => "anthropic".into() },
        model: "-".into(),
        account: None,
        provider: None,
        plan: None,
        status: 0,
        ms: 0,
        attempts: 0,
        error: None,
    }));
    {
        let (model, _) = upstream::peek_meta(body.as_deref());
        log.lock().unwrap_or_else(|e| e.into_inner()).model = model;
    }
    // 1. Translate the request body into the Anthropic shape when the client
    //    speaks OpenAI; Anthropic clients pass through.
    let anthropic_body: Option<Value> = match format {
        Format::OpenAi => {
            let Some(raw) = body.as_deref().filter(|b| !b.is_empty()) else {
                return error_response(format, 400, "translation_failed", "OpenAI request body is empty; cannot translate.");
            };
            let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
                return error_response(format, 400, "translation_failed", "OpenAI request body is not valid JSON.");
            };
            match translate_request_openai_to_anthropic(&parsed) {
                Ok(v) => Some(v),
                Err(e) => {
                    return error_response(format, 400, "translation_failed", &format!("OpenAI→Anthropic translation failed: {e}"))
                }
            }
        }
        Format::Anthropic => body.as_deref().and_then(|b| serde_json::from_str(b).ok()),
    };
    let (model, _stream) = upstream::peek_meta(body.as_deref());

    // 2. Pick candidate accounts from the pool.
    let snap = ctx.pool.snapshot().await;
    let candidates = ctx.pool.pick_candidates(&snap, MAX_ATTEMPTS).await;
    if candidates.is_empty() {
        let msg = if snap.entries.is_empty() {
            "账号池为空：请先在 Z·SWITCH 中保存或登录至少一个账号".to_string()
        } else {
            let reasons: Vec<String> = snap
                .entries
                .iter()
                .filter(|e| !e.unusable_reason.is_empty())
                .map(|e| format!("{}: {}", e.name, e.unusable_reason))
                .collect();
            format!("账号池中没有可用账号。{}", reasons.join("；"))
        };
        return error_response(format, 503, "no_available_account", &msg);
    }

    let session_id = uuid::Uuid::new_v4().to_string();
    let env = env_prompt_info();
    let app_version = crate::quota::zcode_app_version();

    // Accept-encoding policy: translate mode must READ the body (force
    // identity); passthrough forwards the client's list so the upstream
    // compresses only when the client can decode it.
    let accept_encoding = match format {
        Format::OpenAi => "identity".to_string(),
        Format::Anthropic => inbound_headers
            .get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("gzip")
            .to_string(),
    };

    let mut last_error: Option<(u16, String, String)> = None;
    let mut attempts = 0usize;
    let mut busy_count = 0usize;
    let mut terminal: Option<axum::response::Response> = None;

    for entry in &candidates {
        if attempts >= MAX_ATTEMPTS {
            break;
        }
        attempts += 1;
        match run_attempt(ctx, entry, false, &log, &anthropic_body, &body, inbound_headers, &accept_encoding, &session_id, &env, &app_version, format, &model, attempts).await {
            AttemptOutcome::Terminal(resp) => {
                terminal = Some(resp);
                break;
            }
            AttemptOutcome::Busy => busy_count += 1,
            AttemptOutcome::Next(err) => {
                if let Some((st, _, msg)) = &err {
                    let mut l = log.lock().unwrap_or_else(|e| e.into_inner());
                    l.status = *st;
                    l.error = Some(msg.chars().take(200).collect());
                }
                last_error = err;
            }
        }
    }

    // 所有候选账号都到了并发上限：退回等待最优先（轮询起点）账号的空位，
    // 而不是立刻对客户端报错。
    if terminal.is_none() && busy_count == attempts {
        attempts += 1;
        match run_attempt(ctx, &candidates[0], true, &log, &anthropic_body, &body, inbound_headers, &accept_encoding, &session_id, &env, &app_version, format, &model, attempts).await {
            AttemptOutcome::Terminal(resp) => terminal = Some(resp),
            AttemptOutcome::Busy => {}
            AttemptOutcome::Next(err) => {
                if let Some((st, _, msg)) = &err {
                    let mut l = log.lock().unwrap_or_else(|e| e.into_inner());
                    l.status = *st;
                    l.error = Some(msg.chars().take(200).collect());
                }
                last_error = err;
            }
        }
    }

    {
        let mut l = log.lock().unwrap_or_else(|e| e.into_inner());
        l.attempts = attempts;
        l.ms = started.elapsed().as_millis() as u64;
        if l.status == 0 {
            l.status = 502;
        }
        super::logs::push(l.clone());
    }

    if let Some(resp) = terminal {
        return resp;
    }

    // 6. Every candidate failed — surface the last upstream error.
    let (status, etype, message) =
        last_error.unwrap_or((502, "upstream_error".to_string(), "all upstream attempts failed".to_string()));
    error_response(format, status, &etype, &message)
}

#[allow(clippy::too_many_arguments)]
async fn run_attempt(
    ctx: &GatewayContext,
    entry: &PoolEntry,
    wait: bool,
    log: &std::sync::Arc<std::sync::Mutex<super::logs::GatewayLogEntry>>,
    anthropic_body: &Option<Value>,
    raw_body: &Option<String>,
    inbound_headers: &reqwest::header::HeaderMap,
    accept_encoding: &str,
    session_id: &str,
    env: &super::identity::EnvPromptInfo,
    app_version: &str,
    format: Format,
    model: &str,
    attempts: usize,
) -> AttemptOutcome {
    // 2.5 每账号并发闸门：拿不到许可就换下一个账号（全忙时 wait=true 阻塞等位）。
    //     许可随响应持有——流式响应把它移进流里，流结束才释放。
    let sem = ctx.pool.semaphore_for(&entry.account_id, ctx.per_account_concurrency).await;
    let permit = if wait {
        sem.acquire_owned().await.ok()
    } else {
        sem.try_acquire_owned().ok()
    };
    let Some(permit) = permit else {
        return AttemptOutcome::Busy;
    };
    {
        let mut l = log.lock().unwrap_or_else(|e| e.into_inner());
        l.account = Some(entry.name.clone());
        l.provider = Some(entry.provider.clone());
        l.plan = Some(entry.plan.clone());
    }

    // 3. Per-account body transform (metadata.user_id carries the account's
    //    own device mid; start-plan gets the identity blocks).
    let body_str = match anthropic_body {
        Some(base) => {
            let mut clone = base.clone();
            if let Some(obj) = clone.as_object_mut() {
                let metadata_user_id = upstream::metadata_user_id_for(entry, session_id);
                transform_anthropic_body(obj, entry.plan == "start-plan", Some(&entry.provider), &metadata_user_id, env);
            }
            clone.to_string()
        }
        None => raw_body.clone().unwrap_or_default(),
    };

    // 4. Build upstream headers and resolve endpoint routing (fail-open).
    let header_pairs = upstream::build_upstream_headers(entry, session_id, inbound_headers, accept_encoding);
    let original_url = entry.messages_url.clone();
    let credential: Option<String> = if entry.plan == "coding-plan" {
        Some(entry.credential.clone())
    } else {
        None
    };
    let mut send_url = original_url.clone();
    if let Some(routing) = &ctx.routing {
        let (routed, resolved) = routing.resolve(&original_url, credential.as_deref()).await;
        if routed {
            send_url = resolved;
        }
    }

    let send = |pairs: Vec<(String, String)>| {
        let send_url = send_url.clone();
        let body_str = body_str.clone();
        let http = ctx.http.clone();
        async move {
            let mut builder = http.post(&send_url);
            for (k, v) in &pairs {
                builder = builder.header(k.as_str(), v.as_str());
            }
            builder.body(body_str).send().await
        }
    };

    // 5. Client signing V4 (coding-plan only, fail-open).
    let mut send_pairs = header_pairs.clone();
    if entry.plan == "start-plan" {
        // zcode2api 式主动供票：start-plan 请求发起前先取票预挂，正常永不遇挑战。
        // 池空时给预解循环 ≤8s 窗口（traceless 一轮秒级，urgent 已加速）——
        // 这是等后台自动解票，不是等人工；超时才裸奔（挑战后走故障转移）。
        let mut ticket = super::captcha::take_ticket();
        if ticket.is_none() {
            super::captcha::mark_urgent();
            for _ in 0..16 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if let Some(t) = super::captcha::take_ticket() {
                    ticket = Some(t);
                    break;
                }
            }
        }
        if let Some(t) = ticket {
            send_pairs.extend(super::captcha::ticket_headers(&t));
        }
    }
    let mut signed = false;
    if entry.plan == "coding-plan" {
        if let Some(signer) = &ctx.signing {
            let outcome = signer
                .sign(&original_url, header_pairs.clone(), credential.as_deref().unwrap_or_default(), app_version)
                .await;
            signed = outcome.signed;
            send_pairs = outcome.pairs;
        }
    }

    let resp = match send(send_pairs).await {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("connect: {e}");
            ctx.pool.report_failure(&entry.account_id, FailureKind::Network, msg.clone()).await;
            return AttemptOutcome::Next(Some((502, "upstream_unreachable".into(), format!("{}: {msg}", entry.name))));
        }
    };

    let status = resp.status().as_u16();

    // Signing rejection ladder: 401 VERIFY → re-handshake + re-sign → second
    // VERIFY → permanent bypass + unsigned. Mirrors sendWithClientSigning.
    if status == 401 && signed {
        let body_text = resp.text().await.unwrap_or_default();
        if SigningManager::is_verify_failure(401, &body_text) {
            if let Some(signer) = &ctx.signing {
                signer.invalidate(&original_url, credential.as_deref().unwrap_or_default()).await;
                let outcome = signer
                    .sign(&original_url, header_pairs.clone(), credential.as_deref().unwrap_or_default(), app_version)
                    .await;
                let resigned = outcome.signed;
                match send(outcome.pairs).await {
                    Ok(r2) => {
                        let st2 = r2.status().as_u16();
                        if st2 >= 200 && st2 < 300 {
                            return AttemptOutcome::Terminal(
                                finish_success(ctx, entry, r2, permit, format, model, attempts, log).await,
                            );
                        }
                        let body2 = r2.text().await.unwrap_or_default();
                        if st2 == 401 && resigned && SigningManager::is_verify_failure(401, &body2) {
                            signer.set_bypass(&original_url, credential.as_deref().unwrap_or_default()).await;
                            // third send: unsigned original pairs
                            match send(header_pairs.clone()).await {
                                Ok(r3) => {
                                    let st3 = r3.status().as_u16();
                                    if st3 >= 200 && st3 < 300 {
                                        return AttemptOutcome::Terminal(
                                            finish_success(ctx, entry, r3, permit, format, model, attempts, log).await,
                                        );
                                    }
                                    let body3 = r3.text().await.unwrap_or_default();
                                    record_status_failure(ctx, entry, st3, &body3).await;
                                    return AttemptOutcome::Next(Some(last_error_tuple(entry, st3, &body3)));
                                }
                                Err(e) => {
                                    ctx.pool.report_failure(&entry.account_id, FailureKind::Network, format!("connect: {e}")).await;
                                    return AttemptOutcome::Next(Some((502, "upstream_unreachable".into(), format!("{}: connect failed: {e}", entry.name))));
                                }
                            }
                        }
                        record_status_failure(ctx, entry, st2, &body2).await;
                        return AttemptOutcome::Next(Some(last_error_tuple(entry, st2, &body2)));
                    }
                    Err(e) => {
                        ctx.pool.report_failure(&entry.account_id, FailureKind::Network, format!("connect: {e}")).await;
                        return AttemptOutcome::Next(Some((502, "upstream_unreachable".into(), format!("{}: connect failed: {e}", entry.name))));
                    }
                }
            }
        }
        record_status_failure(ctx, entry, 401, &body_text).await;
        return AttemptOutcome::Next(Some(last_error_tuple(entry, 401, &body_text)));
    }

    if (200..300).contains(&status) {
        return AttemptOutcome::Terminal(finish_success(ctx, entry, resp, permit, format, model, attempts, log).await);
    }

    let upstream_headers = resp.headers().clone();
    let body_text = resp.text().await.unwrap_or_default();

    // start-plan 人机验证挑战（响应头 / 3007 / 文案）→ 非阻塞处理：
    // 标记待验证（前端轮询拉起弹窗）→ 该账号按 403 冷却 → 立刻故障转移。
    // 决不原地等待用户解票（客户端会先超时）；用户解完票后重试请求时，
    // 网关会预挂票据直接通过。
    if entry.plan == "start-plan" && super::captcha::is_challenge(status, &upstream_headers, &body_text) {
        // 池空才走到这里：标记 urgent 让预解循环立刻补票（zcode-api urgentCaptchaRefill），
        // 并置交互待处理标志——预解窗口的 traceless 若需人工会自行显形。
        super::captcha::mark_urgent();
        super::captcha::begin_interactive();
        {
            let mut l = log.lock().unwrap_or_else(|e| e.into_inner());
            l.status = 403;
            l.error = Some(crate::i18n::tr("err.gateway.captcha").to_string());
            super::logs::push(l.clone());
        }
        ctx.pool
            .report_failure(&entry.account_id, FailureKind::Forbidden, crate::i18n::tr("err.gateway.captcha").to_string())
            .await;
        return AttemptOutcome::Next(Some((
            403,
            "captcha_required".into(),
            format!("{}: {}", entry.name, crate::i18n::tr("err.gateway.captcha")),
        )));
    }

    // Failover decision on error statuses.
    record_status_failure(ctx, entry, status, &body_text).await;
    if failure_kind_for_status(status).is_some() {
        return AttemptOutcome::Next(Some(last_error_tuple(entry, status, &body_text)));
    }
    // Client-class error (400 etc.): surface immediately, no failover.
    AttemptOutcome::Terminal(raw_error_response(format, status, &body_text, &entry.name, attempts))
}

fn last_error_tuple(entry: &PoolEntry, status: u16, body: &str) -> (u16, String, String) {
    let snippet: String = body.chars().take(300).collect();
    (
        status,
        "upstream_error".to_string(),
        format!("{} ({} {}): HTTP {status} {snippet}", entry.name, entry.provider, entry.plan),
    )
}

async fn record_status_failure(ctx: &GatewayContext, entry: &PoolEntry, status: u16, body: &str) {
    if let Some(kind) = failure_kind_for_status(status) {
        ctx.pool
            .report_failure(&entry.account_id, kind, format!("HTTP {status}: {}", body.chars().take(120).collect::<String>()))
            .await;
    }
}

/// Handle a successful upstream response: stream or batch, translate or
/// passthrough depending on the inbound format.
async fn finish_success(
    ctx: &GatewayContext,
    entry: &PoolEntry,
    resp: reqwest::Response,
    permit: tokio::sync::OwnedSemaphorePermit,
    format: Format,
    model: &str,
    attempts: usize,
    log: &std::sync::Arc<std::sync::Mutex<super::logs::GatewayLogEntry>>,
) -> axum::response::Response {
    ctx.pool.report_success(&entry.account_id).await;
    {
        let mut l = log.lock().unwrap_or_else(|e| e.into_inner());
        l.status = resp.status().as_u16();
        l.error = None;
    }
    let status = resp.status();
    let upstream_headers = resp.headers().clone();
    let is_sse = upstream_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/event-stream"))
        .unwrap_or(false);

    match format {
        Format::Anthropic => {
            // Passthrough: stream raw bytes, forward the allowlisted headers.
            // 并发许可跟随流——流结束（或客户端断开）才归还。
            let headers = finalize_headers(reqwest::header::HeaderMap::new(), &upstream_headers, &entry.name, attempts);
            let mut builder = axum::http::Response::builder().status(status);
            for (k, v) in headers.iter() {
                builder = builder.header(k, v);
            }
            let mut byte_stream = resp.bytes_stream();
            let stream = async_stream::stream! {
                let _permit = permit;
                while let Some(item) = byte_stream.next().await {
                    yield item;
                }
            };
            builder
                .body(axum::body::Body::from_stream(stream))
                .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Format::OpenAi => {
            if is_sse {
                let mut translator = SseTranslator::new(model);
                let mut feeder = Utf8Feeder::new();
                let mut byte_stream = resp.bytes_stream();
                let headers = {
                    let mut h = reqwest::header::HeaderMap::new();
                    h.insert("content-type", reqwest::header::HeaderValue::from_static("text/event-stream"));
                    h.insert("cache-control", reqwest::header::HeaderValue::from_static("no-cache"));
                    finalize_headers(h, &upstream_headers, &entry.name, attempts)
                };
                let mut builder = axum::http::Response::builder().status(axum::http::StatusCode::OK);
                for (k, v) in headers.iter() {
                    builder = builder.header(k, v);
                }
                let stream = async_stream::stream! {
                    let _permit = permit;
                    while let Some(item) = byte_stream.next().await {
                        match item {
                            Ok(chunk) => {
                                let text = feeder.feed(&chunk);
                                if text.is_empty() { continue; }
                                for piece in translator.feed(&text) {
                                    yield Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(piece));
                                }
                            }
                            Err(_e) => {
                                // Stream broke mid-flight: flush what we have, then stop.
                                let tail = feeder.finish();
                                for piece in translator.feed(&tail) {
                                    yield Ok(axum::body::Bytes::from(piece));
                                }
                                for piece in translator.finish() {
                                    yield Ok(axum::body::Bytes::from(piece));
                                }
                                return;
                            }
                        }
                    }
                    let tail = feeder.finish();
                    if !tail.is_empty() {
                        for piece in translator.feed(&tail) {
                            yield Ok(axum::body::Bytes::from(piece));
                        }
                    }
                    for piece in translator.finish() {
                        yield Ok(axum::body::Bytes::from(piece));
                    }
                };
                builder
                    .body(axum::body::Body::from_stream(stream))
                    .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
            } else {
                // Batch: read, parse, translate Anthropic → OpenAI.
                let raw = resp.bytes().await.unwrap_or_default();
                let mut feeder = Utf8Feeder::new();
                let text = feeder.feed(&raw) + &feeder.finish();
                let headers = finalize_headers(reqwest::header::HeaderMap::new(), &upstream_headers, &entry.name, attempts);
                let Ok(parsed) = serde_json::from_str::<Value>(&text) else {
                    let snippet: String = text.chars().take(200).collect();
                    return error_response(format, 502, "translation_failed", &format!("upstream returned non-JSON body: {snippet}"));
                };
                if parsed.get("type").and_then(|t| t.as_str()) != Some("message")
                    || parsed.get("role").and_then(|r| r.as_str()) != Some("assistant")
                {
                    let snippet: String = text.chars().take(200).collect();
                    return error_response(format, 502, "translation_failed", &format!("upstream returned invalid Anthropic message: {snippet}"));
                }
                match translate_response_anthropic_to_openai(&parsed, model) {
                    Ok(out) => json_response(status.as_u16(), headers, out),
                    Err(e) => error_response(format, 502, "translation_failed", &format!("Anthropic→OpenAI translation failed: {e}")),
                }
            }
        }
    }
}

/// Surface a client-class upstream error (400 etc.) with its native body.
fn raw_error_response(format: Format, status: u16, body: &str, account: &str, attempts: usize) -> axum::response::Response {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(hs("content-type"), reqwest::header::HeaderValue::from_static("application/json"));
    if let Some(val) = hv_str(account) {
        headers.insert(hs("x-zswitch-account"), val);
    }
    headers.insert(hs("x-zswitch-attempts"), reqwest::header::HeaderValue::from(attempts as u32));
    let out_body = if format == Format::OpenAi && !body.contains("\"error\"") {
        super::translate::openai_error_body(&format!("upstream rejected the request: {body}"), "upstream_error").to_string()
    } else {
        body.to_string()
    };
    let mut builder = axum::http::Response::builder().status(status);
    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(out_body))
        .unwrap_or_else(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// GET /v1/models — the pinned catalog in OpenAI format.
pub async fn handle_list_models() -> axum::response::Response {
    let list = serde_json::json!({
        "object": "list",
        "data": models::MODELS.iter().map(|m| serde_json::json!({
            "id": m.id,
            "object": "model",
            "owned_by": "zcode-switch-gateway",
        })).collect::<Vec<_>>(),
    });
    json_response(200, base_response_headers(), list)
}
