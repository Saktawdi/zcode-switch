//! Start-plan captcha handling — the zcode.z.ai gateway challenges requests
//! with an Aliyun captcha (response header `x-aliyun-captcha-verify-param` or
//! in-body `{"code":3007}`); challenged requests must retry with
//! `x-aliyun-captcha-verify-param` / `-region` headers.
//!
//! The headless solver from zcode-api (captcha-happy, ~2.5k lines) is not
//! ported; instead we reuse zcode-switch's proven interactive captcha window
//! (the claim flow's Aliyun SDK popup): on challenge the gateway asks the UI
//! for a solve, the user completes it once, and the ticket retries the
//! request. Tickets are single-use and short-lived.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static TICKET: Mutex<Option<Ticket>> = Mutex::new(None);
static NOTIFY: tokio::sync::Notify = tokio::sync::Notify::const_new();
static INTERACTIVE_PENDING: AtomicBool = AtomicBool::new(false);

/// Ticket validity — Aliyun verify params are short-lived; a stale ticket is
/// discarded rather than burned on a doomed request.
const TICKET_TTL: Duration = Duration::from_secs(240);

#[derive(Debug, Clone)]
pub struct Ticket {
    pub verify_param: String,
    pub region: Option<String>,
    pub created_at: Instant,
}

/// Store a user-solved ticket and wake all waiting requests.
pub fn store_ticket(verify_param: &str, region: Option<String>) {
    let t = Ticket {
        verify_param: verify_param.trim().to_string(),
        region,
        created_at: Instant::now(),
    };
    if t.verify_param.is_empty() {
        return;
    }
    *ticket_cell() = Some(t);
    NOTIFY.notify_waiters();
    INTERACTIVE_PENDING.store(false, Ordering::SeqCst);
}

/// Take a fresh ticket (single-use).
pub fn take_ticket() -> Option<Ticket> {
    let t = ticket_cell().take()?;
    (t.created_at.elapsed() < TICKET_TTL).then_some(t)
}

/// Peek without consuming (UI status).
pub fn has_fresh_ticket() -> bool {
    ticket_cell()
        .as_ref()
        .map(|t| t.created_at.elapsed() < TICKET_TTL)
        .unwrap_or(false)
}

/// Wait for a user-solved ticket up to `timeout`.
pub async fn wait_ticket(timeout: Duration) -> Option<Ticket> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(t) = take_ticket() {
            return Some(t);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let _ = tokio::time::timeout(deadline - now, NOTIFY.notified()).await;
    }
}

/// Mark an interactive solve as pending; returns true for the single caller
/// that should raise the popup (event coalescing for concurrent challenges).
pub fn begin_interactive() -> bool {
    !INTERACTIVE_PENDING.swap(true, Ordering::SeqCst)
}

pub fn end_interactive() {
    INTERACTIVE_PENDING.store(false, Ordering::SeqCst);
}

fn ticket_cell() -> std::sync::MutexGuard<'static, Option<Ticket>> {
    TICKET.lock().unwrap_or_else(|e| e.into_inner())
}

/// Detect an upstream captcha challenge:
///   1. response header variant — non-empty `x-aliyun-captcha-verify-param`;
///   2. in-body variant — HTTP 400 with `{"code":3007}` in the JSON body;
///   3. defensive — any status whose body literally mentions the upstream's
///      "captcha verify failed" rejection (observed in the wild).
pub fn is_challenge(status: u16, headers: &reqwest::header::HeaderMap, body: &str) -> bool {
    if let Some(v) = headers.get("x-aliyun-captcha-verify-param") {
        if let Ok(s) = v.to_str() {
            if !s.trim().is_empty() {
                return true;
            }
        }
    }
    if body.contains("\"code\":3007") || body.contains("\"code\": 3007") {
        return true;
    }
    let _ = status;
    body.to_ascii_lowercase().contains("captcha verify failed")
}

/// The two upstream headers a solved ticket turns into.
pub fn ticket_headers(t: &Ticket) -> Vec<(String, String)> {
    let mut h = vec![(
        "x-aliyun-captcha-verify-param".to_string(),
        t.verify_param.clone(),
    )];
    if let Some(r) = t.region.as_deref().filter(|r| !r.trim().is_empty()) {
        h.push(("x-aliyun-captcha-verify-region".to_string(), r.to_string()));
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_detection() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(!is_challenge(200, &headers, "{}"));
        headers.insert(
            "x-aliyun-captcha-verify-param",
            reqwest::header::HeaderValue::from_static("challenge-token"),
        );
        assert!(is_challenge(403, &headers, "ignored"));
        let mut empty = reqwest::header::HeaderMap::new();
        empty.insert(
            "x-aliyun-captcha-verify-param",
            reqwest::header::HeaderValue::from_static(""),
        );
        assert!(!is_challenge(403, &empty, "ok"));
        assert!(is_challenge(400, &empty, "{\"code\":3007,\"msg\":\"need captcha\"}"));
        assert!(is_challenge(400, &empty, "captcha verify failed"));
        assert!(!is_challenge(400, &empty, "normal error"));
    }

    #[tokio::test]
    async fn ticket_store_and_wait() {
        store_ticket("abc", Some("cn".into()));
        assert!(has_fresh_ticket());
        let t = wait_ticket(Duration::from_millis(100)).await.unwrap();
        assert_eq!(t.verify_param, "abc");
        assert!(!has_fresh_ticket(), "single-use");
        // wake-before-wait race: store then immediate wait must return fast
        store_ticket("def", None);
        let t = wait_ticket(Duration::from_millis(50)).await.unwrap();
        assert_eq!(t.verify_param, "def");
    }
}
