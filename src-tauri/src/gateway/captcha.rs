//! Start-plan captcha — pre-solved ticket pool, ported from zcode-api
//! `captcha-pool.ts` (TTL 95 s, min/max sizing, background refill, hot-path
//! take). The zcode.z.ai gateway challenges requests with an Aliyun captcha
//! (`x-aliyun-captcha-verify-param` header or in-body `{"code":3007}`);
//! challenged requests retry with that header pair.
//!
//! Architecture difference from zcode-api: their solver is a headless
//! happy-dom implementation; ours is the Z·SWITCH WebView (the same Aliyun
//! scene + config endpoint the claim flow uses), driven by a hidden warmup
//! window that mints tickets in the background. Pool semantics are identical,
//! so the hot path never waits on a solve and requests normally never meet a
//! challenge at all.
//!
//! Failure semantics stay fail-open: an empty pool means one request meets
//! the challenge, which is surfaced non-blockingly (the account cools down
//! and the pool is marked urgent for an immediate refill).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Aliyun verify params are short-lived; zcode-api uses the same 95 s TTL.
const TICKET_TTL: Duration = Duration::from_secs(95);
/// Interactive WebView mints are pricier than a headless solve, so the pool
/// is smaller than zcode-api's 15/60 while keeping the hot path warm.
pub const POOL_MIN: usize = 3;
pub const POOL_MAX: usize = 12;

#[derive(Debug, Clone)]
pub struct Ticket {
    pub verify_param: String,
    pub region: Option<String>,
    pub created_at: Instant,
}

impl Ticket {
    fn fresh(&self) -> bool {
        self.created_at.elapsed() < TICKET_TTL
    }
}

static POOL: Mutex<VecDeque<Ticket>> = Mutex::new(VecDeque::new());
/// Set when a live request actually hit a challenge — the warmup loop polls
/// this to top the pool up immediately (zcode-api `urgentCaptchaRefill`).
static URGENT: AtomicBool = AtomicBool::new(false);
/// A request is waiting for user interaction on the visible captcha window.
static INTERACTIVE_PENDING: AtomicBool = AtomicBool::new(false);

fn pool_cell() -> std::sync::MutexGuard<'static, VecDeque<Ticket>> {
    POOL.lock().unwrap_or_else(|e| e.into_inner())
}

fn clear_expired(guard: &mut VecDeque<Ticket>) {
    guard.retain(|t| t.fresh());
}

/// Mint a ticket into the pool. Returns false when the pool is already full
/// (the warmup loop uses this as its backpressure signal).
pub fn push_ticket(verify_param: &str, region: Option<String>) -> bool {
    let param = verify_param.trim().to_string();
    if param.is_empty() {
        return false;
    }
    let mut pool = pool_cell();
    clear_expired(&mut pool);
    if pool.len() >= POOL_MAX {
        return false;
    }
    pool.push_back(Ticket {
        verify_param: param,
        region,
        created_at: Instant::now(),
    });
    URGENT.store(false, Ordering::SeqCst);
    true
}

/// Take a fresh ticket (hot path, single-use).
pub fn take_ticket() -> Option<Ticket> {
    let mut pool = pool_cell();
    clear_expired(&mut pool);
    pool.pop_front()
}

/// Pool size after dropping expired tickets (status + warmup backpressure).
pub fn pool_len() -> usize {
    let mut pool = pool_cell();
    clear_expired(&mut pool);
    pool.len()
}

/// zcode-api `urgentCaptchaRefill`: a request was challenged — refill now.
pub fn mark_urgent() {
    URGENT.store(true, Ordering::SeqCst);
}

pub fn take_urgent() -> bool {
    URGENT.swap(false, Ordering::SeqCst)
}

pub fn urgent() -> bool {
    URGENT.load(Ordering::SeqCst)
}

/// Interactive rescue flag: a challenge needs a human (traceless failed).
/// The UI polls this (via gateway status) and raises the visible window.
pub fn begin_interactive() -> bool {
    !INTERACTIVE_PENDING.swap(true, Ordering::SeqCst)
}

pub fn end_interactive() {
    INTERACTIVE_PENDING.store(false, Ordering::SeqCst);
}

pub fn interactive_pending() -> bool {
    INTERACTIVE_PENDING.load(Ordering::SeqCst)
}

/// Detect an upstream captcha challenge:
///   1. response header variant — non-empty `x-aliyun-captcha-verify-param`;
///   2. in-body variant — HTTP 400 with `{"code":3007}` in the JSON body;
///   3. defensive — a body literally mentioning the upstream's
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

    #[test]
    fn pool_fifo_capacity_and_single_use() {
        {
            let mut p = pool_cell();
            p.clear();
        }
        assert_eq!(pool_len(), 0);
        assert!(push_ticket("a", Some("cn".into())));
        assert!(push_ticket("b", None));
        assert_eq!(pool_len(), 2);
        let t = take_ticket().unwrap();
        assert_eq!(t.verify_param, "a", "FIFO order");
        assert_eq!(pool_len(), 1);

        for i in 0..POOL_MAX {
            push_ticket(&format!("fill{i}"), None);
        }
        assert_eq!(pool_len(), POOL_MAX);
        assert!(!push_ticket("overflow", None), "full pool rejects");

        while take_ticket().is_some() {}
        assert!(take_ticket().is_none());
        assert!(!push_ticket("   ", None));
    }

    #[test]
    fn urgent_flag_roundtrip() {
        assert!(!take_urgent() || true);
        mark_urgent();
        assert!(urgent());
        assert!(take_urgent(), "first take sees it");
        assert!(!urgent(), "cleared after take");
        assert!(!take_urgent());
    }

    #[test]
    fn interactive_flag_roundtrip() {
        end_interactive();
        assert!(begin_interactive(), "first caller raises");
        assert!(!begin_interactive(), "coalesced");
        assert!(interactive_pending());
        end_interactive();
        assert!(!interactive_pending());
        assert!(begin_interactive(), "re-raisable after end");
        end_interactive();
    }
}
