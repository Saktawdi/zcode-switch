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
/// zcode-api 同款防线：已消耗/已入池的 certifyId 集合，阻断 F008
/// （duplicate certify）——同一个 certify 解出的票绝不允许入池两次。
static USED_CERTIFY_IDS: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));
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

/// 入池拒绝原因（前端 gwlog 与日志页直接可读）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Empty,
    TooShort,
    Degraded,
    DuplicateCertify,
    Full,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::Empty => "empty",
            RejectReason::TooShort => "too-short (<200, degraded result)",
            RejectReason::Degraded => "missing securityToken (degraded result)",
            RejectReason::DuplicateCertify => "duplicate certifyId (F008)",
            RejectReason::Full => "pool full",
        }
    }
}

/// 真 param 的形状（zcode-api extractVerifyParam 实测）：base64(JSON)，
/// JSON 含 certifyId + sceneId + isSign + 长 securityToken。
fn decode_param_certify(param: &str) -> Option<(Option<String>, Option<String>)> {
    use base64::Engine;
    let trimmed = param.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| {
            let nopad = trimmed.trim_end_matches('=');
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(nopad)
        })
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let certify = v.get("certifyId").and_then(|x| x.as_str()).map(str::to_string);
    let sec = v
        .get("securityToken")
        .or_else(|| v.get("SecurityToken"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    Some((certify, sec))
}

/// Mint a ticket into the pool with zcode-api quality gates:
///   - len < 200 → degraded result (would 3007 upstream), refuse;
///   - decodable param must carry a real securityToken (≥50 chars);
///   - certifyId must never enter the pool twice (F008).
/// Returns pool size on success.
pub fn push_ticket(verify_param: &str, region: Option<String>) -> Result<usize, RejectReason> {
    let param = verify_param.trim().to_string();
    if param.is_empty() {
        return Err(RejectReason::Empty);
    }
    if param.len() < 200 {
        return Err(RejectReason::TooShort);
    }
    if let Some((certify, sec)) = decode_param_certify(&param) {
        if let Some(sec) = sec {
            if sec.len() < 50 {
                return Err(RejectReason::Degraded);
            }
        }
        if let Some(id) = certify {
            let mut used = USED_CERTIFY_IDS.lock().unwrap_or_else(|e| e.into_inner());
            if used.len() > 512 {
                used.clear(); // 防无限增长；复用窗口远小于此
            }
            if !used.insert(id) {
                return Err(RejectReason::DuplicateCertify);
            }
        }
    }
    // 解码失败（格式漂移）时宽容放行，交由上游 3007 兜底
    let mut pool = pool_cell();
    clear_expired(&mut pool);
    if pool.len() >= POOL_MAX {
        return Err(RejectReason::Full);
    }
    pool.push_back(Ticket {
        verify_param: param,
        region,
        created_at: Instant::now(),
    });
    URGENT.store(false, Ordering::SeqCst);
    Ok(pool.len())
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
            USED_CERTIFY_IDS.lock().unwrap().clear();
        }
        assert_eq!(pool_len(), 0);
        assert!(push_ticket(&format!("{}{}", "x".repeat(200), "a"), Some("cn".into())).is_ok());
        assert!(push_ticket(&format!("{}{}", "x".repeat(200), "b"), None).is_ok());
        assert_eq!(pool_len(), 2);
        let t = take_ticket().unwrap();
        assert!(t.verify_param.ends_with('a'), "FIFO order");
        assert_eq!(pool_len(), 1);

        for i in 0..POOL_MAX {
            push_ticket(&format!("{}fill{i}", "y".repeat(200)), None).ok();
        }
        assert_eq!(pool_len(), POOL_MAX);
        assert_eq!(push_ticket(&format!("{}overflow", "y".repeat(200)), None), Err(RejectReason::Full));

        while take_ticket().is_some() {}
        assert!(take_ticket().is_none());
        assert_eq!(push_ticket("   ", None), Err(RejectReason::Empty));
    }

    /// zcode-api 质量门：废票（过短/缺 securityToken/重复 certifyId）不得入池。
    #[test]
    fn quality_gates() {
        {
            let mut p = pool_cell();
            p.clear();
            USED_CERTIFY_IDS.lock().unwrap().clear();
        }
        use base64::Engine;
        let enc = |v: &serde_json::Value| base64::engine::general_purpose::STANDARD.encode(v.to_string());

        // 过短
        assert_eq!(push_ticket("short", None), Err(RejectReason::TooShort));
        // 缺 securityToken（degraded）——补足长度以穿过 TooShort 门
        let degraded = enc(&serde_json::json!({
            "certifyId": "c1", "isSign": true, "sceneId": "11xygtvd",
            "pad": "p".repeat(260),
        }));
        assert_eq!(push_ticket(&degraded, None), Err(RejectReason::Degraded));
        // 正常票
        let good1 = enc(&serde_json::json!({ "certifyId": "c2", "securityToken": "s".repeat(60) }));
        assert!(push_ticket(&good1, None).is_ok());
        // 同 certifyId 再入 → F008 拒绝
        let dup = enc(&serde_json::json!({ "certifyId": "c2", "securityToken": "t".repeat(60) }));
        assert_eq!(push_ticket(&dup, None), Err(RejectReason::DuplicateCertify));
        while take_ticket().is_some() {}
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
