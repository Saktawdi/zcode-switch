//! Account pool — the fusion centerpiece. Turns zcode-switch's account store
//! into the gateway's upstream credential pool: multi-account rotation with
//! per-account health tracking, cooldowns and failover.
//!
//! Each account resolves to at most one upstream credential, preferring the
//! coding-plan API key (`builtin:{provider}-coding-plan` → `{key}` or
//! `{key}.{secret}`) and falling back to the start-plan JWT
//! (`zcodejwttoken`). The account's virtual device mid (zcode-switch's
//! per-account fingerprint isolation) rides every request this account makes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::store::{self, Paths};
use crate::zcrypto;

const POOL_TTL: Duration = Duration::from_secs(3);

/// How long an account sits out after a given failure class.
pub fn cooldown_for_failure(kind: FailureKind) -> Duration {
    match kind {
        // Invalid credentials / expired token — needs re-login on the client side.
        FailureKind::Unauthorized => Duration::from_secs(300),
        // Quota exhausted (402) or captcha challenge (403) — wait out the window.
        FailureKind::PaymentRequired | FailureKind::Forbidden => Duration::from_secs(120),
        // Rate limited — short cooldown.
        FailureKind::RateLimited => Duration::from_secs(30),
        // Upstream blip / network error — brief cooldown.
        FailureKind::ServerError | FailureKind::Network => Duration::from_secs(15),
        // Client errors are the caller's fault — never cool the account down.
        FailureKind::BadRequest => Duration::ZERO,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Unauthorized,
    PaymentRequired,
    Forbidden,
    RateLimited,
    ServerError,
    Network,
    BadRequest,
}

/// One usable upstream route resolved from a stored account.
#[derive(Debug, Clone, Serialize)]
pub struct PoolEntry {
    pub account_id: String,
    pub name: String,
    pub provider: String,
    pub plan: String,
    /// Coding-plan credential string (`{key}` or `{key}.{secret}`); empty for start-plan.
    pub credential: String,
    /// Start-plan JWT; empty for coding-plan.
    pub jwt: String,
    /// Per-account virtual device mid (fingerprint isolation).
    pub device_mid: Option<String>,
    /// Full POST URL for Anthropic messages on this account's upstream.
    pub messages_url: String,
    /// 用户主动将该账号排除出网关池（账号行动态增删）。
    pub excluded: bool,
    /// Why this account is not usable (empty when usable).
    pub unusable_reason: String,
}

/// Per-account runtime health, shared across requests.
#[derive(Debug, Clone, Serialize)]
pub struct PoolHealth {
    pub total: u64,
    pub ok: u64,
    pub fail: u64,
    #[serde(skip)]
    pub cooldown_until: Instant,
    pub last_error: Option<String>,
}

impl Default for PoolHealth {
    fn default() -> Self {
        PoolHealth {
            total: 0,
            ok: 0,
            fail: 0,
            cooldown_until: Instant::now(),
            last_error: None,
        }
    }
}

#[derive(Clone)]
pub struct PoolSnapshot {
    pub generated_at: Instant,
    pub entries: Vec<PoolEntry>,
}

pub struct AccountPool {
    home: PathBuf,
    cache: tokio::sync::RwLock<Option<(Instant, Arc<PoolSnapshot>)>>,
    health: tokio::sync::Mutex<HashMap<String, PoolHealth>>,
    /// Per-account concurrency limit: one semaphore per account (default 3
    /// permits). Config changes restart the gateway, rebuilding the pool and
    /// its semaphores.
    semaphores: tokio::sync::Mutex<HashMap<String, Arc<Semaphore>>>,
    rr: AtomicUsize,
}

impl AccountPool {
    pub fn new(home: PathBuf) -> Self {
        AccountPool {
            home,
            cache: tokio::sync::RwLock::new(None),
            health: tokio::sync::Mutex::new(HashMap::new()),
            semaphores: tokio::sync::Mutex::new(HashMap::new()),
            rr: AtomicUsize::new(0),
        }
    }

    /// Get (or lazily create) the concurrency semaphore for one account.
    pub async fn semaphore_for(&self, account_id: &str, permits: u32) -> Arc<Semaphore> {
        let mut sems = self.semaphores.lock().await;
        sems.entry(account_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(permits.max(1) as usize)))
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn inject_snapshot_for_tests(&mut self, entries: Vec<PoolEntry>) {
        self.cache = tokio::sync::RwLock::new(Some((
            Instant::now() + Duration::from_secs(3600),
            Arc::new(PoolSnapshot {
                generated_at: Instant::now(),
                entries,
            }),
        )));
    }

    /// Load a pool snapshot, refreshing from disk when stale.
    pub async fn snapshot(&self) -> Arc<PoolSnapshot> {
        {
            let cache = self.cache.read().await;
            if let Some((at, snap)) = cache.as_ref() {
                if snap.entries.len() > 0 && at.elapsed() < POOL_TTL {
                    return snap.clone();
                }
                if snap.entries.is_empty() && at.elapsed() < POOL_TTL {
                    return snap.clone();
                }
            }
        }
        let home = self.home.clone();
        let entries = tokio::task::spawn_blocking(move || build_entries(&home)).await.unwrap_or_default();
        let snap = Arc::new(PoolSnapshot {
            generated_at: Instant::now(),
            entries,
        });
        let mut cache = self.cache.write().await;
        // only one writer wins the refresh race; both keep a fresh enough view
        if cache.as_ref().map(|(at, _)| at.elapsed() >= POOL_TTL).unwrap_or(true) {
            *cache = Some((Instant::now(), snap.clone()));
        }
        snap
    }

    /// Ordered candidate list for failover: usable accounts, healthy before
    /// cooling, rotated by a round-robin cursor.
    pub async fn pick_candidates(&self, snap: &PoolSnapshot, max: usize) -> Vec<PoolEntry> {
        let now = Instant::now();
        let health = self.health.lock().await;
        let mut usable: Vec<&PoolEntry> = snap
            .entries
            .iter()
            .filter(|e| e.unusable_reason.is_empty())
            .collect();
        usable.sort_by_key(|e| {
            let cooling = health
                .get(&e.account_id)
                .map(|h| h.cooldown_until > now)
                .unwrap_or(false);
            (cooling as u8, 0u8)
        });
        let n = usable.len();
        if n == 0 {
            return vec![];
        }
        let start = self.rr.fetch_add(1, Ordering::Relaxed) % n;
        let mut out = vec![];
        for i in 0..n.min(max) {
            out.push(usable[(start + i) % n].clone());
        }
        out
    }

    pub async fn report_success(&self, account_id: &str) {
        let mut health = self.health.lock().await;
        let h = health.entry(account_id.to_string()).or_default();
        h.total += 1;
        h.ok += 1;
        h.cooldown_until = Instant::now();
        h.last_error = None;
    }

    pub async fn report_failure(&self, account_id: &str, kind: FailureKind, message: String) {
        let mut health = self.health.lock().await;
        let h = health.entry(account_id.to_string()).or_default();
        h.total += 1;
        h.fail += 1;
        h.last_error = Some(message);
        let cd = cooldown_for_failure(kind);
        if cd > Duration::ZERO {
            h.cooldown_until = Instant::now() + cd;
        }
    }

    pub async fn clear_cooldown(&self, account_id: &str) {
        let mut health = self.health.lock().await;
        if let Some(h) = health.get_mut(account_id) {
            h.cooldown_until = Instant::now();
        }
    }

    /// Serializable pool status for the UI / status endpoint.
    pub async fn status(&self) -> Vec<PoolStatusEntry> {
        let snap = self.snapshot().await;
        let now = Instant::now();
        let health = self.health.lock().await;
        snap.entries
            .iter()
            .map(|e| {
                let h = health.get(&e.account_id).cloned().unwrap_or_default();
                PoolStatusEntry {
                    account_id: e.account_id.clone(),
                    name: e.name.clone(),
                    provider: e.provider.clone(),
                    plan: e.plan.clone(),
                    usable: e.unusable_reason.is_empty(),
                    excluded: e.excluded,
                    unusable_reason: e.unusable_reason.clone(),
                    cooling: h.cooldown_until > now,
                    last_error: h.last_error.clone(),
                    total: h.total,
                    ok: h.ok,
                    fail: h.fail,
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolStatusEntry {
    pub account_id: String,
    pub name: String,
    pub provider: String,
    pub plan: String,
    pub usable: bool,
    pub excluded: bool,
    pub unusable_reason: String,
    pub cooling: bool,
    pub last_error: Option<String>,
    pub total: u64,
    pub ok: u64,
    pub fail: u64,
}

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------

fn decrypt_field(creds: &Value, key: &str, secret: &str) -> Option<String> {
    let v = creds.get(key)?.as_str()?;
    if zcrypto::is_encrypted(v) {
        zcrypto::decrypt_with_secret(v, secret).ok()
    } else {
        Some(v.to_string())
    }
}

/// Coding-plan API key from the account's mirrored client config:
/// `provider["builtin:{provider}-coding-plan"].options.apiKey`.
fn resolve_coding_key(config: Option<&Value>, provider: &str) -> Option<String> {
    let config = config?;
    let providers = config.get("provider")?.as_object()?;
    for plan in ["coding-plan"] {
        let key_id = format!("builtin:{provider}-{plan}");
        let key = providers
            .get(&key_id)?
            .pointer("/options/apiKey")
            .and_then(|k| k.as_str())
            .map(str::trim)
            .filter(|k| !k.is_empty())?;
        return Some(key.to_string());
    }
    None
}

fn anthropic_base_for(provider: &str) -> Option<&'static str> {
    match provider {
        "zai" => Some("https://api.z.ai/api/anthropic"),
        "bigmodel" => Some("https://open.bigmodel.cn/api/anthropic"),
        _ => None,
    }
}

const START_PLAN_MESSAGES_URL: &str = "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages";

/// JWT `exp` (unix seconds) → expired?
fn jwt_is_expired(jwt: &str) -> bool {
    let Some(payload) = zcrypto::decode_jwt(jwt) else {
        // Undecodable JWT: let the upstream be the judge rather than skipping.
        return false;
    };
    match payload.get("exp") {
        Some(Value::Number(n)) => n
            .as_f64()
            .map(|exp| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0) > exp)
            .unwrap_or(false),
        _ => false,
    }
}

/// Build the pool entries from the on-disk account store. Accounts listed in
/// settings' `gateway_excluded` are marked excluded (user-controlled dynamic
/// pool membership) and never picked as candidates.
fn build_entries(home: &std::path::Path) -> Vec<PoolEntry> {
    let paths = Paths { home: home.to_path_buf() };
    let Ok(accounts) = store::list_accounts(&paths) else {
        return vec![];
    };
    let excluded_ids: std::collections::HashSet<String> =
        store::load_settings(&paths).gateway_excluded_ids().into_iter().collect();
    let secret = zcrypto::default_secret(home);
    let mut out = vec![];
    for acc in accounts {
        let excluded = excluded_ids.contains(&acc.id);
        let provider = decrypt_field(&acc.credentials, "oauth:active_provider", &secret)
            .unwrap_or_else(|| "bigmodel".to_string());
        let provider = match provider.as_str() {
            "zai" | "bigmodel" => provider,
            _ => "bigmodel".to_string(),
        };
        let jwt = decrypt_field(&acc.credentials, "zcodejwttoken", &secret)
            .map(|j| j.trim().to_string())
            .filter(|j| !j.is_empty())
            .unwrap_or_default();
        let coding_key = resolve_coding_key(acc.config.as_ref(), &provider).unwrap_or_default();

        // Prefer the coding-plan key (robust, no system-prompt contract);
        // fall back to the start-plan JWT.
        let (plan, credential, jwt_used, messages_url, unusable_reason) = if !coding_key.is_empty() {
            (
                "coding-plan".to_string(),
                coding_key.clone(),
                String::new(),
                format!("{}/v1/messages", anthropic_base_for(&provider).unwrap_or_default()),
                String::new(),
            )
        } else if !jwt.is_empty() {
            if jwt_is_expired(&jwt) {
                (
                    "start-plan".to_string(),
                    String::new(),
                    jwt,
                    START_PLAN_MESSAGES_URL.to_string(),
                    "start-plan JWT 已过期（重新登录后刷新）".to_string(),
                )
            } else {
                (
                    "start-plan".to_string(),
                    String::new(),
                    jwt.clone(),
                    START_PLAN_MESSAGES_URL.to_string(),
                    String::new(),
                )
            }
        } else {
            (
                "none".to_string(),
                String::new(),
                String::new(),
                String::new(),
                "无可用的 coding-plan key 或 start-plan JWT".to_string(),
            )
        };

        out.push(PoolEntry {
            account_id: acc.id,
            name: acc.name,
            provider,
            plan,
            credential,
            jwt: jwt_used,
            device_mid: acc.virtual_device_mid.clone().filter(|m| !m.trim().is_empty()),
            messages_url,
            excluded,
            unusable_reason: if excluded { "已由用户移出网关池".to_string() } else { unusable_reason },
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_semantics() {
        assert_eq!(cooldown_for_failure(FailureKind::BadRequest), Duration::ZERO);
        assert!(cooldown_for_failure(FailureKind::Unauthorized) > cooldown_for_failure(FailureKind::RateLimited));
        assert!(cooldown_for_failure(FailureKind::RateLimited) > cooldown_for_failure(FailureKind::ServerError));
    }

    /// 用户排除的账号被标记 excluded，且不再作为候选。
    #[tokio::test]
    async fn excluded_accounts_leave_the_pool() {
        let sandbox = std::env::temp_dir().join(format!("zsw-pool-ex-{}", uuid::Uuid::new_v4().simple()));
        let store = sandbox.join(".zcode-switch");
        std::fs::create_dir_all(store.join("accounts")).unwrap();
        // payload {"exp":9999999999}（未过期），明文凭据即可
        let jwt = "h.eyJleHAiOjk5OTk5OTk5OTl9.s";
        let mk = |id: &str, name: &str| serde_json::json!({
            "id": id, "name": name, "created_at": "2026-01-01 00:00", "updated_at": "2026-01-01 00:00",
            "hash": "h",
            "credentials": { "oauth:active_provider": "zai", "zcodejwttoken": jwt }
        }).to_string();
        std::fs::write(store.join("accounts").join("aaa.json"), mk("aaa", "A")).unwrap();
        std::fs::write(store.join("accounts").join("bbb.json"), mk("bbb", "B")).unwrap();
        std::fs::write(
            store.join("settings.json"),
            serde_json::json!({ "gateway_excluded": ["bbb"] }).to_string(),
        )
        .unwrap();

        let pool = AccountPool::new(sandbox.clone());
        let snap = pool.snapshot().await;
        assert_eq!(snap.entries.len(), 2);
        let bbb = snap.entries.iter().find(|e| e.account_id == "bbb").unwrap();
        let aaa = snap.entries.iter().find(|e| e.account_id == "aaa").unwrap();
        assert!(bbb.excluded && !bbb.unusable_reason.is_empty());
        assert!(!aaa.excluded && aaa.unusable_reason.is_empty());

        let cands = pool.pick_candidates(&snap, 5).await;
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].account_id, "aaa");
    }

    /// 单账号信号量：同账号共享、上限正确；不同账号相互独立。
    #[tokio::test]
    async fn per_account_semaphore_limits_concurrency() {
        let sandbox = std::env::temp_dir().join(format!("zsw-pool-sem-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(sandbox.join("accounts")).unwrap();
        std::env::set_var("ZCODE_SWITCH_HOME", &sandbox);
        let pool = AccountPool::new(sandbox);

        let s1 = pool.semaphore_for("acc1", 3).await;
        let s1b = pool.semaphore_for("acc1", 3).await;
        let s2 = pool.semaphore_for("acc2", 3).await;
        assert!(Arc::ptr_eq(&s1, &s1b), "same account shares one semaphore");
        assert!(!Arc::ptr_eq(&s1, &s2), "different accounts get their own");

        let p1 = s1.try_acquire().unwrap();
        let p2 = s1.try_acquire().unwrap();
        let p3 = s1.try_acquire().unwrap();
        assert!(s1.try_acquire().is_err(), "4th concurrent request on the same account is rejected");
        assert!(s2.try_acquire().is_ok(), "other accounts are unaffected");
        drop((p1, p2, p3));
        assert!(s1.try_acquire().is_ok(), "permits return after release");
    }
}
