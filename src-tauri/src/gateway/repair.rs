//! Coding-plan key self-healing. Accounts that fall back to the start-plan
//! JWT are the ones that hit the zcode.z.ai gateway's captcha challenges; a
//! coding-plan API key makes them captcha-free. This loop re-resolves the
//! `zcode-api-key` (same biz endpoints the OAuth login uses) for accounts
//! whose mirrored config lost its coding-plan key, and writes it back into
//! the stored account.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use crate::store::{self, Paths};
use crate::zcrypto;

static REPAIR_RUNNING: AtomicBool = AtomicBool::new(false);

fn decrypt_field(creds: &Value, key: &str, secret: &str) -> Option<String> {
    let v = creds.get(key)?.as_str()?;
    if zcrypto::is_encrypted(v) {
        zcrypto::decrypt_with_secret(v, secret).ok()
    } else {
        Some(v.to_string())
    }
}

fn coding_key_present(config: Option<&Value>, provider: &str) -> bool {
    config
        .and_then(|c| c.get("provider")?.get(format!("builtin:{provider}-coding-plan")))
        .and_then(|p| p.pointer("/options/apiKey"))
        .and_then(|k| k.as_str())
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false)
}

fn anthropic_base_for(provider: &str) -> &'static str {
    match provider {
        "zai" => "https://api.z.ai/api/anthropic",
        _ => "https://open.bigmodel.cn/api/anthropic",
    }
}

/// One repair pass over the whole account store. Network-heavy (biz API) and
/// therefore run outside any locks; the final read-modify-save re-checks the
/// account under the store lock. Returns the number of repaired accounts.
pub fn repair_pass(home: &std::path::Path) -> usize {
    let paths = Paths { home: home.to_path_buf() };
    let Ok(accounts) = store::list_accounts(&paths) else {
        return 0;
    };
    let secret = zcrypto::default_secret(home);
    let mut repaired = 0;

    for acc in accounts {
        let provider = decrypt_field(&acc.credentials, "oauth:active_provider", &secret)
            .unwrap_or_else(|| "bigmodel".to_string());
        let provider = match provider.as_str() {
            "zai" | "bigmodel" => provider,
            _ => continue,
        };
        if coding_key_present(acc.config.as_ref(), &provider) {
            continue; // already has a coding-plan key
        }
        let access_key = format!("oauth:{provider}:access_token");
        let Some(access) = decrypt_field(&acc.credentials, &access_key, &secret)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };

        // Resolve OUTSIDE the store lock — this talks to the biz API.
        let auth = match provider.as_str() {
            "zai" => crate::oauth::resolve_zai_business_token(&access).map(|b| format!("Bearer {b}")),
            _ => Some(access),
        };
        let Some(auth) = auth else { continue };
        let base = match provider.as_str() {
            "zai" => crate::oauth::ZAI_API_BASE,
            _ => crate::oauth::BIGMODEL_BIZ_BASE,
        };
        let Some(key) = crate::oauth::resolve_biz_api_key(base, &auth, provider != "bigmodel") else {
            continue;
        };

        // Re-check under the store lock, then write back.
        let _guard = crate::store_guard();
        let Ok(mut fresh) = store::load_account(&paths, &acc.id) else { continue };
        if coding_key_present(fresh.config.as_ref(), &provider) {
            continue; // someone else fixed it meanwhile
        }
        let mut cfg = fresh.config.clone().unwrap_or_else(|| json!({ "provider": {} }));
        if !cfg.is_object() {
            continue;
        }
        let entry = json!({
            "name": if provider == "zai" { "Z.ai - Coding Plan" } else { "BigModel - Coding Plan" },
            "kind": "anthropic",
            "options": { "apiKey": key, "baseURL": anthropic_base_for(&provider) },
            "enabled": true,
            "source": "custom",
        });
        cfg["provider"][format!("builtin:{provider}-coding-plan")] = entry;
        fresh.config = Some(cfg);
        fresh.updated_at = store::now_ts();
        if store::save_account(&paths, &fresh).is_ok() {
            repaired += 1;
            super::logs::push(super::logs::GatewayLogEntry {
                ts: chrono::Utc::now().timestamp_millis(),
                route: "repair".into(),
                format: "repair".into(),
                model: "coding-plan key".into(),
                account: Some(fresh.name.clone()),
                provider: Some(provider.clone()),
                plan: Some("coding-plan".into()),
                status: 200,
                ms: 0,
                attempts: 1,
                error: None,
            });
        }
    }
    repaired
}

/// Background self-heal loop: one pass shortly after startup, then every
/// 90 s while the gateway is running (the task dies with the gateway via
/// the shutdown watch).
pub async fn run_loop(
    home: std::path::PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut first = true;
    loop {
        if shutdown.has_changed().map(|v| v).unwrap_or(true) {
            return;
        }
        if !REPAIR_RUNNING.swap(true, Ordering::SeqCst) {
            let h = home.clone();
            let _ = tokio::task::spawn_blocking(move || repair_pass(&h)).await;
            REPAIR_RUNNING.store(false, Ordering::SeqCst);
        }
        let wait = if first {
            first = false;
            Duration::from_secs(5)
        } else {
            Duration::from_secs(90)
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
    }
}
