
use crate::i18n::{tr, trf};
use crate::quota;
use crate::zcrypto;
use chrono::Local;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(windows)]
fn no_window(prog: &str) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut c = std::process::Command::new(prog);
    c.creation_flags(0x0800_0000);
    c
}
#[cfg(not(windows))]
fn no_window(prog: &str) -> std::process::Command {
    std::process::Command::new(prog)
}

#[cfg(windows)]
fn detached(mut c: std::process::Command) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    c.creation_flags(0x0000_0008 | 0x0000_0200);
    c
}
#[cfg(not(windows))]
fn detached(mut c: std::process::Command) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    c.process_group(0);
    c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    c
}

pub struct Paths {
    pub home: PathBuf,
}

pub(crate) fn pick_home(zswitch: Option<PathBuf>, userprofile: Option<PathBuf>, home_env: Option<PathBuf>) -> PathBuf {
    zswitch
        .or(userprofile)
        .or(home_env)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl Paths {
    pub fn detect() -> Paths {
        let home = pick_home(
            std::env::var("ZCODE_SWITCH_HOME").ok().map(PathBuf::from),
            std::env::var("USERPROFILE").ok().map(PathBuf::from),
            std::env::var("HOME").ok().map(PathBuf::from),
        );
        Paths { home }
    }

    #[cfg(test)]
    pub fn new(home: impl AsRef<Path>) -> Paths {
        Paths { home: home.as_ref().to_path_buf() }
    }

    pub fn store_dir(&self) -> PathBuf { self.home.join(".zcode-switch") }
    pub fn accounts_dir(&self) -> PathBuf { self.store_dir().join("accounts") }
    pub fn settings_file(&self) -> PathBuf { self.store_dir().join("settings.json") }
    pub fn live_file(&self) -> PathBuf { self.home.join(".zcode").join("v2").join("credentials.json") }
    pub fn live_config(&self) -> PathBuf { self.home.join(".zcode").join("v2").join("config.json") }
    pub fn live_telemetry(&self) -> PathBuf { self.home.join(".zcode").join("v2").join("telemetry-state.json") }
    pub fn live_setting(&self) -> PathBuf { self.home.join(".zcode").join("v2").join("setting.json") }
    pub fn live_plan_cache(&self) -> PathBuf { self.home.join(".zcode").join("v2").join("coding-plan-cache.json") }

    pub fn ensure_dirs(&self) -> Result<(), String> {
        fs::create_dir_all(self.accounts_dir()).map_err(|e| trf("err.store.mk_accounts_dir", &[("e", &e.to_string())]))?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub hash: String,
    pub credentials: Value,
    #[serde(default)]
    pub config: Option<Value>,
    #[serde(default)]
    pub virtual_device_mid: Option<String>,
    #[serde(default)]
    pub virtual_arms_uid: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Settings {
    pub zcode_path: Option<String>,
    pub launch_after_switch: Option<bool>,
    pub close_to_tray: Option<bool>,
    #[serde(default)]
    pub hot_switch: Option<bool>,
    #[serde(default)]
    pub auth_proxy_on: Option<bool>,
    #[serde(default)]
    pub auth_proxy_url: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub auto_claim: Option<bool>,
}

impl Settings {
    pub fn launch_after_switch(&self) -> bool { self.launch_after_switch.unwrap_or(true) }
    pub fn close_to_tray(&self) -> bool { self.close_to_tray.unwrap_or(true) }
    pub fn hot_switch(&self) -> bool { self.hot_switch.unwrap_or(false) }
    pub fn auto_claim(&self) -> bool { self.auto_claim.unwrap_or(false) }
    pub fn auth_proxy(&self) -> Option<&str> {
        if self.auth_proxy_on.unwrap_or(false) {
            self.auth_proxy_url.as_deref().map(str::trim).filter(|s| !s.is_empty())
        } else {
            None
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct AccountSummary {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub is_active: bool,
    pub has_config: bool,
    pub has_user_info: bool,
    pub identity: zcrypto::Identity,
}

#[derive(Serialize, Clone, Debug)]
pub struct AppState {
    pub zcode_running: bool,
    pub live_exists: bool,
    pub live_logged_in: bool,
    pub live_hash: Option<String>,
    pub active_account_id: Option<String>,
    pub live_identity: Option<zcrypto::Identity>,
    pub accounts: Vec<AccountSummary>,
    pub zcode_path: String,
    pub zcode_path_ok: bool,
    pub store_dir: String,
    pub launch_after_switch: bool,
    pub close_to_tray: bool,
    pub hot_switch: bool,
    pub auto_claim: bool,
    pub auth_proxy_on: bool,
    pub auth_proxy_url: Option<String>,
    pub language: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct SwitchResult {
    pub switched: bool,
    pub already_active: bool,
    pub name: String,
    pub preserved_as: Option<String>,
    pub killed: bool,
    pub launched: bool,
    pub hot: bool,
    #[serde(default)]
    pub config_stale: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ImportReport {
    pub picked: bool,
    pub added: Vec<String>,
    pub skipped: Vec<String>,
    pub errors: Vec<String>,
}

pub fn now_ts() -> String {
    Local::now().format("%Y-%m-%d %H:%M").to_string()
}

const DEVICE_KEY_PREFIX: &str = "web-remote-control:";

pub fn canonical_hash(v: &Value) -> String {
    let filtered = match v.as_object() {
        Some(map) if map.keys().any(|k| k.starts_with(DEVICE_KEY_PREFIX)) => {
            let kept: serde_json::Map<String, Value> = map
                .iter()
                .filter(|(k, _)| !k.starts_with(DEVICE_KEY_PREFIX))
                .map(|(k, val)| (k.clone(), val.clone()))
                .collect();
            Value::Object(kept)
        }
        _ => v.clone(),
    };
    let bytes = serde_json::to_vec(&filtered).unwrap_or_default();
    let d = Sha256::digest(&bytes);
    format!("{d:x}")
}

pub fn is_logged_in(v: &Value) -> bool {
    let Some(map) = v.as_object() else { return false };
    if map.keys().any(|k| k.starts_with("oauth:") && k.ends_with(":access_token")) {
        return true;
    }
    map.get("zcodejwttoken")
        .and_then(|t| t.as_str())
        .map(|t| !t.trim().is_empty())
        .unwrap_or(false)
}

pub fn atomic_write(path: &Path, data: &str) -> Result<(), String> {
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
    fs::write(&tmp, data).map_err(|e| trf("err.write_file", &[("path", &path.display().to_string()), ("e", &e.to_string())]))?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(trf("err.rename_fail", &[("path", &path.display().to_string()), ("e", &e.to_string())]));
    }
    Ok(())
}

pub fn read_live(paths: &Paths) -> Result<Option<Value>, String> {
    if !paths.live_file().exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(paths.live_file())
        .map_err(|e| trf("err.read", &[("path", &paths.live_file().display().to_string()), ("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&raw)
        .map_err(|e| trf("err.bad_json", &[("path", &paths.live_file().display().to_string()), ("e", &e.to_string())]))?;
    if !v.is_object() {
        return Err(tr("err.store.not_object"));
    }
    Ok(Some(v))
}

pub fn read_live_config(paths: &Paths) -> Option<Value> {
    let raw = fs::read_to_string(paths.live_config()).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn write_live(paths: &Paths, v: &Value) -> Result<(), String> {
    if let Some(parent) = paths.live_file().parent() {
        fs::create_dir_all(parent).map_err(|e| trf("err.mkdir", &[("e", &e.to_string())]))?;
    }
    let body = serde_json::to_string_pretty(v).unwrap_or_default() + "\n";
    atomic_write(&paths.live_file(), &body)
}

pub fn write_live_config(paths: &Paths, v: &Value) -> Result<(), String> {
    let body = serde_json::to_string_pretty(v).unwrap_or_default() + "\n";
    atomic_write(&paths.live_config(), &body)
}

fn in_sandbox() -> bool {
    std::env::var("ZCODE_SWITCH_HOME").is_ok()
}

#[cfg(windows)]
pub fn zcode_running() -> bool {
    if in_sandbox() {
        return false;
    }
    let out = no_window("tasklist")
        .args(["/FI", "IMAGENAME eq ZCode.exe", "/FO", "CSV", "/NH"])
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|l| l.to_lowercase().starts_with("\"zcode.exe\"")),
        Err(_) => false,
    }
}

#[cfg(not(windows))]
pub fn zcode_running() -> bool {
    if in_sandbox() {
        return false;
    }
    ["zcode", "ZCode"].iter().any(|name| {
        no_window("pgrep")
            .args(["-x", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

#[cfg(windows)]
pub fn kill_zcode() -> Result<bool, String> {
    if in_sandbox() {
        return Ok(true);
    }
    if !zcode_running() {
        return Ok(true);
    }
    let _ = no_window("taskkill")
        .args(["/F", "/IM", "ZCode.exe"])
        .output();
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if !zcode_running() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    Ok(!zcode_running())
}

#[cfg(not(windows))]
pub fn kill_zcode() -> Result<bool, String> {
    if in_sandbox() {
        return Ok(true);
    }
    if !zcode_running() {
        return Ok(true);
    }
    for name in ["zcode", "ZCode"] {
        let _ = no_window("pkill").args(["-x", name]).output();
    }
    let soft_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < soft_deadline {
        if !zcode_running() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    if zcode_running() {
        for name in ["zcode", "ZCode"] {
            let _ = no_window("pkill").args(["-9", "-x", name]).output();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if !zcode_running() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    Ok(!zcode_running())
}

pub fn launch_zcode(path: &str) -> Result<(), String> {
    if in_sandbox() {
        return Ok(());
    }
    let p = PathBuf::from(path);
    if !p.exists() {
        return Err(trf("err.zcode.missing", &[("path", path)]));
    }
    detached(Command::new(&p))
        .spawn()
        .map_err(|e| trf("err.zcode.launch", &[("e", &e.to_string())]))?;
    Ok(())
}

pub fn open_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("仅支持 https 链接".into());
    }
    if in_sandbox() {
        return Ok(());
    }
    #[cfg(windows)]
    let cmd = {
        let mut c = no_window("cmd");
        c.args(["/c", "start", "", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let cmd = {
        let mut c = no_window("open");
        c.arg(url);
        c
    };
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let cmd = {
        let mut c = no_window("xdg-open");
        c.arg(url);
        c
    };
    let _ = detached(cmd).spawn();
    Ok(())
}

pub fn load_settings(paths: &Paths) -> Settings {
    match fs::read_to_string(paths.settings_file()) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            eprintln!("settings.json 损坏，已回退默认值：{e}");
            Settings::default()
        }),
        Err(_) => Settings::default(),
    }
}

pub fn save_settings(paths: &Paths, s: &Settings) -> Result<(), String> {
    paths.ensure_dirs()?;
    let body = serde_json::to_string_pretty(s).unwrap_or_default() + "\n";
    atomic_write(&paths.settings_file(), &body)
}

pub fn client_path_candidates(os: &str) -> Vec<String> {
    match os {
        "macos" => vec![
            "/Applications/ZCode.app/Contents/MacOS/ZCode".to_string(),
            format!("{}/Applications/ZCode.app/Contents/MacOS/ZCode", std::env::var("HOME").unwrap_or_default()),
            "/usr/local/bin/zcode".to_string(),
        ],
        "windows" => vec![
            r"C:\Program Files\ZCode\ZCode.exe".to_string(),
            std::env::var("LOCALAPPDATA")
                .map(|l| format!(r"{}\Programs\ZCode\ZCode.exe", l))
                .unwrap_or_default(),
        ],
        _ => vec![
            "/usr/local/bin/zcode".to_string(),
            "/usr/bin/zcode".to_string(),
            "/opt/ZCode/zcode".to_string(),
            format!("{}/.local/bin/zcode", std::env::var("HOME").unwrap_or_default()),
        ],
    }
}

pub fn normalize_zcode_path(raw: &str) -> Option<String> {
    let mut t = raw.trim();
    if t.len() >= 2 {
        let b = t.as_bytes();
        let quoted = (b[0] == b'"' && b[t.len() - 1] == b'"') || (b[0] == b'\'' && b[t.len() - 1] == b'\'');
        if quoted {
            t = t[1..t.len() - 1].trim();
        }
    }
    (!t.is_empty()).then(|| t.to_string())
}

pub fn effective_zcode_path(paths: &Paths) -> (String, bool) {
    effective_zcode_path_in(paths, &client_path_candidates(std::env::consts::OS))
}

fn effective_zcode_path_in(paths: &Paths, candidates: &[String]) -> (String, bool) {
    let s = load_settings(paths);
    if let Some(p) = s.zcode_path.as_ref().filter(|p| PathBuf::from(p).exists()) {
        return (p.clone(), true);
    }
    for c in candidates {
        if !c.is_empty() && PathBuf::from(c).exists() {
            return (c.clone(), true);
        }
    }
    if let Some(p) = s.zcode_path {
        return (p, false);
    }
    (candidates.first().cloned().unwrap_or_default(), false)
}

pub fn list_accounts(paths: &Paths) -> Result<Vec<Account>, String> {
    let dir = paths.accounts_dir();
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    for entry in fs::read_dir(&dir).map_err(|e| trf("err.store.list_fail", &[("e", &e.to_string())]))? {
        let entry = entry.map_err(|e| trf("err.store.list_fail", &[("e", &e.to_string())]))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(mut a) = serde_json::from_str::<Account>(&raw) {
                migrate_account_hash_inplace(&mut a);
                out.push(a);
            }
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at).then(a.name.cmp(&b.name)));
    Ok(out)
}

pub fn save_account(paths: &Paths, acc: &Account) -> Result<(), String> {
    paths.ensure_dirs()?;
    let path = paths.accounts_dir().join(format!("{}.json", acc.id));
    let body = serde_json::to_string_pretty(acc).unwrap_or_default() + "\n";
    atomic_write(&path, &body)
}

pub fn load_account(paths: &Paths, id: &str) -> Result<Account, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(tr("err.store.bad_id"));
    }
    let path = paths.accounts_dir().join(format!("{id}.json"));
    let raw = fs::read_to_string(&path).map_err(|_| trf("err.store.no_account_id", &[("id", id)]))?;
    let mut a: Account = serde_json::from_str(&raw).map_err(|e| trf("err.store.corrupt", &[("e", &e.to_string())]))?;
    migrate_account_hash_inplace(&mut a);
    Ok(a)
}

fn migrate_account_hash_inplace(acc: &mut Account) {
    let want = canonical_hash(&acc.credentials);
    if want != acc.hash {
        acc.hash = want;
    }
}

fn name_exists(accounts: &[Account], name: &str) -> bool {
    accounts.iter().any(|a| a.name.eq_ignore_ascii_case(name))
}

pub fn unique_name(accounts: &[Account], base: &str) -> String {
    if !name_exists(accounts, base) {
        return base.to_string();
    }
    for n in 2..1000 {
        let cand = format!("{base} {n}");
        if !name_exists(accounts, &cand) {
            return cand;
        }
    }
    format!("{base} {}", Uuid::new_v4().simple())
}

pub fn capture_current(paths: &Paths, name: Option<String>) -> Result<Account, String> {
    let live = read_live(paths)?.ok_or(tr("err.live.no_creds_file"))?;
    if !is_logged_in(&live) {
        return Err(tr("err.live.no_credentials"));
    }
    let hash = canonical_hash(&live);
    let accounts = list_accounts(paths)?;
    if let Some(i) = find_same_login(&live, &hash, &accounts, &paths.home) {
        return Err(trf("err.live.dup_saved", &[("name", &accounts[i].name)]));
    }
    let config = read_live_config(paths);
    let name = match name {
        Some(n) => unique_name(&accounts, &n),
        None => {
            let id = zcrypto::account_identity(&live, &paths.home);
            unique_name(&accounts, &id.label().unwrap_or_else(|| "Account 1".into()))
        }
    };
    let ts = now_ts();
    let mut acc = Account {
        id: Uuid::new_v4().to_string(),
        name,
        created_at: ts.clone(),
        updated_at: ts,
        hash,
        credentials: live,
        config,
        virtual_device_mid: None,
        virtual_arms_uid: None,
    };
    adopt_virtual_device_mid(paths, &mut acc)?;
    adopt_virtual_arms_uid(paths, &mut acc)?;
    Ok(acc)
}

pub(crate) fn find_same_login(live: &Value, live_hash: &str, accounts: &[Account], home: &Path) -> Option<usize> {
    if let Some(i) = accounts.iter().position(|a| a.hash == live_hash) {
        return Some(i);
    }
    let live_id = zcrypto::account_identity(live, home);
    if !identity_has_signal(&live_id) {
        return None;
    }
    accounts.iter().position(|a| {
        identity_matches(&live_id, &zcrypto::account_identity(&a.credentials, home))
    })
}

fn auto_preserve(paths: &Paths, accounts: &[Account], target_hash: &str) -> Result<Option<String>, String> {
    let live = match read_live(paths)? {
        Some(v) if is_logged_in(&v) => v,
        _ => return Ok(None),
    };
    let hash = canonical_hash(&live);
    if hash == target_hash {
        return Ok(None);
    }
    if find_same_login(&live, &hash, accounts, &paths.home).is_some() {
        return Ok(None);
    }
    let name = unique_name(accounts, &format!("Auto {}", Local::now().format("%m-%d %H%M")));
    let ts = now_ts();
    let mut acc = Account {
        id: Uuid::new_v4().to_string(),
        name: name.clone(),
        created_at: ts.clone(),
        updated_at: ts,
        hash,
        credentials: live,
        config: read_live_config(paths),
        virtual_device_mid: None,
        virtual_arms_uid: None,
    };
    adopt_virtual_device_mid(paths, &mut acc)?;
    adopt_virtual_arms_uid(paths, &mut acc)?;
    Ok(Some(name))
}

fn cred_plain(creds: &Value, key: &str, home: &std::path::Path) -> Option<String> {
    let v = creds.get(key)?.as_str()?;
    if zcrypto::is_encrypted(v) {
        zcrypto::decrypt_with_secret(v, &zcrypto::default_secret(home)).ok()
    } else {
        Some(v.to_string())
    }
}

fn sync_live_back_to_source(paths: &Paths, accounts: &[Account]) -> Result<(), String> {
    let Some(live) = read_live(paths)? else { return Ok(()) };
    if !is_logged_in(&live) { return Ok(()); }
    let live_hash = canonical_hash(&live);
    let live_id = zcrypto::account_identity(&live, &paths.home);
    let has_id = identity_has_signal(&live_id);
    let source = accounts.iter().find(|a| a.hash == live_hash).cloned().or_else(|| {
        if !has_id { return None; }
        accounts.iter().find(|a| {
            identity_matches(&live_id, &zcrypto::account_identity(&a.credentials, &paths.home))
        }).cloned()
    });
    let Some(mut src) = source else { return Ok(()); };
    let mut changed = false;
    if src.credentials != live {
        src.credentials = live.clone();
        src.hash = live_hash;
        changed = true;
    }
    if src.config.is_some() {
        let cfg = read_live_config(paths);
        if cfg.is_some() && cfg != src.config {
            src.config = cfg;
            changed = true;
        }
    }
    if changed {
        src.updated_at = now_ts();
        save_account(paths, &src)?;
    }
    Ok(())
}

fn reset_live_plan_cache(paths: &Paths) {
    let p = paths.live_plan_cache();
    if p.exists() {
        if let Err(e) = fs::remove_file(&p) {
            eprintln!("删除 coding-plan-cache.json 失败(忽略): {e}");
        }
    }
}

fn align_family_domain(paths: &Paths, target: &Account) {
    let Some(provider) = cred_plain(&target.credentials, "oauth:active_provider", &paths.home)
        .filter(|p| p == "bigmodel" || p == "zai") else { return; };
    let Ok(raw) = fs::read_to_string(paths.live_setting()) else { return; };
    let Ok(mut v) = serde_json::from_str::<Value>(&raw) else {
        eprintln!("setting.json 解析失败,跳过 family domain 对齐");
        return;
    };
    let Some(obj) = v.as_object_mut() else { return; };
    let now_ms = chrono::Local::now().timestamp_millis();
    obj.insert("providerFamilyDomain".into(), Value::String(provider));
    obj.insert("providerFamilyDomainUpdatedAt".into(), Value::from(now_ms));
    let body = serde_json::to_string_pretty(&v).unwrap_or_default() + "\n";
    if let Err(e) = atomic_write(&paths.live_setting(), &body) {
        eprintln!("setting.json family domain 写回失败(忽略): {e}");
    }
}

fn rematerialize_wiped_builtins(paths: &Paths, target: &Account) {
    if target.config.is_none() { return; }
    let Some(provider) = cred_plain(&target.credentials, "oauth:active_provider", &paths.home)
        .filter(|p| p == "bigmodel" || p == "zai") else { return; };
    let Some(jwt) = cred_plain(&target.credentials, "zcodejwttoken", &paths.home)
        .filter(|j| !j.trim().is_empty()) else { return; };
    let Some(live) = read_live_config(paths) else { return; };
    let mut out = match live.as_object() { Some(o) => o.clone(), None => return };
    let Some(live_prov) = out.get("provider").and_then(|v| v.as_object()) else { return };

    let wiped = |cur: &Value| {
        cur.get("options").and_then(|o| o.get("apiKey"))
            .map(|k| k.as_str().map(str::trim).unwrap_or("").is_empty())
            .unwrap_or(true)
            || (cur.get("enabled").and_then(|e| e.as_bool()) == Some(false)
                && cur.get("systemDisabledReason").and_then(|s| s.as_str())
                    == Some("oauth_provider_inactive"))
    };
    let family_prefix = format!("builtin:{provider}");

    let has_candidate = live_prov
        .iter()
        .any(|(id, cur)| id.starts_with(&family_prefix) && wiped(cur));
    if !has_candidate { return; }

    let at_key = format!("oauth:{provider}:access_token");
    let access_token = match (in_sandbox(), cred_plain(&target.credentials, &at_key, &paths.home)) {
        (true, _) => String::new(),
        (false, Some(at)) => at.trim().to_string(),
        (false, None) => String::new(),
    };
    let access_token = if provider == "zai" && !access_token.is_empty() {
        crate::oauth::resolve_zai_business_token(&access_token).unwrap_or(access_token)
    } else {
        access_token
    };
    let fresh = crate::oauth::assemble_config(&provider, &jwt, &access_token);
    let Some(fresh_map) = fresh.get("provider").and_then(|v| v.as_object()) else { return; };
    let mut live_prov = live_prov.clone();
    let mut changed = false;
    for (id, fresh_entry) in fresh_map {
        let Some(cur) = live_prov.get(id) else { continue; };
        if !wiped(cur) { continue; }
        let Some(new_key) = fresh_entry.pointer("/options/apiKey")
            .and_then(|k| k.as_str()).map(str::trim)
            .filter(|k| !k.is_empty()) else { continue; };
        let mut patched = cur.clone();
        if let Some(opts) = patched.get_mut("options").and_then(|o| o.as_object_mut()) {
            opts.insert("apiKey".into(), Value::String(new_key.to_string()));
            opts.remove("apiKeyRequired");
        }
        if let Some(obj) = patched.as_object_mut() {
            obj.insert("enabled".into(), Value::Bool(true));
            obj.remove("systemDisabledReason");
        }
        live_prov.insert(id.clone(), patched);
        changed = true;
    }
    if changed {
        out.insert("provider".into(), Value::Object(live_prov));
        let body = serde_json::to_string_pretty(&Value::Object(out)).unwrap_or_default() + "\n";
        if let Err(e) = atomic_write(&paths.live_config(), &body) {
            eprintln!("重物化 builtin apiKey 写回失败(忽略): {e}");
        }
    }
}

pub fn switch_to(paths: &Paths, id: &str, force: bool, restart: bool, hot: bool) -> Result<SwitchResult, String> {
    let target = load_account(paths, id)?;
    let accounts = list_accounts(paths)?;
    let live = read_live(paths)?;
    let live_hash = live.as_ref().map(canonical_hash);

    let already = live_hash.as_deref() == Some(target.hash.as_str())
        || live.as_ref().is_some_and(|v| {
            is_logged_in(v) && {
                let (li, ti) = (
                    zcrypto::account_identity(v, &paths.home),
                    zcrypto::account_identity(&target.credentials, &paths.home),
                );
                identity_has_signal(&li) && identity_has_signal(&ti) && identity_matches(&li, &ti)
            }
        });
    if already {
        if live_hash.as_deref() != Some(target.hash.as_str()) {
            if let Err(e) = sync_live_back_to_source(paths, &accounts) {
                eprintln!("sync-back 失败(不阻断 already 返回): {e}");
            }
        }
        let mid = ensure_virtual_device_mid_locked(paths, &target.id)?;
        write_live_device_mid(paths, &mid)?;
        let uid = ensure_virtual_arms_uid_locked(paths, &target.id)?;
        if !zcode_running() {
            let _ = write_live_arms_uid(paths, &uid);
        }
        return Ok(SwitchResult {
            switched: false,
            already_active: true,
            name: target.name,
            preserved_as: None,
            killed: false,
            launched: false,
            hot: false,
            config_stale: false,
        });
    }

    let running = zcode_running();
    if hot && running {
        if let Err(e) = sync_live_back_to_source(paths, &accounts) {
            eprintln!("sync-back 失败(不阻断切换): {e}");
        }
        let accounts = list_accounts(paths)?;
        let preserved_as = auto_preserve(paths, &accounts, &target.hash)?;
        let creds = inject_relay_pass_hash(&target.credentials, current_relay_pass(paths).as_ref());
        hot_swap_verified(paths, &target, &creds)?;
        backfill_relay_pass_hash(paths, &target.id, &creds);
        reset_live_plan_cache(paths);
        let mid = ensure_virtual_device_mid_locked(paths, &target.id)?;
        write_live_device_mid(paths, &mid)?;
        ensure_virtual_arms_uid_locked(paths, &target.id)?;
        return Ok(SwitchResult {
            switched: true,
            already_active: false,
            name: target.name,
            preserved_as,
            killed: false,
            launched: false,
            hot: true,
            config_stale: target.config.is_none() && paths.live_config().exists(),
        });
    }

    let mut killed = false;
    if running {
        if !force {
            return Err(tr("err.switch.running"));
        }
        if !kill_zcode()? {
            return Err(tr("err.switch.kill_timeout"));
        }
        killed = true;
    }

    if let Err(e) = sync_live_back_to_source(paths, &accounts) {
        eprintln!("sync-back 失败(不阻断切换): {e}");
    }
    let accounts = list_accounts(paths)?;

    let preserved_as = auto_preserve(paths, &accounts, &target.hash)?;

    let creds = inject_relay_pass_hash(&target.credentials, current_relay_pass(paths).as_ref());
    write_live(paths, &creds)?;
    backfill_relay_pass_hash(paths, &target.id, &creds);
    if let Some(cfg) = &target.config {
        write_live_config(paths, cfg)?;
    }
    reset_live_plan_cache(paths);
    align_family_domain(paths, &target);
    rematerialize_wiped_builtins(paths, &target);
    let mid = ensure_virtual_device_mid_locked(paths, &target.id)?;
    write_live_device_mid(paths, &mid)?;
    let uid = ensure_virtual_arms_uid_locked(paths, &target.id)?;
    let _ = write_live_arms_uid(paths, &uid);

    let mut launched = false;
    if restart {
        let (p, ok) = effective_zcode_path(paths);
        if ok && launch_zcode(&p).is_ok() {
            launched = true;
        }
    }

    Ok(SwitchResult {
        switched: true,
        already_active: false,
        name: target.name,
        preserved_as,
        killed,
        launched,
        hot: false,
        config_stale: target.config.is_none() && paths.live_config().exists(),
    })
}

const RELAY_PASS_KEY: &str = "web-remote-control:external-relay:pass_hash";

fn inject_relay_pass_hash(creds: &Value, relay: Option<&Value>) -> Value {
    let Some(relay) = relay else { return creds.clone() };
    let mut out = creds.clone();
    if let Some(map) = out.as_object_mut() {
        map.insert(RELAY_PASS_KEY.to_string(), relay.clone());
    }
    out
}

fn current_relay_pass(paths: &Paths) -> Option<Value> {
    read_live(paths)
        .ok()
        .flatten()
        .and_then(|v| v.get(RELAY_PASS_KEY).cloned())
}

fn backfill_relay_pass_hash(paths: &Paths, target_id: &str, creds: &Value) {
    let Ok(mut acc) = load_account(paths, target_id) else { return };
    if acc.credentials != *creds {
        acc.credentials = creds.clone();
        acc.updated_at = now_ts();
        if let Err(e) = save_account(paths, &acc) {
            eprintln!("relay 回填失败(不阻断切换): {e}");
        }
    }
}

fn hot_swap_verified(paths: &Paths, target: &Account, creds: &Value) -> Result<(), String> {
    let want = zcrypto::account_identity(&target.credentials, &paths.home);
    let use_hash = !identity_has_signal(&want);
    let verify = |v: &Value| {
        if use_hash {
            canonical_hash(v) == target.hash
        } else {
            identity_matches(&want, &zcrypto::account_identity(v, &paths.home))
        }
    };
    let mut last_err: Option<String> = None;
    let backoff = |attempt: u32| std::thread::sleep(std::time::Duration::from_millis(250 + u64::from(attempt) * 250));
    for attempt in 0..3u32 {
        if let Err(e) = write_live(paths, creds) {
            last_err = Some(trf("err.write", &[("e", &e)]));
            backoff(attempt);
            continue;
        }
        if let Some(cfg) = &target.config {
            if let Err(e) = write_live_config(paths, cfg) {
                last_err = Some(trf("err.write_config", &[("e", &e)]));
                backoff(attempt);
                continue;
            }
        }
        if let Ok(Some(v)) = read_live(paths) {
            if verify(&v) {
                std::thread::sleep(std::time::Duration::from_millis(150));
                if let Ok(Some(v2)) = read_live(paths) {
                    if verify(&v2) {
                        return Ok(());
                    }
                }
            }
        }
        backoff(attempt);
    }
    Err(last_err.unwrap_or_else(|| tr("err.hot.verify")))
}

fn identity_has_signal(id: &zcrypto::Identity) -> bool {
    id.user_id.as_deref().is_some_and(|s| !s.is_empty())
        || id.email.as_deref().is_some_and(|s| !s.is_empty())
        || id.username.as_deref().is_some_and(|s| !s.is_empty())
}

fn identity_matches(a: &zcrypto::Identity, b: &zcrypto::Identity) -> bool {
    let norm = |s: &str| s.trim().to_lowercase();
    let opt = |s: &Option<String>| norm(s.as_deref().unwrap_or("")).to_string();
    let (au, ae, ap, an) = (opt(&a.user_id), opt(&a.email), norm(&a.provider), opt(&a.username));
    let (bu, be, bp, bn) = (opt(&b.user_id), opt(&b.email), norm(&b.provider), opt(&b.username));
    if !au.is_empty() && !bu.is_empty() {
        if au != bu {
            return false;
        }
        if !ae.is_empty() && !be.is_empty() && ae != be {
            return false;
        }
        return true;
    }
    if !ae.is_empty() && !be.is_empty() {
        return ae == be;
    }
    ap == bp && !an.is_empty() && an == bn
}

pub fn rename_account(paths: &Paths, id: &str, new_name: &str) -> Result<Account, String> {
    let name = new_name.trim();
    if name.is_empty() {
        return Err(tr("err.name.empty"));
    }
    if name.chars().count() > 40 {
        return Err(tr("err.name.too_long"));
    }
    let mut acc = load_account(paths, id)?;
    let accounts = list_accounts(paths)?;
    if let Some(other) = accounts
        .iter()
        .find(|a| a.id != id && a.name.eq_ignore_ascii_case(name))
    {
        return Err(trf("err.name.taken", &[("name", name), ("other", &other.name)]));
    }
    acc.name = name.to_string();
    acc.updated_at = now_ts();
    save_account(paths, &acc)?;
    Ok(acc)
}

pub fn delete_account(paths: &Paths, id: &str) -> Result<(), String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(tr("err.store.bad_id"));
    }
    let path = paths.accounts_dir().join(format!("{id}.json"));
    if !path.exists() {
        return Err(tr("err.store.no_account"));
    }
    fs::remove_file(&path).map_err(|e| trf("err.store.delete_fail", &[("e", &e.to_string())]))
}

pub fn update_account_from_live(paths: &Paths, id: &str) -> Result<Account, String> {
    let live = read_live(paths)?.ok_or(tr("err.live.no_file"))?;
    if !is_logged_in(&live) {
        return Err(tr("err.live.logged_out"));
    }
    let hash = canonical_hash(&live);
    let accounts = list_accounts(paths)?;
    if let Some(i) = find_same_login(&live, &hash, &accounts, &paths.home) {
        if accounts[i].id != id {
            return Err(trf("err.live.same", &[("name", &accounts[i].name)]));
        }
    }
    let mut acc = load_account(paths, id)?;
    acc.hash = hash;
    acc.credentials = live;
    acc.config = read_live_config(paths);
    acc.updated_at = now_ts();
    save_account(paths, &acc)?;
    Ok(acc)
}

pub fn live_quota(paths: &Paths) -> Result<quota::QuotaOverview, String> {
    let creds = read_live(paths)?.ok_or(tr("err.live.no_file"))?;
    if !is_logged_in(&creds) {
        return Err(tr("err.live.quota"));
    }
    quota::quota_for_live(&paths.home, &creds, read_live_config(paths).as_ref())
}

pub fn account_quota(paths: &Paths, id: &str) -> Result<quota::QuotaOverview, String> {
    let acc = load_account(paths, id)?;
    quota::quota_for_snapshot(&paths.home, &acc.credentials, acc.config.as_ref())
}

fn ensure_virtual_device_mid_locked(paths: &Paths, id: &str) -> Result<String, String> {
    {
        let acc = load_account(paths, id)?;
        if let Some(m) = acc.virtual_device_mid.clone() {
            if !m.trim().is_empty() {
                return Ok(m);
            }
        }
    }
    let mut acc = load_account(paths, id)?;
    if let Some(m) = acc.virtual_device_mid.clone() {
        if !m.trim().is_empty() {
            return Ok(m);
        }
    }
    let m = Uuid::new_v4().to_string();
    acc.virtual_device_mid = Some(m.clone());
    acc.updated_at = now_ts();
    save_account(paths, &acc)?;
    Ok(m)
}

pub fn ensure_virtual_device_mid(paths: &Paths, id: &str) -> Result<String, String> {
    if let Ok(acc) = load_account(paths, id) {
        if let Some(m) = acc.virtual_device_mid.clone() {
            if !m.trim().is_empty() {
                return Ok(m);
            }
        }
    }
    let _guard = crate::store_guard();
    ensure_virtual_device_mid_locked(paths, id)
}

pub fn write_live_device_mid(paths: &Paths, mid: &str) -> Result<(), String> {
    let mut v: Value = fs::read_to_string(paths.live_telemetry())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}));
    if !v.is_object() {
        v = json!({});
    }
    if v.get("deviceMid").and_then(|m| m.as_str()) == Some(mid) {
        return Ok(());
    }
    v["deviceMid"] = json!(mid);
    atomic_write(&paths.live_telemetry(), &(serde_json::to_string(&v).unwrap_or_default() + "\n"))
}

fn adopt_virtual_device_mid(paths: &Paths, acc: &mut Account) -> Result<(), String> {
    if acc.virtual_device_mid.as_deref().map_or(false, |m| !m.trim().is_empty()) {
        return Ok(());
    }
    let live_mid: Option<String> = fs::read_to_string(paths.live_telemetry())
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("deviceMid").and_then(|m| m.as_str()).map(String::from))
        .filter(|m| !m.trim().is_empty());
    let taken = |m: &str| {
        list_accounts(paths)
            .map(|accs| accs.iter().any(|a| a.virtual_device_mid.as_deref() == Some(m)))
            .unwrap_or(false)
    };
    let mid = match live_mid {
        Some(m) if !taken(&m) => m,
        _ => Uuid::new_v4().to_string(),
    };
    acc.virtual_device_mid = Some(mid);
    acc.updated_at = now_ts();
    save_account(paths, acc)
}

const ARMS_DEFAULT_STORE_FILE: &str = "ZGVmYXVsdA.json";

pub fn new_arms_uid() -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let uuid = Uuid::new_v4();
    let suffix: String = uuid.as_bytes()
        .iter()
        .take(16)
        .map(|b| ALPHABET[(*b as usize) % 36] as char)
        .collect();
    format!("uid_{suffix}")
}

fn arms_store_dirs_from(
    win_appdata: Option<PathBuf>,
    mac_appsupport: Option<PathBuf>,
    unix_base: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push_if_new = |dir: PathBuf| {
        let lowered = dir.to_string_lossy().to_lowercase();
        if !out.iter().any(|d| d.to_string_lossy().to_lowercase() == lowered) {
            out.push(dir);
        }
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    let groups: [(Option<PathBuf>, &[&str]); 3] = [
        (win_appdata, &["ZCode", "zcode", "ZCode Preview", "ZCode Dev"]),
        (mac_appsupport, &["ZCode", "zcode", "ZCode Preview", "ZCode Dev"]),
        (unix_base, &["zcode", "ZCode"]),
    ];
    for (base, names) in groups {
        let Some(base) = base else { continue };
        for name in names {
            candidates.push(base.join(name).join("rum-electron-store"));
        }
        if let Ok(rd) = fs::read_dir(&base) {
            let extras: Vec<PathBuf> = rd
                .flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    n.starts_with("zcode") && e.path().join("rum-electron-store").is_dir()
                })
                .map(|e| e.path().join("rum-electron-store"))
                .collect();
            candidates.extend(extras);
        }
    }
    let existing: Vec<PathBuf> = candidates.iter().filter(|c| c.is_dir()).cloned().collect();
    if existing.is_empty() {
        candidates.truncate(1);
        candidates
    } else {
        for c in existing {
            push_if_new(c);
        }
        out
    }
}

fn arms_store_dirs_for(paths: &Paths) -> Vec<PathBuf> {
    if in_sandbox() {
        return vec![paths.home.join("arms-store-sandbox")];
    }
    #[cfg(windows)]
    let (appdata, mac_base, unix_base) =
        (std::env::var("APPDATA").ok().map(PathBuf::from), None, None);
    #[cfg(target_os = "macos")]
    let (appdata, mac_base, unix_base) = (
        None,
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Application Support")),
        None,
    );
    #[cfg(all(unix, not(target_os = "macos")))]
    let (appdata, mac_base, unix_base) = (
        None,
        None,
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config"))),
    );
    arms_store_dirs_from(appdata, mac_base, unix_base)
}

fn ensure_virtual_arms_uid_locked(paths: &Paths, id: &str) -> Result<String, String> {
    {
        let acc = load_account(paths, id)?;
        if let Some(u) = acc.virtual_arms_uid.clone() {
            if !u.trim().is_empty() {
                return Ok(u);
            }
        }
    }
    let mut acc = load_account(paths, id)?;
    if let Some(u) = acc.virtual_arms_uid.clone() {
        if !u.trim().is_empty() {
            return Ok(u);
        }
    }
    let u = new_arms_uid();
    acc.virtual_arms_uid = Some(u.clone());
    acc.updated_at = now_ts();
    save_account(paths, &acc)?;
    Ok(u)
}

fn read_live_arms_uid_from(dirs: &[PathBuf]) -> Option<String> {
    let read_uid = |f: &Path| -> Option<String> {
        fs::read_to_string(f)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.get("_arms_uid").and_then(|u| u.as_str()).map(String::from))
            .filter(|u| !u.trim().is_empty())
    };
    let mut files: Vec<PathBuf> = Vec::new();
    for d in dirs {
        if let Ok(rd) = fs::read_dir(d) {
            let mut jsons: Vec<PathBuf> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                .collect();
            jsons.sort_by_key(|p| !p.file_name().map(|n| n == ARMS_DEFAULT_STORE_FILE).unwrap_or(false));
            files.extend(jsons);
        }
    }
    files.iter().find_map(|f| read_uid(f))
}

pub fn write_live_arms_uid_to(dirs: &[PathBuf], uid: &str) -> Result<(), String> {
    for d in dirs {
        let mut jsons: Vec<PathBuf> = fs::read_dir(d)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default();
        if jsons.is_empty() {
            fs::create_dir_all(d).map_err(|e| format!("mkdir {}: {e}", d.display()))?;
            jsons.push(d.join(ARMS_DEFAULT_STORE_FILE));
        }
        let mut first_err: Option<String> = None;
        for f in jsons {
            let mut v: Value = fs::read_to_string(&f)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| json!({}));
            if !v.is_object() {
                v = json!({});
            }
            if v.get("_arms_uid").and_then(|u| u.as_str()) == Some(uid)
                && v.get("_arms_session").is_none()
            {
                continue;
            }
            let obj = v.as_object_mut().unwrap();
            obj.insert("_arms_uid".into(), json!(uid));
            obj.remove("_arms_session");
            if let Err(e) = atomic_write(&f, &(serde_json::to_string(&v).unwrap_or_default() + "\n")) {
                first_err.get_or_insert(e);
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
    }
    Ok(())
}

fn write_live_arms_uid(paths: &Paths, uid: &str) -> Result<(), String> {
    write_live_arms_uid_to(&arms_store_dirs_for(paths), uid)
}

fn adopt_virtual_arms_uid(paths: &Paths, acc: &mut Account) -> Result<(), String> {
    if acc.virtual_arms_uid.as_deref().is_some_and(|u| !u.trim().is_empty()) {
        return Ok(());
    }
    let live_uid = read_live_arms_uid_from(&arms_store_dirs_for(paths));
    let taken = |u: &str| {
        list_accounts(paths)
            .map(|accs| accs.iter().any(|a| a.virtual_arms_uid.as_deref() == Some(u)))
            .unwrap_or(false)
    };
    let uid = match live_uid {
        Some(u) if !taken(&u) => u,
        _ => new_arms_uid(),
    };
    acc.virtual_arms_uid = Some(uid);
    acc.updated_at = now_ts();
    save_account(paths, acc)
}

pub fn export_bundle_value(accounts: &[Account]) -> Value {
    json!({
        "format": "zcode-accounts-bundle",
        "version": 2,
        "exportedAt": now_ts(),
        "accounts": accounts.iter().map(|a| json!({
            "name": a.name,
            "createdAt": a.created_at,
            "credentials": a.credentials,
            "config": a.config,
        })).collect::<Vec<_>>(),
    })
}

type ImportCandidate = (Option<String>, Value, Option<Value>);

fn import_candidates(v: &Value) -> Result<Vec<ImportCandidate>, String> {
    if v.get("format").and_then(|f| f.as_str()) == Some("zcode-accounts-bundle") {
        let arr = v
            .get("accounts")
            .and_then(|a| a.as_array())
            .ok_or(tr("err.bundle.no_accounts"))?;
        let mut out = vec![];
        for item in arr {
            let creds = item.get("credentials").cloned().ok_or(tr("err.bundle.no_creds"))?;
            out.push((
                item.get("name").and_then(|n| n.as_str()).map(String::from),
                creds,
                item.get("config").cloned(),
            ));
        }
        return Ok(out);
    }
    Err(tr("err.bundle.unrecognized"))
}

pub fn import_values(paths: &Paths, files: &[(String, Value)]) -> Result<ImportReport, String> {
    let mut report = ImportReport { picked: true, ..Default::default() };
    let accounts = list_accounts(paths)?;

    let mut new_accounts: Vec<Account> = vec![];

    for (fname, v) in files {
        let cands = match import_candidates(v) {
            Ok(c) => c,
            Err(e) => {
                report.errors.push(trf("err.import.wrap", &[("fname", fname.as_str()), ("e", e.as_str())]));
                continue;
            }
        };
        for (name_opt, creds, config_opt) in cands {
            if !is_logged_in(&creds) {
                report.skipped.push(trf("err.import.no_creds", &[("fname", fname.as_str())]));
                continue;
            }
            let hash = canonical_hash(&creds);
            if accounts.iter().any(|a| a.hash == hash) || new_accounts.iter().any(|a| a.hash == hash) {
                report.skipped.push(trf("err.import.dup", &[("fname", fname.as_str())]));
                continue;
            }
            let base_name = name_opt.unwrap_or_else(|| {
                let id = zcrypto::account_identity(&creds, &paths.home);
                id.label().unwrap_or_else(|| format!("Import {}", Local::now().format("%m-%d %H%M")))
            });
            let name = unique_name(&accounts, &base_name);
            let ts = now_ts();
            let acc = Account {
                id: Uuid::new_v4().to_string(),
                name: name.clone(),
                created_at: ts.clone(),
                updated_at: ts,
                hash,
                credentials: creds,
                config: config_opt,
                virtual_device_mid: None,
                virtual_arms_uid: None,
            };
            new_accounts.push(acc);
            report.added.push(name);
        }
    }

    for acc in &new_accounts {
        save_account(paths, acc)?;
    }
    Ok(report)
}

pub fn get_state(paths: &Paths) -> Result<AppState, String> {
    let accounts = list_accounts(paths)?;
    let live = read_live(paths)?;
    let live_hash = live.as_ref().map(canonical_hash);
    let live_logged_in = live.as_ref().map(is_logged_in).unwrap_or(false);
    let active_account_id = live_hash
        .as_ref()
        .and_then(|h| accounts.iter().find(|a| &a.hash == h).map(|a| a.id.clone()));
    let live_identity = live
        .as_ref()
        .filter(|_| live_logged_in)
        .map(|v| zcrypto::account_identity(v, &paths.home));
    let (zcode_path, zcode_path_ok) = effective_zcode_path(paths);
    let settings = load_settings(paths);
    let summaries = accounts
        .iter()
        .map(|a| AccountSummary {
            id: a.id.clone(),
            name: a.name.clone(),
            created_at: a.created_at.clone(),
            updated_at: a.updated_at.clone(),
            is_active: live_hash.as_deref() == Some(a.hash.as_str()),
            has_config: a.config.is_some(),
            has_user_info: crate::claim::telemetry_user_id(&paths.home, &a.credentials).is_some(),
            identity: zcrypto::account_identity(&a.credentials, &paths.home),
        })
        .collect();
    Ok(AppState {
        zcode_running: zcode_running(),
        live_exists: paths.live_file().exists(),
        live_logged_in,
        live_hash,
        active_account_id,
        live_identity,
        accounts: summaries,
        zcode_path,
        zcode_path_ok,
        store_dir: paths.store_dir().to_string_lossy().to_string(),
        launch_after_switch: settings.launch_after_switch(),
        close_to_tray: settings.close_to_tray(),
        hot_switch: settings.hot_switch(),
        auto_claim: settings.auto_claim(),
        auth_proxy_on: settings.auth_proxy_on.unwrap_or(false),
        auth_proxy_url: settings.auth_proxy_url.clone(),
        language: crate::i18n::current().as_str().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;

    fn fake_home(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zswitch-test-{}-{}", tag, Uuid::new_v4().simple()));
        fs::create_dir_all(dir.join(".zcode").join("v2")).unwrap();
        std::env::set_var("ZCODE_SWITCH_HOME", &dir);
        dir
    }

    fn write_live_raw(home: &Path, marker: &str) -> Value {
        let v = json!({
            "oauth:bigmodel:access_token": format!("enc:v1:AAA{marker}"),
            "oauth:bigmodel:user_info": "enc:v1:BBBB",
            "oauth:active_provider": "enc:v1:CCCC",
            "zcodejwttoken": "enc:v1:DDDD",
        });
        let raw = if marker.chars().next().map(|c| c as u32).unwrap_or(0).is_multiple_of(2) {
            serde_json::to_string(&v).unwrap()
        } else {
            let m = v.as_object().unwrap();
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.reverse();
            let mut o = Map::new();
            for k in keys { let val = m[&k].clone(); o.insert(k, val); }
            serde_json::to_string(&Value::Object(o)).unwrap()
        };
        fs::write(home.join(".zcode/v2/credentials.json"), raw).unwrap();
        v
    }

    fn write_config_raw(home: &Path, marker: &str) -> Value {
        let v = json!({ "provider": { "builtin:bigmodel-coding-plan": {
            "options": { "apiKey": format!("key-{marker}"), "baseURL": "https://open.bigmodel.cn/api/anthropic" }
        }}});
        fs::write(home.join(".zcode/v2/config.json"), serde_json::to_string(&v).unwrap()).unwrap();
        v
    }

    #[test]
    fn canonical_hash_excludes_device_level_keys() {
        assert!(RELAY_PASS_KEY.starts_with(DEVICE_KEY_PREFIX), "relay 键必须落在设备级命名空间内");
        let base = json!({
            "zcodejwttoken": "J",
            "web-remote-control:external-relay:pass_hash": "enc:v1:A",
        });
        let rotated = json!({
            "zcodejwttoken": "J",
            "web-remote-control:external-relay:pass_hash": "enc:v1:B",
        });
        let none = json!({ "zcodejwttoken": "J" });
        assert_eq!(canonical_hash(&base), canonical_hash(&rotated));
        assert_eq!(canonical_hash(&base), canonical_hash(&none));
        let other = json!({ "zcodejwttoken": "J2", "web-remote-control:external-relay:pass_hash": "enc:v1:A" });
        assert_ne!(canonical_hash(&base), canonical_hash(&other));
    }

    #[test]
    fn legacy_full_tree_hash_migrated_on_load() {
        let home = fake_home("hashmig");
        let p = Paths::new(&home);
        let mut legacy = Account {
            id: Uuid::new_v4().to_string(),
            name: "旧口径账号".into(),
            created_at: now_ts(),
            updated_at: "2000-01-01 00:00".into(),
            hash: String::new(),
            credentials: json!({
                "zcodejwttoken": "enc:v1:JJJ",
                "web-remote-control:external-relay:pass_hash": "enc:v1:OLDRELAY",
            }),
            config: None,
            virtual_device_mid: None,
            virtual_arms_uid: None,
        };
        let full = Sha256::digest(serde_json::to_vec(&legacy.credentials).unwrap());
        legacy.hash = format!("{full:x}");
        let legacy_full_tree_hash_as_saved = legacy.hash.clone();
        assert_ne!(legacy.hash, canonical_hash(&legacy.credentials), "前置:新旧口径必须不同");
        save_account(&p, &legacy).unwrap();

        let listed = list_accounts(&p).unwrap();
        let got = listed.iter().find(|a| a.id == legacy.id).unwrap();
        assert_eq!(got.hash, canonical_hash(&got.credentials), "读出即迁移到新口径");
        assert_eq!(got.updated_at, "2000-01-01 00:00", "迁移不得动 updated_at");
        let reloaded = load_account(&p, &legacy.id).unwrap();
        assert_eq!(reloaded.hash, canonical_hash(&reloaded.credentials), "重读仍给出迁移后内存值");
        let raw: Value = serde_json::from_str(&fs::read_to_string(p.accounts_dir().join(format!("{}.json", legacy.id))).unwrap()).unwrap();
        assert_eq!(raw["hash"].as_str(), Some(legacy_full_tree_hash_as_saved.as_str()), "读路径不落盘:盘上保持旧口径,由下次真实 save 收敛");

        let mut live = legacy.credentials.clone();
        live["web-remote-control:external-relay:pass_hash"] = json!("enc:v1:NEWRELAY");
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();
        let st = get_state(&p).unwrap();
        assert_eq!(st.active_account_id.as_deref(), Some(legacy.id.as_str()), "设备键轮换不再打断当前账号识别");
        assert!(st.accounts.iter().find(|a| a.id == legacy.id).unwrap().is_active);
    }

    #[test]
    fn home_pick_prefers_override_then_platform_home() {
        assert_eq!(
            pick_home(Some(PathBuf::from("/x")), Some(PathBuf::from("/up")), Some(PathBuf::from("/h"))),
            PathBuf::from("/x")
        );
        assert_eq!(
            pick_home(None, Some(PathBuf::from("/up")), Some(PathBuf::from("/h"))),
            PathBuf::from("/up")
        );
        assert_eq!(
            pick_home(None, None, Some(PathBuf::from("/h"))),
            PathBuf::from("/h")
        );
        assert_eq!(pick_home(None, None, None), PathBuf::from("."));
    }

    #[test]
    fn zcode_path_candidates_cover_three_oses() {
        let win = client_path_candidates("windows");
        assert!(win[0].contains("ZCode.exe"), "windows 首选应为 Program Files 下的 exe");
        let mac = client_path_candidates("macos");
        assert!(mac.iter().any(|p| p.contains("ZCode.app/Contents/MacOS")), "mac 应含 .app 包内可执行");
        let linux = client_path_candidates("linux");
        assert!(linux.iter().any(|p| p == "/usr/local/bin/zcode" || p == "/usr/bin/zcode"), "linux 应含系统路径");
        assert!(
            client_path_candidates("windows").iter().all(|p| !p.contains(".app")),
            "windows 候选不得混入 mac 路径"
        );
    }

    #[test]
    fn capture_list_rename_delete_roundtrip() {
        let home = fake_home("cap");
        let p = Paths::new(&home);
        write_live_raw(&home, "X1");

        let acc = capture_current(&p, Some("主号".into())).unwrap();
        assert_eq!(acc.name, "主号");
        assert!(acc.config.is_none(), "没有 config 文件时应为 None");

        write_config_raw(&home, "C1");
        write_live_raw(&home, "X2");
        let acc2 = capture_current(&p, Some("二号".into())).unwrap();
        assert!(acc2.config.is_some(), "config 文件存在时应一起快照");

        let list = list_accounts(&p).unwrap();
        assert_eq!(list.len(), 2);

        let err = capture_current(&p, Some("again".into())).unwrap_err();
        assert!(err.contains("二号"));

        let r = rename_account(&p, &acc.id, "工作号").unwrap();
        assert_eq!(r.name, "工作号");
        assert!(rename_account(&p, &acc2.id, "工作号").is_err());
        assert!(rename_account(&p, &acc2.id, "  ").is_err());

        delete_account(&p, &acc2.id).unwrap();
        assert_eq!(list_accounts(&p).unwrap().len(), 1);

        let outside = home.join("outside-victim.json");
        fs::write(&outside, "{}").unwrap();
        assert!(delete_account(&p, "../../outside-victim").is_err(), "相对穿越必须被拒");
        let abs_no_ext = outside.with_extension("");
        let abs_id = abs_no_ext.to_string_lossy().to_string();
        assert!(delete_account(&p, &abs_id).is_err(), "绝对路径必须被拒");
        assert!(delete_account(&p, "C:/evil").is_err(), "盘符路径必须被拒");
        assert!(delete_account(&p, "").is_err());
        assert!(outside.exists(), "库外文件不允许被删除");
    }

    #[test]
    fn capture_auto_name_from_identity() {
        let home = fake_home("idn");
        let p = Paths::new(&home);
        let secret = zcrypto::default_secret(&home);
        let ui = zcrypto::encrypt_with_secret(r#"{"username":"vcjzxsv6","displayName":"小明"}"#, &secret).unwrap();
        let ap = zcrypto::encrypt_with_secret("bigmodel", &secret).unwrap();
        let at = zcrypto::encrypt_with_secret("access-token-1234567890abcdef", &secret).unwrap();
        fs::write(
            home.join(".zcode/v2/credentials.json"),
            serde_json::to_string(&json!({
                "oauth:bigmodel:access_token": at,
                "oauth:bigmodel:user_info": ui,
                "oauth:active_provider": ap,
            }))
            .unwrap(),
        )
        .unwrap();
        let acc = capture_current(&p, None).unwrap();
        assert_eq!(acc.name, "小明", "自动命名应取 displayName");

        let st = get_state(&p).unwrap();
        assert_eq!(st.live_identity.as_ref().unwrap().username.as_deref(), Some("vcjzxsv6"));
        assert_eq!(st.accounts[0].identity.display_name.as_deref(), Some("小明"));
    }

    #[test]
    fn switch_with_config_replaces_live() {
        let home = fake_home("sw2");
        let p = Paths::new(&home);
        write_live_raw(&home, "A1");
        write_config_raw(&home, "CA");
        let a = capture_current(&p, Some("A".into())).unwrap();

        let r = switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(r.already_active && !r.switched);

        write_live_raw(&home, "B7");
        write_config_raw(&home, "CB");
        let _b = capture_current(&p, Some("B".into())).unwrap();

        write_live_raw(&home, "B8");
        let r = switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(r.switched);
        assert!(r.preserved_as.is_some());
        assert!(!r.killed, "沙箱模式下视为未运行，无需 kill 也能完成切换");

        let live_cred = fs::read_to_string(p.live_file()).unwrap();
        assert!(live_cred.contains("A1"));
        let live_cfg = fs::read_to_string(p.live_config()).unwrap();
        assert!(live_cfg.contains("key-CA"), "config 应切到 A 的快照");
    }

    fn write_live_plain(home: &Path, access_token: &str, jwt: &str) -> Value {
        write_live_plain_as(home, "u1", "n1", access_token, jwt)
    }

    fn write_live_plain_as(home: &Path, uid: &str, username: &str, access_token: &str, jwt: &str) -> Value {
        let ui = serde_json::to_string(&json!({ "id": uid, "username": username, "displayName": "N1" })).unwrap();
        let v = json!({
            "oauth:active_provider": "bigmodel",
            "oauth:bigmodel:user_info": ui,
            "oauth:bigmodel:access_token": access_token,
            "zcodejwttoken": jwt,
        });
        fs::write(home.join(".zcode/v2/credentials.json"), serde_json::to_string(&v).unwrap()).unwrap();
        v
    }

    #[test]
    fn sync_back_updates_source_on_identity_drift() {
        let home = fake_home("syncback1");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "J1");
        write_config_raw(&home, "CA");
        let a = capture_current(&p, Some("A".into())).unwrap();

        write_live_raw(&home, "B1");
        write_config_raw(&home, "CB");
        let b = capture_current(&p, Some("B".into())).unwrap();

        let drifted = write_live_plain(&home, "T2", "J2");
        write_config_raw(&home, "CA2");

        let r = switch_to(&p, &b.id, true, false, false).unwrap();
        assert!(r.switched);
        assert!(r.preserved_as.is_none(), "回同步对齐 hash 后不应再保全 Auto 账号");
        let list = list_accounts(&p).unwrap();
        assert_eq!(list.len(), 2, "不得出现 Auto 重复账号: {:?}", list.iter().map(|x| x.name.clone()).collect::<Vec<_>>());

        let a2 = load_account(&p, &a.id).unwrap();
        assert_eq!(a2.credentials["oauth:bigmodel:access_token"], "T2", "漂移后的凭证应回同步进源账号快照");
        assert_eq!(a2.hash, canonical_hash(&drifted), "快照 hash 应对齐漂移后的 live");
        let cfg_str = serde_json::to_string(&a2.config).unwrap();
        assert!(cfg_str.contains("key-CA2"), "漂移后的 config 应回同步: {cfg_str}");

        switch_to(&p, &a.id, true, false, false).unwrap();
        let live_cred = fs::read_to_string(p.live_file()).unwrap();
        assert!(live_cred.contains("T2"), "切回应带回最新凭证");
        let live_cfg = fs::read_to_string(p.live_config()).unwrap();
        assert!(live_cfg.contains("key-CA2"), "切回应带回最新 config");
    }

    #[test]
    fn sync_back_skips_config_for_none_snapshot() {
        let home = fake_home("syncback2");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "J1");
        write_config_raw(&home, "CA");
        let a = capture_current(&p, Some("A".into())).unwrap();
        let mut a0 = load_account(&p, &a.id).unwrap();
        a0.config = None;
        save_account(&p, &a0).unwrap();

        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();

        write_live_plain(&home, "T1", "J1");
        write_config_raw(&home, "CX");
        switch_to(&p, &b.id, true, false, false).unwrap();

        let a2 = load_account(&p, &a.id).unwrap();
        assert!(a2.config.is_none(), "config=None 的快照不得回同步他人遗留的 live config");
    }

    #[test]
    fn sync_back_noop_when_logged_out() {
        let home = fake_home("syncback3");
        let p = Paths::new(&home);
        write_live_raw(&home, "A1");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();

        fs::write(home.join(".zcode/v2/credentials.json"), "{}").unwrap();
        let r = switch_to(&p, &b.id, true, false, false).unwrap();
        assert!(r.switched, "登出态切换应照常完成");
        assert!(r.preserved_as.is_none());
        assert_eq!(list_accounts(&p).unwrap().len(), 2);
        let live_cred = fs::read_to_string(p.live_file()).unwrap();
        assert!(live_cred.contains("B1"), "目标凭证应正常写入");
        let a2 = load_account(&p, &a.id).unwrap();
        assert_eq!(a2.hash, a.hash, "登出态下快照不得被回同步改写");
    }

    #[test]
    fn sync_back_hash_exact_syncs_config_only() {
        let home = fake_home("syncback4");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "J1");
        write_config_raw(&home, "CA");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();

        write_live_plain(&home, "T1", "J1");
        write_config_raw(&home, "CA2");
        let r = switch_to(&p, &b.id, true, false, false).unwrap();
        assert!(r.preserved_as.is_none(), "源账号在库且 hash 命中，不应保全 Auto");
        assert_eq!(list_accounts(&p).unwrap().len(), 2);

        let a2 = load_account(&p, &a.id).unwrap();
        let cfg_str = serde_json::to_string(&a2.config).unwrap();
        assert!(cfg_str.contains("key-CA2"), "hash 命中时 live config 应回同步进快照: {cfg_str}");
        assert_eq!(a2.credentials["oauth:bigmodel:access_token"], "T1", "凭证未漂移则原样保留");
        assert_eq!(a2.credentials["zcodejwttoken"], "J1", "凭证未漂移则原样保留");
    }

    #[test]
    fn derived_state_cache_deleted_on_cold_switch() {
        let home = fake_home("derived1");
        let p = Paths::new(&home);
        write_live_raw(&home, "A1");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();

        let cache = home.join(".zcode/v2/coding-plan-cache.json");
        fs::write(&cache, r#"{"status":"unavailable","updatedAt":1}"#).unwrap();

        switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(!cache.exists(), "冷切换后套餐缓存应被删除，强制客户端重查");
        let _ = b;
    }

    #[test]
    fn derived_state_family_domain_aligned() {
        let home = fake_home("derived2");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "J1");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();

        let setting = home.join(".zcode/v2/setting.json");
        fs::write(&setting, r#"{"locale":"zh-CN","providerFamilyDomain":"zai","providerFamilyDomainUpdatedAt":1,"theme":"dark"}"#).unwrap();

        switch_to(&p, &a.id, true, false, false).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&setting).unwrap()).unwrap();
        assert_eq!(v["providerFamilyDomain"], "bigmodel", "domain 应对齐目标账号的族");
        let ts = v["providerFamilyDomainUpdatedAt"].as_i64().expect("UpdatedAt 应为 int");
        assert!(ts > 1, "UpdatedAt 应刷新为当前毫秒 epoch: {ts}");
        assert_eq!(v["locale"], "zh-CN", "其余键必须原样保留");
        assert_eq!(v["theme"], "dark", "其余键必须原样保留");
        let _ = b;
    }

    #[test]
    fn derived_state_setting_untouched_when_absent_or_corrupt() {
        let home = fake_home("derived3a");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "J1");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();
        let setting = home.join(".zcode/v2/setting.json");
        assert!(!setting.exists());
        switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(!setting.exists(), "setting.json 缺失时不得创建");

        let home2 = fake_home("derived3b");
        let p2 = Paths::new(&home2);
        write_live_plain(&home2, "T1", "J1");
        let a2 = capture_current(&p2, Some("A".into())).unwrap();
        write_live_raw(&home2, "B1");
        let b2 = capture_current(&p2, Some("B".into())).unwrap();
        let setting2 = home2.join(".zcode/v2/setting.json");
        let corrupt = "{not valid json";
        fs::write(&setting2, corrupt).unwrap();
        let r = switch_to(&p2, &a2.id, true, false, false).unwrap();
        assert!(r.switched, "setting.json 损坏不应阻断切换");
        assert_eq!(fs::read_to_string(&setting2).unwrap(), corrupt, "损坏文件必须原样保留");
        let _ = (b, b2);
    }

    #[test]
    fn derived_state_align_guards() {
        let home = fake_home("derived4");
        let p = Paths::new(&home);
        let mk = |provider: &str| Account {
            id: "x".into(),
            name: "X".into(),
            created_at: now_ts(),
            updated_at: now_ts(),
            hash: "h".into(),
            credentials: json!({ "oauth:active_provider": provider }),
            config: None,
            virtual_device_mid: None,
            virtual_arms_uid: None,
        };

        let setting = home.join(".zcode/v2/setting.json");
        align_family_domain(&p, &mk("feishu"));
        assert!(!setting.exists(), "词表外 provider 不得创建 setting.json");

        let body = r#"{"locale":"zh-CN","providerFamilyDomain":"zai","providerFamilyDomainUpdatedAt":1}"#;
        fs::write(&setting, body).unwrap();
        align_family_domain(&p, &mk("feishu"));
        assert_eq!(fs::read_to_string(&setting).unwrap(), body, "词表外 provider 不得改写 setting.json");

        let mut no_provider = mk("bigmodel");
        no_provider.credentials = json!({ "zcodejwttoken": "J" });
        align_family_domain(&p, &no_provider);
        assert_eq!(fs::read_to_string(&setting).unwrap(), body);
    }

    #[test]
    fn auto_preserve_no_dup_on_identity_drift() {
        let home = fake_home("autopre4");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "J1");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();

        write_live_plain(&home, "T2", "J2");

        let stored = list_accounts(&p).unwrap();
        let preserved = auto_preserve(&p, &stored, &b.hash).unwrap();
        assert!(preserved.is_none(), "身份命中的漂移登录不得重复保全: {preserved:?}");

        let r = switch_to(&p, &b.id, true, false, false).unwrap();
        assert!(r.preserved_as.is_none());
        let list = list_accounts(&p).unwrap();
        assert_eq!(list.len(), 2, "不得出现 Auto 重复账号: {:?}", list.iter().map(|x| x.name.clone()).collect::<Vec<_>>());

        write_live_plain_as(&home, "u9", "n9", "X1", "Y1");
        let stored2 = list_accounts(&p).unwrap();
        let preserved2 = auto_preserve(&p, &stored2, &a.hash).unwrap();
        assert!(preserved2.is_some(), "不同身份的新登录必须保全，不得被身份判重吞掉");
        let _ = &a;
    }

    fn write_config_json(home: &Path, v: &Value) {
        fs::write(home.join(".zcode/v2/config.json"), serde_json::to_string(v).unwrap()).unwrap();
    }

    fn wiped_entry() -> Value {
        json!({
            "name": "BigModel- Coding Plan",
            "kind": "anthropic",
            "options": { "apiKey": "", "apiKeyRequired": true, "baseURL": "https://x" },
            "enabled": false,
            "systemDisabledReason": "oauth_provider_inactive",
            "source": "custom"
        })
    }

    fn read_live_config_json(p: &Paths) -> Value {
        serde_json::from_str(&fs::read_to_string(p.live_config()).unwrap()).unwrap()
    }

    #[test]
    fn rematerialize_restores_wiped_start_plan() {
        let home = fake_home("remat1");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "JWT-X");
        write_config_json(&home, &json!({ "provider": { "builtin:bigmodel-start-plan": wiped_entry() } }));
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        write_config_raw(&home, "CB");
        let b = capture_current(&p, Some("B".into())).unwrap();

        switch_to(&p, &b.id, true, false, false).unwrap();
        switch_to(&p, &a.id, true, false, false).unwrap();

        let cfg = read_live_config_json(&p);
        let sp = &cfg["provider"]["builtin:bigmodel-start-plan"];
        assert_eq!(sp["options"]["apiKey"], "JWT-X", "被清洗的 start-plan 应用 jwt 重物化");
        assert!(sp["options"].get("apiKeyRequired").is_none(), "apiKeyRequired 标记应随治愈移除");
        assert_eq!(sp["enabled"], true, "治愈后应重新启用");
        assert!(sp.get("systemDisabledReason").is_none(), "清洗原因应随治愈移除");
    }

    #[test]
    fn rematerialize_skips_healthy_entries() {
        let home = fake_home("remat2");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "JWT-X");
        let healthy = json!({
            "name": "BigModel- Coding Plan",
            "kind": "anthropic",
            "options": { "apiKey": "KEEP-ME", "baseURL": "https://x" },
            "enabled": true,
            "source": "custom"
        });
        write_config_json(&home, &json!({ "provider": { "builtin:bigmodel-start-plan": healthy } }));
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        write_config_raw(&home, "CB");
        let b = capture_current(&p, Some("B".into())).unwrap();

        switch_to(&p, &b.id, true, false, false).unwrap();
        switch_to(&p, &a.id, true, false, false).unwrap();

        let cfg = read_live_config_json(&p);
        let sp = &cfg["provider"]["builtin:bigmodel-start-plan"];
        assert_eq!(sp["options"]["apiKey"], "KEEP-ME", "健康条目（key 非空）不得被重物化覆盖");
        assert_eq!(sp["enabled"], true);
    }

    #[test]
    fn rematerialize_skips_network_entries_in_sandbox() {
        let home = fake_home("remat3");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "JWT-X");
        let wiped = wiped_entry();
        write_config_json(&home, &json!({ "provider": { "builtin:bigmodel-coding-plan": wiped.clone() } }));
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        write_config_raw(&home, "CB");
        let b = capture_current(&p, Some("B".into())).unwrap();

        switch_to(&p, &b.id, true, false, false).unwrap();
        switch_to(&p, &a.id, true, false, false).unwrap();

        let cfg = read_live_config_json(&p);
        assert_eq!(cfg["provider"]["builtin:bigmodel-coding-plan"], wiped, "空 key 签发结果不得覆盖原条目");
    }

    #[test]
    fn rematerialize_noop_without_config_snapshot() {
        let home = fake_home("remat4");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "JWT-X");
        let a = capture_current(&p, Some("A".into())).unwrap();
        assert!(a.config.is_none());
        write_live_raw(&home, "B1");
        write_config_raw(&home, "CB");
        let _b = capture_current(&p, Some("B".into())).unwrap();

        switch_to(&p, &a.id, true, false, false).unwrap();
        let cfg = fs::read_to_string(p.live_config()).unwrap();
        assert!(cfg.contains("key-CB"), "config=None 的切入不得触碰 live config");
    }

    #[test]
    fn rematerialize_never_touches_non_family_and_custom() {
        let home = fake_home("remat5");
        let p = Paths::new(&home);
        write_live_plain(&home, "T1", "JWT-X");
        let custom_wiped = json!({
            "name": "My Custom", "kind": "anthropic",
            "options": { "apiKey": "", "apiKeyRequired": true, "baseURL": "https://x" },
            "enabled": false, "systemDisabledReason": "oauth_provider_inactive", "source": "custom"
        });
        let zai_wiped = wiped_entry();
        write_config_json(&home, &json!({ "provider": {
            "builtin:bigmodel-start-plan": wiped_entry(),
            "my-custom-provider": custom_wiped.clone(),
            "builtin:zai-start-plan": zai_wiped.clone(),
        }}));
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        write_config_raw(&home, "CB");
        let b = capture_current(&p, Some("B".into())).unwrap();

        switch_to(&p, &b.id, true, false, false).unwrap();
        switch_to(&p, &a.id, true, false, false).unwrap();

        let cfg = read_live_config_json(&p);
        let sp = &cfg["provider"]["builtin:bigmodel-start-plan"];
        assert_eq!(sp["options"]["apiKey"], "JWT-X", "本族被清洗条目应治愈");
        assert_eq!(sp["enabled"], true);
        assert!(sp.get("systemDisabledReason").is_none());
        assert_eq!(cfg["provider"]["my-custom-provider"], custom_wiped, "自定义 provider 必须零写回");
        assert_eq!(cfg["provider"]["builtin:zai-start-plan"], zai_wiped, "非本族 builtin 必须零写回");
    }

    #[test]
    fn identity_extraction_skips_null_uid() {
        let secret = zcrypto::default_secret(Path::new("."));
        let enc_ui = |inner: &str| zcrypto::encrypt_with_secret(inner, &secret).unwrap();
        let creds = json!({
            "oauth:bigmodel:access_token": enc_ui("access-token-1234567890abcdef"),
            "oauth:bigmodel:user_info": enc_ui(r#"{"id":null,"username":"x","email":"e@x.com"}"#),
            "oauth:active_provider": enc_ui("bigmodel"),
        });
        let id = zcrypto::identity_with_secret(&creds, &secret);
        assert!(id.user_id.is_none(), "null id 不得落成字符串: {:?}", id.user_id);
        assert_eq!(id.email.as_deref(), Some("e@x.com"));
    }

    #[test]
    fn auto_preserve_skips_when_identity_matches_existing() {
        let home = fake_home("apd");
        let p = Paths::new(&home);
        let secret = zcrypto::default_secret(&home);
        let write_live_ident = |uid: &str, token: &str| {
            let ui = zcrypto::encrypt_with_secret(
                &format!(r#"{{"id":"{uid}","username":"vcjzxsv6","displayName":"小明"}}"#),
                &secret,
            )
            .unwrap();
            let at = zcrypto::encrypt_with_secret(token, &secret).unwrap();
            fs::write(
                home.join(".zcode/v2/credentials.json"),
                serde_json::to_string(&json!({
                    "oauth:bigmodel:access_token": at,
                    "oauth:bigmodel:user_info": ui,
                    "oauth:active_provider": "enc:v1:CCCC",
                }))
                .unwrap(),
            )
            .unwrap();
        };

        write_live_ident("u-8888", "access-b-0000000000000000");
        let b = capture_current(&p, Some("B".into())).unwrap();
        write_live_ident("u-9527", "access-a-old-aaaaaaaaaa");
        let a = capture_current(&p, Some("A".into())).unwrap();

        write_live_ident("u-9527", "access-a-new-bbbbbbbbbb");
        let drifted_a = canonical_hash(&read_live(&p).unwrap().unwrap());
        assert_ne!(drifted_a, a.hash, "前置：token 变化必须导致整文件哈希漂移，否则本测试无意义");

        let r = switch_to(&p, &b.id, true, false, false).unwrap();
        assert!(r.switched);
        assert!(r.preserved_as.is_none(), "身份已入库（仅 token 漂移）不应生成 Auto，实际生成: {:?}", r.preserved_as);
        assert_eq!(list_accounts(&p).unwrap().len(), 2, "账号数不应增长");

        write_live_ident("u-7777", "access-c-1111111111111111");
        let r = switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(r.switched);
        assert!(r.preserved_as.is_some(), "未入库的新登录必须保全，绝不丢登录");
        assert_eq!(list_accounts(&p).unwrap().len(), 3);

        write_live_ident("u-8888", "access-b-new-dddddddd");
        let drifted_b = canonical_hash(&read_live(&p).unwrap().unwrap());
        let r = switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(r.switched);
        assert!(r.preserved_as.is_none());
        let b2 = list_accounts(&p).unwrap().into_iter().find(|x| x.id == b.id).unwrap();
        assert_eq!(b2.hash, drifted_b, "库内 B 快照应刷成漂移后的最新 live");

        write_live_ident("u-9527", "access-a-newest-eeeeee");
        let before = canonical_hash(&read_live(&p).unwrap().unwrap());
        let r = switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(!r.switched && r.already_active, "身份即目标的漂移登录应判 already，不得走真切换");
        let after = canonical_hash(&read_live(&p).unwrap().unwrap());
        assert_eq!(before, after, "already 分支不得改写登录文件");
        let a3 = list_accounts(&p).unwrap().into_iter().find(|x| x.id == a.id).unwrap();
        assert_eq!(a3.hash, before, "already 分支的回同步应把 A 快照刷成最新 live（token 不丢）");

        write_live_ident("u-8888", "access-b-newest-ffffffff");
        let err = capture_current(&p, Some("再来一份".into())).unwrap_err();
        assert!(err.contains("B"), "漂移登录捕获应报与 B 重复: {err}");

        let err = update_account_from_live(&p, &a.id).unwrap_err();
        assert!(err.contains("B"), "live 属 B 时刷新 A 应被拒: {err}");
        write_live_ident("u-9527", "access-a-final-gggggggggg");
        let me = update_account_from_live(&p, &a.id).unwrap();
        let live_now = canonical_hash(&read_live(&p).unwrap().unwrap());
        assert_eq!(me.hash, live_now, "刷新自己应同步最新哈希");

        write_live_raw(&home, "F1");
        let _opaque = capture_current(&p, Some("不透明".into())).unwrap();
        write_live_ident("u-6666", "access-d-2222222222222222");
        let r = switch_to(&p, &a.id, true, false, false).unwrap();
        assert!(r.switched);
        assert!(r.preserved_as.is_some(), "库内不可解账号不得让可解新身份被误判为已入库");
        assert_eq!(list_accounts(&p).unwrap().len(), 5);
    }

    #[test]
    fn switch_blocked_without_force_when_running_not_sandbox() {
        let home = fake_home("sw3");
        let p = Paths::new(&home);
        write_live_raw(&home, "A1");
        let a = capture_current(&p, Some("A".into())).unwrap();
        write_live_raw(&home, "B1");
        let b = capture_current(&p, Some("B".into())).unwrap();
        let r = switch_to(&p, &a.id, false, false, false).unwrap();
        assert!(r.switched, "未运行时 force=false 也应可切");
        let _ = b;
    }

    #[test]
    fn export_import_roundtrip_with_config() {
        let home = fake_home("ex2");
        let p = Paths::new(&home);
        write_live_raw(&home, "E1");
        write_config_raw(&home, "CE");
        let a = capture_current(&p, Some("导出源".into())).unwrap();

        let ev = export_bundle_value(std::slice::from_ref(&a));
        assert_eq!(ev["accounts"][0]["config"]["provider"]["builtin:bigmodel-coding-plan"]["options"]["apiKey"], "key-CE");

        let home3 = fake_home("ex2c");
        let p3 = Paths::new(&home3);
        let rep = import_values(&p3, &[("all.zsb".into(), export_bundle_value(std::slice::from_ref(&a)))]).unwrap();
        assert_eq!(rep.added.len(), 1);
        let rep = import_values(&p3, &[("all.zsb".into(), export_bundle_value(&[a]))]).unwrap();
        assert_eq!(rep.added.len(), 0);
        assert_eq!(rep.skipped.len(), 1);
        let accs = list_accounts(&p3).unwrap();
        assert!(accs[0].config.is_some(), "导入应带 config");

        let target = &accs[0];
        write_live_raw(&home3, "Z9");
        switch_to(&p3, &target.id, true, false, false).unwrap();
        let cfg = fs::read_to_string(p3.live_config()).unwrap();
        assert!(cfg.contains("key-CE"));
    }

    #[test]
    fn import_rejects_non_bundle_payloads() {
        let home = fake_home("ex3");
        let p = Paths::new(&home);
        let single = json!({ "format": "zcode-account", "version": 2, "credentials": { "oauth:bigmodel:access_token": "enc:v1:X" } });
        let rep = import_values(&p, &[("old-format.zs".into(), single)]).unwrap();
        assert_eq!(rep.added.len(), 0);
        assert!(rep.errors[0].contains("无法识别"), "err: {:?}", rep.errors);
        let raw = json!({ "oauth:bigmodel:access_token": "enc:v1:X", "zcodejwttoken": "enc:v1:J" });
        let rep = import_values(&p, &[("credentials.json".into(), raw)]).unwrap();
        assert_eq!(rep.added.len(), 0);
        assert!(rep.errors[0].contains("无法识别"), "err: {:?}", rep.errors);
    }

    #[test]
    fn state_reflects_active_and_identity() {
        let home = fake_home("st2");
        let p = Paths::new(&home);
        write_live_raw(&home, "S1");
        let a = capture_current(&p, Some("活跃".into())).unwrap();
        let st = get_state(&p).unwrap();
        assert!(st.live_logged_in);
        assert_eq!(st.active_account_id.as_deref(), Some(a.id.as_str()));
        assert!(st.accounts[0].is_active);
        assert!(st.launch_after_switch && st.close_to_tray, "行为默认开启");

        write_live_raw(&home, "S2");
        let st = get_state(&p).unwrap();
        assert_eq!(st.active_account_id, None);
        assert!(!st.accounts[0].is_active);
    }

    #[test]
    fn update_account_from_live_syncs_config() {
        let home = fake_home("up2");
        let p = Paths::new(&home);
        write_live_raw(&home, "U1");
        let a = capture_current(&p, Some("U".into())).unwrap();
        assert!(a.config.is_none());
        write_live_raw(&home, "U2");
        write_config_raw(&home, "CU2");
        let upd = update_account_from_live(&p, &a.id).unwrap();
        assert!(upd.config.is_some());
        let st = get_state(&p).unwrap();
        assert_eq!(st.active_account_id.as_deref(), Some(upd.id.as_str()));
    }

    #[test]
    fn hot_switch_settings_default_and_roundtrip() {
        let home = fake_home("hot-cfg");
        let paths = Paths::new(&home);
        assert!(!load_settings(&paths).hot_switch(), "默认关：冷切换保证设备码生效");
        let mut s = load_settings(&paths);
        s.hot_switch = Some(false);
        save_settings(&paths, &s).unwrap();
        assert!(!load_settings(&paths).hot_switch());
        let mut s = load_settings(&paths);
        s.hot_switch = Some(true);
        save_settings(&paths, &s).unwrap();
        assert!(load_settings(&paths).hot_switch());
    }

    #[test]
    fn auto_claim_settings_default_and_roundtrip() {
        let home = fake_home("auto-claim");
        let paths = Paths::new(&home);
        assert!(!load_settings(&paths).auto_claim(), "默认关：自动领取必须显式开启");
        let mut s = load_settings(&paths);
        s.auto_claim = Some(true);
        save_settings(&paths, &s).unwrap();
        assert!(load_settings(&paths).auto_claim());
        let mut s = load_settings(&paths);
        s.auto_claim = Some(false);
        save_settings(&paths, &s).unwrap();
        assert!(!load_settings(&paths).auto_claim());
        let raw = r#"{"launch_after_switch":true}"#;
        let legacy: Settings = serde_json::from_str(raw).unwrap();
        assert!(!legacy.auto_claim());
    }

    #[test]
    fn auth_proxy_gate_and_roundtrip() {
        let home = fake_home("auth-proxy");
        let paths = Paths::new(&home);
        assert_eq!(load_settings(&paths).auth_proxy(), None);
        let mut s = Settings {
            auth_proxy_on: Some(false),
            auth_proxy_url: Some("http://127.0.0.1:7890".into()),
            ..Settings::default()
        };
        assert_eq!(s.auth_proxy(), None);
        s.auth_proxy_on = Some(true);
        s.auth_proxy_url = Some("  socks5://127.0.0.1:1080  ".into());
        assert_eq!(s.auth_proxy(), Some("socks5://127.0.0.1:1080"));
        for empty in ["", "   "] {
            s.auth_proxy_url = Some(empty.into());
            assert_eq!(s.auth_proxy(), None);
        }
        s.auth_proxy_url = None;
        assert_eq!(s.auth_proxy(), None);
        save_settings(&paths, &s).unwrap();
        let mut s2 = load_settings(&paths);
        assert_eq!(s2.auth_proxy_on, Some(true));
        assert_eq!(s2.auth_proxy_url, None);
        s2.auth_proxy_on = Some(true);
        s2.auth_proxy_url = Some("http://proxy.lan:8080".into());
        save_settings(&paths, &s2).unwrap();
        let s3 = load_settings(&paths);
        assert_eq!(s3.auth_proxy(), Some("http://proxy.lan:8080"));
    }

    #[test]
    fn identity_matches_by_user_id_then_email_then_fallback() {
        let mk = |uid: Option<&str>, email: Option<&str>, provider: &str, user: Option<&str>| zcrypto::Identity {
            provider: provider.into(), username: user.map(String::from),
            display_name: None, email: email.map(String::from), user_id: uid.map(String::from),
        };
        let a = mk(Some("u-123"), Some("a@x.com"), "bigmodel", Some("aa"));
        assert!(identity_matches(&a, &mk(Some("U-123 "), None, "zai", None)), "user_id 命中即等");
        assert!(!identity_matches(&a, &mk(Some("u-999"), Some("a@x.com"), "bigmodel", Some("aa"))), "user_id 不同时不能算等（防串号）");
        let b = mk(None, Some("B@x.com"), "bigmodel", Some("bb"));
        assert!(identity_matches(&b, &mk(None, Some(" b@X.COM "), "zai", None)), "email 命中即等");
        let c = mk(None, None, "bigmodel", Some("cc"));
        assert!(identity_matches(&c, &mk(None, None, "BigModel", Some("CC"))), "兜底：provider+username");
        assert!(!identity_matches(&c, &mk(None, None, "zai", Some("cc"))));
        let e1 = mk(None, None, "bigmodel", None);
        assert!(!identity_matches(&e1, &mk(None, None, "bigmodel", None)), "空对空不得判等");
        assert!(!identity_matches(&e1, &mk(None, None, "bigmodel", Some("x"))), "一方有 username 时不判等");
        assert!(identity_has_signal(&mk(Some("u"), None, "p", None)));
        assert!(!identity_has_signal(&mk(None, None, "p", None)), "仅 provider 不算可判别信号");
    }

    #[test]
    fn identity_matches_rejects_sentinel_uid_collision() {
        let mk = |uid: &str, email: &str| zcrypto::Identity {
            provider: "zai".into(),
            user_id: Some(uid.into()),
            email: Some(email.into()),
            ..Default::default()
        };
        assert!(!identity_matches(&mk("unknown", "a@x.com"), &mk("unknown", "b@x.com")));
        assert!(!identity_matches(&mk("null", "a@x.com"), &mk("null", "b@x.com")));
        assert!(identity_matches(&mk("u-1", "same@x.com"), &mk("u-1", "same@x.com")));
        assert!(identity_matches(&mk("u-1", "same@x.com"), &mk("u-1", "")));
        assert!(!identity_matches(&mk("u-1", "same@x.com"), &mk("u-2", "same@x.com")));
    }

    #[test]
    fn hot_swap_verified_replaces_live_and_passes() {
        let home = fake_home("hot-swap");
        let paths = Paths::new(&home);
        write_live_raw(&home, "before");
        let target = {
            let mut a = capture_current(&paths, None).unwrap();
            a.name = "target".into();
            a
        };
        write_live_raw(&home, "other");
        let before_hash = canonical_hash(&read_live(&paths).unwrap().unwrap());
        assert_ne!(before_hash, target.hash);
        hot_swap_verified(&paths, &target, &target.credentials).unwrap();
        let after = read_live(&paths).unwrap().unwrap();
        assert_eq!(canonical_hash(&after), target.hash, "热切换后 live 即目标账号");
    }

    #[test]
    fn switch_preserves_relay_pass_hash_and_backfills_snapshot() {
        let home = fake_home("relaykeep");
        let p = Paths::new(&home);
        let mut live = write_live_raw(&home, "S1");
        live[RELAY_PASS_KEY] = json!("enc:v1:RELAY-LIVE");
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();
        capture_current(&p, Some("源号".into())).unwrap();
        let mut target = Account {
            id: Uuid::new_v4().to_string(),
            name: "目标号".into(),
            created_at: now_ts(),
            updated_at: "2000-01-01 00:00".into(),
            hash: String::new(),
            credentials: write_live_raw(&home, "T1"),
            config: None,
            virtual_device_mid: None,
            virtual_arms_uid: None,
        };
        target.hash = canonical_hash(&target.credentials);
        save_account(&p, &target).unwrap();
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();

        switch_to(&p, &target.id, true, false, false).unwrap();

        let after = read_live(&p).unwrap().unwrap();
        assert_eq!(after[RELAY_PASS_KEY].as_str(), Some("enc:v1:RELAY-LIVE"), "切换后 live 保留机器当前 relay 密钥");
        assert_eq!(after["oauth:bigmodel:access_token"], json!("enc:v1:AAAT1"), "账号凭证确实是目标号");
        let snap = load_account(&p, &target.id).unwrap();
        assert_eq!(snap.credentials[RELAY_PASS_KEY].as_str(), Some("enc:v1:RELAY-LIVE"), "快照被回填");
        assert_ne!(snap.updated_at, "2000-01-01 00:00", "回填递增 updated_at");
    }

    #[test]
    fn switch_does_not_mint_relay_key_when_live_lacks_it() {
        let home = fake_home("relaynomint");
        let p = Paths::new(&home);
        write_live_raw(&home, "S1");
        capture_current(&p, Some("源号".into())).unwrap();
        let mut target = Account {
            id: Uuid::new_v4().to_string(),
            name: "目标号".into(),
            created_at: now_ts(),
            updated_at: "2000-01-01 00:00".into(),
            hash: String::new(),
            credentials: write_live_raw(&home, "T1"),
            config: None,
            virtual_device_mid: Some(Uuid::new_v4().to_string()),
            virtual_arms_uid: Some("arms-uid-fixed".into()),
        };
        target.hash = canonical_hash(&target.credentials);
        save_account(&p, &target).unwrap();
        write_live_raw(&home, "S1");

        switch_to(&p, &target.id, true, false, false).unwrap();

        let after = read_live(&p).unwrap().unwrap();
        assert!(after.get(RELAY_PASS_KEY).is_none(), "live 无键时绝不代铸");
        let snap = load_account(&p, &target.id).unwrap();
        assert!(snap.credentials.get(RELAY_PASS_KEY).is_none(), "快照也不得被塞键");
        assert_eq!(snap.updated_at, "2000-01-01 00:00", "无注入则无回填,updated_at 不动");
    }

    #[test]
    fn hot_swap_verified_accepts_injected_creds() {
        let home = fake_home("relayhot");
        let p = Paths::new(&home);
        let mut live = write_live_raw(&home, "before");
        live[RELAY_PASS_KEY] = json!("enc:v1:RELAY-LIVE");
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();
        let mut target = Account {
            id: Uuid::new_v4().to_string(),
            name: "目标号".into(),
            created_at: now_ts(),
            updated_at: now_ts(),
            hash: String::new(),
            credentials: write_live_raw(&home, "tgt"),
            config: None,
            virtual_device_mid: None,
            virtual_arms_uid: None,
        };
        target.hash = canonical_hash(&target.credentials);
        save_account(&p, &target).unwrap();

        let creds = inject_relay_pass_hash(&target.credentials, live.get(RELAY_PASS_KEY));
        hot_swap_verified(&p, &target, &creds).unwrap();

        let after = read_live(&p).unwrap().unwrap();
        assert_eq!(after[RELAY_PASS_KEY].as_str(), Some("enc:v1:RELAY-LIVE"), "注入键随切换落 live");
        assert_eq!(canonical_hash(&after), target.hash, "含注入键的 live 哈希校验仍过(排除式哈希自洽)");
    }

    #[test]
    fn current_relay_pass_reads_disk_at_call_time_not_capture_time() {
        let home = fake_home("relayfresh");
        let p = Paths::new(&home);
        let mut live = write_live_raw(&home, "S1");
        live[RELAY_PASS_KEY] = json!("enc:v1:OLD");
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();

        let v1 = current_relay_pass(&p);
        assert_eq!(
            v1.as_ref().and_then(|v| v.as_str()),
            Some("enc:v1:OLD"),
            "读到的必须是盘上当前值"
        );

        live[RELAY_PASS_KEY] = json!("enc:v1:NEW");
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();

        let v2 = current_relay_pass(&p);
        assert_eq!(
            v2.as_ref().and_then(|v| v.as_str()),
            Some("enc:v1:NEW"),
            "轮换后必须读到新值——入口快照语义则恒为 OLD"
        );
    }

    #[test]
    fn switch_overwrites_stale_relay_key_in_snapshot() {
        let home = fake_home("relaystale");
        let p = Paths::new(&home);
        let mut live = write_live_raw(&home, "S1");
        live[RELAY_PASS_KEY] = json!("enc:v1:NEWRELAY");
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();
        capture_current(&p, Some("源号".into())).unwrap();
        let mut target = Account {
            id: Uuid::new_v4().to_string(),
            name: "目标号".into(),
            created_at: now_ts(),
            updated_at: now_ts(),
            hash: String::new(),
            credentials: write_live_raw(&home, "T1"),
            config: None,
            virtual_device_mid: Some(Uuid::new_v4().to_string()),
            virtual_arms_uid: Some("arms-uid-fixed".into()),
        };
        target.credentials[RELAY_PASS_KEY] = json!("enc:v1:OLDRELAY");
        target.hash = canonical_hash(&target.credentials);
        save_account(&p, &target).unwrap();
        fs::write(p.live_file(), serde_json::to_string(&live).unwrap()).unwrap();

        switch_to(&p, &target.id, true, false, false).unwrap();

        let after = read_live(&p).unwrap().unwrap();
        assert_eq!(after[RELAY_PASS_KEY].as_str(), Some("enc:v1:NEWRELAY"), "live 取机器当前值(NEW),不是快照旧值(OLD)");
        assert_eq!(after["oauth:bigmodel:access_token"], json!("enc:v1:AAAT1"), "账号凭证确实是目标号");
        let snap = load_account(&p, &target.id).unwrap();
        assert_eq!(snap.credentials[RELAY_PASS_KEY].as_str(), Some("enc:v1:NEWRELAY"), "快照旧值被覆盖回填");
    }

    #[test]
    fn settings_behavior_toggle() {
        let home = fake_home("cfg2");
        let p = Paths::new(&home);
        let mut s = load_settings(&p);
        s.launch_after_switch = Some(false);
        s.close_to_tray = Some(false);
        save_settings(&p, &s).unwrap();
        let st = get_state(&p).unwrap();
        assert!(!st.launch_after_switch);
        assert!(!st.close_to_tray);
        let (path, _ok) = effective_zcode_path(&p);
        assert!(!path.is_empty());
    }

    #[test]
    fn effective_zcode_path_dangling_saved_falls_back_to_candidate() {
        let home = fake_home("zpath1");
        let p = Paths::new(&home);
        let cand = home.join("installed").join("ZCode.exe");
        fs::create_dir_all(cand.parent().unwrap()).unwrap();
        fs::write(&cand, b"stub").unwrap();
        let mut s = load_settings(&p);
        s.zcode_path = Some(home.join("gone").join("ZCode.exe").to_string_lossy().to_string());
        save_settings(&p, &s).unwrap();
        let (path, ok) = effective_zcode_path_in(&p, &[cand.to_string_lossy().to_string()]);
        assert!(ok, "悬空保存路径应回落到存在的候选");
        assert_eq!(path, cand.to_string_lossy());
    }

    #[test]
    fn effective_zcode_path_dangling_saved_without_candidate_keeps_saved() {
        let home = fake_home("zpath2");
        let p = Paths::new(&home);
        let mut s = load_settings(&p);
        let saved = home.join("gone").join("ZCode.exe").to_string_lossy().to_string();
        s.zcode_path = Some(saved.clone());
        save_settings(&p, &s).unwrap();
        let (path, ok) = effective_zcode_path_in(&p, &[home.join("nowhere.exe").to_string_lossy().to_string()]);
        assert!(!ok);
        assert_eq!(path, saved);
    }

    #[test]
    fn effective_zcode_path_existing_saved_wins_over_candidates() {
        let home = fake_home("zpath3");
        let p = Paths::new(&home);
        let saved = home.join("custom").join("ZCode.exe");
        fs::create_dir_all(saved.parent().unwrap()).unwrap();
        fs::write(&saved, b"stub").unwrap();
        let mut s = load_settings(&p);
        s.zcode_path = Some(saved.to_string_lossy().to_string());
        save_settings(&p, &s).unwrap();
        let cand = home.join("installed").join("ZCode.exe");
        fs::create_dir_all(cand.parent().unwrap()).unwrap();
        fs::write(&cand, b"stub").unwrap();
        let (path, ok) = effective_zcode_path_in(&p, &[cand.to_string_lossy().to_string()]);
        assert!(ok, "真实存在的保存路径优先于候选");
        assert_eq!(path, saved.to_string_lossy());
    }

    #[test]
    fn zcode_path_empty_input_normalizes_to_none() {
        assert_eq!(normalize_zcode_path("   "), None);
        assert_eq!(normalize_zcode_path(""), None);
        assert_eq!(normalize_zcode_path(" \" \" "), None);
        assert_eq!(
            normalize_zcode_path("  C:\\Program Files\\ZCode\\ZCode.exe  "),
            Some("C:\\Program Files\\ZCode\\ZCode.exe".to_string())
        );
        assert_eq!(
            normalize_zcode_path("\"C:\\Program Files\\ZCode\\ZCode.exe\""),
            Some("C:\\Program Files\\ZCode\\ZCode.exe".to_string())
        );
        assert_eq!(
            normalize_zcode_path("'C:\\Program Files\\ZCode\\ZCode.exe'"),
            Some("C:\\Program Files\\ZCode\\ZCode.exe".to_string())
        );
        assert_eq!(
            normalize_zcode_path("\"C:\\Program Files\\ZCode"),
            Some("\"C:\\Program Files\\ZCode".to_string())
        );
    }

    #[test]
    fn sealed_export_import_roundtrip() {
        let home = fake_home("seal");
        let p = Paths::new(&home);
        write_live_raw(&home, "S1");
        write_config_raw(&home, "CS");
        let a = capture_current(&p, Some("加密号".into())).unwrap();

        let payload = export_bundle_value(&[a]);
        let sealed = crate::cipher::seal(&payload, "pass-123456", crate::cipher::FORMAT_BUNDLE).unwrap();
        let raw = serde_json::to_string(&sealed).unwrap();
        assert!(!raw.contains("加密号"));
        assert!(!raw.contains("oauth:bigmodel"));

        let env: Value = serde_json::from_str(&raw).unwrap();
        assert!(crate::cipher::open(&env, "wrong").is_err());

        let home2 = fake_home("seal2");
        let p2 = Paths::new(&home2);
        let opened = crate::cipher::open(&env, "pass-123456").unwrap();
        let rep = import_values(&p2, &[("加密号.zsb".into(), opened)]).unwrap();
        assert_eq!(rep.added.len(), 1, "errs: {:?}", rep.errors);
        let accs = list_accounts(&p2).unwrap();
        assert!(accs[0].config.is_some(), "解密导入应带 config");

        write_live_raw(&home2, "X9");
        switch_to(&p2, &accs[0].id, true, false, false).unwrap();
        let cfg = fs::read_to_string(p2.live_config()).unwrap();
        assert!(cfg.contains("key-CS"), "切换后 config 应来自加密导入的捆包");
    }

    #[test]
    fn quota_commands_read_files() {
        let home = fake_home("qt");
        let p = Paths::new(&home);
        let e = live_quota(&p).unwrap_err();
        assert!(e.contains("未登录") || e.contains("没有"));
        write_live_raw(&home, "Q1");
        let _ = live_quota(&p);
    }

    #[test]
    fn ensure_virtual_device_mid_stable_and_persisted() {
        let home = fake_home("vmid");
        let p = Paths::new(&home);
        write_live_raw(&home, "V1");
        let acc = capture_current(&p, Some("虚拟设备号".into())).unwrap();
        let m0 = acc.virtual_device_mid.expect("capture 应已生成虚拟 mid");
        assert_eq!(m0.len(), 36, "应为标准 UUID v4 长度");

        let m1 = ensure_virtual_device_mid(&p, &acc.id).unwrap();
        assert_eq!(m0, m1, "ensure 必须复用已有 mid");
        let m2 = ensure_virtual_device_mid(&p, &acc.id).unwrap();
        assert_eq!(m1, m2, "重复调用必须恒定");
        let reloaded = load_account(&p, &acc.id).unwrap();
        assert_eq!(reloaded.virtual_device_mid.as_deref(), Some(m1.as_str()));
        let raw = fs::read_to_string(p.accounts_dir().join(format!("{}.json", acc.id))).unwrap();
        let legacy: Account = serde_json::from_str(&raw.replace(
            &format!("\"virtual_device_mid\": \"{m1}\""),
            "\"virtual_device_mid\": null",
        ))
        .unwrap();
        assert!(legacy.virtual_device_mid.is_none());
    }

    #[test]
    fn capture_adopts_live_device_mid_with_collision_fallback() {
        let home = fake_home("adopt");
        let p = Paths::new(&home);
        write_live_raw(&home, "A1");

        let a1 = capture_current(&p, Some("一号".into())).unwrap();
        let m1 = a1.virtual_device_mid.unwrap();
        assert_eq!(m1.len(), 36);

        let real_mid = "11111111-2222-3333-4444-555555555555";
        fs::write(
            p.live_telemetry(),
            json!({ "deviceMid": real_mid, "lastDailyActiveDate": "2026-08-28" }).to_string(),
        )
        .unwrap();
        write_live_raw(&home, "B1");
        let a2 = capture_current(&p, Some("二号".into())).unwrap();
        assert_eq!(a2.virtual_device_mid.as_deref(), Some(real_mid), "无人占用应收养真实 mid");

        write_live_raw(&home, "C1");
        let a3 = capture_current(&p, Some("三号".into())).unwrap();
        let m3 = a3.virtual_device_mid.unwrap();
        assert_ne!(m3, real_mid, "占用冲突必须发新 mid");
        assert_ne!(m3, m1);
    }

    #[test]
    fn switch_rewrites_live_device_mid() {
        let home = fake_home("swmid");
        let p = Paths::new(&home);
        fs::write(
            p.live_telemetry(),
            json!({ "deviceMid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "lastDailyActiveDate": "2026-08-01" }).to_string(),
        )
        .unwrap();
        write_live_raw(&home, "S1");
        let a = capture_current(&p, Some("源号".into())).unwrap();
        write_live_raw(&home, "S2");
        let b = capture_current(&p, Some("目标号".into())).unwrap();
        assert_ne!(
            a.virtual_device_mid, b.virtual_device_mid,
            "前置条件：两号不同设备"
        );

        write_live_raw(&home, "S1");
        switch_to(&p, &b.id, false, false, false).unwrap();
        let t: Value =
            serde_json::from_str(&fs::read_to_string(p.live_telemetry()).unwrap()).unwrap();
        assert_eq!(
            t.get("deviceMid").and_then(|m| m.as_str()),
            b.virtual_device_mid.as_deref(),
            "切换后设备身份必须是目标账号的虚拟 mid"
        );
        assert_eq!(
            t.get("lastDailyActiveDate").and_then(|m| m.as_str()),
            Some("2026-08-01"),
            "其它 telemetry 字段必须保留"
        );
    }

    fn arms_dir(home: &Path) -> PathBuf {
        let d = home.join("arms-store-sandbox");
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn arms_uid_format_matches_sdk_shape() {
        for _ in 0..256 {
            let u = new_arms_uid();
            assert!(u.starts_with("uid_"), "前缀必须是 uid_：{u}");
            assert_eq!(u.len(), 20, "SDK 同构长度 = 4 + 16：{u}");
            assert!(
                u[4..].chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()),
                "字符集 ⊂ base36：{u}"
            );
        }
        let seen: std::collections::HashSet<char> =
            (0..256).map(|_| new_arms_uid()).flat_map(|u| u[4..].chars().collect::<Vec<_>>()).collect();
        assert!(
            seen.iter().any(|c| c.is_ascii_alphabetic() && *c > 'f'),
            "全 base36 字母表采样必须出现 g-z 字符，否则与真 SDK uid 存在统计特征差异"
        );
    }

    #[test]
    fn arms_store_dirs_resolver_dedup_variant_scan_and_fallback() {
        let tmp = std::env::temp_dir().join(format!("zswitch-arms-res-{}", Uuid::new_v4().simple()));
        let appdata = tmp.join("Roaming");
        fs::create_dir_all(appdata.join("ZCode").join("rum-electron-store")).unwrap();
        fs::create_dir_all(appdata.join("zcode-preview").join("rum-electron-store")).unwrap();
        fs::create_dir_all(appdata.join("unrelated")).unwrap();

        let dirs = arms_store_dirs_from(Some(appdata.clone()), None, None);
        assert_eq!(
            dirs.iter().filter(|d| d.to_string_lossy().to_lowercase().contains("zcode")).filter(|d| !d.to_string_lossy().contains("preview")).count(),
            1,
            "ZCode/zcode 候选必须去重为 1：{dirs:?}"
        );
        assert!(
            dirs.iter().any(|d| d.to_string_lossy().contains("zcode-preview")),
            "变体目录必须被 read_dir 扫描收进：{dirs:?}"
        );
        assert!(
            !dirs.iter().any(|d| d.to_string_lossy().contains("unrelated")),
            "非 zcode* 目录不得混入：{dirs:?}"
        );

        let empty_appdata = tmp.join("EmptyRoaming");
        fs::create_dir_all(&empty_appdata).unwrap();
        assert_eq!(
            arms_store_dirs_from(Some(empty_appdata.clone()), None, None),
            vec![empty_appdata.join("ZCode").join("rum-electron-store")],
            "win 保底首选必须是 ZCode 规范路径"
        );
        let empty_unix = tmp.join("EmptyConfig");
        fs::create_dir_all(&empty_unix).unwrap();
        assert_eq!(
            arms_store_dirs_from(None, None, Some(empty_unix.clone())),
            vec![empty_unix.join("zcode").join("rum-electron-store")],
            "unix 保底首选必须是 zcode 规范路径"
        );
        let mac = tmp.join("AppSupport");
        fs::create_dir_all(mac.join("ZCode").join("rum-electron-store")).unwrap();
        assert_eq!(
            arms_store_dirs_from(None, Some(mac.clone()), None),
            vec![mac.join("ZCode").join("rum-electron-store")]
        );
        assert!(arms_store_dirs_from(None, None, None).is_empty());
    }

    #[test]
    fn write_arms_uid_idempotent_skip() {
        let home = fake_home("armsidem");
        let d = arms_dir(&home);
        let f = d.join(ARMS_DEFAULT_STORE_FILE);
        fs::write(&f, json!({ "_arms_uid": "uid_samesamesame1" }).to_string()).unwrap();
        let mtime_before = fs::metadata(&f).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_live_arms_uid_to(&[d.clone()], "uid_samesamesame1").unwrap();
        assert_eq!(
            fs::metadata(&f).unwrap().modified().unwrap(),
            mtime_before,
            "幂等路径必须免写（mtime 不变）"
        );
        fs::write(&f, json!({ "_arms_uid": "uid_samesamesame1", "_arms_session": "x" }).to_string()).unwrap();
        write_live_arms_uid_to(&[d], "uid_samesamesame1").unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&f).unwrap()).unwrap();
        assert!(v.get("_arms_session").is_none(), "session 残留时不得短路");
    }

    #[test]
    fn write_arms_uid_rewrites_namespaces_and_resets_session() {
        let home = fake_home("armsrw");
        let d = arms_dir(&home);
        fs::write(
            d.join(ARMS_DEFAULT_STORE_FILE),
            json!({ "_arms_uid": "uid_oldoldoldoldold", "_arms_session": "sess-1234-1-99-99", "keep": 1 }).to_string(),
        )
        .unwrap();
        fs::write(
            d.join("YW90aGVy.json"),
            json!({ "_arms_uid": "uid_oldoldoldoldold", "_arms_session": "x", "_v": "0.0.3" }).to_string(),
        )
        .unwrap();
        write_live_arms_uid_to(&[d.clone()], "uid_newnewnewnewne").unwrap();
        for f in [d.join(ARMS_DEFAULT_STORE_FILE), d.join("YW90aGVy.json")] {
            let v: Value = serde_json::from_str(&fs::read_to_string(&f).unwrap()).unwrap();
            assert_eq!(v.get("_arms_uid").and_then(|u| u.as_str()), Some("uid_newnewnewnewne"));
            assert!(v.get("_arms_session").is_none(), "session 必须重置：{f:?}");
        }
        let def: Value =
            serde_json::from_str(&fs::read_to_string(d.join(ARMS_DEFAULT_STORE_FILE)).unwrap()).unwrap();
        assert_eq!(def.get("keep").and_then(|k| k.as_i64()), Some(1), "无关键必须保留");
    }

    #[test]
    fn write_arms_uid_creates_default_store_when_missing() {
        let home = fake_home("armsmk");
        let d = home.join("arms-store-sandbox");
        write_live_arms_uid_to(&[d.clone()], "uid_freshfreshfre1").unwrap();
        let f = d.join(ARMS_DEFAULT_STORE_FILE);
        let v: Value = serde_json::from_str(&fs::read_to_string(&f).unwrap()).unwrap();
        assert_eq!(v.get("_arms_uid").and_then(|u| u.as_str()), Some("uid_freshfreshfre1"));
    }

    #[test]
    fn read_arms_uid_prefers_default_namespace_then_fallback() {
        let home = fake_home("armsrd");
        let d = arms_dir(&home);
        fs::write(d.join("YW90aGVy.json"), json!({ "_arms_uid": "uid_fallbackfbck1" }).to_string()).unwrap();
        assert_eq!(read_live_arms_uid_from(&[d.clone()]).as_deref(), Some("uid_fallbackfbck1"));
        fs::write(
            d.join(ARMS_DEFAULT_STORE_FILE),
            json!({ "_arms_uid": "uid_defaultdflt1" }).to_string(),
        )
        .unwrap();
        assert_eq!(read_live_arms_uid_from(&[d.clone()]).as_deref(), Some("uid_defaultdflt1"));
        let empty = home.join("arms-store-empty");
        fs::create_dir_all(&empty).unwrap();
        assert_eq!(read_live_arms_uid_from(&[empty]), None);
    }

    #[test]
    fn ensure_virtual_arms_uid_stable_and_persisted() {
        let home = fake_home("armsuid");
        let p = Paths::new(&home);
        write_live_raw(&home, "U1");
        let acc = capture_current(&p, Some("遥测号".into())).unwrap();
        let u0 = acc.virtual_arms_uid.expect("capture 应已生成虚拟 uid");
        assert!(u0.starts_with("uid_") && u0.len() == 20);

        let u1 = ensure_virtual_arms_uid_locked(&p, &acc.id).unwrap();
        assert_eq!(u0, u1, "ensure 必须复用已有 uid");
        let reloaded = load_account(&p, &acc.id).unwrap();
        assert_eq!(reloaded.virtual_arms_uid.as_deref(), Some(u1.as_str()), "必须落盘快照");
        let raw = fs::read_to_string(p.accounts_dir().join(format!("{}.json", acc.id))).unwrap();
        let legacy: Account =
            serde_json::from_str(&raw.replace(&format!("\"virtual_arms_uid\": \"{u1}\""), "\"virtual_arms_uid\": null")).unwrap();
        assert!(legacy.virtual_arms_uid.is_none());
    }

    #[test]
    fn switch_rewrites_live_arms_uid_in_sandbox_only() {
        let home = fake_home("armssw");
        let p = Paths::new(&home);
        write_live_raw(&home, "S1");
        let a = capture_current(&p, Some("源号".into())).unwrap();
        write_live_raw(&home, "S2");
        let b = capture_current(&p, Some("目标号".into())).unwrap();
        assert_ne!(a.virtual_arms_uid, b.virtual_arms_uid, "两号必须不同 uid");

        write_live_raw(&home, "S1");
        switch_to(&p, &b.id, false, false, false).unwrap();
        let got = read_live_arms_uid_from(&[arms_dir(&home)]).expect("切换后沙箱 ARMS 存储必须有 uid");
        assert_eq!(got, b.virtual_arms_uid.unwrap(), "切换后 ARMS uid 必须是目标账号的");
    }

    #[test]
    fn switch_to_under_held_store_lock_with_legacy_account_completes() {
        let home = fake_home("lockreg");
        let p = Paths::new(&home);
        write_live_raw(&home, "S1");
        let _ = capture_current(&p, Some("源号".into())).unwrap();

        let mut legacy = Account {
            id: Uuid::new_v4().to_string(),
            name: "老账号".into(),
            created_at: now_ts(),
            updated_at: now_ts(),
            hash: String::new(),
            credentials: json!({
                "oauth:bigmodel:access_token": "enc:v1:AAAlegacy",
                "oauth:bigmodel:user_info": "enc:v1:BBBB",
                "oauth:active_provider": "enc:v1:CCCC",
                "zcodejwttoken": "enc:v1:DDDD",
            }),
            config: None,
            virtual_device_mid: None,
            virtual_arms_uid: None,
        };
        legacy.hash = canonical_hash(&legacy.credentials);
        save_account(&p, &legacy).unwrap();

        write_live_raw(&home, "S1");

        let home2 = home.clone();
        let target_id = legacy.id.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        std::thread::spawn(move || {
            let p2 = Paths::new(&home2);
            let _guard = crate::store_guard();
            let _ = tx.send(switch_to(&p2, &target_id, true, false, false).map(|_| ()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("持锁切换存量账号应成功：{e}"),
            Err(_) => panic!("switch_to 在外层持 STORE_LOCK 时死锁（issue #3 回归）"),
        }

        let reloaded = load_account(&p, &legacy.id).unwrap();
        assert!(
            reloaded.virtual_device_mid.as_deref().is_some_and(|m| !m.trim().is_empty()),
            "冷切换必须补齐存量账号的 mid"
        );
        assert!(
            reloaded.virtual_arms_uid.as_deref().is_some_and(|u| !u.trim().is_empty()),
            "冷切换必须补齐存量账号的 arms uid"
        );
    }

    #[test]
    fn switch_to_already_path_under_held_store_lock_with_legacy_account_completes() {
        let home = fake_home("lockreg2");
        let p = Paths::new(&home);

        let mut legacy = Account {
            id: Uuid::new_v4().to_string(),
            name: "老账号".into(),
            created_at: now_ts(),
            updated_at: now_ts(),
            hash: String::new(),
            credentials: json!({
                "oauth:bigmodel:access_token": "enc:v1:AAAlegacy",
                "oauth:bigmodel:user_info": "enc:v1:BBBB",
                "oauth:active_provider": "enc:v1:CCCC",
                "zcodejwttoken": "enc:v1:DDDD",
            }),
            config: None,
            virtual_device_mid: None,
            virtual_arms_uid: None,
        };
        legacy.hash = canonical_hash(&legacy.credentials);
        save_account(&p, &legacy).unwrap();

        fs::write(
            p.live_file(),
            serde_json::to_string(&legacy.credentials).unwrap(),
        )
        .unwrap();

        let home2 = home.clone();
        let target_id = legacy.id.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<SwitchResult, String>>();
        std::thread::spawn(move || {
            let p2 = Paths::new(&home2);
            let _guard = crate::store_guard();
            let _ = tx.send(switch_to(&p2, &target_id, false, false, false));
        });
        let r = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(v) => v.expect("持锁 already 切换应成功"),
            Err(_) => panic!("switch_to already 路径在外层持 STORE_LOCK 时死锁（issue #3 回归）"),
        };
        assert!(r.already_active && !r.switched, "前置条件：必须命中 already 分支");

        let reloaded = load_account(&p, &legacy.id).unwrap();
        assert!(
            reloaded.virtual_device_mid.as_deref().is_some_and(|m| !m.trim().is_empty()),
            "already 对齐必须补齐存量账号的 mid"
        );
        assert!(
            reloaded.virtual_arms_uid.as_deref().is_some_and(|u| !u.trim().is_empty()),
            "already 对齐必须补齐存量账号的 arms uid"
        );
    }
}
