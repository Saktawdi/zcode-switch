
use crate::quota;
use serde_json::{json, Value};
use std::time::Duration;

const TOKEN_URL: &str = "https://zcode.z.ai/api/v1/oauth/token";
const FLOW_INIT_URL: &str = "https://zcode.z.ai/api/v1/oauth/cli/init";
pub const FLOW_TIMEOUT_MS: u64 = 300_000;
pub const LOGIN_WINDOW_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct OAuthProvider {
    pub id: &'static str,
    pub display: &'static str,
}

pub const OAUTH_PROVIDERS: &[OAuthProvider] = &[
    OAuthProvider { id: "bigmodel", display: "BigModel（智谱开放平台）" },
    OAuthProvider { id: "zai", display: "z.ai（国际站）" },
];

const REDIRECT_ENC: &str = "zcode%3A%2F%2Foauth%2Fcallback";

pub fn bridge_redirect_uri() -> String {
    format!("https://zcode.z.ai/app/oauth/login?redirect={REDIRECT_ENC}&app_version={}", quota::CLIENT_APP_VERSION)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub struct FlowInit {
    pub authorize_url: String,
    pub state: String,
    pub poll_url: String,
    pub poll_token: String,
    pub expires_at_ms: u128,
    pub poll_interval_ms: u64,
}

pub fn new_poll_token() -> String {
    let mut buf = [0u8; 32];
    getrandom_fallback(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn init_flow(provider: &str, mid: &str) -> Result<FlowInit, String> {
    init_flow_at(FLOW_INIT_URL, provider, mid)
}

fn init_flow_at(url: &str, provider: &str, mid: &str) -> Result<FlowInit, String> {
    let poll_token = new_poll_token();
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build();
    let mut req = agent.post(url);
    for (k, v) in quota::zai_oauth_headers_with_mid(&poll_token, Some(mid.to_string())).0 {
        req = req.set(&k, &v);
    }
    let resp = req
        .send_json(json!({ "provider": provider }))
        .map_err(|e| crate::i18n::trf("err.oauth.init", &[("e", &e.to_string())]))?
        .into_string()
        .map_err(|e| crate::i18n::trf("err.oauth.init", &[("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    let invalid = || crate::i18n::tr("err.oauth.init_invalid");
    if v.get("code").and_then(|c| c.as_i64()) != Some(0) {
        let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("");
        return Err(crate::i18n::trf("err.oauth.init_invalid_msg", &[("msg", msg)]));
    }
    let data = v.get("data").ok_or_else(invalid)?;
    let flow_id = data.get("flow_id").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty())
        .ok_or_else(invalid)?;
    let authorize = data.get("authorize_url").and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty())
        .ok_or_else(invalid)?;
    let poll_token = data
        .get("poll_token")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or(poll_token);
    let expires_at_ms = data.get("expires_at").and_then(|x| x.as_f64()).map(|s| (s * 1000.0) as u128)
        .ok_or_else(invalid)?;
    let poll_interval_ms = data.get("poll_interval_sec").and_then(|x| x.as_f64()).map(|s| (s * 1000.0) as u64)
        .ok_or_else(invalid)?;

    let auth_url: tauri::Url = authorize.parse().map_err(|_| invalid())?;
    let state = auth_url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .and_then(|(_, v)| {
            let s = v.trim().to_string();
            (!s.is_empty()).then_some(s)
        })
        .ok_or_else(invalid)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let remaining = expires_at_ms.saturating_sub(now);
    if auth_url.scheme() != "https" || remaining == 0 || poll_interval_ms < 1_000 || poll_interval_ms as u128 >= remaining {
        return Err(invalid());
    }
    let init_base: String = url
        .parse::<tauri::Url>()
        .map(|u| u.origin().ascii_serialization())
        .map_err(|_| invalid())?;
    Ok(FlowInit {
        authorize_url: auth_url.to_string(),
        state,
        poll_url: format!("{init_base}/api/v1/oauth/cli/poll/{}", urlencode(flow_id)),
        poll_token,
        expires_at_ms,
        poll_interval_ms,
    })
}

#[derive(Debug)]
pub enum PollOutcome {
    Pending,
    Ready(Value),
}

pub fn poll_flow_once(url: &str, poll_token: &str, mid: &str) -> Result<PollOutcome, String> {
    let agent = web_agent();
    let mut req = agent.get(url);
    for (k, v) in quota::zai_oauth_headers_with_mid(poll_token, Some(mid.to_string())).0 {
        req = req.set(&k, &v);
    }
    let resp = match req.call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code, resp)) if (400..500).contains(&code) && code != 408 && code != 429 => {
            let body = resp.into_string().unwrap_or_default();
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if v.get("code").and_then(|c| c.as_i64()) == Some(3004) {
                return Err(crate::i18n::tr("err.oauth.expired"));
            }
            return Err(crate::i18n::trf("err.oauth.poll_terminal", &[("code", &code.to_string())]));
        }
        Err(_) => return Ok(PollOutcome::Pending),
    };
    let body = match resp.into_string() {
        Ok(b) => b,
        Err(_) => return Ok(PollOutcome::Pending),
    };
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::String(body));
    let invalid = || crate::i18n::tr("err.oauth.poll_invalid");
    if v.get("code").and_then(|c| c.as_i64()) != Some(0) {
        let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("");
        return Err(crate::i18n::trf("err.oauth.poll_invalid_msg", &[("msg", msg)]));
    }
    let data = v.get("data").cloned().ok_or_else(invalid)?;
    match data.get("status").and_then(|s| s.as_str()).unwrap_or("") {
        "pending" => Ok(PollOutcome::Pending),
        "failed" => Err(crate::i18n::tr("err.oauth.flow_failed")),
        "ready" => {
            let br_str = |ptr: &str| {
                data.pointer(ptr)
                    .and_then(|x| x.as_str())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
            };
            let token = br_str("/token");
            let access = match data.get("zai").or_else(|| data.get("bigmodel")) {
                Some(p) => br_str2(p, &["access_token", "accessToken"]),
                None => None,
            };
            let user_id = br_str("/user/user_id");
            if token.is_none() || access.is_none() || user_id.is_none() {
                return Err(invalid());
            }
            Ok(PollOutcome::Ready(data))
        }
        _ => Err(invalid()),
    }
}

fn br_str2(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(|x| x.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

#[derive(Debug, PartialEq)]
pub enum CallbackKind {
    Code { code: String, state: String },
    Attribution,
}

pub fn parse_callback(url: &str) -> Result<CallbackKind, String> {
    let rest = url
        .strip_prefix("zcode://oauth/callback")
        .ok_or_else(|| crate::i18n::tr("err.oauth.not_callback"))?;
    let qs = rest.trim_start_matches('?');
    let mut code = String::new();
    let mut state = String::new();
    let mut has_attribution = false;
    for kv in qs.split('&') {
        let (k, v) = kv.split_once('=').ok_or_else(|| crate::i18n::tr("err.oauth.bad_cb"))?;
        match urldecode(k).as_str() {
            "authCode" => code = urldecode(v),
            "code" if code.is_empty() => code = urldecode(v),
            "state" => state = urldecode(v),
            "channel_id" | "utm_source" | "utm_campaign" => has_attribution = true,
            _ => {}
        }
    }
    if state.is_empty() {
        return Err(crate::i18n::tr("err.oauth.state"));
    }
    if !code.is_empty() {
        return Ok(CallbackKind::Code { code, state });
    }
    if has_attribution {
        return Ok(CallbackKind::Attribution);
    }
    Err(crate::i18n::tr("err.oauth.no_code_state"))
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push(h << 4 | l);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn getrandom_fallback(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(16) {
        let u = uuid::Uuid::new_v4();
        chunk.copy_from_slice(&u.as_bytes()[..chunk.len()]);
    }
}

pub fn parse_proxy_url(input: &str) -> Result<String, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err(crate::i18n::tr("err.proxy.empty"));
    }
    let lower = s.to_ascii_lowercase();
    let (scheme, rest) = if let Some(r) = lower.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = lower.strip_prefix("socks5://") {
        ("socks5", r)
    } else {
        return Err(crate::i18n::tr("err.proxy.scheme"));
    };
    if rest.contains('@') {
        return Err(crate::i18n::tr("err.proxy.no_auth"));
    }
    if rest.contains('/') || rest.contains('\\') {
        return Err(crate::i18n::tr("err.proxy.no_path"));
    }
    let Some((host, port)) = rest.rsplit_once(':') else {
        return Err(crate::i18n::tr("err.proxy.need_port"));
    };
    if host.is_empty() {
        return Err(crate::i18n::tr("err.proxy.empty_host"));
    }
    if host.contains(' ') || host.contains(':') {
        return Err(crate::i18n::tr("err.proxy.bad_host"));
    }
    let port_num: u32 = port.parse().map_err(|_| crate::i18n::trf("err.proxy.port_nan", &[("port", port)]))?;
    if !(1..=65535).contains(&port_num) {
        return Err(crate::i18n::trf("err.proxy.port_range", &[("port", &port_num.to_string())]));
    }
    Ok(format!("{scheme}://{host}:{port_num}"))
}

pub fn exchange_token(provider: &str, code: &str, state: &str, mid: &str) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build();
    let mut req = agent.post(TOKEN_URL);
    for (k, v) in quota::zai_oauth_headers_with_mid("", Some(mid.to_string())).0 {
        if k == "Authorization" {
            continue;
        }
        req = req.set(&k, &v);
    }
    let resp = req
        .send_json(json!({
            "provider": provider,
            "code": code,
            "redirect_uri": bridge_redirect_uri(),
            "state": state,
        }))
        .map_err(|e| crate::i18n::trf("err.oauth.exchange_req", &[("e", &e.to_string())]))?
        .into_string()
        .map_err(|e| crate::i18n::trf("err.http.read", &[("e", &e.to_string())]))?;
    let v: Value = serde_json::from_str(&resp).unwrap_or(Value::String(resp));
    let code_n = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
    if code_n != 0 {
        let msg = v.get("msg").and_then(|m| m.as_str()).unwrap_or("");
        return Err(crate::i18n::trf("err.oauth.exchange", &[("code", &code_n.to_string()), ("msg", msg)]));
    }
    let token = v
        .pointer("/data/token")
        .and_then(|t| t.as_str())
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| crate::i18n::tr("err.oauth.no_token"))?;
    Ok(json!({ "jwt": token, "raw": v }))
}

pub fn extract_user_profile(provider: &str, raw: &Value) -> Option<Value> {
    if provider != "zai" {
        return None;
    }
    raw.pointer("/data/user").and_then(backend_user_profile)
}

pub fn extract_poll_user_profile(raw: &Value) -> Option<Value> {
    raw.pointer("/data/user").and_then(backend_user_profile)
}

fn backend_user_profile(u: &Value) -> Option<Value> {
    let nonempty = |k: &str| {
        u.get(k)
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
    };
    if !["user_id", "email", "name", "avatar"].iter().any(|k| nonempty(k)) {
        return None;
    }
    let id = u
        .get("user_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let name = u
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| u.get("email").and_then(|v| v.as_str()).filter(|s| !s.is_empty()))
        .or(id);
    Some(json!({
        "id": id,
        "username": name.unwrap_or(""),
        "displayName": name.unwrap_or(""),
        "email": u.get("email").and_then(|v| v.as_str()).unwrap_or(""),
        "avatarUrl": u.get("avatar").and_then(|v| v.as_str()).unwrap_or(""),
    }))
}

pub fn fetch_userinfo(provider: &str, token: &str) -> Option<Value> {
    let (url, bearer) = match provider {
        "bigmodel" => ("https://bigmodel.cn/api/biz/customer/getCustomerInfo", false),
        "zai" => ("https://chat.z.ai/api/oauth/userinfo", true),
        _ => return None,
    };
    let auth = if bearer {
        format!("Bearer {token}")
    } else {
        token.to_string()
    };
    let resp = web_agent()
        .get(url)
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .set("User-Agent", LOGIN_WINDOW_UA)
        .call()
        .ok()?
        .into_string()
        .ok()?;
    let v: Value = serde_json::from_str(&resp).ok()?;
    if v.get("code").and_then(|c| c.as_i64()).map(|c| c != 0).unwrap_or(false) {
        return None;
    }
    let data = v.get("data").cloned().unwrap_or(v);
    let pick = |k: &str, alts: &[&str]| -> Option<String> {
        alts.iter()
            .find_map(|a| data.get(a).and_then(|x| x.as_str()).map(String::from))
            .or_else(|| data.get(k).and_then(|x| x.as_str()).map(String::from))
    };
    Some(json!({
        "id": pick("id", &["customerNumber", "sub", "id"]),
        "username": pick("username", &["username", "name", "preferred_username", "email"]),
        "displayName": pick("displayName", &["username", "name", "preferred_username"]),
        "avatarUrl": pick("avatarUrl", &["avatar", "picture"]),
        "email": pick("email", &["email"]),
    }))
}

pub fn extract_refresh_token(provider: &str, raw: &Value) -> Option<String> {
    if provider != "bigmodel" {
        return None;
    }
    raw.pointer("/data/bigmodel/refresh_token")
        .or_else(|| raw.pointer("/data/bigmodel/refreshToken"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
}

pub fn assemble_credentials_with_token(
    provider: &str,
    jwt: &str,
    userinfo: Option<&Value>,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("zcodejwttoken".into(), json!(jwt));
    m.insert("oauth:active_provider".into(), json!(provider));
    if let Some(at) = access_token.filter(|s| !s.trim().is_empty()) {
        m.insert(format!("oauth:{provider}:access_token"), json!(at));
    }
    if let Some(rt) = refresh_token.filter(|s| !s.trim().is_empty()) {
        m.insert(format!("oauth:{provider}:refresh_token"), json!(rt));
    }
    if let Some(ui) = userinfo {
        m.insert(format!("oauth:{provider}:user_info"), json!(ui.to_string()));
    }
    Value::Object(m)
}

pub const BIGMODEL_BIZ_BASE: &str = "https://bigmodel.cn";
pub const ZAI_API_BASE: &str = "https://api.z.ai";
pub const ZAI_BUSINESS_LOGIN_URL: &str = "https://api.z.ai/api/auth/z/login";
pub const BIGMODEL_ANTHROPIC_BASE: &str = "https://open.bigmodel.cn/api/anthropic";
pub const ZAI_ANTHROPIC_BASE: &str = "https://api.z.ai/api/anthropic";
pub const START_PLAN_ANTHROPIC_BASE: &str = "https://zcode.z.ai/api/v1/zcode-plan/anthropic";
const API_KEY_NAME: &str = "zcode-api-key";

fn web_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(15))
        .build()
}

pub fn extract_access_token(provider: &str, raw: &Value) -> Option<String> {
    let pick = |v: &Value| -> Option<String> {
        ["access_token", "accessToken"]
            .iter()
            .find_map(|k| v.get(k).and_then(|x| x.as_str()))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    let data = raw.get("data")?;
    match provider {
        "bigmodel" => data.get("bigmodel").and_then(&pick).or_else(|| pick(data)),
        "zai" => data.get("zai").and_then(&pick),
        _ => None,
    }
}

pub fn pick_org_project(customer: &Value) -> Option<(String, String)> {
    let root = customer.get("data").unwrap_or(customer);
    let orgs = root.get("organizations")?.as_array()?;
    let id_of = |v: &Value| -> Option<String> {
        match v {
            Value::String(s) => (!s.is_empty()).then(|| s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    };
    let keep = |p: &Value| -> bool {
        match p.get("projectType") {
            Some(Value::String(s)) => s.trim() != "2",
            Some(Value::Number(n)) => n.to_string() != "2",
            _ => true,
        }
    };
    let mut cands: Vec<(&Value, String, Vec<&Value>)> = vec![];
    for o in orgs {
        let Some(org_id) = o.get("organizationId").and_then(id_of) else {
            continue;
        };
        let projects: Vec<&Value> = o
            .get("projects")
            .and_then(|p| p.as_array())
            .map(|a| a.iter().filter(|p| keep(p)).collect())
            .unwrap_or_default();
        if projects.is_empty() {
            continue;
        }
        cands.push((o, org_id, projects));
    }
    fn name_of<'a>(v: &'a Value, key: &str) -> &'a str {
        v.get(key).and_then(|x| x.as_str()).unwrap_or("")
    }
    let (_, org_id, projects) = cands
        .iter()
        .find(|(o, _, _)| name_of(o, "organizationName").contains("默认机构"))
        .or_else(|| cands.first())?;
    let proj = projects
        .iter()
        .find(|p| name_of(p, "projectName").contains("默认项目"))
        .or_else(|| projects.first())?;
    let pid = proj.get("projectId").and_then(id_of)?;
    Some((org_id.clone(), pid))
}

fn keys_array(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => o.get("data").and_then(|d| d.as_array()).map(|a| a.iter().collect()).unwrap_or_default(),
        _ => vec![],
    }
}

pub fn resolve_biz_api_key(base: &str, auth: &str, require_secret: bool) -> Option<String> {
    let agent = web_agent();
    let get_json = |url: &str| -> Option<Value> {
        agent
            .get(url)
            .set("Authorization", auth)
            .set("Content-Type", "application/json")
            .call()
            .ok()?
            .into_string()
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
    };
    let cust = get_json(&format!("{base}/api/biz/customer/getCustomerInfo"))?;
    let (org, proj) = pick_org_project(&cust)?;
    let keys_url = format!("{base}/api/biz/v1/organization/{org}/projects/{proj}/api_keys");
    let list = get_json(&keys_url)?;
    let mut found = keys_array(&list)
        .into_iter()
        .find(|k| k.get("name").and_then(|n| n.as_str()) == Some(API_KEY_NAME))
        .map(|k| k.clone());
    if found.is_none() {
        found = agent
            .post(&keys_url)
            .set("Authorization", auth)
            .set("Content-Type", "application/json")
            .send_json(json!({ "name": API_KEY_NAME }))
            .ok()?
            .into_string()
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
    }
    let key = found
        .as_ref()
        .and_then(|k| k.get("apiKey").and_then(|v| v.as_str()))
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let secret = get_json(&format!("{keys_url}/copy/{}", urlencode(&key)))
        .and_then(|v| v.get("secretKey").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_default();
    if secret.trim().is_empty() {
        return if require_secret { None } else { Some(key) };
    }
    Some(format!("{key}.{}", secret.trim()))
}

pub fn resolve_zai_business_token(zai_access_token: &str) -> Option<String> {
    resolve_zai_business_token_at(ZAI_BUSINESS_LOGIN_URL, zai_access_token)
}

fn resolve_zai_business_token_at(url: &str, zai_access_token: &str) -> Option<String> {
    let resp = web_agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_json(json!({ "token": zai_access_token }))
        .ok()?
        .into_string()
        .ok()?;
    let v: Value = serde_json::from_str(&resp).ok()?;
    ["access_token", "accessToken"]
        .iter()
        .find_map(|k| {
            v.pointer(&format!("/data/{k}"))
                .and_then(|x| x.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
}

pub fn assemble_config(provider: &str, jwt: &str, access_token: &str) -> Value {
    let entry = |name: &str, key: &str, base: &str| {
        let k = key.trim();
        json!({
            "name": name,
            "kind": "anthropic",
            "options": if k.is_empty() {
                json!({ "apiKey": "", "apiKeyRequired": true, "baseURL": base })
            } else {
                json!({ "apiKey": k, "baseURL": base })
            },
            "enabled": !k.is_empty(),
            "source": "custom",
        })
    };
    let mut providers = serde_json::Map::new();
    match provider {
        "bigmodel" => {
            let key = if access_token.trim().is_empty() {
                None
            } else {
                resolve_biz_api_key(BIGMODEL_BIZ_BASE, access_token.trim(), false)
            }
            .unwrap_or_default();
            providers.insert("builtin:bigmodel".into(), entry("Bigmodel - API Key", &key, BIGMODEL_ANTHROPIC_BASE));
            providers.insert(
                "builtin:bigmodel-coding-plan".into(),
                entry("BigModel - Coding Plan", &key, BIGMODEL_ANTHROPIC_BASE),
            );
            providers.insert(
                "builtin:bigmodel-start-plan".into(),
                entry("BigModel- Coding Plan", jwt, START_PLAN_ANTHROPIC_BASE),
            );
        }
        "zai" => {
            providers.insert(
                "builtin:zai".into(),
                entry("Z.ai - API Key", "", ZAI_ANTHROPIC_BASE),
            );
            providers.insert(
                "builtin:zai-start-plan".into(),
                entry("Z.ai - Coding Plan", jwt, START_PLAN_ANTHROPIC_BASE),
            );
            let key = if access_token.trim().is_empty() {
                None
            } else {
                resolve_biz_api_key(ZAI_API_BASE, &format!("Bearer {}", access_token.trim()), true)
            }
            .unwrap_or_default();
            providers.insert(
                "builtin:zai-coding-plan".into(),
                entry("Z.ai - Coding Plan", &key, ZAI_ANTHROPIC_BASE),
            );
        }
        _ => {}
    }
    json!({ "provider": providers })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_redirect_uri_shape() {
        let b = bridge_redirect_uri();
        assert!(b.starts_with("https://zcode.z.ai/app/oauth/login?redirect="), "{b}");
        assert!(b.contains("zcode%3A%2F%2Foauth%2Fcallback"), "深链须编码：{b}");
        assert_eq!(
            b, format!("https://zcode.z.ai/app/oauth/login?redirect=zcode%3A%2F%2Foauth%2Fcallback&app_version={}", quota::CLIENT_APP_VERSION),
            "app_version 恒取官方当前版：{b}"
        );
    }

    #[test]
    fn oauth_flow_headers_pin_official_version() {
        for h in quota::zai_oauth_headers_with_mid("PT", Some("MID".into())).0 {
            let (k, v) = (h.0.as_str(), h.1.as_str());
            match k {
                "User-Agent" => assert_eq!(v, format!("ZCode/{}", quota::CLIENT_APP_VERSION), "{k}"),
                "X-ZCode-App-Version" => assert_eq!(v, quota::CLIENT_APP_VERSION, "{k}"),
                "X-Device-Mid" => assert_eq!(v, "MID", "{k}"),
                "Authorization" => assert_eq!(v, "Bearer PT", "{k}"),
                _ => {}
            }
        }
    }

    #[test]
    fn poll_token_is_random_hex() {
        let a = new_poll_token();
        let b = new_poll_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn callback_parsing_roundtrip() {
        let k = parse_callback("zcode://oauth/callback?code=A%2Bb%3D&state=deadbeef").unwrap();
        assert_eq!(k, CallbackKind::Code { code: "A+b=".into(), state: "deadbeef".into() });
        let k = parse_callback("zcode://oauth/callback?authCode=XY&state=s1").unwrap();
        assert_eq!(k, CallbackKind::Code { code: "XY".into(), state: "s1".into() });
        let k = parse_callback("zcode://oauth/callback?code=A&authCode=B&state=s2").unwrap();
        assert_eq!(k, CallbackKind::Code { code: "B".into(), state: "s2".into() });
        let k = parse_callback("zcode://oauth/callback?authCode=B&code=A&state=s3").unwrap();
        assert_eq!(k, CallbackKind::Code { code: "B".into(), state: "s3".into() });
        assert_eq!(parse_callback("zcode://oauth/callback?state=s&utm_source=ad").unwrap(), CallbackKind::Attribution);
        assert_eq!(
            parse_callback("zcode://oauth/callback?state=s&channel_id=c42").unwrap(),
            CallbackKind::Attribution
        );
        assert!(parse_callback("zcode://oauth/callback?code=x").is_err(), "缺 state");
        assert!(parse_callback("zcode://oauth/callback?state=x").is_err(), "无 code 无归因");
        assert!(parse_callback("zcode://oauth/callback?state=s&error=denied").is_err(), "error 分支不视为归因");
        assert!(parse_callback("https://zcode.z.ai/x").is_err(), "非回调地址");
    }

    #[test]
    fn credentials_assembly_shape() {
        let ui = json!({ "username": "ethan", "email": "e@x.com" });
        let c = assemble_credentials_with_token("bigmodel", "JWT123", Some(&ui), None, None);
        assert_eq!(c["zcodejwttoken"], "JWT123");
        assert_eq!(c["oauth:active_provider"], "bigmodel");
        let ui_str = c["oauth:bigmodel:user_info"].as_str().expect("user_info 必须为字符串");
        let parsed: Value = serde_json::from_str(ui_str).expect("字符串内容必须是合法 JSON");
        assert_eq!(parsed["username"], "ethan");
        assert!(c.get("oauth:zai:user_info").is_none());
    }

    #[test]
    fn assembled_credentials_identity_roundtrip() {
        let ui = json!({ "username": "ethan", "displayName": "Ethan", "email": "e@x.com", "id": "C42" });
        let c = assemble_credentials_with_token("bigmodel", "x".repeat(40).as_str(), Some(&ui), None, None);
        let id = crate::zcrypto::identity_with_secret(&c, "any-secret");
        assert_eq!(id.username.as_deref(), Some("ethan"));
        assert_eq!(id.email.as_deref(), Some("e@x.com"));
        assert_eq!(id.user_id.as_deref(), Some("C42"));
        assert!(crate::store::is_logged_in(&c), "zcodejwttoken 应视为已登录");
    }

    #[test]
    fn urldecode_edge_cases() {
        assert_eq!(urldecode("A%41"), "AA");
        assert_eq!(urldecode("%41"), "A");
        assert_eq!(urldecode("a%4"), "a%4");
        assert_eq!(urldecode("100%"), "100%");
        assert_eq!(urldecode("a+b"), "a b");
        assert_eq!(urldecode("%zz"), "%zz");
    }

    #[test]
    fn extract_access_token_fallback_chain() {
        let raw = json!({ "code": 0, "data": { "token": "JWT", "bigmodel": { "access_token": "BM-AT" } } });
        assert_eq!(extract_access_token("bigmodel", &raw).as_deref(), Some("BM-AT"));
        let raw = json!({ "data": { "bigmodel": { "accessToken": "BM-C" } } });
        assert_eq!(extract_access_token("bigmodel", &raw).as_deref(), Some("BM-C"));
        let raw = json!({ "data": { "access_token": "TOP" } });
        assert_eq!(extract_access_token("bigmodel", &raw).as_deref(), Some("TOP"));
        let raw = json!({ "data": { "token": "JWT", "zai": { "access_token": " ZAI-AT " } } });
        assert_eq!(extract_access_token("zai", &raw).as_deref(), Some("ZAI-AT"));
        let raw = json!({ "data": { "zai": { "access_token": "  " } } });
        assert!(extract_access_token("zai", &raw).is_none());
        assert!(extract_access_token("bigmodel", &json!({ "data": {} })).is_none());
    }

    #[test]
    fn pick_org_project_prefers_defaults_and_filters_type2() {
        let cust = json!({ "data": { "organizations": [
            { "organizationId": "org-b", "organizationName": "备用机构", "projects": [
                { "projectId": "p-b1", "projectName": "测试", "projectType": "1" },
                { "projectId": "p-b2", "projectName": "隐藏", "projectType": "2" },
            ]},
            { "organizationId": "org-a", "organizationName": "默认机构", "projects": [
                { "projectId": "p-a2", "projectName": "默认项目", "projectType": "1" },
                { "projectId": "p-a1", "projectName": "其他", "projectType": "1" },
            ]},
        ]}});
        assert_eq!(pick_org_project(&cust), Some(("org-a".into(), "p-a2".into())));
        let cust = json!({ "organizations": [
            { "organizationId": "org-x", "organizationName": "X", "projects": [
                { "projectId": "p-x9", "projectName": "任意", "projectType": "1" },
            ]},
        ]});
        assert_eq!(pick_org_project(&cust), Some(("org-x".into(), "p-x9".into())));
        let bad = json!({ "organizations": [
            { "organizationId": "o", "projects": [ { "projectId": "p", "projectType": "2" } ] },
        ]});
        assert!(pick_org_project(&bad).is_none());
        let bad = json!({ "organizations": [
            { "organizationId": "o", "projects": [ { "projectId": "p", "projectType": 2 } ] },
            { "organizationId": "o2", "projects": [ { "projectId": "p2", "projectType": " 2 " } ] },
        ]});
        assert!(pick_org_project(&bad).is_none());
        let num = json!({ "organizations": [
            { "organizationId": 42, "projects": [ { "projectId": 7, "projectType": 1 } ] },
        ]});
        assert_eq!(pick_org_project(&num), Some(("42".into(), "7".into())));
    }

    #[test]
    fn assemble_config_shapes_match_client_providers() {
        let cfg = assemble_config("bigmodel", "JWT-X", "");
        let p = &cfg["provider"];
        assert_eq!(p["builtin:bigmodel"]["name"], "Bigmodel - API Key");
        assert_eq!(p["builtin:bigmodel"]["options"]["baseURL"], "https://open.bigmodel.cn/api/anthropic");
        assert_eq!(p["builtin:bigmodel-coding-plan"]["name"], "BigModel - Coding Plan");
        assert_eq!(p["builtin:bigmodel-coding-plan"]["options"]["apiKey"], "");
        assert_eq!(p["builtin:bigmodel-coding-plan"]["kind"], "anthropic");
        assert_eq!(p["builtin:bigmodel-coding-plan"]["source"], "custom");
        assert_eq!(p["builtin:bigmodel-coding-plan"]["enabled"], false);
        assert_eq!(p["builtin:bigmodel-coding-plan"]["options"]["apiKeyRequired"], true);
        assert_eq!(p["builtin:bigmodel-start-plan"]["name"], "BigModel- Coding Plan");
        assert_eq!(p["builtin:bigmodel-start-plan"]["options"]["apiKey"], "JWT-X");
        assert_eq!(p["builtin:bigmodel-start-plan"]["enabled"], true);
        assert_eq!(
            p["builtin:bigmodel-start-plan"]["options"]["baseURL"],
            "https://zcode.z.ai/api/v1/zcode-plan/anthropic"
        );
        assert_eq!(p["builtin:bigmodel-start-plan"]["options"].get("apiKeyRequired"), None);

        let cfg = assemble_config("zai", "JWT-Y", "");
        let p = &cfg["provider"];
        assert_eq!(p["builtin:zai"]["name"], "Z.ai - API Key");
        assert_eq!(p["builtin:zai"]["enabled"], false);
        assert_eq!(p["builtin:zai"]["options"]["apiKeyRequired"], true);
        assert_eq!(p["builtin:zai"]["options"]["baseURL"], "https://api.z.ai/api/anthropic");
        assert_eq!(p["builtin:zai-start-plan"]["name"], "Z.ai - Coding Plan");
        assert_eq!(p["builtin:zai-start-plan"]["options"]["apiKey"], "JWT-Y");
        assert_eq!(p["builtin:zai-coding-plan"]["name"], "Z.ai - Coding Plan");
        assert_eq!(p["builtin:zai-coding-plan"]["options"]["baseURL"], "https://api.z.ai/api/anthropic");
        assert_eq!(p["builtin:zai-coding-plan"]["enabled"], false);
        assert_eq!(p["builtin:zai-coding-plan"]["options"]["apiKey"], "");
    }

    fn mock_server(routes: Vec<(&'static str, Value)>) -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (route, body) in routes {
                let (mut stream, _) = match listener.accept() {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let mut buf: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 4096];
                let head_end: Option<usize> = loop {
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(p + 4);
                    }
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                };
                if let Some(he) = head_end {
                    let cl: usize = String::from_utf8_lossy(&buf[..he])
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < he + cl {
                        let n = stream.read(&mut chunk).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let _ = tx.send(head.clone());
                let line = head.lines().next().unwrap_or_default().to_string();
                if !line.starts_with(route) {
                    let _ = stream.write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    continue;
                }
                let body_str = body.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_str}",
                    body_str.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}"), rx)
    }

    #[test]
    fn resolve_biz_api_key_full_chain_against_loopback() {
        let cust = json!({ "data": { "organizations": [
            { "organizationId": "o1", "organizationName": "默认机构", "projects": [
                { "projectId": "p1", "projectName": "默认项目", "projectType": "1" },
            ]},
        ]}});
        let (base, rx) = mock_server(vec![
            ("GET /api/biz/customer/getCustomerInfo", cust),
            (
                "GET /api/biz/v1/organization/o1/projects/p1/api_keys",
                json!({ "data": [ { "name": "other-key", "apiKey": "OLD" } ] }),
            ),
            (
                "POST /api/biz/v1/organization/o1/projects/p1/api_keys",
                json!({ "name": "zcode-api-key", "apiKey": "NEWKEY" }),
            ),
            (
                "GET /api/biz/v1/organization/o1/projects/p1/api_keys/copy/NEWKEY",
                json!({ "secretKey": "SEC" }),
            ),
        ]);
        let key = resolve_biz_api_key(&base, "TOK", true).expect("全链成功必出组合 key");
        assert_eq!(key, "NEWKEY.SEC");
        assert!(rx.recv().unwrap().starts_with("GET /api/biz/customer/"));
        assert!(rx.recv().unwrap().starts_with("GET /api/biz/v1/"));
        assert!(rx.recv().unwrap().starts_with("POST /api/biz/v1/"));
        let copy = rx.recv().unwrap();
        assert!(copy.contains("/copy/NEWKEY"), "copy 路径须带 apiKey：{copy}");
    }

    #[test]
    fn resolve_biz_api_key_existing_key_and_secret_requirement() {
        let routes = || {
            vec![
                (
                    "GET /api/biz/customer/getCustomerInfo",
                    json!({ "organizations": [
                        { "organizationId": 42, "projects": [ { "projectId": 7 } ] },
                    ]}),
                ),
                (
                    "GET /api/biz/v1/organization/42/projects/7/api_keys",
                    json!({ "data": [ { "name": "zcode-api-key", "apiKey": "HAVE" } ] }),
                ),
                (
                    "GET /api/biz/v1/organization/42/projects/7/api_keys/copy/HAVE",
                    json!({ "data": {} }),
                ),
            ]
        };
        let (base1, _rx1) = mock_server(routes());
        assert_eq!(resolve_biz_api_key(&base1, "TOK", true), None, "无 secret 且必须带 secret → None");
        let (base2, _rx2) = mock_server(routes());
        assert_eq!(resolve_biz_api_key(&base2, "TOK", false).as_deref(), Some("HAVE"));
    }

    #[test]
    fn resolve_zai_business_token_against_loopback() {
        let (base, rx) = mock_server(vec![
            ("POST /api/auth/z/login", json!({ "code": 0, "data": { "access_token": " BT99 " } })),
        ]);
        let url = format!("{base}/api/auth/z/login");
        assert_eq!(resolve_zai_business_token_at(&url, "ZAI-AT").as_deref(), Some("BT99"));
        let line = rx.recv().unwrap();
        assert!(line.starts_with("POST /api/auth/z/login"));
        let (base2, _rx2) = mock_server(vec![
            ("POST /api/auth/z/login", json!({ "code": 0, "data": {} })),
        ]);
        let url2 = format!("{base2}/api/auth/z/login");
        assert_eq!(resolve_zai_business_token_at(&url2, "ZAI-AT"), None);
    }

    fn future_ts(sec: u64) -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            + u128::from(sec) * 1000
    }

    #[test]
    fn init_flow_keeps_server_redirect_and_adopts_poll_token() {
        let init_body = json!({
            "code": 0,
            "data": {
                "flow_id": "fl-abc.123",
                "poll_token": "SRV-POLL-TOKEN-64HEX",
                "authorize_url": "https://bigmodel.cn/login?redirect=https%3A%2F%2Fzcode.z.ai%2Fapi%2Fv1%2Foauth%2Fcli%2Fcallback%2Fbigmodel&appId=zcode&state=cafe01",
                "expires_at": (future_ts(600) / 1000) as i64,
                "poll_interval_sec": 3,
            }
        });
        let (base, rx) = mock_server(vec![("POST /api/v1/oauth/cli/init", init_body)]);
        let f = init_flow_at(&format!("{base}/api/v1/oauth/cli/init"), "bigmodel", "MID").expect("init 成功");
        assert_eq!(f.state, "cafe01");
        assert_eq!(f.poll_url, format!("{base}/api/v1/oauth/cli/poll/fl-abc.123"), "flow_id 须编码拼接");
        assert_eq!(f.poll_token, "SRV-POLL-TOKEN-64HEX", "轮询凭证须用服务端下发值");
        assert!(f.authorize_url.starts_with("https://bigmodel.cn/login?"), "{}", f.authorize_url);
        assert!(f.authorize_url.contains("redirect=https%3A%2F%2Fzcode.z.ai%2Fapi%2Fv1%2Foauth%2Fcli%2Fcallback%2Fbigmodel"), "{}", f.authorize_url);
        assert!(f.authorize_url.contains("appId=zcode"), "{}", f.authorize_url);
        assert!(f.authorize_url.contains("state=cafe01"), "{}", f.authorize_url);
        assert!(f.expires_at_ms > 0);
        assert_eq!(f.poll_interval_ms, 3000);
        let head = rx.recv().unwrap();
        assert!(head.starts_with("POST /api/v1/oauth/cli/init"));
        assert!(head.contains(&format!("X-ZCode-App-Version: {}", quota::CLIENT_APP_VERSION)), "{head}");
        assert!(head.contains(&format!("User-Agent: ZCode/{}", quota::CLIENT_APP_VERSION)), "{head}");
        assert!(head.contains("Authorization: Bearer "), "{head}");
        assert!(head.contains("X-Device-Mid: MID"), "{head}");

        let init_body = json!({
            "code": 0,
            "data": {
                "flow_id": "fl-z",
                "poll_token": "SRV-ZAI-TOKEN",
                "authorize_url": "https://chat.z.ai/api/oauth/authorize?redirect_uri=https%3A%2F%2Fzcode.z.ai%2Fapi%2Fv1%2Foauth%2Fcli%2Fcallback%2Fzai&response_type=code&client_id=c&state=zz11",
                "expires_at": (future_ts(600) / 1000) as i64,
                "poll_interval_sec": 2,
            }
        });
        let (base2, _rx2) = mock_server(vec![("POST /api/v1/oauth/cli/init", init_body)]);
        let f2 = init_flow_at(&format!("{base2}/api/v1/oauth/cli/init"), "zai", "MID").unwrap();
        assert_eq!(f2.poll_token, "SRV-ZAI-TOKEN");
        assert!(f2.authorize_url.contains("redirect_uri=https%3A%2F%2Fzcode.z.ai%2Fapi%2Fv1%2Foauth%2Fcli%2Fcallback%2Fzai"), "{}", f2.authorize_url);
        assert!(f2.authorize_url.contains("response_type=code"), "{}", f2.authorize_url);

        let legacy = json!({
            "code": 0,
            "data": {
                "flow_id": "fl-old",
                "authorize_url": "https://bigmodel.cn/login?redirect=r&state=st9",
                "expires_at": (future_ts(600) / 1000) as i64,
                "poll_interval_sec": 2,
            }
        });
        let (base3, _rx3) = mock_server(vec![("POST /api/v1/oauth/cli/init", legacy)]);
        let f3 = init_flow_at(&format!("{base3}/api/v1/oauth/cli/init"), "bigmodel", "MID").unwrap();
        assert!(f3.poll_token.len() == 64 && f3.poll_token.chars().all(|c| c.is_ascii_hexdigit()), "回落自造 pollToken");
    }

    #[test]
    fn init_flow_rejects_invalid_responses() {
        let mk = |data: Value| {
            let (base, _rx) = mock_server(vec![("POST /api/v1/oauth/cli/init", json!({ "code": 0, "data": data }))]);
            format!("{base}/api/v1/oauth/cli/init")
        };
        let full = |exp: i64, int: i64| json!({
            "flow_id": "f", "authorize_url": "https://bigmodel.cn/login?state=st",
            "expires_at": exp, "poll_interval_sec": int
        });
        assert!(init_flow_at(&mk(json!({})), "bigmodel", "M").is_err(), "空 data");
        assert!(init_flow_at(&mk(full((future_ts(600) / 1000) as i64, 0)), "bigmodel", "M").is_err(), "间隔 0s");
        assert!(init_flow_at(&mk(full((future_ts(600) / 1000) as i64, 999)), "bigmodel", "M").is_err(), "间隔 <1s");
        assert!(init_flow_at(&mk(full(1, 5)), "bigmodel", "M").is_err(), "已过期");
        let http_url = {
            let (base, _rx) = mock_server(vec![(
                "POST /api/v1/oauth/cli/init",
                json!({ "code": 0, "data": {
                    "flow_id": "f",
                    "authorize_url": "http://bigmodel.cn/login?state=st",
                    "expires_at": (future_ts(600) / 1000) as i64, "poll_interval_sec": 5,
                }}),
            )]);
            format!("{base}/api/v1/oauth/cli/init")
        };
        assert!(init_flow_at(&http_url, "bigmodel", "M").is_err(), "非 https authorize");
        let bad_code = {
            let (base, _rx) = mock_server(vec![("POST /api/v1/oauth/cli/init", json!({ "code": 3001, "msg": "denied" }))]);
            format!("{base}/api/v1/oauth/cli/init")
        };
        assert!(init_flow_at(&bad_code, "bigmodel", "M").is_err(), "code!=0");
    }

    #[test]
    fn poll_flow_once_states() {
        let (b, _r) = mock_server(vec![("GET /poll", json!({ "code": 0, "data": { "status": "pending" } }))]);
        assert!(matches!(poll_flow_once(&format!("{b}/poll"), "T", "M"), Ok(PollOutcome::Pending)));
        let ready = json!({ "code": 0, "data": {
            "status": "ready", "token": "JWT9",
            "user": { "user_id": "U9", "name": "Ethan" },
            "zai": { "access_token": "ZAT" },
        }});
        let (b2, rx2) = mock_server(vec![("GET /poll", ready)]);
        match poll_flow_once(&format!("{b2}/poll"), "T", "M") {
            Ok(PollOutcome::Ready(d)) => {
                assert_eq!(d["token"], "JWT9");
                assert_eq!(d["zai"]["access_token"], "ZAT");
                assert_eq!(d["user"]["user_id"], "U9");
            }
            other => panic!("ready 应出 Ready：{other:?}"),
        }
        let head2 = rx2.recv().unwrap();
        assert!(head2.starts_with("GET /poll"));
        assert!(head2.contains(&format!("X-ZCode-App-Version: {}", quota::CLIENT_APP_VERSION)), "{head2}");
        assert!(head2.contains(&format!("User-Agent: ZCode/{}", quota::CLIENT_APP_VERSION)), "{head2}");
        let ready_bm = json!({ "code": 0, "data": {
            "status": "ready", "token": "J",
            "user": { "user_id": "U" },
            "bigmodel": { "accessToken": "BM-AT" },
        }});
        let (b3, _r3) = mock_server(vec![("GET /poll", ready_bm)]);
        assert!(matches!(poll_flow_once(&format!("{b3}/poll"), "T", "M"), Ok(PollOutcome::Ready(_))));
        let broken = json!({ "code": 0, "data": { "status": "ready", "token": "J", "user": {} } });
        let (b4, _r4) = mock_server(vec![("GET /poll", broken)]);
        assert!(poll_flow_once(&format!("{b4}/poll"), "T", "M").is_err());
        for body in [
            json!({ "code": 0, "data": { "status": "failed" } }),
            json!({ "code": 0, "data": { "status": "weird" } }),
            json!({ "code": 3001, "msg": "x" }),
        ] {
            let (b5, _r5) = mock_server(vec![("GET /poll", body.clone())]);
            assert!(poll_flow_once(&format!("{b5}/poll"), "T", "M").is_err(), "{body}");
        }
        let (b6, _r6) = mock_server(vec![("GET /other", json!({}))]);
        assert!(poll_flow_once(&format!("{b6}/poll"), "T", "M").is_err(), "404 终态");
    }

    fn raw_server_once(status_line: &'static str, body: &'static str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        });
        format!("http://{addr}/poll")
    }

    #[test]
    fn poll_4xx_body_codes_are_translated() {
        let url = raw_server_once("HTTP/1.1 400 Bad Request", "{\"code\":3004,\"msg\":\"invalid_flow\"}");
        let e = poll_flow_once(&url, "T", "M").unwrap_err();
        assert_eq!(e, crate::i18n::tr("err.oauth.expired"), "3004 须映射为过期文案：{e}");
        let url2 = raw_server_once("HTTP/1.1 403 Forbidden", "{\"code\":3001,\"msg\":\"denied\"}");
        let e2 = poll_flow_once(&url2, "T", "M").unwrap_err();
        assert_eq!(e2, crate::i18n::trf("err.oauth.poll_terminal", &[("code", "403")]), "{e2}");
    }

    #[test]
    fn credentials_carry_access_token_conditionally() {
        let c = assemble_credentials_with_token("bigmodel", "JWT", None, Some("BM-AT"), None);
        assert_eq!(c["oauth:bigmodel:access_token"], "BM-AT");
        let c = assemble_credentials_with_token("zai", "JWT", None, Some("  "), None);
        assert!(c.get("oauth:zai:access_token").is_none());
        assert!(c.get("oauth:bigmodel:access_token").is_none());
        let c = assemble_credentials_with_token("bigmodel", "JWT", None, Some("AT"), Some("RT9"));
        assert_eq!(c["oauth:bigmodel:refresh_token"], "RT9");
        let c = assemble_credentials_with_token("bigmodel", "JWT", None, Some("AT"), Some(" "));
        assert!(c.get("oauth:bigmodel:refresh_token").is_none());
        let c = assemble_credentials_with_token("zai", "JWT", None, Some("BT"), Some("RT"));
        assert_eq!(c["oauth:zai:refresh_token"], "RT");
    }

    #[test]
    fn refresh_token_extraction_bigmodel_only() {
        let raw = json!({ "data": { "bigmodel": { "refresh_token": " R1 " } } });
        assert_eq!(extract_refresh_token("bigmodel", &raw).as_deref(), Some("R1"));
        let raw = json!({ "data": { "bigmodel": { "refreshToken": "R2" } } });
        assert_eq!(extract_refresh_token("bigmodel", &raw).as_deref(), Some("R2"));
        let raw = json!({ "data": { "zai": { "refresh_token": "X" } } });
        assert!(extract_refresh_token("zai", &raw).is_none());
        let raw = json!({ "data": { "bigmodel": {} } });
        assert!(extract_refresh_token("bigmodel", &raw).is_none());
    }

    #[test]
    fn zai_profile_from_exchange_response() {
        let raw = json!({ "data": { "user": {
            "user_id": "U42", "name": " Ethan ", "email": "e@x.com", "avatar": "http://a/x.png",
        }}});
        let p = extract_user_profile("zai", &raw).expect("有后端用户必出 profile");
        assert_eq!(p["id"], "U42");
        assert_eq!(p["username"], "Ethan");
        assert_eq!(p["email"], "e@x.com");
        let raw = json!({ "data": { "user": { "user_id": "U7", "email": "z@x.com" } } });
        let p = extract_user_profile("zai", &raw).unwrap();
        assert_eq!(p["username"], "z@x.com");
        let raw = json!({ "data": { "user": { "user_id": "  " } } });
        assert!(extract_user_profile("zai", &raw).is_none());
        assert!(extract_user_profile("zai", &json!({ "data": {} })).is_none());
        assert!(extract_user_profile("bigmodel", &raw).is_none());
        let raw = json!({ "data": { "user": { "user_id": "BM1", "name": "Bo" } } });
        let p = extract_poll_user_profile(&raw).expect("poll 路径 bigmodel 也取 data.user");
        assert_eq!(p["id"], "BM1");
        assert_eq!(p["username"], "Bo");
        assert_eq!(extract_poll_user_profile(&json!({ "data": {} })), None);
        let raw = json!({ "data": { "user": { "name": "Ethan", "email": "e@x.com", "avatar": "http://a/x.png" } } });
        let p = extract_user_profile("zai", &raw).unwrap();
        assert!(p["id"].is_null(), "缺 user_id 时 id 必须为 null，不得为 unknown: {}", p["id"]);
        assert_eq!(p["username"], "Ethan");
    }

    #[test]
    fn proxy_url_validation() {
        assert_eq!(parse_proxy_url("http://127.0.0.1:7890").unwrap(), "http://127.0.0.1:7890");
        assert_eq!(parse_proxy_url("socks5://127.0.0.1:1080").unwrap(), "socks5://127.0.0.1:1080");
        assert_eq!(parse_proxy_url("  HTTP://proxy.lan:8080 ").unwrap(), "http://proxy.lan:8080");
        assert_eq!(parse_proxy_url("http://127.0.0.1:07890").unwrap(), "http://127.0.0.1:7890");

        assert!(parse_proxy_url("").is_err(), "空");
        assert!(parse_proxy_url("   ").is_err(), "纯空白");
        assert!(parse_proxy_url("127.0.0.1:7890").is_err(), "缺 scheme");
        assert!(parse_proxy_url("https://127.0.0.1:7890").is_err(), "https 不在支持列表");
        assert!(parse_proxy_url("socks4://127.0.0.1:1080").is_err(), "socks4 不支持");
        assert!(parse_proxy_url("http://127.0.0.1").is_err(), "缺端口");
        assert!(parse_proxy_url("http://127.0.0.1:0").is_err(), "端口 0");
        assert!(parse_proxy_url("http://127.0.0.1:70000").is_err(), "端口超范围");
        assert!(parse_proxy_url("http://127.0.0.1:abc").is_err(), "端口非数字");
        assert!(parse_proxy_url("http://user:pw@127.0.0.1:7890").is_err(), "带认证不支持");
        assert!(parse_proxy_url("http://127.0.0.1:7890/path").is_err(), "带路径");
        assert!(parse_proxy_url("http://:7890").is_err(), "主机为空");
        assert!(parse_proxy_url("http://fe80::1:7890").is_err(), "IPv6 裸址不支持");
        assert!(parse_proxy_url("http://a b:7890").is_err(), "主机含空格");
        let norm = parse_proxy_url("socks5://127.0.0.1:1080").unwrap();
        assert!(norm.parse::<tauri::Url>().is_ok());
    }

    #[test]
    fn userinfo_maps_fields() {
        let v = json!({ "data": { "customerNumber": "C123", "username": "u1", "avatar": "http://a" } });
        let data = &v["data"];
        let get = |k: &str| data.get(k).and_then(|x| x.as_str());
        assert_eq!(get("customerNumber"), Some("C123"));
        assert_eq!(get("username"), Some("u1"));
        assert_eq!(get("avatar"), Some("http://a"));
    }
}
