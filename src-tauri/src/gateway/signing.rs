//! Client Request Signing V4 — port of zcode-api `src/proxy/client-signing.ts`
//! (itself a mirror of the ZCode 3.12.3 `ClientRequestSigningV4Signer`).
//!
//! Per-request Ed25519 signatures + proof-of-work over coding-plan traffic.
//! All message templates join their fields with literal NEWLINES (verified
//! byte-exact upstream; space-joined → rejected):
//! ```text
//! handshake HMAC   "get_sign_key\n{apiKeyId}\n{ts}\n{nonce}"
//! business Ed25519 "{apiKeyId}\n{ts}\n{clientVersion}\n{sessionId}\n{nonce}"
//! PoW challenge    sha256("{apiKeyId}\nzcode\n{sessionId}\n{ts}") hex[:32]
//! PoW answer       sha256("{challenge}\n{answer}")
//! ```
//! Everything is fail-open: gate disabled/unreachable → unsigned; handshake
//! failure → unsigned; two consecutive 401 VERIFY_* rejections → permanent
//! bypass for that (origin, credential) pair.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const DEFAULT_ORIGIN: &str = "https://zcode.z.ai";
const GATE_PATH: &str = "/api/v1/agent/configs";
const HANDSHAKE_PATH: &str = "/api/paas/c1f3a7e2/v2/client";
const APP_ID: &str = "zcode";
const POW_BITS: u32 = 8;
const NONCE_BYTES: usize = 16;
const POW_NONCE_BYTES: usize = 12;
const KDF_SALT: &[u8] = b"WD_CLIENT_SIGN_KDF_SALT";
const KDF_INFO_HMAC: &[u8] = b"getSignKey_hmac";
const KDF_INFO_ED25519: &[u8] = b"ed25519_priv";
const HANDSHAKE_METHOD: &str = "get_sign_key";
const GATE_TTL: Duration = Duration::from_secs(3_600);
const GATE_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);
const GATE_UNAVAILABLE_COOLDOWN: Duration = Duration::from_secs(30);
const GATE_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const VERIFY_SIGNATURE_INVALID: &str = "VERIFY_SIGNATURE_INVALID";
const VERIFY_APIKEY_EXPIRED: &str = "VERIFY_APIKEY_EXPIRED";

/// Paths the client never signs.
const UNSIGNED_PATHS: &[&str] = &[
    "/api/v1/zcode-plan/anthropic/v1/messages",
    "/api/v1/zcode-plan/chat/completions",
    "/api/v1/off-peak/anthropic/v1/messages",
];

const SIGNING_HEADER_NAMES: &[&str] = &[
    "x-client-ts",
    "x-client-version",
    "x-client-sig",
    "x-client-nonce",
    "x-app-id",
    "x-client-pow",
    "x-client-sign-verified",
];

#[derive(Clone)]
pub struct SigningManager {
    client: reqwest::Client,
    gate_url: String,
    /// identity headers for the gate probe (LLM `g6n` set).
    identity_headers: Arc<Vec<(String, String)>>,
    states: Arc<tokio::sync::Mutex<HashMap<String, SignerState>>>,
}

#[derive(Clone)]
struct SignerState {
    gate_enabled: bool,
    gate_expires_at: Instant,
    gate_neg_until: Instant,
    priv_key: Option<SigningKey>,
    bypass: bool,
}

impl SignerState {
    fn new() -> Self {
        SignerState {
            gate_enabled: false,
            gate_expires_at: Instant::now(),
            gate_neg_until: Instant::now(),
            priv_key: None,
            bypass: false,
        }
    }
}

fn hkdf_bytes(secret: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(KDF_SALT), secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 bytes is a valid HKDF length");
    okm
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn random_hex(byte_count: usize) -> String {
    let mut buf = vec![0u8; byte_count];
    rand::thread_rng().fill_bytes(&mut buf);
    bytes_to_hex(&buf)
}

fn has_leading_zero_bits(bytes: &[u8], bits: u32) -> bool {
    let full = bits / 8;
    for b in bytes.iter().take(full as usize) {
        if *b != 0 {
            return false;
        }
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = (255u16 << (8 - rem)) as u8 & 0xff;
    match bytes.get(full as usize) {
        Some(b) => b & mask == 0,
        None => false,
    }
}

fn parse_signing_credential(credential: &str) -> Option<(String, String)> {
    let dot = credential.find('.')?;
    if credential[dot + 1..].contains('.') {
        return None;
    }
    let id = credential[..dot].trim();
    let secret = credential[dot + 1..].trim();
    if id.is_empty() || secret.is_empty() {
        return None;
    }
    Some((id.to_string(), secret.to_string()))
}

fn is_unsigned_path(path: &str) -> bool {
    UNSIGNED_PATHS.iter().any(|p| path.trim_end_matches('/') == *p)
}

fn find_header<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let lower = name.to_ascii_lowercase();
    pairs
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase() == lower)
        .map(|(_, v)| v.as_str())
}

/// Outcome of a signing pass.
pub struct SignOutcome {
    pub pairs: Vec<(String, String)>,
    pub signed: bool,
}

enum GateOutcome {
    Enabled,
    Disabled,
    Unavailable,
    NetworkFail,
}

impl SigningManager {
    pub fn new(client: reqwest::Client, origin: Option<&str>, identity_headers: Vec<(String, String)>) -> Self {
        let base = origin
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .unwrap_or(DEFAULT_ORIGIN);
        SigningManager {
            client,
            gate_url: format!("{}{GATE_PATH}", base.trim_end_matches('/')),
            identity_headers: Arc::new(identity_headers),
            states: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    async fn state_for(&self, key: &str) -> SignerState {
        let mut states = self.states.lock().await;
        states.entry(key.to_string()).or_insert_with(SignerState::new).clone()
    }

    async fn update_state<F: FnOnce(&mut SignerState)>(&self, key: &str, f: F) {
        let mut states = self.states.lock().await;
        let st = states.entry(key.to_string()).or_insert_with(SignerState::new);
        f(st);
    }

    /// Probe the signing gate. Cached per (origin, credential); fail-open.
    /// Definitive "disabled" answers cache for the full TTL; network failures
    /// and unavailable responses get a short negative cooldown.
    async fn gate_enabled(&self, state_key: &str, credential: &str) -> bool {
        let now = Instant::now();
        {
            let st = self.state_for(state_key).await;
            if st.gate_expires_at > now {
                return st.gate_enabled;
            }
            if st.gate_neg_until > now {
                return false;
            }
        }
        let outcome = self.probe_gate(credential).await;
        let enabled = matches!(outcome, GateOutcome::Enabled);
        let now = Instant::now();
        self.update_state(state_key, |st| {
            st.gate_enabled = enabled;
            if enabled {
                st.gate_expires_at = now + GATE_TTL;
                st.gate_neg_until = now;
            } else if matches!(outcome, GateOutcome::Disabled) {
                st.gate_expires_at = now + GATE_TTL;
                st.gate_neg_until = now;
            } else if matches!(outcome, GateOutcome::NetworkFail) {
                st.gate_neg_until = now + GATE_FAILURE_COOLDOWN;
            } else {
                st.gate_neg_until = now + GATE_UNAVAILABLE_COOLDOWN;
            }
        })
        .await;
        enabled
    }

    async fn probe_gate(&self, credential: &str) -> GateOutcome {
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in self.identity_headers.iter() {
            if let (Ok(name), Ok(val)) = (reqwest::header::HeaderName::try_from(k.as_str()), reqwest::header::HeaderValue::try_from(v.as_str())) {
                headers.insert(name, val);
            }
        }
        if let Ok(val) = reqwest::header::HeaderValue::try_from(credential.to_string()) {
            headers.insert(reqwest::header::HeaderName::from_static("x-api-key"), val);
        }        let resp = match self
            .client
            .get(&self.gate_url)
            .headers(headers)
            .timeout(GATE_TIMEOUT)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => return GateOutcome::NetworkFail,
        };
        if !resp.status().is_success() {
            return GateOutcome::Unavailable;
        }
        let Ok(parsed) = resp.json::<serde_json::Value>().await else {
            return GateOutcome::Unavailable;
        };
        if parsed.get("code").and_then(|c| c.as_i64()) != Some(0) {
            return GateOutcome::Unavailable;
        }
        match parsed.pointer("/data/codingPlanSignature/enable") {
            Some(serde_json::Value::Bool(true)) => GateOutcome::Enabled,
            Some(serde_json::Value::Bool(false)) => GateOutcome::Disabled,
            // no codingPlanSignature key at all → disabled
            _ => GateOutcome::Disabled,
        }
    }

    async fn ensure_private_key(
        &self,
        state_key: &str,
        api_key_id: &str,
        secret: &str,
        origin: &str,
    ) -> Option<SigningKey> {
        let st = self.state_for(state_key).await;
        if let Some(k) = &st.priv_key {
            return Some(k.clone());
        }
        match self.perform_handshake(api_key_id, secret, origin).await {
            Ok(k) => {
                self.update_state(state_key, |st| st.priv_key = Some(k.clone())).await;
                Some(k)
            }
            Err(_) => None,
        }
    }

    async fn perform_handshake(&self, api_key_id: &str, secret: &str, origin: &str) -> Result<SigningKey, String> {
        let ts = now_ms().to_string();
        let nonce = random_hex(NONCE_BYTES);
        let key = hkdf_bytes(secret.as_bytes(), KDF_INFO_HMAC);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|e| e.to_string())?;
        mac.update(format!("{HANDSHAKE_METHOD}\n{api_key_id}\n{ts}\n{nonce}").as_bytes());
        let sig = B64.encode(mac.finalize().into_bytes());

        let url = format!("{origin}{HANDSHAKE_PATH}");
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("{api_key_id}.{secret}"))
            .header("Content-Type", "application/json")
            .timeout(HANDSHAKE_TIMEOUT)
            .body(json!({ "apiKey": format!("{api_key_id}.{secret}"), "nonce": nonce, "sig": sig, "ts": ts }).to_string())
            .send()
            .await
            .map_err(|e| format!("handshake network: {e}"))?;
        if resp.status() != reqwest::StatusCode::OK {
            return Err(format!("handshake_http_{}", resp.status().as_u16()));
        }
        let envelope: serde_json::Value = resp.json().await.map_err(|e| format!("handshake json: {e}"))?;
        let code = envelope.get("code").and_then(|c| c.as_i64()).unwrap_or_default();
        if code == 500 {
            return Err("handshake_server_500".into());
        }
        if code != 200 {
            return Err(format!(
                "handshake_rejected: {}",
                envelope.get("msg").and_then(|m| m.as_str()).unwrap_or("?")
            ));
        }
        let cipher = envelope
            .pointer("/data/privateCipher")
            .and_then(|c| c.as_str())
            .filter(|c| !c.is_empty())
            .ok_or("handshake_omitted_privateCipher")?;
        decrypt_signing_private_key(api_key_id, secret, cipher)
    }

    /// Add the V4 signing headers to an upstream header-pair list. Returns the
    /// input pairs unchanged whenever signing does not apply. Never fails.
    pub async fn sign(
        &self,
        url: &str,
        pairs: Vec<(String, String)>,
        credential: &str,
        app_version: &str,
    ) -> SignOutcome {
        let Ok(parsed) = url::parse(url) else {
            return SignOutcome { pairs, signed: false };
        };
        if parsed.scheme != "https" {
            return SignOutcome { pairs, signed: false };
        }
        if is_unsigned_path(&parsed.path) {
            return SignOutcome { pairs, signed: false };
        }
        if pairs.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-client-sig")) {
            return SignOutcome { pairs, signed: false };
        }

        let state_key = format!("{}\n{credential}", parsed.origin);
        let st = self.state_for(&state_key).await;
        if st.bypass {
            return SignOutcome { pairs, signed: false };
        }

        let Some((api_key_id, secret)) = parse_signing_credential(credential) else {
            return SignOutcome { pairs, signed: false };
        };
        let session_id = find_header(&pairs, "x-session-id")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let Some(session_id) = session_id else {
            return SignOutcome { pairs, signed: false };
        };

        if !self.gate_enabled(&state_key, credential).await {
            return SignOutcome { pairs, signed: false };
        }

        let Some(private_key) = self.ensure_private_key(&state_key, &api_key_id, &secret, &parsed.origin).await else {
            return SignOutcome { pairs, signed: false };
        };

        let ts = now_ms().to_string();
        let nonce = random_hex(NONCE_BYTES);
        let pow = create_proof_of_work(&api_key_id, &session_id, &ts);
        let sig = {
            let msg = format!("{api_key_id}\n{ts}\n{app_version}\n{session_id}\n{nonce}");
            B64.encode(private_key.sign(msg.as_bytes()).to_bytes())
        };

        let mut cleaned: Vec<(String, String)> = pairs
            .into_iter()
            .filter(|(k, _)| {
                let lower = k.to_ascii_lowercase();
                !SIGNING_HEADER_NAMES.contains(&lower.as_str()) && lower != "x-session-id"
            })
            .collect();
        cleaned.push(("X-Client-Ts".into(), ts));
        cleaned.push(("X-Client-Version".into(), app_version.to_string()));
        cleaned.push(("X-Client-Sig".into(), sig));
        cleaned.push(("X-Session-Id".into(), session_id.to_string()));
        cleaned.push(("X-Client-Nonce".into(), nonce));
        cleaned.push(("X-App-Id".into(), APP_ID.to_string()));
        cleaned.push(("X-Client-Pow".into(), pow));
        SignOutcome { pairs: cleaned, signed: true }
    }

    /// True when the response is a signing rejection the client retries on:
    /// HTTP 401 whose envelope mentions VERIFY_SIGNATURE_INVALID / EXPIRED.
    pub fn is_verify_failure(status: u16, body: &str) -> bool {
        const VERIFY_MATCHERS: [&str; 2] = [VERIFY_SIGNATURE_INVALID, VERIFY_APIKEY_EXPIRED];
        if status != 401 {
            return false;
        }
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
            return false;
        };
        if parsed.is_null() {
            return false;
        }
        let candidates = [
            parsed.get("msg"),
            parsed.get("reason"),
            parsed.pointer("/data/reason"),
            parsed.pointer("/error/reason"),
            parsed.pointer("/error/message"),
        ];
        candidates
            .iter()
            .filter_map(|v| v.and_then(|x| x.as_str()))
            .any(|v| VERIFY_MATCHERS.contains(&v))
    }

    /// Drop the cached signing key for a (origin, credential) pair.
    pub async fn invalidate(&self, url: &str, credential: &str) {
        if let Some(origin) = url::origin_of(url) {
            let key = format!("{origin}\n{credential}");
            self.update_state(&key, |st| st.priv_key = None).await;
        }
    }

    /// Permanently stop signing for a (origin, credential) pair.
    pub async fn set_bypass(&self, url: &str, credential: &str) {
        if let Some(origin) = url::origin_of(url) {
            let key = format!("{origin}\n{credential}");
            self.update_state(&key, |st| st.bypass = true).await;
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// PoW: seed = sha256("{apiKeyId}\nzcode\n{sessionId}\n{ts}") hex[:32];
/// mine sha256("{seed}\n{nonce}{counter:08x}") for 8 leading zero bits.
fn create_proof_of_work(api_key_id: &str, session_id: &str, ts: &str) -> String {
    let seed_digest = Sha256::digest(format!("{api_key_id}\n{APP_ID}\n{session_id}\n{ts}").as_bytes());
    let seed = &bytes_to_hex(&seed_digest)[..32];
    let nonce = random_hex(POW_NONCE_BYTES);
    for counter in 0u32..=u32::MAX {
        let candidate = format!("{nonce}{counter:08x}");
        let digest = Sha256::digest(format!("{seed}\n{candidate}").as_bytes());
        if has_leading_zero_bits(&digest, POW_BITS) {
            return candidate;
        }
    }
    unreachable!("PoW at 8 bits always solvable within u32 counter space")
}

/// Decrypt the handshake's `privateCipher`: base64 → [12-byte IV | GCM ct+tag],
/// key = HKDF(secret, "ed25519_priv"), AAD = apiKeyId; plaintext is a base64
/// PKCS#8 Ed25519 private key.
fn decrypt_signing_private_key(api_key_id: &str, secret: &str, private_cipher: &str) -> Result<SigningKey, String> {
    let cipher = B64.decode(private_cipher).map_err(|e| format!("privateCipher base64: {e}"))?;
    if cipher.len() <= 12 + 16 {
        return Err("privateCipher is too short".into());
    }
    let aes_key = hkdf_bytes(secret.as_bytes(), KDF_INFO_ED25519);
    let gcm = Aes256Gcm::new_from_slice(&aes_key).map_err(|e| format!("aes init: {e}"))?;
    let nonce = Nonce::from_slice(&cipher[..12]);
    let payload = Payload {
        msg: &cipher[12..],
        aad: api_key_id.as_bytes(),
    };
    let plain = gcm
        .decrypt(nonce, payload)
        .map_err(|_| "privateCipher decrypt failed".to_string())?;
    let pkcs8_b64 = String::from_utf8(plain).map_err(|_| "privateCipher plaintext not utf8".to_string())?;
    let pkcs8 = B64
        .decode(pkcs8_b64.trim())
        .map_err(|e| format!("pkcs8 base64: {e}"))?;
    SigningKey::from_pkcs8_der(&pkcs8).map_err(|e| format!("ed25519 pkcs8 import: {e}"))
}

/// Minimal URL splitting helpers (avoid pulling the `url` crate).
mod url {
    pub struct Parsed {
        pub scheme: String,
        pub origin: String,
        pub path: String,
    }

    pub fn parse(url: &str) -> Result<Parsed, ()> {
        let (scheme, rest) = url.split_once("://").ok_or(())?;
        if scheme != "https" && scheme != "http" {
            return Err(());
        }
        let (host_part, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let host = host_part.split('@').next_back().unwrap_or(host_part);
        let origin = format!("{scheme}://{host}");
        Ok(Parsed { scheme: scheme.to_string(), origin, path: path.to_string() })
    }

    pub fn origin_of(url: &str) -> Option<String> {
        parse(url).ok().map(|p| p.origin)
    }
}

/// Constant-time equality helper (used by the server's proxy-key check).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_parsing() {
        assert!(parse_signing_credential("id.secret").is_some());
        assert!(parse_signing_credential("id.secret.extra").is_none());
        assert!(parse_signing_credential("nokey").is_none());
        assert!(parse_signing_credential(".secret").is_none());
        assert!(parse_signing_credential("id.").is_none());
    }

    #[test]
    fn pow_leading_zero_bits() {
        assert!(has_leading_zero_bits(&[0x00, 0xff], 8));
        assert!(has_leading_zero_bits(&[0x00, 0x3f], 10));
        assert!(!has_leading_zero_bits(&[0x01, 0x00], 8));
        assert!(has_leading_zero_bits(&[0x00, 0x00], 16));
        assert!(!has_leading_zero_bits(&[0x00, 0x80], 16));
        assert!(has_leading_zero_bits(&[], 0));
    }

    #[test]
    fn unsigned_paths() {
        assert!(is_unsigned_path("/api/v1/zcode-plan/anthropic/v1/messages"));
        assert!(is_unsigned_path("/api/v1/zcode-plan/anthropic/v1/messages/"));
        assert!(!is_unsigned_path("/api/anthropic/v1/messages"));
    }

    #[test]
    fn verify_failure_detection() {
        let body = r#"{"code":401,"msg":"VERIFY_SIGNATURE_INVALID"}"#;
        assert!(SigningManager::is_verify_failure(401, body));
        assert!(!SigningManager::is_verify_failure(200, body));
        assert!(!SigningManager::is_verify_failure(401, r#"{"msg":"other"}"#));
    }

    #[test]
    fn pow_solves_quickly() {
        let start = std::time::Instant::now();
        let answer = create_proof_of_work("testkey", "session", "123");
        assert!(!answer.is_empty());
        assert!(start.elapsed().as_secs() < 5);
    }
}
