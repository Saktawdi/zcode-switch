//! Identity header builders — mirror the ZCode desktop client's companion
//! headers so gateway traffic is indistinguishable from the official client.
//!
//! Two distinct builders are ported from zcode-api `src/proxy/identity.ts`
//! (which mirror the ZCode 3.12.3 bundle):
//!
//! 1. `build_llm_identity_headers` (bundle `g6n`) — LLM completion requests
//!    AND the coding-plan-signature gate fetches. Carries `X-ZCode-Agent`
//!    inline 8th, NEVER carries `X-Device-Mid`.
//! 2. `build_control_identity_headers` (bundle `TV`) — endpoint-routing /
//!    claim / billing control plane. No `X-ZCode-Agent`, carries the
//!    optional `X-Device-Mid`.

use crate::quota;

/// Printable-ASCII gate copied from the ZCode bundle's `fio` helper.
fn is_printable_ascii(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn normalize_printable(raw: &str) -> Option<&str> {
    let t = raw.trim();
    is_printable_ascii(t).then_some(t)
}

fn node_platform() -> &'static str {
    crate::zcrypto::node_platform_for(std::env::consts::OS)
}

fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn os_category() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

fn client_language() -> String {
    sys_locale::get_locale()
        .filter(|l| !l.trim().is_empty())
        .unwrap_or_else(|| "zh-CN".to_string())
}

fn client_timezone() -> String {
    quota::client_timezone()
}

fn app_version() -> String {
    quota::zcode_app_version()
}

fn os_version() -> Option<String> {
    quota::os_version()
}

/// Shared values for both builders.
struct IdentityValues {
    version: Option<String>,
    platform: Option<String>,
    arch: Option<String>,
    release: Option<String>,
    release_channel: String,
    language: String,
    timezone: String,
}

fn resolve_values() -> IdentityValues {
    IdentityValues {
        version: normalize_printable(&app_version()).map(str::to_string),
        platform: Some(node_platform().to_string()),
        arch: Some(node_arch().to_string()),
        release: os_version(),
        release_channel: "production".to_string(),
        language: client_language(),
        timezone: client_timezone(),
    }
}

/// Identity headers for LLM completion requests (bundle `g6n`). Order and
/// case follow the TypeScript port; `X-Device-Mid` is NEVER sent here.
pub fn build_llm_identity_headers(source_title: &str, referer_origin: &str) -> Vec<(String, String)> {
    let v = resolve_values();
    let mut h = vec![
        ("HTTP-Referer".to_string(), referer_origin.to_string()),
        (
            "User-Agent".to_string(),
            format!("ZCode/{}", v.version.as_deref().unwrap_or("unknown")),
        ),
    ];
    if let Some(ver) = &v.version {
        h.push(("X-ZCode-App-Version".to_string(), ver.clone()));
    }
    h.push(("X-Title".to_string(), format!("Z Code@{source_title}")));
    h.push(("X-Release-Channel".to_string(), v.release_channel.clone()));
    h.push(("X-Client-Language".to_string(), v.language.clone()));
    h.push(("X-Client-Timezone".to_string(), v.timezone.clone()));
    h.push(("X-ZCode-Agent".to_string(), "glm".to_string()));
    if let (Some(p), Some(a)) = (&v.platform, &v.arch) {
        h.push(("X-Platform".to_string(), format!("{p}-{a}")));
    }
    h.push(("X-Os-Category".to_string(), os_category().to_string()));
    if let Some(r) = &v.release {
        h.push(("X-Os-Version".to_string(), r.clone()));
    }
    h
}

/// Context-shaped identity headers (bundle `TV`) for the control plane:
/// endpoint routing, signing gate probes, billing. Carries `X-Device-Mid`
/// when `device_mid` is provided; no `X-ZCode-Agent`.
pub fn build_control_identity_headers(
    source_title: &str,
    referer_origin: &str,
    device_mid: Option<&str>,
) -> Vec<(String, String)> {
    let v = resolve_values();
    let mut h = vec![
        (
            "User-Agent".to_string(),
            format!("ZCode/{}", v.version.as_deref().unwrap_or("unknown")),
        ),
        ("HTTP-Referer".to_string(), referer_origin.to_string()),
        ("X-Title".to_string(), format!("Z Code@{source_title}")),
    ];
    if let Some(ver) = &v.version {
        h.push(("X-ZCode-App-Version".to_string(), ver.clone()));
    }
    if let (Some(p), Some(a)) = (&v.platform, &v.arch) {
        h.push(("X-Platform".to_string(), format!("{p}-{a}")));
    }
    h.push(("X-Release-Channel".to_string(), v.release_channel.clone()));
    h.push(("X-Client-Language".to_string(), v.language.clone()));
    h.push(("X-Client-Timezone".to_string(), v.timezone.clone()));
    h.push(("X-Os-Category".to_string(), os_category().to_string()));
    if let Some(r) = &v.release {
        h.push(("X-Os-Version".to_string(), r.clone()));
    }
    if let Some(mid) = device_mid.map(str::trim).filter(|m| !m.is_empty()) {
        h.push(("X-Device-Mid".to_string(), mid.to_string()));
    }
    h
}

/// Environment-info values for the start-plan system prompt's Environment
/// section (mirrors `resolveEnvPromptInfo`). Platform/arch/release ride the
/// same source as the identity headers so the prompt can never contradict
/// them. `cwd` is never "unknown" in real traffic.
pub struct EnvPromptInfo {
    pub cwd: String,
    pub platform: String,
    pub shell: String,
    pub os_version: String,
}

pub fn env_prompt_info() -> EnvPromptInfo {
    let platform = node_platform().to_string();
    let release = os_version().unwrap_or_default();
    let arch = node_arch().to_string();
    let os_version = [platform.as_str(), release.as_str(), arch.as_str()]
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let shell_raw = std::env::var("SHELL")
        .or_else(|_| std::env::var("ComSpec"))
        .or_else(|_| std::env::var("COMSPEC"))
        .unwrap_or_default();
    let shell = if shell_raw.is_empty() {
        "unknown".to_string()
    } else {
        std::path::Path::new(&shell_raw)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or(shell_raw)
    };
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| ".".to_string());
    EnvPromptInfo { cwd, platform, shell, os_version }
}
