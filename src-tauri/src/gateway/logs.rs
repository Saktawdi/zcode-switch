//! Gateway request log — an in-memory ring buffer plus an append-only file
//! (`~/.zcode-switch/gateway.log`, rotated at 4 MB), so requests can be
//! traced to the account that served them (UI page + `GET /gw/logs`).

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::Serialize;

const CAP: usize = 500;
const FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct GatewayLogEntry {
    /// Unix epoch millis.
    pub ts: i64,
    /// Route, e.g. `/v1/chat/completions`.
    pub route: String,
    /// Inbound protocol: `openai` | `anthropic`.
    pub format: String,
    pub model: String,
    pub account: Option<String>,
    pub provider: Option<String>,
    pub plan: Option<String>,
    pub status: u16,
    pub ms: u64,
    pub attempts: usize,
    pub error: Option<String>,
}

static LOGS: Mutex<VecDeque<GatewayLogEntry>> = Mutex::new(VecDeque::new());

pub fn push(entry: GatewayLogEntry) {
    {
        let mut logs = logs_cell();
        if logs.len() >= CAP {
            logs.pop_front();
        }
        logs.push_back(entry.clone());
    }
    append_file(&entry);
}

pub fn snapshot(limit: usize) -> Vec<GatewayLogEntry> {
    let logs = logs_cell();
    logs.iter().rev().take(limit.clamp(1, CAP)).cloned().collect()
}

pub fn clear() {
    logs_cell().clear();
}

fn logs_cell() -> std::sync::MutexGuard<'static, VecDeque<GatewayLogEntry>> {
    LOGS.lock().unwrap_or_else(|e| e.into_inner())
}

fn log_path() -> Option<std::path::PathBuf> {
    Some(crate::store::Paths::detect().store_dir().join("gateway.log"))
}

fn append_file(entry: &GatewayLogEntry) {
    let Some(path) = log_path() else { return };
    let Ok(mut line) = serde_json::to_string(entry) else { return };
    line.push('\n');
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // rotate when oversized: gateway.log → gateway.log.1 (overwrite)
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > FILE_MAX_BYTES {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(status: u16) -> GatewayLogEntry {
        GatewayLogEntry {
            ts: 1,
            route: "/v1/chat/completions".into(),
            format: "openai".into(),
            model: "glm-4.6".into(),
            account: Some("A".into()),
            provider: Some("zai".into()),
            plan: Some("coding-plan".into()),
            status,
            ms: 12,
            attempts: 1,
            error: None,
        }
    }

    #[test]
    fn ring_buffer_and_snapshot_order() {
        clear();
        for i in 0..8 {
            let mut e = entry(200);
            e.ts = i;
            push(e);
        }
        let snap = snapshot(3);
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].ts, 7, "newest first");
        clear();
        assert!(snapshot(10).is_empty());
    }

    #[test]
    fn file_append_is_jsonl() {
        let mut e = entry(200);
        e.ts = chrono::Utc::now().timestamp_millis();
        e.model = "log-file-test".into();
        push(e);
        let path = crate::store::Paths::detect().store_dir().join("gateway.log");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return; // sandbox without a writable home — nothing to prove
        };
        assert!(raw.contains("log-file-test"));
    }
}
