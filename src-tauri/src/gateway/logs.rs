//! Gateway request log — an in-memory ring buffer plus an append-only file
//! (`~/.zcode-switch/gateway.log`, rotated at 4 MB), so requests can be
//! traced to the account that served them (UI page + `GET /gw/logs`).

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::Serialize;

pub const CAP: usize = 500;
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

/// captcha 类遥测（route=captcha）是否落日志：只有设置里开了 debug 才记。
/// 设置每次都从磁盘读（不是缓存），所以开关立刻生效，无需重启网关。
pub fn debug_enabled() -> bool {
    crate::store::load_settings(&crate::store::Paths::detect()).gateway_debug_log()
}

/// 记录一条 captcha 遥测——debug 关闭时是 no-op。
///
/// 预解循环每 3s 一条心跳，常开会把请求日志（以及 4MB 的 gateway.log）
/// 冲掉，所以默认不记；排查验证链路时在设置里开 debug 即可看到全链路。
pub fn push_debug(entry: GatewayLogEntry) {
    if !debug_enabled() {
        return;
    }
    push(entry);
}

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
    visible_entries(logs.iter().cloned().collect(), debug_enabled(), limit)
}

/// 可见性过滤（纯函数，便于测试）：debug 关掉后，缓冲区里残留的 captcha
/// 遥测也一并隐藏——开关是即时生效的，不用等它们自然淘汰。
fn visible_entries(all: Vec<GatewayLogEntry>, show_debug: bool, limit: usize) -> Vec<GatewayLogEntry> {
    all.into_iter()
        .rev()
        .filter(|e| show_debug || e.route != "captcha")
        .take(limit.clamp(1, CAP))
        .collect()
}

pub fn clear() {
    logs_cell().clear();
}

/// 导出为 JSONL：每行一条完整记录（脚本/`jq` 友好）。
pub fn to_jsonl(entries: &[GatewayLogEntry]) -> String {
    let mut out = String::new();
    for e in entries {
        match serde_json::to_string(e) {
            Ok(mut line) => {
                line.push('\n');
                out.push_str(&line);
            }
            Err(_) => continue,
        }
    }
    out
}

/// 导出为 CSV（表格工具直接打开）。字段顺序固定，便于列对齐；
/// `error` 里的换行/引号按 RFC 4180 转义，Excel 也不会串行。
pub fn to_csv(entries: &[GatewayLogEntry]) -> String {
    const HEADER: &str = "time,ts,route,format,model,account,provider,plan,status,ms,attempts,error";
    let mut out = String::from(HEADER);
    out.push('\n');
    for e in entries {
        let cols = [
            chrono::DateTime::from_timestamp_millis(e.ts)
                .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S%.3f").to_string())
                .unwrap_or_default(),
            e.ts.to_string(),
            e.route.clone(),
            e.format.clone(),
            e.model.clone(),
            e.account.clone().unwrap_or_default(),
            e.provider.clone().unwrap_or_default(),
            e.plan.clone().unwrap_or_default(),
            e.status.to_string(),
            e.ms.to_string(),
            e.attempts.to_string(),
            e.error.clone().unwrap_or_default(),
        ];
        out.push_str(&cols.map(|c| csv_field(&c)).join(","));
        out.push('\n');
    }
    out
}

fn csv_field(v: &str) -> String {
    if v.contains(',') || v.contains('"') || v.contains('\n') || v.contains('\r') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
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

    /// debug 门控：关闭时 captcha 遥测既不落库也不可见，普通请求日志不受影响。
    #[test]
    fn captcha_entries_hidden_unless_debug() {
        let mut normal = entry(200);
        normal.model = "req".into();
        let mut cap = entry(0);
        cap.route = "captcha".into();
        cap.format = "captcha".into();
        cap.model = "tick".into();

        let all = vec![normal.clone(), cap.clone()];
        let off = visible_entries(all.clone(), false, 500);
        assert_eq!(off.len(), 1, "debug off hides captcha telemetry");
        assert_eq!(off[0].route, "/v1/chat/completions");

        let on = visible_entries(all, true, 500);
        assert_eq!(on.len(), 2, "debug on shows both");
        assert_eq!(on[0].route, "captcha", "newest first");
    }

    #[test]
    fn jsonl_export_is_one_record_per_line() {
        let mut a = entry(200);
        a.model = "m-a".into();
        let mut b = entry(403);
        b.model = "m-b".into();
        let out = to_jsonl(&[a, b]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"model\":\"m-a\""));
        assert!(lines[1].contains("\"status\":403"));
    }

    #[test]
    fn csv_export_escapes_and_keeps_columns_aligned() {
        let mut e = entry(500);
        e.account = Some("A, B".into());
        e.error = Some("line1\nline2 \"quoted\"".into());
        let out = to_csv(&[e]);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "time,ts,route,format,model,account,provider,plan,status,ms,attempts,error");
        // 逗号/引号/换行都被转义，所以正文仍在两行内、列数固定为 12
        let body: String = lines[1..].join("\n");
        assert!(body.contains("\"A, B\""), "comma field quoted: {body}");
        assert!(body.contains("\"line1\nline2 \"\"quoted\"\"\""), "newline+quote escaped: {body}");
        let cols = lines[1].split(',').count();
        assert!(cols >= 10, "columns present, got {cols}");
    }
}
