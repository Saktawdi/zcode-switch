
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();
static WRITE_LOCK: Mutex<()> = Mutex::new(());

const MAX_BYTES: u64 = 256 * 1024;

pub fn init(base: &Path) {
    let dir = base.join("logs");
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = LOG_PATH.set(dir.join("oauth.log"));
    }
}

pub fn log(flow: &str, event: &str, detail: &str) {
    let Some(path) = LOG_PATH.get() else { return };
    append(path, &format_line(flow, event, detail));
}

fn format_line(flow: &str, event: &str, detail: &str) -> String {
    let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let tag: String = flow.chars().take(8).collect();
    let clean: String = detail.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        format!("{ts} [{tag}] {event}\n")
    } else {
        format!("{ts} [{tag}] {event} {clean}\n")
    }
}

fn append(path: &Path, line: &str) {
    let _guard = match WRITE_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if std::fs::metadata(path).map(|m| m.len() > MAX_BYTES).unwrap_or(false) {
        let old = path.with_extension("log.old");
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(path, &old);
    }
    let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    let _ = f.write_all(line.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zsw-flowlog-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn append_writes_lines_and_creates_file() {
        let dir = tmpdir("write");
        let p = dir.join("oauth.log");
        append(&p, "2026-09-06 12:00:00 [abcd1234] begin provider=zai proxy=on\n");
        append(&p, "2026-09-06 12:00:01 [abcd1234] poll-ready\n");
        let s = std::fs::read_to_string(&p).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.contains("[abcd1234] begin provider=zai proxy=on"));
        assert!(s.contains("[abcd1234] poll-ready"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_over_limit_keeping_one_generation() {
        let dir = tmpdir("rotate");
        let p = dir.join("oauth.log");
        std::fs::write(&p, "x".repeat(MAX_BYTES as usize + 1024)).unwrap();
        append(&p, "2026-09-06 12:00:00 [abcd1234] begin\n");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "2026-09-06 12:00:00 [abcd1234] begin\n");
        let old = p.with_extension("log.old");
        assert!(
            std::fs::metadata(&old).map(|m| m.len() as usize >= MAX_BYTES as usize).unwrap_or(false),
            "旧内容应整体挪入 .old"
        );
        append(&p, "2026-09-06 12:00:01 [abcd1234] init-ok\n");
        assert!(std::fs::read_to_string(&p).unwrap().contains("init-ok"));
        let line = "2026-09-06 12:00:02 [abcd1234] poll-ready\n";
        std::fs::write(&p, "y".repeat(MAX_BYTES as usize + 1024)).unwrap();
        append(&p, line);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), line, "再次超限应重开新文件");
        assert!(
            std::fs::read_to_string(&old).unwrap().starts_with('y'),
            "上一代内容应顶替 .old"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_line_truncates_tag_and_flattens_newlines() {
        let l = format_line("1a2b3c4d-9999-8888-7777-666666666666", "exchange-fail", "token 交换失败（500）：boom\r\n2026-01-01 [evil] persist-ok forged");
        assert_eq!(l.lines().count(), 1, "输出必须是单行");
        assert!(l.contains("[1a2b3c4d] exchange-fail token 交换失败（500）：boom 2026-01-01 [evil] persist-ok forged"), "{l}");
        let l = format_line("1a2b3c4d-9999", "poll-ready", "");
        assert!(l.ends_with("[1a2b3c4d] poll-ready\n"), "{l}");
        let l = format_line("1a2b3c4d-9999", "poll-ready", "\n");
        assert!(l.ends_with("[1a2b3c4d] poll-ready\n"), "纯换行压平后应为空 detail：{l}");
        let l = format_line("ab", "begin", "provider=zai");
        assert!(l.contains("[ab] begin provider=zai"), "{l}");
    }

    #[test]
    fn log_without_init_is_silent_noop() {
        log("ffffffff-1111-2222-3333-444444444444", "begin", "provider=zai");
        log("ffffffff-1111", "poll-ready", "");
    }
}
