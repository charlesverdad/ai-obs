//! Transcript tailer: the durable source of tokens, branches, and PR links.
//!
//! Polls ~/.claude/projects for grown .jsonl files every few seconds, resumes
//! from byte-offset checkpoints, and tolerates unknown record types and parse
//! failures — the format is Claude Code's private business and may change.

use crate::store::{LlmUsageRecord, Store};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const POLL_SECS: u64 = 3;

pub fn projects_dir() -> PathBuf {
    if let Ok(p) = std::env::var("AI_OBS_PROJECTS_DIR") {
        return PathBuf::from(p);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude/projects")
}

pub async fn run(store: Arc<Store>) {
    let root = projects_dir();
    loop {
        let store2 = store.clone();
        let root2 = root.clone();
        let res = tokio::task::spawn_blocking(move || scan_once(&store2, &root2)).await;
        if let Err(e) = res {
            tracing::error!("tailer panic: {e}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

/// One pass: find candidate files, tail each from its checkpoint.
/// Returns number of new usage rows.
pub fn scan_once(store: &Store, root: &Path) -> usize {
    let mut new_rows = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|x| x.to_str()) != Some("jsonl") {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            let key = path.to_string_lossy().into_owned();
            let offset = store.checkpoint(&key).unwrap_or(0);
            if meta.len() <= offset {
                continue; // nothing new (or truncated — leave alone)
            }
            new_rows += tail_file(store, &path, offset).unwrap_or(0);
        }
    }
    new_rows
}

fn tail_file(store: &Store, path: &Path, offset: u64) -> anyhow::Result<usize> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    let f = std::fs::File::open(path)?;
    let mut r = BufReader::new(f);
    r.seek(SeekFrom::Start(offset))?;
    let mut pos = offset;
    let mut count = 0;
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        // Only advance the checkpoint past complete lines; a partially
        // written line is retried next poll.
        if !line.ends_with('\n') {
            break;
        }
        pos += n as u64;
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if ingest_record(store, &v).unwrap_or(false) {
                count += 1;
            }
        }
    }
    store.set_checkpoint(&path.to_string_lossy(), pos)?;
    Ok(count)
}

fn get_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn parse_ts_ms(v: &Value) -> i64 {
    // Timestamps are RFC3339 like 2026-06-13T01:40:57.084Z. A full parser is
    // overkill: unix ms ordering only needs to be roughly right, and SQLite
    // rows carry the original string anyway via message ordering. Parse
    // manually; fall back to 0.
    let Some(s) = v.get("timestamp").and_then(|x| x.as_str()) else {
        return 0;
    };
    rfc3339_to_ms(s).unwrap_or(0)
}

/// Minimal RFC3339 (UTC 'Z' only) → unix ms. Days-from-civil algorithm.
pub fn rfc3339_to_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s.get(from..to)?.parse().ok() };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let ms = if b.get(19) == Some(&b'.') {
        num(20, 23).unwrap_or(0)
    } else {
        0
    };
    // days from civil (Howard Hinnant's algorithm)
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(((days * 24 + h) * 3600 + mi * 60 + sec) * 1000 + ms)
}

/// Returns Ok(true) when a new llm_usage row was written.
fn ingest_record(store: &Store, v: &Value) -> anyhow::Result<bool> {
    let rtype = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    let sid = get_str(v, "sessionId").unwrap_or_default();
    match rtype {
        "assistant" => {
            if sid.is_empty() {
                return Ok(false);
            }
            let Some(msg) = v.get("message") else { return Ok(false) };
            let Some(usage) = msg.get("usage") else { return Ok(false) };
            let Some(uuid) = get_str(v, "uuid") else { return Ok(false) };
            let model = msg
                .get("model")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown")
                .to_string();
            let tok = |k: &str| usage.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
            let (inp, out) = (tok("input_tokens"), tok("output_tokens"));
            let (cr, cc) = (
                tok("cache_read_input_tokens"),
                tok("cache_creation_input_tokens"),
            );
            // Make sure the session row exists (transcript-only sessions).
            ensure_session(store, v, &sid);
            let cost = crate::pricing::cost_usd(&model, inp, out, cr, cc);
            let rec = LlmUsageRecord {
                session_id: sid,
                message_uuid: uuid,
                request_id: get_str(v, "requestId"),
                ts: parse_ts_ms(v),
                model,
                is_sidechain: v
                    .get("isSidechain")
                    .and_then(|x| x.as_bool())
                    .unwrap_or(false),
                input_tokens: inp,
                output_tokens: out,
                cache_read: cr,
                cache_creation: cc,
                cost_usd: cost,
                cost_source: if cost.is_some() { "computed" } else { "unknown" },
            };
            Ok(store.insert_llm_usage(&rec)?)
        }
        "pr-link" => {
            if sid.is_empty() {
                return Ok(false);
            }
            let n = v.get("prNumber").and_then(|x| x.as_i64());
            let url = get_str(v, "prUrl");
            if let (Some(n), Some(url)) = (n, url) {
                let _ = store.set_session_pr(&sid, n, &url);
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn ensure_session(store: &Store, v: &Value, sid: &str) {
    let cwd = get_str(v, "cwd");
    let branch = get_str(v, "gitBranch");
    let version = get_str(v, "version");
    let project_id = cwd.as_deref().and_then(|c| {
        let root = crate::correlator::project_root_of(c);
        store.upsert_project(&root).ok()
    });
    let _ = store.upsert_session(
        sid,
        project_id,
        None,
        branch.as_deref(),
        version.as_deref(),
        parse_ts_ms(v),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;

    #[test]
    fn ts_parse() {
        // cross-checked with `date -u -j -f ...` / python datetime
        assert_eq!(rfc3339_to_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_to_ms("2026-06-13T01:40:57.084Z"), Some(1781401257084));
        assert_eq!(rfc3339_to_ms("garbage"), None);
    }

    #[test]
    fn tails_assistant_and_prlink_records() {
        let dir = std::env::temp_dir().join(format!("ai-obs-tail-{}", std::process::id()));
        let proj = dir.join("projects/-Users-x-work-demo");
        std::fs::create_dir_all(&proj).unwrap();
        let db = dir.join("t.db");
        let store = Store::open(&db).unwrap();

        let jsonl = proj.join("abc.jsonl");
        let rec = serde_json::json!({
            "type": "assistant", "sessionId": "s1", "uuid": "u1",
            "timestamp": "2026-08-13T01:00:00.000Z",
            "cwd": "/tmp", "gitBranch": "main", "version": "2.1.177",
            "isSidechain": false,
            "message": {"model": "claude-sonnet-5",
                "usage": {"input_tokens": 100, "output_tokens": 50,
                          "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 10}}
        });
        let pr = serde_json::json!({
            "type": "pr-link", "sessionId": "s1", "prNumber": 42,
            "prUrl": "https://github.com/x/demo/pull/42", "prRepository": "x/demo",
            "timestamp": "2026-08-13T01:01:00.000Z"
        });
        std::fs::write(&jsonl, format!("{rec}\n{pr}\n")).unwrap();

        let n = scan_once(&store, &dir.join("projects"));
        assert_eq!(n, 1);
        // Idempotent: second scan reads nothing new.
        let n = scan_once(&store, &dir.join("projects"));
        assert_eq!(n, 0);

        // Appending a line picks up from the checkpoint.
        let rec2 = serde_json::json!({
            "type": "assistant", "sessionId": "s1", "uuid": "u2",
            "timestamp": "2026-08-13T01:02:00.000Z",
            "message": {"model": "claude-fable-5", "usage": {"input_tokens": 5, "output_tokens": 5}}
        });
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&jsonl).unwrap();
        writeln!(f, "{rec2}").unwrap();
        let n = scan_once(&store, &dir.join("projects"));
        assert_eq!(n, 1);

        let rows = store
            .query_json(
                "SELECT model, cost_usd, cost_source, (SELECT pr_number FROM session WHERE id='s1') pr
                 FROM llm_usage ORDER BY ts",
                &[],
            )
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["cost_source"], "computed");
        assert!(rows[0]["cost_usd"].as_f64().unwrap() > 0.0);
        // fable is unknown: cost stays NULL, honestly.
        assert_eq!(rows[1]["cost_source"], "unknown");
        assert!(rows[1]["cost_usd"].is_null());
        assert_eq!(rows[0]["pr"], 42);
        std::fs::remove_dir_all(&dir).ok();
    }
}
