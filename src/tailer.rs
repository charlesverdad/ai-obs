//! Transcript tailer: the durable source of tokens, branches, and PR links.
//!
//! Polls ~/.claude/projects for grown .jsonl files every few seconds, resumes
//! from byte-offset checkpoints, and tolerates unknown record types and parse
//! failures — the format is Claude Code's private business and may change.

use crate::store::{LlmUsageRecord, Store};
use serde_json::Value;
use std::collections::HashMap;
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

/// Cross-record state the tailer needs to remember between poll cycles (but
/// never persists to disk): a `tool_use_id -> description` map bridging a
/// Task/Agent tool_use block (assistant message) to its tool_result
/// (subsequent user message), possibly several lines — or, since the tailer
/// resumes per-file from a byte offset, even several *poll cycles* — later.
/// See `remember_tool_use`/`resolve_agent_title` and the module-level design
/// note above `extract_agent_id`.
#[derive(Default)]
pub struct TailerState {
    pending_task_titles: HashMap<String, String>,
}

/// Cap on `TailerState::pending_task_titles` — tool_use blocks whose result
/// never matched an `agentId:` (ordinary non-agent tool calls vastly
/// outnumber Task/Agent calls, but every tool_use passes through here, so
/// this must not grow unboundedly over a long-running daemon). Dropping the
/// whole map past this size is harmless: at worst a handful of in-flight
/// agent titles are missed, and the UI's fallback (agent_type / short id)
/// covers it.
const PENDING_TASK_TITLES_CAP: usize = 500;

pub async fn run(store: Arc<Store>) {
    let root = projects_dir();
    let state = Arc::new(std::sync::Mutex::new(TailerState::default()));
    loop {
        let store2 = store.clone();
        let root2 = root.clone();
        let state2 = state.clone();
        let res = tokio::task::spawn_blocking(move || {
            let mut state = state2.lock().unwrap();
            scan_once_stateful(&store2, &root2, &mut state)
        })
        .await;
        if let Err(e) = res {
            tracing::error!("tailer panic: {e}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

/// One pass: find candidate files, tail each from its checkpoint.
/// Returns number of new usage rows. Convenience wrapper over
/// [`scan_once_stateful`] for tests that don't care about agent-title
/// correlation surviving across calls (the real daemon loop in `run` keeps
/// its own long-lived `TailerState` and calls `scan_once_stateful`
/// directly).
#[cfg(test)]
pub fn scan_once(store: &Store, root: &Path) -> usize {
    let mut state = TailerState::default();
    scan_once_stateful(store, root, &mut state)
}

pub fn scan_once_stateful(store: &Store, root: &Path, state: &mut TailerState) -> usize {
    let mut new_rows = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
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
            let agent_id = agent_id_from_path(&path);
            new_rows += tail_file(store, &path, offset, agent_id.as_deref(), state).unwrap_or(0);
        }
    }
    new_rows
}

/// Subagent transcripts live at `.../subagents/agent-<id>.jsonl` (observed
/// both directly under a session dir and nested one level deeper under a
/// session-named dir). Extract `<id>` from the filename; `None` means this
/// is a main-transcript file.
fn agent_id_from_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".jsonl")?;
    stem.strip_prefix("agent-").map(|s| s.to_string())
}

fn tail_file(
    store: &Store,
    path: &Path,
    offset: u64,
    agent_id: Option<&str>,
    state: &mut TailerState,
) -> anyhow::Result<usize> {
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
            if ingest_record(store, &v, agent_id).unwrap_or(false) {
                count += 1;
            }
            ingest_agent_title(store, &v, state);
        }
    }
    store.set_checkpoint(&path.to_string_lossy(), pos)?;
    Ok(count)
}

/// Extract the id following an `agentId:` marker in free text — e.g.
/// `"agentId: a89cd9688c7487959 (internal ID - do not mention...)"` from a
/// real transcript's Task/Agent tool_result. Takes the run of alphanumeric
/// characters immediately after `agentId:` (optional whitespace), stopping
/// at the first non-alphanumeric byte (space, paren, punctuation, newline).
fn extract_agent_id(text: &str) -> Option<String> {
    let idx = text.find("agentId:")?;
    let rest = text[idx + "agentId:".len()..].trim_start();
    let id: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect();
    if id.is_empty() {
        None
    } else {
        Some(id)
    }
}

/// Correlate a subagent's task title into `agent_span.title`, from the
/// PARENT transcript's own Task/Agent tool_use + tool_result pair (a
/// subagent's own transcript never contains the tool_use that spawned it).
/// Two record shapes matter, verified against real transcripts in
/// `~/.claude/projects/-Users-charles-work-ai-obs/*.jsonl`
/// (2026-08-14, this account's harness — see the module-level design note):
///
/// - `{"type":"assistant","message":{"content":[{"type":"tool_use",
///   "id":"toolu_...","name":"Task","input":{"description":"Fix build",...}}
///   ]}}` — remember `id -> description` in `state.pending_task_titles`.
/// - `{"type":"user","message":{"content":[{"type":"tool_result",
///   "tool_use_id":"toolu_...","content":[{"type":"text",
///   "text":"...agentId: a89cd9688c7487959 (internal ID...)..."}]}]},
///   "toolUseResult":{"agentId":"a89cd9688c7487959",...}}` — resolve via
///   `tool_use_id` into the pending map, preferring the structured
///   `toolUseResult.agentId` field (present in this account's transcripts)
///   and falling back to `extract_agent_id` over the result's text content
///   (the shape named in this task's spec, for harnesses/versions that only
///   put it in prose).
///
/// This account's harness names the tool `"Agent"`, not `"Task"` — both are
/// accepted since the concept (task title + async agent id) is identical
/// and a stock Claude Code CLI transcript is documented to use `"Task"`.
fn ingest_agent_title(store: &Store, v: &Value, state: &mut TailerState) {
    let rtype = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    match rtype {
        "assistant" => {
            let Some(content) = v
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_array())
            else {
                return;
            };
            for item in content {
                if item.get("type").and_then(|x| x.as_str()) != Some("tool_use") {
                    continue;
                }
                let name = item.get("name").and_then(|x| x.as_str()).unwrap_or("");
                if name != "Task" && name != "Agent" {
                    continue;
                }
                let Some(id) = item.get("id").and_then(|x| x.as_str()) else {
                    continue;
                };
                let Some(desc) = item
                    .get("input")
                    .and_then(|i| i.get("description"))
                    .and_then(|d| d.as_str())
                else {
                    continue;
                };
                if state.pending_task_titles.len() >= PENDING_TASK_TITLES_CAP {
                    state.pending_task_titles.clear();
                }
                state
                    .pending_task_titles
                    .insert(id.to_string(), desc.to_string());
            }
        }
        "user" => {
            let sid = get_str(v, "sessionId").unwrap_or_default();
            if sid.is_empty() {
                return;
            }
            // Prefer the structured field when present; it's a cleaner
            // source than scraping prose and doesn't depend on exact
            // wording.
            let structured_agent_id = v
                .get("toolUseResult")
                .and_then(|r| r.get("agentId"))
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let Some(content) = v
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_array())
            else {
                return;
            };
            for item in content {
                if item.get("type").and_then(|x| x.as_str()) != Some("tool_result") {
                    continue;
                }
                let Some(tool_use_id) = item.get("tool_use_id").and_then(|x| x.as_str()) else {
                    continue;
                };
                let agent_id = structured_agent_id.clone().or_else(|| {
                    // Fall back to scanning the result's text content for
                    // `agentId: <hex-id>` — the shape used when a harness
                    // only exposes it in prose, not as structured JSON.
                    let texts = item.get("content").and_then(|c| c.as_array())?;
                    texts.iter().find_map(|t| {
                        t.get("text")
                            .and_then(|x| x.as_str())
                            .and_then(extract_agent_id)
                    })
                });
                let Some(agent_id) = agent_id else { continue };
                let Some(title) = state.pending_task_titles.remove(tool_use_id) else {
                    continue;
                };
                if let Err(e) = store.set_agent_title(&sid, &agent_id, &title) {
                    tracing::debug!("set_agent_title failed: {e:#}");
                }
            }
        }
        _ => {}
    }
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
fn ingest_record(store: &Store, v: &Value, agent_id: Option<&str>) -> anyhow::Result<bool> {
    let rtype = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    let sid = get_str(v, "sessionId").unwrap_or_default();
    match rtype {
        "assistant" => {
            if sid.is_empty() {
                return Ok(false);
            }
            let Some(msg) = v.get("message") else {
                return Ok(false);
            };
            let Some(usage) = msg.get("usage") else {
                return Ok(false);
            };
            let Some(uuid) = get_str(v, "uuid") else {
                return Ok(false);
            };
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
                cost_source: if cost.is_some() {
                    "computed"
                } else {
                    "unknown"
                },
                agent_id: agent_id.map(|s| s.to_string()),
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
        assert_eq!(
            rfc3339_to_ms("2026-06-13T01:40:57.084Z"),
            Some(1781314857084)
        );
        assert_eq!(rfc3339_to_ms("garbage"), None);
    }

    #[test]
    fn agent_id_extraction() {
        assert_eq!(
            agent_id_from_path(Path::new(
                "/x/projects/proj/sess1/subagents/agent-abc123.jsonl"
            )),
            Some("abc123".to_string())
        );
        assert_eq!(
            agent_id_from_path(Path::new(
                "/x/projects/proj/sess1/subagents/sess1/agent-abc123.jsonl"
            )),
            Some("abc123".to_string())
        );
        assert_eq!(
            agent_id_from_path(Path::new("/x/projects/proj/sess1.jsonl")),
            None
        );
        assert_eq!(
            agent_id_from_path(Path::new("/x/agent-.jsonl")),
            Some("".to_string())
        );
    }

    #[test]
    fn subagent_transcript_sets_agent_id() {
        let dir = std::env::temp_dir().join(format!("ai-obs-tail-sub-{}", std::process::id()));
        let sub = dir.join("projects/-Users-x-work-demo/sess1/subagents");
        std::fs::create_dir_all(&sub).unwrap();
        let db = dir.join("t.db");
        let store = Store::open(&db).unwrap();

        let jsonl = sub.join("agent-testagent1.jsonl");
        let rec = serde_json::json!({
            "type": "assistant", "sessionId": "s1", "uuid": "u1",
            "timestamp": "2026-08-13T01:00:00.000Z",
            "isSidechain": true,
            "message": {"model": "claude-sonnet-5",
                "usage": {"input_tokens": 10, "output_tokens": 20}}
        });
        std::fs::write(&jsonl, format!("{rec}\n")).unwrap();

        let n = scan_once(&store, &dir.join("projects"));
        assert_eq!(n, 1);
        let rows = store
            .query_json(
                "SELECT agent_id FROM llm_usage WHERE message_uuid='u1'",
                &[],
            )
            .unwrap();
        assert_eq!(rows[0]["agent_id"], "testagent1");
        std::fs::remove_dir_all(&dir).ok();
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
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&jsonl)
            .unwrap();
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

    #[test]
    fn extract_agent_id_from_prose() {
        assert_eq!(
            extract_agent_id(
                "Async agent launched successfully.\nagentId: a89cd9688c7487959 (internal ID - do not mention)"
            ),
            Some("a89cd9688c7487959".to_string())
        );
        assert_eq!(extract_agent_id("no marker here"), None);
        assert_eq!(extract_agent_id("agentId: "), None);
    }

    fn task_use_line(id: &str, description: &str) -> String {
        serde_json::json!({
            "type": "assistant", "sessionId": "s1", "uuid": format!("u-{id}"),
            "timestamp": "2026-08-14T01:00:00.000Z",
            "message": {"model": "claude-sonnet-5", "content": [
                {"type": "tool_use", "id": id, "name": "Task",
                 "input": {"description": description}}
            ], "usage": {"input_tokens": 1, "output_tokens": 1}}
        })
        .to_string()
    }

    fn task_result_line_structured(id: &str, agent_id: &str) -> String {
        serde_json::json!({
            "type": "user", "sessionId": "s1", "uuid": format!("r-{id}"),
            "timestamp": "2026-08-14T01:00:01.000Z",
            "message": {"content": [
                {"type": "tool_result", "tool_use_id": id, "content": [
                    {"type": "text", "text": "Async agent launched successfully."}
                ]}
            ]},
            "toolUseResult": {"agentId": agent_id}
        })
        .to_string()
    }

    fn task_result_line_prose(id: &str, agent_id: &str) -> String {
        serde_json::json!({
            "type": "user", "sessionId": "s1", "uuid": format!("r-{id}"),
            "timestamp": "2026-08-14T01:00:01.000Z",
            "message": {"content": [
                {"type": "tool_result", "tool_use_id": id, "content": [
                    {"type": "text", "text": format!(
                        "Async agent launched successfully.\nagentId: {agent_id} (internal ID - do not mention)")}
                ]}
            ]}
        })
        .to_string()
    }

    /// Order 1: the title (tool_use + tool_result) is tailed BEFORE the
    /// agent_span row exists (SubagentStart hasn't landed yet, or the
    /// tailer's ~3s poll just happens to run first). The title must land in
    /// Store's pending map and get applied the moment open_agent_span runs.
    #[test]
    fn agent_title_applied_when_span_opens_after_title_seen() {
        let dir = std::env::temp_dir().join(format!("ai-obs-tail-title-a-{}", std::process::id()));
        let proj = dir.join("projects/-Users-x-work-demo");
        std::fs::create_dir_all(&proj).unwrap();
        let store = Store::open(&dir.join("t.db")).unwrap();
        std::fs::write(
            proj.join("main.jsonl"),
            format!(
                "{}\n{}\n",
                task_use_line("toolu_1", "Fix build until verify green"),
                task_result_line_structured("toolu_1", "agent123")
            ),
        )
        .unwrap();

        let mut state = TailerState::default();
        scan_once_stateful(&store, &dir.join("projects"), &mut state);
        // Title seen, but no agent_span row yet -> stashed pending, not lost.
        let rows = store
            .query_json(
                "SELECT title FROM agent_span WHERE agent_id='agent123'",
                &[],
            )
            .unwrap();
        assert!(rows.is_empty());

        store
            .open_agent_span("s1", "agent123", Some("general-purpose"), 2000)
            .unwrap();
        let rows = store
            .query_json(
                "SELECT title FROM agent_span WHERE agent_id='agent123'",
                &[],
            )
            .unwrap();
        assert_eq!(rows[0]["title"], "Fix build until verify green");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Order 2: the agent_span row already exists (SubagentStart's HTTP
    /// push beat the transcript tailer) — the title must UPDATE it directly.
    /// Also exercises the prose-fallback (`agentId:` in tool_result text,
    /// no structured `toolUseResult.agentId`) instead of order 1's
    /// structured-field path.
    #[test]
    fn agent_title_updates_existing_span_via_prose_fallback() {
        let dir = std::env::temp_dir().join(format!("ai-obs-tail-title-b-{}", std::process::id()));
        let proj = dir.join("projects/-Users-x-work-demo");
        std::fs::create_dir_all(&proj).unwrap();
        let store = Store::open(&dir.join("t.db")).unwrap();
        store
            .upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        store
            .open_agent_span("s1", "agentXYZ", Some("code-reviewer"), 2000)
            .unwrap();

        std::fs::write(
            proj.join("main.jsonl"),
            format!(
                "{}\n{}\n",
                task_use_line("toolu_2", "Review dashboard PR"),
                task_result_line_prose("toolu_2", "agentXYZ")
            ),
        )
        .unwrap();
        let mut state = TailerState::default();
        scan_once_stateful(&store, &dir.join("projects"), &mut state);

        let rows = store
            .query_json(
                "SELECT title FROM agent_span WHERE agent_id='agentXYZ'",
                &[],
            )
            .unwrap();
        assert_eq!(rows[0]["title"], "Review dashboard PR");
        std::fs::remove_dir_all(&dir).ok();
    }
}
