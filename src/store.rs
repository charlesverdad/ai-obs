//! SQLite persistence. One writer (the daemon) plus read-only consumers
//! (report, top fallback) — WAL mode makes that safe.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub fn default_db_path() -> PathBuf {
    if let Ok(p) = std::env::var("AI_OBS_DB") {
        return PathBuf::from(p);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".local/share/ai-obs/ai-obs.db")
}

pub struct Store {
    conn: Mutex<Connection>,
}

/// A closed tool span plus its per-process rows, written in one transaction.
pub struct SpanRecord {
    pub session_id: String,
    pub tool_use_id: Option<String>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub tool_name: String,
    pub cmd_digest: Option<String>,
    pub started_at: i64,
    pub ended_at: i64,
    pub ok: Option<bool>,
    pub cpu_ns: Option<u64>,
    pub cpu_ns_sampled: u64,
    pub peak_footprint: u64,
    pub disk_read: u64,
    pub disk_write: u64,
    pub proc_count: u32,
    pub leaked_count: u32,
}

pub struct ProcRecord {
    pub pid: i32,
    pub ppid: i32,
    pub depth: i32,
    pub comm: String,
    pub name: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub exited: bool,
    pub cpu_user_ns: u64,
    pub cpu_sys_ns: u64,
    pub peak_footprint: u64,
    pub disk_read: u64,
    pub disk_write: u64,
    pub attribution: &'static str,
    pub orphaned: bool,
}

/// Per-session token/cost rollup from `llm_usage`.
#[derive(Debug, Clone, Default)]
pub struct TokenTotals {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read: i64,
    #[allow(dead_code)] // queried for completeness; not yet surfaced by any consumer
    pub cache_creation: i64,
    pub cost_usd: f64,
    /// Count of rows with a NULL cost_usd (i.e. cost unknown/unpriced).
    pub unpriced: i64,
}

pub struct LlmUsageRecord {
    pub session_id: String,
    pub message_uuid: String,
    pub request_id: Option<String>,
    pub ts: i64,
    pub model: String,
    pub is_sidechain: bool,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_read: i64,
    pub cache_creation: i64,
    pub cost_usd: Option<f64>,
    pub cost_source: &'static str,
    /// Subagent id (from `.../subagents/agent-<id>.jsonl`); NULL for the
    /// main transcript.
    pub agent_id: Option<String>,
}

/// One closed span, as returned by [`Store::recent_spans_all_sessions`].
pub struct RecentSpanRow {
    pub span_id: i64,
    pub tool_name: String,
    pub cmd_digest: Option<String>,
    pub duration_ms: i64,
    pub cpu_ns: u64,
    pub peak_footprint: u64,
    pub ok: Option<bool>,
    pub leaked_count: i32,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS project (
  id INTEGER PRIMARY KEY,
  root TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS session (
  id TEXT PRIMARY KEY,
  project_id INTEGER REFERENCES project(id),
  claude_pid INTEGER,
  git_branch TEXT,
  pr_number INTEGER,
  pr_url TEXT,
  cc_version TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  end_reason TEXT
);
CREATE TABLE IF NOT EXISTS tool_span (
  id INTEGER PRIMARY KEY,
  session_id TEXT REFERENCES session(id),
  tool_use_id TEXT,
  agent_id TEXT,
  agent_type TEXT,
  tool_name TEXT NOT NULL,
  cmd_digest TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  ok INTEGER,
  cpu_ns INTEGER,
  cpu_ns_sampled INTEGER,
  peak_footprint INTEGER,
  disk_read INTEGER,
  disk_write INTEGER,
  proc_count INTEGER,
  leaked_count INTEGER
);
CREATE INDEX IF NOT EXISTS idx_span_session ON tool_span(session_id, started_at);
CREATE TABLE IF NOT EXISTS proc_stat (
  id INTEGER PRIMARY KEY,
  span_id INTEGER REFERENCES tool_span(id),
  session_id TEXT REFERENCES session(id),
  pid INTEGER, ppid INTEGER, depth INTEGER,
  comm TEXT, name TEXT,
  first_seen INTEGER, last_seen INTEGER, exited INTEGER,
  cpu_user_ns INTEGER, cpu_sys_ns INTEGER,
  peak_footprint INTEGER,
  disk_read INTEGER, disk_write INTEGER,
  attribution TEXT NOT NULL,
  orphaned INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_proc_span ON proc_stat(span_id);
CREATE TABLE IF NOT EXISTS session_sample (
  session_id TEXT, t INTEGER,
  cpu_pct REAL, footprint INTEGER, proc_count INTEGER,
  PRIMARY KEY (session_id, t)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS llm_usage (
  session_id TEXT,
  message_uuid TEXT PRIMARY KEY,
  request_id TEXT, ts INTEGER,
  model TEXT, is_sidechain INTEGER,
  input_tokens INTEGER, output_tokens INTEGER,
  cache_read INTEGER, cache_creation INTEGER,
  cost_usd REAL, cost_source TEXT,
  agent_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_session ON llm_usage(session_id, ts);
CREATE TABLE IF NOT EXISTS tailer_checkpoint (
  path TEXT PRIMARY KEY,
  offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL,
  session_id TEXT,
  span_id INTEGER,
  pid INTEGER,
  message TEXT NOT NULL,
  resolved_at INTEGER
);
"#;

/// Schema migrations that ALTER an existing table rather than CREATE it —
/// needed because `CREATE TABLE IF NOT EXISTS` in [`SCHEMA`] is a no-op
/// against a database the daemon already created before a column existed.
/// Guarded by `pragma table_info` so re-running against an already-migrated
/// (or brand-new, already-correct) db is a harmless no-op: never drops data.
fn migrate(conn: &Connection) -> Result<()> {
    let has_agent_id = {
        let mut stmt = conn.prepare("PRAGMA table_info(llm_usage)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut found = false;
        for n in names {
            if n? == "agent_id" {
                found = true;
                break;
            }
        }
        found
    };
    if !has_agent_id {
        conn.execute("ALTER TABLE llm_usage ADD COLUMN agent_id TEXT", [])?;
    }
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("creating data dir")?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_readonly(path: &Path) -> Result<Store> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    pub fn upsert_project(&self, root: &str) -> Result<i64> {
        let name = Path::new(root)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| root.to_string());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO project(root, name) VALUES (?1, ?2)
             ON CONFLICT(root) DO UPDATE SET name = excluded.name",
            params![root, name],
        )?;
        let id = conn.query_row("SELECT id FROM project WHERE root = ?1", [root], |r| {
            r.get(0)
        })?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_session(
        &self,
        id: &str,
        project_id: Option<i64>,
        claude_pid: Option<i32>,
        git_branch: Option<&str>,
        cc_version: Option<&str>,
        started_at: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO session(id, project_id, claude_pid, git_branch, cc_version, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
               project_id = COALESCE(excluded.project_id, session.project_id),
               claude_pid = COALESCE(excluded.claude_pid, session.claude_pid),
               git_branch = COALESCE(excluded.git_branch, session.git_branch),
               cc_version = COALESCE(excluded.cc_version, session.cc_version)",
            params![id, project_id, claude_pid, git_branch, cc_version, started_at],
        )?;
        Ok(())
    }

    pub fn set_session_pr(&self, id: &str, pr_number: i64, pr_url: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE session SET pr_number = ?2, pr_url = ?3 WHERE id = ?1",
            params![id, pr_number, pr_url],
        )?;
        Ok(())
    }

    pub fn end_session(&self, id: &str, ended_at: i64, reason: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE session SET ended_at = ?2, end_reason = ?3 WHERE id = ?1",
            params![id, ended_at, reason],
        )?;
        Ok(())
    }

    pub fn write_span(&self, span: &SpanRecord, procs: &[ProcRecord]) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO tool_span(session_id, tool_use_id, agent_id, agent_type, tool_name,
               cmd_digest, started_at, ended_at, ok, cpu_ns, cpu_ns_sampled, peak_footprint,
               disk_read, disk_write, proc_count, leaked_count)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                span.session_id,
                span.tool_use_id,
                span.agent_id,
                span.agent_type,
                span.tool_name,
                span.cmd_digest,
                span.started_at,
                span.ended_at,
                span.ok,
                span.cpu_ns.map(|v| v as i64),
                span.cpu_ns_sampled as i64,
                span.peak_footprint as i64,
                span.disk_read as i64,
                span.disk_write as i64,
                span.proc_count,
                span.leaked_count,
            ],
        )?;
        let span_id = tx.last_insert_rowid();
        for p in procs {
            tx.execute(
                "INSERT INTO proc_stat(span_id, session_id, pid, ppid, depth, comm, name,
                   first_seen, last_seen, exited, cpu_user_ns, cpu_sys_ns, peak_footprint,
                   disk_read, disk_write, attribution, orphaned)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    span_id,
                    span.session_id,
                    p.pid,
                    p.ppid,
                    p.depth,
                    p.comm,
                    p.name,
                    p.first_seen,
                    p.last_seen,
                    p.exited,
                    p.cpu_user_ns as i64,
                    p.cpu_sys_ns as i64,
                    p.peak_footprint as i64,
                    p.disk_read as i64,
                    p.disk_write as i64,
                    p.attribution,
                    p.orphaned,
                ],
            )?;
        }
        tx.commit()?;
        Ok(span_id)
    }

    pub fn insert_session_sample(
        &self,
        session_id: &str,
        t: i64,
        cpu_pct: f64,
        footprint: u64,
        proc_count: u32,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO session_sample(session_id, t, cpu_pct, footprint, proc_count)
             VALUES (?1,?2,?3,?4,?5)",
            params![session_id, t, cpu_pct, footprint as i64, proc_count],
        )?;
        Ok(())
    }

    pub fn insert_llm_usage(&self, r: &LlmUsageRecord) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "INSERT OR IGNORE INTO llm_usage(session_id, message_uuid, request_id, ts, model,
               is_sidechain, input_tokens, output_tokens, cache_read, cache_creation,
               cost_usd, cost_source, agent_id)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                r.session_id,
                r.message_uuid,
                r.request_id,
                r.ts,
                r.model,
                r.is_sidechain,
                r.input_tokens,
                r.output_tokens,
                r.cache_read,
                r.cache_creation,
                r.cost_usd,
                r.cost_source,
                r.agent_id,
            ],
        )?;
        Ok(n > 0)
    }

    /// Per-session token/cost totals from `llm_usage`, grouped by session_id.
    /// Sessions with no llm_usage rows simply won't appear in the result map.
    pub fn session_token_totals(&self) -> Result<HashMap<String, TokenTotals>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id,
                COALESCE(SUM(input_tokens),0),
                COALESCE(SUM(output_tokens),0),
                COALESCE(SUM(cache_read),0),
                COALESCE(SUM(cache_creation),0),
                COALESCE(SUM(COALESCE(cost_usd,0)),0),
                SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END)
             FROM llm_usage
             GROUP BY session_id",
        )?;
        let mut out = HashMap::new();
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                TokenTotals {
                    input_tokens: r.get(1)?,
                    output_tokens: r.get(2)?,
                    cache_read: r.get(3)?,
                    cache_creation: r.get(4)?,
                    cost_usd: r.get(5)?,
                    unpriced: r.get::<_, Option<i64>>(6)?.unwrap_or(0),
                },
            ))
        })?;
        for row in rows {
            let (sid, totals) = row?;
            out.insert(sid, totals);
        }
        Ok(out)
    }

    /// Per-(session_id, agent_id) token/cost totals from `llm_usage`.
    /// `agent_id` is `None` for the main transcript.
    pub fn session_agent_token_totals(
        &self,
    ) -> Result<HashMap<(String, Option<String>), TokenTotals>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, agent_id,
                COALESCE(SUM(input_tokens),0),
                COALESCE(SUM(output_tokens),0),
                COALESCE(SUM(cache_read),0),
                COALESCE(SUM(cache_creation),0),
                COALESCE(SUM(COALESCE(cost_usd,0)),0),
                SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END)
             FROM llm_usage
             GROUP BY session_id, agent_id",
        )?;
        let mut out = HashMap::new();
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                TokenTotals {
                    input_tokens: r.get(2)?,
                    output_tokens: r.get(3)?,
                    cache_read: r.get(4)?,
                    cache_creation: r.get(5)?,
                    cost_usd: r.get(6)?,
                    unpriced: r.get::<_, Option<i64>>(7)?.unwrap_or(0),
                },
            ))
        })?;
        for row in rows {
            let (sid, agent_id, totals) = row?;
            out.insert((sid, agent_id), totals);
        }
        Ok(out)
    }

    /// Last `limit` closed spans per session (by `ended_at` desc), across
    /// all sessions in one query via a window function. Used for the
    /// collapsible tree's "recent spans" under each agent.
    pub fn recent_spans_all_sessions(
        &self,
        limit: u32,
    ) -> Result<HashMap<String, Vec<RecentSpanRow>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, id, tool_name, cmd_digest, started_at, ended_at, ok,
                    COALESCE(cpu_ns, cpu_ns_sampled), peak_footprint, leaked_count,
                    agent_id, agent_type
             FROM (
               SELECT *, ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY ended_at DESC) rn
               FROM tool_span WHERE ended_at IS NOT NULL
             ) WHERE rn <= ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            let started_at: i64 = r.get(4)?;
            let ended_at: i64 = r.get(5)?;
            Ok((
                r.get::<_, String>(0)?,
                RecentSpanRow {
                    span_id: r.get(1)?,
                    tool_name: r.get(2)?,
                    cmd_digest: r.get(3)?,
                    duration_ms: ended_at - started_at,
                    ok: r.get::<_, Option<i64>>(6)?.map(|v| v != 0),
                    cpu_ns: r.get::<_, Option<i64>>(7)?.unwrap_or(0) as u64,
                    peak_footprint: r.get::<_, Option<i64>>(8)?.unwrap_or(0) as u64,
                    leaked_count: r.get::<_, Option<i64>>(9)?.unwrap_or(0) as i32,
                    agent_id: r.get(10)?,
                    agent_type: r.get(11)?,
                },
            ))
        })?;
        let mut out: HashMap<String, Vec<RecentSpanRow>> = HashMap::new();
        for row in rows {
            let (sid, rec) = row?;
            out.entry(sid).or_default().push(rec);
        }
        Ok(out)
    }

    pub fn checkpoint(&self, path: &str) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let off: Option<i64> = conn
            .query_row(
                "SELECT offset FROM tailer_checkpoint WHERE path = ?1",
                [path],
                |r| r.get(0),
            )
            .ok();
        Ok(off.unwrap_or(0) as u64)
    }

    pub fn set_checkpoint(&self, path: &str, offset: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tailer_checkpoint(path, offset) VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET offset = excluded.offset",
            params![path, offset as i64],
        )?;
        Ok(())
    }

    pub fn insert_finding(
        &self,
        kind: &str,
        severity: &str,
        session_id: Option<&str>,
        span_id: Option<i64>,
        pid: Option<i32>,
        message: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO finding(ts, kind, severity, session_id, span_id, pid, message)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![now_ms(), kind, severity, session_id, span_id, pid, message],
        )?;
        Ok(())
    }

    /// Recent findings, newest first.
    pub fn recent_findings(&self, limit: u32) -> Result<Vec<(i64, String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT ts, kind, severity, message FROM finding ORDER BY ts DESC LIMIT ?1")?;
        let rows = stmt
            .query_map([limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Run an arbitrary read query returning JSON rows — used by report.
    pub fn query_json(
        &self,
        sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql)?;
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt.query(args)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut obj = serde_json::Map::new();
            for (i, c) in cols.iter().enumerate() {
                let v = match row.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(n) => serde_json::Value::from(n),
                    rusqlite::types::ValueRef::Real(f) => serde_json::Value::from(f),
                    rusqlite::types::ValueRef::Text(t) => {
                        serde_json::Value::from(String::from_utf8_lossy(t).into_owned())
                    }
                    rusqlite::types::ValueRef::Blob(_) => serde_json::Value::Null,
                };
                obj.insert(c.clone(), v);
            }
            out.push(serde_json::Value::Object(obj));
        }
        Ok(out)
    }
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_basic_writes() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        let pid = s.upsert_project("/tmp/proj").unwrap();
        s.upsert_session(
            "sess1",
            Some(pid),
            Some(123),
            Some("main"),
            Some("2.1.0"),
            1000,
        )
        .unwrap();
        let span_id = s
            .write_span(
                &SpanRecord {
                    session_id: "sess1".into(),
                    tool_use_id: Some("toolu_1".into()),
                    agent_id: None,
                    agent_type: None,
                    tool_name: "Bash".into(),
                    cmd_digest: Some("cargo test".into()),
                    started_at: 1000,
                    ended_at: 2000,
                    ok: Some(true),
                    cpu_ns: Some(5_000_000_000),
                    cpu_ns_sampled: 4_900_000_000,
                    peak_footprint: 1 << 30,
                    disk_read: 0,
                    disk_write: 0,
                    proc_count: 3,
                    leaked_count: 1,
                },
                &[ProcRecord {
                    pid: 999,
                    ppid: 123,
                    depth: 1,
                    comm: "cargo".into(),
                    name: "cargo".into(),
                    first_seen: 1100,
                    last_seen: 1900,
                    exited: false,
                    cpu_user_ns: 4_000_000_000,
                    cpu_sys_ns: 900_000_000,
                    peak_footprint: 1 << 30,
                    disk_read: 10,
                    disk_write: 20,
                    attribution: "span",
                    orphaned: true,
                }],
            )
            .unwrap();
        assert!(span_id > 0);
        let rows = s
            .query_json(
                "SELECT tool_name, proc_count, leaked_count FROM tool_span WHERE session_id='sess1'",
                &[],
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["tool_name"], "Bash");
        assert_eq!(rows[0]["leaked_count"], 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migration_is_idempotent_and_preserves_data() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        {
            let s = Store::open(&db).unwrap();
            s.insert_llm_usage(&LlmUsageRecord {
                session_id: "s1".into(),
                message_uuid: "u1".into(),
                request_id: None,
                ts: 1,
                model: "m".into(),
                is_sidechain: false,
                input_tokens: 10,
                output_tokens: 5,
                cache_read: 0,
                cache_creation: 0,
                cost_usd: Some(0.1),
                cost_source: "computed",
                agent_id: Some("agent1".into()),
            })
            .unwrap();
        }
        // Reopening (simulating a daemon restart against an existing db)
        // must not error and must not lose the row already there.
        let s2 = Store::open(&db).unwrap();
        let totals = s2.session_agent_token_totals().unwrap();
        let t = totals
            .get(&("s1".to_string(), Some("agent1".to_string())))
            .unwrap();
        assert_eq!(t.input_tokens, 10);
        assert_eq!(t.output_tokens, 5);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn session_agent_token_totals_groups_main_and_subagents() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-agg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        let mk = |uuid: &str, agent_id: Option<&str>, out: i64| LlmUsageRecord {
            session_id: "s1".into(),
            message_uuid: uuid.into(),
            request_id: None,
            ts: 1,
            model: "m".into(),
            is_sidechain: agent_id.is_some(),
            input_tokens: 1,
            output_tokens: out,
            cache_read: 0,
            cache_creation: 0,
            cost_usd: Some(0.01 * out as f64),
            cost_source: "computed",
            agent_id: agent_id.map(|a| a.to_string()),
        };
        s.insert_llm_usage(&mk("u1", None, 100)).unwrap();
        s.insert_llm_usage(&mk("u2", Some("agentA"), 50)).unwrap();
        s.insert_llm_usage(&mk("u3", Some("agentA"), 25)).unwrap();

        let totals = s.session_agent_token_totals().unwrap();
        assert_eq!(totals[&("s1".to_string(), None)].output_tokens, 100);
        assert_eq!(
            totals[&("s1".to_string(), Some("agentA".to_string()))].output_tokens,
            75
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
