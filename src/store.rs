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
    /// Agent titles ([`Store::set_agent_title`]) that arrived before the
    /// corresponding `agent_span` row existed — SubagentStart is HTTP-push
    /// while the transcript tailer that discovers titles lags ~3s behind, so
    /// either order is possible. Applied (and removed) the moment
    /// `open_agent_span` inserts the matching row; see both methods' docs.
    /// A plain in-memory map is enough: this only bridges a few seconds of
    /// race and doesn't need to survive a daemon restart (the transcript
    /// tailer will simply re-derive it from the same transcript line on
    /// next scan, since it resumes from its own checkpoint — the title
    /// association itself is never persisted anywhere but this map and the
    /// `agent_span.title` column).
    pending_titles: Mutex<HashMap<(String, String), String>>,
}

/// Cap on [`Store::pending_titles`] — titles whose `agent_span` row never
/// showed up (e.g. a subagent whose SubagentStart hook was dropped). Rather
/// than grow unboundedly over a long-running daemon, drop the whole map past
/// this size; losing a handful of not-yet-matched titles is harmless (the
/// UI falls back to agent_type / a short id), unlike leaking memory forever.
const PENDING_TITLES_CAP: usize = 500;

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
    pub orphaned_count: u32,
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
    /// `MAX(ts)` across the grouped rows — last LLM-activity timestamp (unix
    /// ms). Feeds the live tree's idle-age computation (top.rs / daemon.rs
    /// `build_agents`). 0 when the group has no rows (never used as a real
    /// timestamp; callers treat 0 as "no signal" and fall back elsewhere).
    pub last_ts: i64,
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

/// One `agent_span` row, as returned by [`Store::agent_spans_for_session`].
pub struct AgentSpanRow {
    pub agent_id: String,
    pub agent_type: Option<String>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub end_reason: Option<String>,
    /// Task/Agent tool_use `description` correlated in by the tailer (see
    /// `Store::set_agent_title`), when known.
    pub title: Option<String>,
}

/// `(session_id, agent_id) -> (started_at, ended_at, title)`, as returned by
/// [`Store::agent_span_times`].
pub type AgentSpanTimes = HashMap<(String, String), (i64, Option<i64>, Option<String>)>;

/// One closed span, as returned by [`Store::recent_spans_all_sessions`].
pub struct RecentSpanRow {
    pub span_id: i64,
    pub tool_name: String,
    pub cmd_digest: Option<String>,
    pub duration_ms: i64,
    /// Absolute `ended_at` (unix ms) — last-activity signal for the live
    /// tree's idle-age computation.
    pub ended_at: i64,
    pub cpu_ns: u64,
    pub peak_footprint: u64,
    pub ok: Option<bool>,
    pub orphaned_count: i32,
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
  orphaned_count INTEGER
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
  resolved_at INTEGER,
  -- Process start time (unix ms), when known. Part of the process identity
  -- (pid + start time) used to dedup orphan findings across pid reuse — see
  -- Store::recent_finding_exists. NULL for finding kinds that aren't
  -- per-process (contention, memory) or where start time wasn't available.
  proc_start_ms INTEGER
);
-- Backs the dedup check in Store::recent_finding_exists (one query per
-- would-be orphan finding, in the 10s detector loop).
CREATE INDEX IF NOT EXISTS idx_finding_kind_pid ON finding(kind, pid, ts);
-- Historical dashboard aggregates (src/history.rs) range-filter on these
-- columns; CREATE INDEX IF NOT EXISTS is naturally idempotent so this needs
-- no pragma-guarded migration like the ALTER TABLE below.
CREATE INDEX IF NOT EXISTS idx_llm_ts ON llm_usage(ts);
CREATE INDEX IF NOT EXISTS idx_span_started ON tool_span(started_at);
-- Subagent lifetime, opened on SubagentStart and closed on SubagentStop (or
-- swept closed by session end / staleness — see end_reason). A single
-- agent_id can only be open once per session: the UNIQUE constraint backs
-- the idempotent open/close semantics in Store::open_agent_span /
-- close_agent_span (see their docs for the exact duplicate-event policy).
-- Sessions survive daemon restarts and subagents may legitimately still be
-- running, so nothing is closed at daemon startup; the only backstops are
-- SessionEnd ('session_end') and the detector loop's stale sweep ('stale',
-- Store::close_stale_agent_spans) for rows open far longer than any real
-- subagent run.
-- `title` is the Task/Agent tool_use `input.description` (a short task
-- title), correlated in from the parent transcript by the tailer — see
-- Store::set_agent_title. It may arrive before or after this row exists
-- (SubagentStart is HTTP-push; transcript tailing lags ~3s behind); the
-- guarded ALTER below adds it to pre-existing dbs.
CREATE TABLE IF NOT EXISTS agent_span (
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session(id),
  agent_id TEXT NOT NULL,
  agent_type TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  end_reason TEXT CHECK(end_reason IN ('stop','session_end','stale') OR end_reason IS NULL),
  title TEXT,
  UNIQUE(session_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_agent_span_session ON agent_span(session_id, started_at);
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
    // "leaked" read like a credential-leak security event; the accurate term
    // is "orphaned" (a process that outlived its tool call/session — see the
    // `orphan` finding kind). Renamed 2026-08: guard on the old column name
    // so this is a no-op on both fresh dbs (SCHEMA already has the new name)
    // and already-migrated ones.
    let has_leaked_count = {
        let mut stmt = conn.prepare("PRAGMA table_info(tool_span)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut found = false;
        for n in names {
            if n? == "leaked_count" {
                found = true;
                break;
            }
        }
        found
    };
    if has_leaked_count {
        conn.execute(
            "ALTER TABLE tool_span RENAME COLUMN leaked_count TO orphaned_count",
            [],
        )?;
    }
    let has_proc_start_ms = {
        let mut stmt = conn.prepare("PRAGMA table_info(finding)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut found = false;
        for n in names {
            if n? == "proc_start_ms" {
                found = true;
                break;
            }
        }
        found
    };
    if !has_proc_start_ms {
        conn.execute("ALTER TABLE finding ADD COLUMN proc_start_ms INTEGER", [])?;
    }
    let has_title = {
        let mut stmt = conn.prepare("PRAGMA table_info(agent_span)")?;
        let names = stmt.query_map([], |r| r.get::<_, String>(1))?;
        let mut found = false;
        for n in names {
            if n? == "title" {
                found = true;
                break;
            }
        }
        found
    };
    if !has_title {
        conn.execute("ALTER TABLE agent_span ADD COLUMN title TEXT", [])?;
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
            pending_titles: Mutex::new(HashMap::new()),
        })
    }

    pub fn open_readonly(path: &Path) -> Result<Store> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Store {
            conn: Mutex::new(conn),
            pending_titles: Mutex::new(HashMap::new()),
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
               disk_read, disk_write, proc_count, orphaned_count)
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
                span.orphaned_count,
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
                SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END),
                COALESCE(MAX(ts),0)
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
                    last_ts: r.get(7)?,
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
                SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END),
                COALESCE(MAX(ts),0)
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
                    last_ts: r.get(8)?,
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
                    COALESCE(cpu_ns, cpu_ns_sampled), peak_footprint, orphaned_count,
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
                    ended_at,
                    ok: r.get::<_, Option<i64>>(6)?.map(|v| v != 0),
                    cpu_ns: r.get::<_, Option<i64>>(7)?.unwrap_or(0) as u64,
                    peak_footprint: r.get::<_, Option<i64>>(8)?.unwrap_or(0) as u64,
                    orphaned_count: r.get::<_, Option<i64>>(9)?.unwrap_or(0) as i32,
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

    /// Open a subagent lifetime span (`SubagentStart`). Duplicate starts for
    /// the same `(session_id, agent_id)` — e.g. a redelivered hook — are
    /// ignored: the UNIQUE constraint makes this an `INSERT OR IGNORE`, so
    /// the *first* `started_at`/`agent_type` observed wins and later
    /// duplicates are silent no-ops rather than resetting the clock.
    pub fn open_agent_span(
        &self,
        session_id: &str,
        agent_id: &str,
        agent_type: Option<&str>,
        started_at: i64,
    ) -> Result<()> {
        {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "INSERT OR IGNORE INTO agent_span(session_id, agent_id, agent_type, started_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![session_id, agent_id, agent_type, started_at],
            )?;
        }
        // A title may have arrived (via set_agent_title) before this row
        // existed — the transcript tailer runs on its own ~3s poll and can
        // beat or lag SubagentStart either way. Apply it now if so.
        let pending = {
            let mut pending = self.pending_titles.lock().unwrap();
            pending.remove(&(session_id.to_string(), agent_id.to_string()))
        };
        if let Some(title) = pending {
            self.set_agent_title(session_id, agent_id, &title)?;
        }
        Ok(())
    }

    /// Record the task title for a subagent, correlated in by the tailer
    /// from the parent transcript's Task/Agent tool_use + tool_result pair.
    /// Handles both arrival orders relative to `open_agent_span`:
    /// - row already exists -> UPDATE it directly.
    /// - row doesn't exist yet -> stash in `pending_titles`, applied by
    ///   `open_agent_span` the moment the row is created.
    pub fn set_agent_title(&self, session_id: &str, agent_id: &str, title: &str) -> Result<()> {
        let updated = {
            let conn = self.conn.lock().unwrap();
            conn.execute(
                "UPDATE agent_span SET title = ?3 WHERE session_id = ?1 AND agent_id = ?2",
                params![session_id, agent_id, title],
            )?
        };
        if updated == 0 {
            let mut pending = self.pending_titles.lock().unwrap();
            if pending.len() >= PENDING_TITLES_CAP {
                pending.clear();
            }
            pending.insert(
                (session_id.to_string(), agent_id.to_string()),
                title.to_string(),
            );
        }
        Ok(())
    }

    /// Close a subagent lifetime span (`SubagentStop`). Idempotent: only
    /// rows with `ended_at IS NULL` are updated, so a redelivered Stop (or
    /// one that races the session-end sweep) never overwrites an earlier
    /// close's `ended_at`/`end_reason`.
    pub fn close_agent_span(
        &self,
        session_id: &str,
        agent_id: &str,
        ended_at: i64,
        end_reason: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE agent_span SET ended_at = ?3, end_reason = ?4
             WHERE session_id = ?1 AND agent_id = ?2 AND ended_at IS NULL",
            params![session_id, agent_id, ended_at, end_reason],
        )?;
        Ok(())
    }

    /// Close every still-open agent span for a session — used at
    /// `SessionEnd` (`end_reason = "session_end"`) to cover subagents whose
    /// `SubagentStop` never arrived (abnormal termination). Deliberately
    /// *not* called at daemon startup: sessions survive daemon restarts and
    /// a subagent may legitimately still be running when the daemon comes
    /// back up. The other backstop — spans that outlive both `SubagentStop`
    /// and `SessionEnd` (e.g. the daemon crashes and the session is never
    /// resumed) — is [`Store::close_stale_agent_spans`], run periodically
    /// from the detector loop.
    pub fn close_all_open_agent_spans_for_session(
        &self,
        session_id: &str,
        end_reason: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE agent_span SET ended_at = ?2, end_reason = ?3
             WHERE session_id = ?1 AND ended_at IS NULL",
            params![session_id, now_ms(), end_reason],
        )?;
        Ok(())
    }

    /// Close every still-open agent span across *all* sessions whose
    /// `started_at` is older than `max_age_ms` (`end_reason = "stale"`).
    /// The backstop for spans that outlive both `SubagentStop` and
    /// `SessionEnd` — e.g. the daemon crashes mid-session and the session
    /// is never resumed, so neither hook ever fires. Returns the number of
    /// rows closed. Intended to be called periodically (see the detector
    /// loop in daemon.rs), not at daemon startup — see the schema comment
    /// on `agent_span` for why.
    pub fn close_stale_agent_spans(&self, max_age_ms: i64) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let cutoff = now_ms() - max_age_ms;
        let n = conn.execute(
            "UPDATE agent_span SET ended_at = ?1, end_reason = 'stale'
             WHERE ended_at IS NULL AND started_at < ?2",
            params![now_ms(), cutoff],
        )?;
        Ok(n)
    }

    /// All `agent_span` rows for one session, oldest first — feeds the
    /// history dashboard's replay gantt (agent lanes).
    pub fn agent_spans_for_session(&self, session_id: &str) -> Result<Vec<AgentSpanRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT agent_id, agent_type, started_at, ended_at, end_reason, title
             FROM agent_span WHERE session_id = ?1 ORDER BY started_at",
        )?;
        let rows = stmt
            .query_map([session_id], |r| {
                Ok(AgentSpanRow {
                    agent_id: r.get(0)?,
                    agent_type: r.get(1)?,
                    started_at: r.get(2)?,
                    ended_at: r.get(3)?,
                    end_reason: r.get(4)?,
                    title: r.get(5)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// `(session_id, agent_id) -> (started_at, ended_at, title)` for every
    /// agent_span row, across all sessions — feeds the live `/api/top` tree
    /// (agent row duration + title) via a short-TTL cache, same pattern as
    /// [`Store::recent_spans_all_sessions`].
    pub fn agent_span_times(&self) -> Result<AgentSpanTimes> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT session_id, agent_id, started_at, ended_at, title FROM agent_span")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (sid, aid, started_at, ended_at, title) = row?;
            out.insert((sid, aid), (started_at, ended_at, title));
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

    #[allow(clippy::too_many_arguments)]
    pub fn insert_finding(
        &self,
        kind: &str,
        severity: &str,
        session_id: Option<&str>,
        span_id: Option<i64>,
        pid: Option<i32>,
        message: &str,
        proc_start_ms: Option<i64>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO finding(ts, kind, severity, session_id, span_id, pid, message, proc_start_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                now_ms(),
                kind,
                severity,
                session_id,
                span_id,
                pid,
                message,
                proc_start_ms
            ],
        )?;
        Ok(())
    }

    /// True if a finding of this `kind` for this exact process identity
    /// (pid + `proc_start_ms`, when known — falls back to pid alone when
    /// `proc_start_ms` is `None`) was already recorded within `since_ts`.
    /// Backs orphan-finding dedup: the in-memory `reported` flags on
    /// `OrphanWatch`/`LooseProc` already stop the *same* tracked struct from
    /// refiring, but a process can independently re-enter tracking (e.g.
    /// re-discovered as a loose proc after its span-based orphan_watch entry
    /// already fired, or the daemon restarted) — this DB-backed check is the
    /// single source of truth that catches those cases too.
    pub fn recent_finding_exists(
        &self,
        kind: &str,
        pid: i32,
        proc_start_ms: Option<i64>,
        since_ts: i64,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn.query_row(
            "SELECT EXISTS(
               SELECT 1 FROM finding
               WHERE kind = ?1 AND pid = ?2 AND ts > ?3
                 AND (proc_start_ms IS ?4 OR ?4 IS NULL)
             )",
            params![kind, pid, since_ts, proc_start_ms],
            |r| r.get(0),
        )?;
        Ok(exists)
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
                    orphaned_count: 1,
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
                "SELECT tool_name, proc_count, orphaned_count FROM tool_span WHERE session_id='sess1'",
                &[],
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["tool_name"], "Bash");
        assert_eq!(rows[0]["orphaned_count"], 1);
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
    fn leaked_count_column_is_renamed_and_idempotent() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-leak-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        {
            // Build a db with the OLD schema shape (leaked_count) by hand,
            // simulating an install that predates the rename.
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE tool_span (
                   id INTEGER PRIMARY KEY,
                   session_id TEXT,
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
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO tool_span(session_id, tool_use_id, tool_name, started_at, ended_at, \
                 proc_count, leaked_count) VALUES ('s1','tu1','Bash',1000,2000,3,2)",
                [],
            )
            .unwrap();
        }
        // Reopening through Store::open runs SCHEMA (CREATE TABLE IF NOT
        // EXISTS — no-op on the existing table) then migrate(), which must
        // detect leaked_count and rename it, preserving the row.
        let s = Store::open(&db).unwrap();
        let rows = s
            .query_json(
                "SELECT tool_name, proc_count, orphaned_count FROM tool_span WHERE session_id='s1'",
                &[],
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["tool_name"], "Bash");
        assert_eq!(rows[0]["proc_count"], 3);
        assert_eq!(rows[0]["orphaned_count"], 2);
        drop(s);

        // Reopening again (already-migrated db) must be a harmless no-op:
        // same data, no error, leaked_count stays gone.
        let s2 = Store::open(&db).unwrap();
        let cols: Vec<String> = {
            let conn = s2.conn.lock().unwrap();
            let mut stmt = conn.prepare("PRAGMA table_info(tool_span)").unwrap();
            stmt.query_map([], |r| r.get::<_, String>(1))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert!(!cols.iter().any(|c| c == "leaked_count"));
        assert!(cols.iter().any(|c| c == "orphaned_count"));
        let rows2 = s2
            .query_json(
                "SELECT orphaned_count FROM tool_span WHERE session_id='s1'",
                &[],
            )
            .unwrap();
        assert_eq!(rows2[0]["orphaned_count"], 2);
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

    #[test]
    fn agent_span_open_close_lifecycle() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-asl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        s.open_agent_span("s1", "agentA", Some("Explore"), 1000)
            .unwrap();
        let spans = s.agent_spans_for_session("s1").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].agent_id, "agentA");
        assert_eq!(spans[0].agent_type.as_deref(), Some("Explore"));
        assert_eq!(spans[0].started_at, 1000);
        assert!(spans[0].ended_at.is_none());

        s.close_agent_span("s1", "agentA", 2000, "stop").unwrap();
        let spans = s.agent_spans_for_session("s1").unwrap();
        assert_eq!(spans[0].ended_at, Some(2000));
        assert_eq!(spans[0].end_reason.as_deref(), Some("stop"));

        // Idempotent close: a second (redelivered) Stop must not overwrite
        // the first close's ended_at/end_reason.
        s.close_agent_span("s1", "agentA", 9999, "session_end")
            .unwrap();
        let spans = s.agent_spans_for_session("s1").unwrap();
        assert_eq!(spans[0].ended_at, Some(2000));
        assert_eq!(spans[0].end_reason.as_deref(), Some("stop"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn agent_span_duplicate_start_is_ignored() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-asd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        s.open_agent_span("s1", "agentA", Some("Explore"), 1000)
            .unwrap();
        // A duplicate SubagentStart for the same agent_id must not error and
        // must not reset started_at/agent_type.
        s.open_agent_span("s1", "agentA", Some("general-purpose"), 5000)
            .unwrap();
        let spans = s.agent_spans_for_session("s1").unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].started_at, 1000);
        assert_eq!(spans[0].agent_type.as_deref(), Some("Explore"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn close_all_open_agent_spans_for_session_only_touches_open_ones() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-asc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        s.open_agent_span("s1", "agentA", Some("Explore"), 1000)
            .unwrap();
        s.open_agent_span("s1", "agentB", Some("general-purpose"), 1500)
            .unwrap();
        s.close_agent_span("s1", "agentA", 2000, "stop").unwrap();

        s.close_all_open_agent_spans_for_session("s1", "session_end")
            .unwrap();
        let mut spans = s.agent_spans_for_session("s1").unwrap();
        spans.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        assert_eq!(spans[0].agent_id, "agentA");
        assert_eq!(spans[0].end_reason.as_deref(), Some("stop")); // untouched
        assert_eq!(spans[1].agent_id, "agentB");
        assert_eq!(spans[1].end_reason.as_deref(), Some("session_end"));
        assert!(spans[1].ended_at.is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn agent_span_times_reflects_open_and_closed_spans() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-ast-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        s.open_agent_span("s1", "agentA", Some("Explore"), 1000)
            .unwrap();
        s.close_agent_span("s1", "agentA", 2000, "stop").unwrap();
        s.open_agent_span("s1", "agentB", None, 3000).unwrap();

        let times = s.agent_span_times().unwrap();
        assert_eq!(
            times[&("s1".to_string(), "agentA".to_string())],
            (1000, Some(2000), None)
        );
        assert_eq!(
            times[&("s1".to_string(), "agentB".to_string())],
            (3000, None, None)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_agent_title_updates_existing_row_directly() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-title-a-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open(&dir.join("t.db")).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        s.open_agent_span("s1", "agentA", Some("Explore"), 1000)
            .unwrap();
        s.set_agent_title("s1", "agentA", "Research subagent hook payloads")
            .unwrap();
        let times = s.agent_span_times().unwrap();
        assert_eq!(
            times[&("s1".to_string(), "agentA".to_string())]
                .2
                .as_deref(),
            Some("Research subagent hook payloads")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_agent_title_before_span_exists_is_applied_on_open() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-title-b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Store::open(&dir.join("t.db")).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();
        // Title arrives first (transcript tailer beat SubagentStart's HTTP
        // push) — no agent_span row exists yet.
        s.set_agent_title("s1", "agentB", "Implement Bash attribution")
            .unwrap();
        assert!(s.agent_span_times().unwrap().is_empty());

        s.open_agent_span("s1", "agentB", Some("general-purpose"), 1000)
            .unwrap();
        let times = s.agent_span_times().unwrap();
        assert_eq!(
            times[&("s1".to_string(), "agentB".to_string())]
                .2
                .as_deref(),
            Some("Implement Bash attribution")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn close_stale_agent_spans_closes_only_old_open_ones() {
        let dir = std::env::temp_dir().join(format!("ai-obs-test-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        s.upsert_session("s1", None, None, None, None, 1000)
            .unwrap();

        let day_ms: i64 = 24 * 60 * 60 * 1000;
        let now = now_ms();
        // Open 25h ago: older than the 24h threshold -> should be swept.
        s.open_agent_span("s1", "stale-agent", Some("Explore"), now - day_ms - 60_000)
            .unwrap();
        // Open 1h ago: well within the threshold -> must stay untouched.
        s.open_agent_span("s1", "fresh-agent", Some("Explore"), now - 60 * 60 * 1000)
            .unwrap();
        // Already closed, opened 2 days ago: must not be touched or
        // reported as swept (ended_at IS NULL is required).
        s.open_agent_span("s1", "closed-agent", Some("Explore"), now - 2 * day_ms)
            .unwrap();
        s.close_agent_span("s1", "closed-agent", now - day_ms, "stop")
            .unwrap();

        let n = s.close_stale_agent_spans(day_ms).unwrap();
        assert_eq!(n, 1);

        let mut spans = s.agent_spans_for_session("s1").unwrap();
        spans.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        let stale = spans.iter().find(|r| r.agent_id == "stale-agent").unwrap();
        assert!(stale.ended_at.is_some());
        assert_eq!(stale.end_reason.as_deref(), Some("stale"));
        let fresh = spans.iter().find(|r| r.agent_id == "fresh-agent").unwrap();
        assert!(fresh.ended_at.is_none());
        let closed = spans.iter().find(|r| r.agent_id == "closed-agent").unwrap();
        assert_eq!(closed.end_reason.as_deref(), Some("stop")); // untouched

        // Idempotent: running again finds nothing left to sweep.
        let n2 = s.close_stale_agent_spans(day_ms).unwrap();
        assert_eq!(n2, 0);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn proc_start_ms_column_is_added_and_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "ai-obs-test-finding-migrate-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        {
            // Pre-migration `finding` table shape (no proc_start_ms).
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE finding (
                   id INTEGER PRIMARY KEY,
                   ts INTEGER NOT NULL,
                   kind TEXT NOT NULL,
                   severity TEXT NOT NULL,
                   session_id TEXT,
                   span_id INTEGER,
                   pid INTEGER,
                   message TEXT NOT NULL,
                   resolved_at INTEGER
                 );",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO finding(ts, kind, severity, pid, message) \
                 VALUES (1000, 'orphan', 'warn', 42, 'pre-migration row')",
                [],
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        // Old row survives, new column is queryable (NULL for the old row).
        let rows = s
            .query_json(
                "SELECT message, proc_start_ms FROM finding WHERE pid = 42",
                &[],
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["message"], "pre-migration row");
        assert!(rows[0]["proc_start_ms"].is_null());
        // recent_finding_exists must work against the migrated table too.
        assert!(s.recent_finding_exists("orphan", 42, None, 0).unwrap());
        drop(s);

        // Reopening an already-migrated db is a harmless no-op.
        let s2 = Store::open(&db).unwrap();
        assert!(s2.recent_finding_exists("orphan", 42, None, 0).unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn orphan_finding_dedup_by_pid_and_start_ms() {
        let dir =
            std::env::temp_dir().join(format!("ai-obs-test-finding-dedup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        let now = now_ms();

        // Nothing recorded yet.
        assert!(!s
            .recent_finding_exists("orphan", 4242, Some(1_000), now - 60_000)
            .unwrap());

        s.insert_finding(
            "orphan",
            "info",
            Some("s1"),
            None,
            Some(4242),
            "caffeinate (pid 4242) ...",
            Some(1_000),
        )
        .unwrap();

        // Same identity (pid + start_ms): dedup hit.
        assert!(s
            .recent_finding_exists("orphan", 4242, Some(1_000), now - 60_000)
            .unwrap());
        // Same pid, different start time (pid was reused by a new process):
        // not the same identity, no hit.
        assert!(!s
            .recent_finding_exists("orphan", 4242, Some(9_999), now - 60_000)
            .unwrap());
        // Outside the lookback window: no hit.
        assert!(!s
            .recent_finding_exists("orphan", 4242, Some(1_000), now + 1)
            .unwrap());
        // Different kind entirely: no hit.
        assert!(!s
            .recent_finding_exists("memory", 4242, Some(1_000), now - 60_000)
            .unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn orphan_finding_dedup_falls_back_to_pid_when_start_ms_unknown() {
        let dir = std::env::temp_dir().join(format!(
            "ai-obs-test-finding-dedup-nostart-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let s = Store::open(&db).unwrap();
        let now = now_ms();

        s.insert_finding(
            "orphan",
            "warn",
            Some("s1"),
            None,
            Some(555),
            "detached, unattributed",
            None, // start time unavailable
        )
        .unwrap();

        // Querying without a start_ms (also unavailable this time) falls
        // back to pid-only matching.
        assert!(s
            .recent_finding_exists("orphan", 555, None, now - 60_000)
            .unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }
}
