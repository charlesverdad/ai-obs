//! The ai-obs daemon: HTTP hook endpoint + adaptive sampler + detectors.

use crate::correlator::{snapshot_map, Correlator, Session, Span};
use crate::store::{now_ms, AgentSpanTimes, RecentSpanRow, Store, TokenTotals};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 8770;

/// Timestamped, refcounted snapshot of `session_token_totals()`.
type TokenTotalsCache = Arc<Mutex<Option<(Instant, Arc<HashMap<String, TokenTotals>>)>>>;

/// Timestamped, refcounted snapshot of `session_agent_token_totals()`.
type AgentTokenTotalsCache =
    Arc<Mutex<Option<(Instant, Arc<HashMap<(String, Option<String>), TokenTotals>>)>>>;

/// Timestamped, refcounted snapshot of `recent_spans_all_sessions()`.
type RecentSpansCache = Arc<Mutex<Option<(Instant, Arc<HashMap<String, Vec<RecentSpanRow>>>)>>>;

/// Timestamped, refcounted snapshot of `agent_span_times()`.
type AgentSpanTimesCache = Arc<Mutex<Option<(Instant, Arc<AgentSpanTimes>)>>>;

/// (kind, severity, session_id, span_id, pid, message)
type Finding = (
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<i32>,
    String,
);

pub fn port() -> u16 {
    std::env::var("AI_OBS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub corr: Arc<Mutex<Correlator>>,
    pub started_at: i64,
    /// Rolling sampler self-cost, ns per second of wall time.
    pub sampler_cost: Arc<Mutex<f64>>,
    /// Cached `session_token_totals()` result, refreshed at most every ~2s —
    /// the tailer only updates llm_usage every 3s so this saves repeated
    /// full-table scans on rapid /api/top polling.
    pub token_totals_cache: TokenTotalsCache,
    /// Same idea, per-(session, agent) — feeds the collapsible tree.
    pub agent_totals_cache: AgentTokenTotalsCache,
    /// Cached last-10-per-session closed spans — feeds the collapsible tree.
    pub recent_spans_cache: RecentSpansCache,
    /// Cached `agent_span_times()` result — feeds the collapsible tree's
    /// per-agent TIME column.
    pub agent_span_times_cache: AgentSpanTimesCache,
    /// `SubagentStart`/`SubagentStop` payload keys already logged at info
    /// level (once per hook_event_name), so we can empirically discover
    /// undocumented fields without spamming the log on every event.
    pub logged_sub_payload_keys: Arc<Mutex<HashSet<String>>>,
    /// Dedicated read-only connection for the historical dashboard
    /// (`/api/history`, `/api/session/{id}`) — never the writer connection,
    /// so a slow aggregate can't block the PreToolUse hot path. WAL makes
    /// concurrent read safe.
    pub dashboard_store: Arc<Store>,
    pub db_path: std::path::PathBuf,
}

pub async fn run(db_path: &std::path::Path) -> anyhow::Result<()> {
    let store = Arc::new(Store::open(db_path)?);
    // Opened after Store::open above so the schema (incl. the dashboard's
    // idx_llm_ts / idx_span_started indexes) already exists.
    let dashboard_store = Arc::new(Store::open_readonly(db_path)?);
    let corr = Arc::new(Mutex::new(Correlator::default()));
    let state = AppState {
        store: store.clone(),
        corr: corr.clone(),
        started_at: now_ms(),
        sampler_cost: Arc::new(Mutex::new(0.0)),
        token_totals_cache: Arc::new(Mutex::new(None)),
        agent_totals_cache: Arc::new(Mutex::new(None)),
        recent_spans_cache: Arc::new(Mutex::new(None)),
        agent_span_times_cache: Arc::new(Mutex::new(None)),
        logged_sub_payload_keys: Arc::new(Mutex::new(HashSet::new())),
        dashboard_store,
        db_path: db_path.to_path_buf(),
    };

    // Sampler loop (blocking-ish work on a dedicated thread-friendly task).
    {
        let state = state.clone();
        tokio::spawn(async move { sampler_loop(state).await });
    }
    // Detector loop.
    {
        let state = state.clone();
        tokio::spawn(async move { detector_loop(state).await });
    }
    // Transcript tailer.
    {
        let store = store.clone();
        tokio::spawn(async move { crate::tailer::run(store).await });
    }

    let app = Router::new()
        .route("/", get(dashboard_html))
        .route("/h/session-start", post(h_session_start))
        .route("/h/pre", post(h_pre))
        .route("/h/post", post(h_post))
        .route("/h/sub", post(h_sub))
        .route("/h/end", post(h_end))
        .route("/api/status", get(api_status))
        .route("/api/top", get(api_top))
        .route("/api/history", get(api_history))
        .route("/api/session/{id}", get(api_session))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(
        "ai-obs daemon listening on {addr}, db {}",
        db_path.display()
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn sampler_loop(state: AppState) {
    let mut last_rollup = 0i64;
    loop {
        let t0 = std::time::Instant::now();
        let procs = tokio::task::spawn_blocking(snapshot_map)
            .await
            .unwrap_or_default();
        let busy = {
            let mut corr = state.corr.lock().unwrap();
            corr.tick(&procs);
            corr.any_span_open()
        };
        // 1 Hz rollup regardless of rate.
        let now = now_ms();
        if now - last_rollup >= 1000 {
            last_rollup = now;
            let rows: Vec<(String, f64, u64, u32)> = {
                let corr = state.corr.lock().unwrap();
                corr.sessions
                    .values()
                    .filter(|s| s.claude_pid.is_some())
                    .map(|s| (s.id.clone(), s.cpu_pct, s.footprint, s.proc_count))
                    .collect()
            };
            for (sid, cpu, fp, n) in rows {
                let _ = state
                    .store
                    .insert_session_sample(&sid, now / 1000, cpu, fp, n);
            }
        }
        let cost_ns = t0.elapsed().as_nanos() as f64;
        // Adaptive rate: 10 Hz while a tool span is open, 1 Hz idle. Back off
        // if our own cost exceeds ~2% of one core at the chosen rate.
        let mut interval = if busy { 100u64 } else { 1000u64 };
        let budget_ns = interval as f64 * 1_000_000.0 * 0.02;
        if cost_ns > budget_ns {
            interval = interval.saturating_mul(2);
        }
        *state.sampler_cost.lock().unwrap() = cost_ns / (interval as f64 * 1_000_000.0);
        tokio::time::sleep(Duration::from_millis(interval)).await;
    }
}

/// Agent spans open longer than this with no `SubagentStop`/`SessionEnd`
/// are assumed abandoned (daemon crash mid-session, session never
/// resumed) and swept closed with `end_reason = "stale"`.
const STALE_AGENT_SPAN_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000;

async fn detector_loop(state: AppState) {
    let mut last_stale_sweep = 0i64;
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let now = now_ms();
        // Piggyback on this loop's 10s cadence but only actually sweep once
        // a minute — closing a handful of hours-old rows doesn't need to
        // run every tick, and the UPDATE is a full-table scan.
        if now - last_stale_sweep >= 60_000 {
            last_stale_sweep = now;
            match state
                .store
                .close_stale_agent_spans(STALE_AGENT_SPAN_MAX_AGE_MS)
            {
                Ok(n) if n > 0 => tracing::info!("swept {n} stale agent_span row(s)"),
                Ok(_) => {}
                Err(e) => tracing::debug!("close_stale_agent_spans failed: {e:#}"),
            }
        }
        let procs = tokio::task::spawn_blocking(snapshot_map)
            .await
            .unwrap_or_default();
        let mut findings: Vec<Finding> = Vec::new();
        {
            let mut corr = state.corr.lock().unwrap();
            let ncores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8) as f64;
            let mut total_cpu_pct = 0.0;
            for sess in corr.sessions.values_mut() {
                total_cpu_pct += sess.cpu_pct;
                let project = sess
                    .project_root
                    .as_deref()
                    .and_then(|r| r.rsplit('/').next())
                    .unwrap_or("?")
                    .to_string();
                // Orphans: alive N seconds after their span closed.
                for w in sess.orphan_watch.iter_mut() {
                    if w.reported {
                        continue;
                    }
                    if !procs.contains_key(&w.pid) {
                        w.reported = true; // exited on its own
                        continue;
                    }
                    if now - w.closed_at > 60_000 {
                        w.reported = true;
                        let fp = crate::mac::usage(w.pid)
                            .map(|u| u.phys_footprint / 1_000_000)
                            .unwrap_or(0);
                        let cmd = w.cmd_digest.as_deref().unwrap_or("?");
                        findings.push((
                            "orphan".into(),
                            "crit".into(),
                            Some(sess.id.clone()),
                            Some(w.span_id),
                            Some(w.pid),
                            format!(
                                "{} (pid {}) from `{}` in {} outlived its tool call by 60s+, {} MB",
                                w.comm, w.pid, cmd, project, fp
                            ),
                        ));
                    }
                }
                sess.orphan_watch
                    .retain(|w| !w.reported || procs.contains_key(&w.pid));

                // Loose-proc orphan sweep: processes that were never attributed
                // to a span at all (e.g. the adopt-at-close fallback also
                // missed them, or they simply appeared with no span open) but
                // have since reparented away from the claude tree and stuck
                // around. Attribution is weaker here than the span-based
                // orphan_watch above, so these report at 'warn' not 'crit'.
                for lf in sess.sweep_loose_orphans(&procs, now) {
                    findings.push((
                        "orphan".into(),
                        "warn".into(),
                        Some(sess.id.clone()),
                        None,
                        Some(lf.pid),
                        format!(
                            "{} (pid {}) detached, unattributed, alive {}m in {}, {} MB",
                            lf.comm,
                            lf.pid,
                            (lf.age_ms / 60_000).max(1),
                            project,
                            lf.footprint_mb
                        ),
                    ));
                }

                // Leak: sustained growth, footprint > 2 GB and cpu evidence over 10 min
                // is done from session_sample by the reporter; here a cheap live check.
                if sess.footprint > 6 << 30 {
                    findings.push((
                        "memory".into(),
                        "warn".into(),
                        Some(sess.id.clone()),
                        None,
                        None,
                        format!(
                            "session in {} at {:.1} GB footprint",
                            project,
                            sess.footprint as f64 / (1u64 << 30) as f64
                        ),
                    ));
                }
            }
            if total_cpu_pct > ncores * 100.0 {
                findings.push((
                    "contention".into(),
                    "warn".into(),
                    None,
                    None,
                    None,
                    format!(
                        "tracked sessions requesting {:.0}% CPU on {} cores",
                        total_cpu_pct, ncores
                    ),
                ));
            }
        }
        for (kind, sev, sid, span, pid, msg) in findings {
            tracing::warn!("[{kind}] {msg}");
            let _ = state
                .store
                .insert_finding(&kind, &sev, sid.as_deref(), span, pid, &msg);
        }
    }
}

// ---------------- hook handlers ----------------
// Hooks must never break the agent: every handler swallows errors and
// returns 200 {} as fast as possible.

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|x| x.to_string())
}

async fn h_session_start(State(st): State<AppState>, Json(v): Json<Value>) -> Json<Value> {
    let Some(sid) = s(&v, "session_id") else {
        return Json(json!({}));
    };
    let cwd = s(&v, "cwd");
    let claude_pid = v
        .get("claude_pid")
        .and_then(|x| x.as_i64())
        .map(|x| x as i32);
    {
        let mut corr = st.corr.lock().unwrap();
        let sess = corr.ensure_session(&sid, cwd.as_deref(), claude_pid);
        if claude_pid.is_some() {
            sess.claude_pid = claude_pid;
        }
        let root = sess.project_root.clone();
        let project_id = root
            .as_deref()
            .and_then(|r| st.store.upsert_project(r).ok());
        sess.project_id = project_id;
        let _ = st.store.upsert_session(
            &sid,
            project_id,
            sess.claude_pid,
            None,
            None,
            sess.started_at,
        );
    }
    tracing::info!("session-start {sid} pid={claude_pid:?} cwd={cwd:?}");
    Json(json!({}))
}

async fn h_pre(State(st): State<AppState>, Json(v): Json<Value>) -> Json<Value> {
    let Some(sid) = s(&v, "session_id") else {
        return Json(json!({}));
    };
    let cwd = s(&v, "cwd");
    let tool_name = s(&v, "tool_name").unwrap_or_else(|| "?".into());
    let tool_use_id = s(&v, "tool_use_id");
    let command = v
        .get("tool_input")
        .and_then(|i| i.get("command"))
        .and_then(|c| c.as_str())
        .map(|c| c.to_string());
    let agent_id = s(&v, "agent_id");
    let agent_type = s(&v, "agent_type");
    let procs = tokio::task::spawn_blocking(snapshot_map)
        .await
        .unwrap_or_default();
    {
        let mut corr = st.corr.lock().unwrap();
        // Register session lazily if SessionStart was missed (daemon restart).
        let sess = corr.ensure_session(&sid, cwd.as_deref(), None);
        if sess.project_id.is_none() {
            if let Some(root) = sess.project_root.clone() {
                sess.project_id = st.store.upsert_project(&root).ok();
                let _ = st.store.upsert_session(
                    &sid,
                    sess.project_id,
                    sess.claude_pid,
                    None,
                    None,
                    sess.started_at,
                );
            }
        }
        corr.open_span(crate::correlator::OpenSpanArgs {
            session_id: &sid,
            cwd: cwd.as_deref(),
            tool_use_id,
            tool_name,
            command: command.as_deref(),
            agent_id,
            agent_type,
            procs: &procs,
        });
    }
    Json(json!({}))
}

async fn h_post(State(st): State<AppState>, Json(v): Json<Value>) -> Json<Value> {
    let Some(sid) = s(&v, "session_id") else {
        return Json(json!({}));
    };
    let tool_use_id = s(&v, "tool_use_id");
    let failed = s(&v, "hook_event_name").as_deref() == Some("PostToolUseFailure")
        || v.get("tool_error").is_some();
    let procs = tokio::task::spawn_blocking(snapshot_map)
        .await
        .unwrap_or_default();
    {
        let mut corr = st.corr.lock().unwrap();
        corr.close_span(
            &st.store,
            &sid,
            tool_use_id.as_deref(),
            Some(!failed),
            &procs,
        );
    }
    Json(json!({}))
}

/// Handles both `SubagentStart` and `SubagentStop` (branching on
/// `hook_event_name`) so `settings.json` only needs one URL for both events.
/// Opens/closes the corresponding `agent_span` row. Unknown event names or
/// missing required fields are logged at debug and otherwise ignored — hooks
/// must never fail the agent.
async fn h_sub(State(st): State<AppState>, Json(v): Json<Value>) -> Json<Value> {
    let event = s(&v, "hook_event_name").unwrap_or_default();
    log_sub_payload_keys_once(&st, &event, &v);
    let Some(sid) = s(&v, "session_id") else {
        tracing::debug!("h_sub: missing session_id, event={event}");
        return Json(json!({}));
    };
    let Some(agent_id) = s(&v, "agent_id") else {
        tracing::debug!("h_sub: missing agent_id, event={event}, session={sid}");
        return Json(json!({}));
    };
    match event.as_str() {
        "SubagentStart" => {
            let agent_type = s(&v, "agent_type");
            if let Err(e) =
                st.store
                    .open_agent_span(&sid, &agent_id, agent_type.as_deref(), now_ms())
            {
                tracing::debug!("h_sub: open_agent_span failed: {e:#}");
            }
        }
        "SubagentStop" => {
            if let Err(e) = st.store.close_agent_span(&sid, &agent_id, now_ms(), "stop") {
                tracing::debug!("h_sub: close_agent_span failed: {e:#}");
            }
        }
        other => {
            tracing::debug!("h_sub: unknown hook_event_name {other:?}");
        }
    }
    Json(json!({}))
}

/// Log (once per `hook_event_name`, info level) the set of top-level keys
/// present in a SubagentStart/SubagentStop payload — never values, to avoid
/// leaking transcript/cwd contents — so undocumented fields can be verified
/// empirically post-deploy without permanently spamming the log.
fn log_sub_payload_keys_once(st: &AppState, event: &str, v: &Value) {
    if event.is_empty() {
        return;
    }
    let mut seen = st.logged_sub_payload_keys.lock().unwrap();
    if !seen.insert(event.to_string()) {
        return;
    }
    let keys: Vec<&str> = v
        .as_object()
        .map(|o| o.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();
    tracing::info!("h_sub: {event} payload keys: {keys:?}");
}

async fn h_end(State(st): State<AppState>, Json(v): Json<Value>) -> Json<Value> {
    let Some(sid) = s(&v, "session_id") else {
        return Json(json!({}));
    };
    let reason = s(&v, "why");
    {
        let mut corr = st.corr.lock().unwrap();
        corr.end_session(&st.store, &sid, reason.as_deref());
    }
    // Cover subagents whose SubagentStop never arrived (abnormal
    // termination, or a client that just doesn't fire it).
    if let Err(e) = st
        .store
        .close_all_open_agent_spans_for_session(&sid, "session_end")
    {
        tracing::debug!("h_end: close_all_open_agent_spans_for_session failed: {e:#}");
    }
    tracing::info!("session-end {sid}");
    Json(json!({}))
}

// ---------------- api ----------------

async fn api_status(State(st): State<AppState>) -> Json<Value> {
    let (nsess, tracked) = {
        let corr = st.corr.lock().unwrap();
        (
            corr.sessions.len(),
            corr.sessions
                .values()
                .map(|s| s.sticky.len())
                .sum::<usize>(),
        )
    };
    Json(json!({
        "ok": true,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_ms": now_ms() - st.started_at,
        "sessions": nsess,
        "tracked_procs": tracked,
        "sampler_cost_frac": *st.sampler_cost.lock().unwrap(),
    }))
}

/// Fetch per-session token totals, using a short-lived cache since the
/// tailer only writes to llm_usage every ~3s.
fn token_totals(st: &AppState) -> Arc<HashMap<String, TokenTotals>> {
    const TTL: Duration = Duration::from_secs(2);
    {
        let cache = st.token_totals_cache.lock().unwrap();
        if let Some((at, map)) = cache.as_ref() {
            if at.elapsed() < TTL {
                return map.clone();
            }
        }
    }
    let map = Arc::new(st.store.session_token_totals().unwrap_or_default());
    *st.token_totals_cache.lock().unwrap() = Some((Instant::now(), map.clone()));
    map
}

/// Same caching pattern as [`token_totals`], for the per-agent breakdown.
fn agent_token_totals(st: &AppState) -> Arc<HashMap<(String, Option<String>), TokenTotals>> {
    const TTL: Duration = Duration::from_secs(2);
    {
        let cache = st.agent_totals_cache.lock().unwrap();
        if let Some((at, map)) = cache.as_ref() {
            if at.elapsed() < TTL {
                return map.clone();
            }
        }
    }
    let map = Arc::new(st.store.session_agent_token_totals().unwrap_or_default());
    *st.agent_totals_cache.lock().unwrap() = Some((Instant::now(), map.clone()));
    map
}

/// Same caching pattern as [`token_totals`], for the last-10-per-session
/// closed spans used to populate each agent's "recent spans" in the tree.
fn recent_spans(st: &AppState) -> Arc<HashMap<String, Vec<RecentSpanRow>>> {
    const TTL: Duration = Duration::from_secs(2);
    {
        let cache = st.recent_spans_cache.lock().unwrap();
        if let Some((at, map)) = cache.as_ref() {
            if at.elapsed() < TTL {
                return map.clone();
            }
        }
    }
    let map = Arc::new(st.store.recent_spans_all_sessions(10).unwrap_or_default());
    *st.recent_spans_cache.lock().unwrap() = Some((Instant::now(), map.clone()));
    map
}

/// Same caching pattern as [`token_totals`], for `agent_span` start/end
/// times — feeds each agent row's TIME column in the collapsible tree.
fn agent_span_times(st: &AppState) -> Arc<AgentSpanTimes> {
    const TTL: Duration = Duration::from_secs(2);
    {
        let cache = st.agent_span_times_cache.lock().unwrap();
        if let Some((at, map)) = cache.as_ref() {
            if at.elapsed() < TTL {
                return map.clone();
            }
        }
    }
    let map = Arc::new(st.store.agent_span_times().unwrap_or_default());
    *st.agent_span_times_cache.lock().unwrap() = Some((Instant::now(), map.clone()));
    map
}

#[derive(Default)]
struct AgentBucket {
    agent_type: Option<String>,
    cost_usd: f64,
    tokens_out: i64,
    open: Vec<Value>,
    recent: Vec<Value>,
    started_at: Option<i64>,
    ended_at: Option<i64>,
}

/// Build the "agents" array for one session: open spans (live, from the
/// correlator) and recent closed spans (from `tool_span`), grouped by
/// agent_id (None = main agent), plus each agent's token/cost totals and
/// (when an `agent_span` row exists) its lifetime started_at/ended_at.
/// Only agents with at least one span or some tokens are included.
fn build_agents(
    sess: &Session,
    agent_totals: &HashMap<(String, Option<String>), TokenTotals>,
    recent_spans_by_session: &HashMap<String, Vec<RecentSpanRow>>,
    agent_span_times: &AgentSpanTimes,
) -> Vec<Value> {
    let now = now_ms();
    let mut buckets: HashMap<Option<String>, AgentBucket> = HashMap::new();

    for span in &sess.open_spans {
        let b = buckets.entry(span.agent_id.clone()).or_default();
        if b.agent_type.is_none() {
            b.agent_type = span.agent_type.clone();
        }
        b.open.push(open_span_json(span, now));
    }

    if let Some(rows) = recent_spans_by_session.get(&sess.id) {
        for r in rows {
            let b = buckets.entry(r.agent_id.clone()).or_default();
            if b.agent_type.is_none() {
                b.agent_type = r.agent_type.clone();
            }
            b.recent.push(json!({
                "span_id": r.span_id,
                "tool_name": r.tool_name,
                "cmd_digest": r.cmd_digest,
                "duration_s": r.duration_ms as f64 / 1000.0,
                "cpu_s": r.cpu_ns as f64 / 1e9,
                "peak_mb": r.peak_footprint / 1_000_000,
                "ok": r.ok,
                "leaked_count": r.leaked_count,
                "running": false,
                "pid": Value::Null,
            }));
        }
    }

    for ((sid, agent_id), totals) in agent_totals {
        if sid != &sess.id {
            continue;
        }
        let b = buckets.entry(agent_id.clone()).or_default();
        b.cost_usd = totals.cost_usd;
        b.tokens_out = totals.output_tokens;
    }

    for ((sid, agent_id), (started_at, ended_at)) in agent_span_times {
        if sid != &sess.id {
            continue;
        }
        let b = buckets.entry(Some(agent_id.clone())).or_default();
        b.started_at = Some(*started_at);
        b.ended_at = *ended_at;
    }

    let mut keys: Vec<Option<String>> = buckets.keys().cloned().collect();
    keys.sort_by(|a, b| match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    });

    keys.into_iter()
        .map(|k| {
            let b = buckets.remove(&k).unwrap();
            let duration_s = b
                .started_at
                .map(|start| ((b.ended_at.unwrap_or(now) - start).max(0)) as f64 / 1000.0);
            json!({
                "agent_id": k,
                "agent_type": b.agent_type,
                "cost_usd": (b.cost_usd * 100.0).round() / 100.0,
                "tokens_out": b.tokens_out,
                "open_spans": b.open,
                "recent_spans": b.recent,
                "started_at": b.started_at,
                "ended_at": b.ended_at,
                "duration_s": duration_s,
            })
        })
        .collect()
}

/// JSON for one live/open span: elapsed time, sampled cpu-seconds and peak
/// footprint summed over its currently-attributed processes, and the pid of
/// its heaviest (most cpu-ns) live process, if any.
fn open_span_json(span: &Span, now: i64) -> Value {
    let mut cpu_ns_total: u64 = 0;
    let mut peak: u64 = 0;
    let mut heaviest: Option<(i32, u64)> = None;
    for (pid, agg) in &span.procs {
        let cpu = agg.last_usage.cpu_user_ns + agg.last_usage.cpu_sys_ns;
        cpu_ns_total += cpu;
        peak = peak.max(agg.peak_footprint);
        if heaviest.map(|(_, c)| cpu > c).unwrap_or(true) {
            heaviest = Some((*pid, cpu));
        }
    }
    json!({
        "tool_use_id": span.tool_use_id,
        "tool_name": span.tool_name,
        "cmd_digest": span.cmd_digest,
        "duration_s": ((now - span.started_at).max(0)) as f64 / 1000.0,
        "cpu_s": cpu_ns_total as f64 / 1e9,
        "peak_mb": peak / 1_000_000,
        "ok": Value::Null,
        "leaked_count": 0,
        "running": true,
        "pid": heaviest.map(|(pid, _)| pid),
    })
}

async fn api_top(State(st): State<AppState>) -> Json<Value> {
    // Query the store outside the correlator lock.
    let totals = token_totals(&st);
    let agent_totals = agent_token_totals(&st);
    let recent = recent_spans(&st);
    let agent_times = agent_span_times(&st);
    let now = now_ms();
    let sessions: Vec<Value> = {
        let corr = st.corr.lock().unwrap();
        let mut rows: Vec<_> = corr.sessions.values().collect();
        rows.sort_by(|a, b| {
            b.cpu_pct
                .partial_cmp(&a.cpu_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        rows.iter()
            .map(|s| {
                let t = totals.get(&s.id);
                let tokens_in = t.map(|t| t.input_tokens).unwrap_or(0);
                let tokens_out = t.map(|t| t.output_tokens).unwrap_or(0);
                let cache_read = t.map(|t| t.cache_read).unwrap_or(0);
                let cost_usd = t
                    .map(|t| (t.cost_usd * 100.0).round() / 100.0)
                    .unwrap_or(0.0);
                let unpriced = t.map(|t| t.unpriced).unwrap_or(0);
                json!({
                    "session_id": s.id,
                    "project": s.project_root.as_deref()
                        .and_then(|r| r.rsplit('/').next()).unwrap_or("?"),
                    "project_root": s.project_root,
                    "claude_pid": s.claude_pid,
                    "started_at": s.started_at,
                    "duration_s": ((now - s.started_at).max(0)) as f64 / 1000.0,
                    "cpu_pct": (s.cpu_pct * 10.0).round() / 10.0,
                    "footprint_mb": s.footprint / 1_000_000,
                    "procs": s.proc_count,
                    "current_tool": s.current_tool,
                    "open_spans": s.open_spans.len(),
                    "tokens_in": tokens_in,
                    "tokens_out": tokens_out,
                    "cache_read": cache_read,
                    "cost_usd": cost_usd,
                    "unpriced": unpriced,
                    "agents": build_agents(s, &agent_totals, &recent, &agent_times),
                })
            })
            .collect()
    };
    let findings = st
        .store
        .recent_findings(10)
        .unwrap_or_default()
        .into_iter()
        .map(
            |(ts, kind, sev, msg)| json!({"ts": ts, "kind": kind, "severity": sev, "message": msg}),
        )
        .collect::<Vec<_>>();
    Json(json!({ "sessions": sessions, "findings": findings }))
}

// ---------------- historical dashboard ----------------

async fn dashboard_html() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

#[derive(Deserialize)]
struct HistoryParams {
    days: Option<i64>,
    project: Option<String>,
}

async fn api_history(
    State(st): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> axum::response::Response {
    let days = crate::history::clamp_days(params.days);
    let store = st.dashboard_store.clone();
    let db_path = st.db_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        crate::history::build_history(&store, days, params.project.as_deref())
    })
    .await;
    match result {
        Ok(Ok(mut v)) => {
            let (path, size_mb) = db_info(&db_path);
            v["db"] = json!({ "path": path, "size_mb": size_mb });
            Json(v).into_response()
        }
        Ok(Err(e)) => {
            tracing::warn!("api_history: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "history query failed").into_response()
        }
        Err(e) => {
            tracing::warn!("api_history: join error {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "history query failed").into_response()
        }
    }
}

async fn api_session(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let store = st.dashboard_store.clone();
    let result =
        tokio::task::spawn_blocking(move || crate::history::build_session(&store, &id)).await;
    match result {
        Ok(Ok(Some(v))) => Json(v).into_response(),
        Ok(Ok(None)) => (StatusCode::NOT_FOUND, "session not found").into_response(),
        Ok(Err(e)) => {
            tracing::warn!("api_session: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "session query failed").into_response()
        }
        Err(e) => {
            tracing::warn!("api_session: join error {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, "session query failed").into_response()
        }
    }
}

/// Real db path + on-disk size in MB, for the dashboard's header note.
fn db_info(db_path: &std::path::Path) -> (String, f64) {
    let size_mb = std::fs::metadata(db_path)
        .map(|m| (m.len() as f64 / 1_000_000.0 * 10.0).round() / 10.0)
        .unwrap_or(0.0);
    (db_path.display().to_string(), size_mb)
}
