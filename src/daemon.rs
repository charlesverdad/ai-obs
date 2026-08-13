//! The ai-obs daemon: HTTP hook endpoint + adaptive sampler + detectors.

use crate::correlator::{snapshot_map, Correlator};
use crate::store::{now_ms, Store};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 8770;

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
}

pub async fn run(db_path: &std::path::Path) -> anyhow::Result<()> {
    let store = Arc::new(Store::open(db_path)?);
    let corr = Arc::new(Mutex::new(Correlator::default()));
    let state = AppState {
        store: store.clone(),
        corr: corr.clone(),
        started_at: now_ms(),
        sampler_cost: Arc::new(Mutex::new(0.0)),
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
        .route("/h/session-start", post(h_session_start))
        .route("/h/pre", post(h_pre))
        .route("/h/post", post(h_post))
        .route("/h/sub", post(h_sub))
        .route("/h/end", post(h_end))
        .route("/api/status", get(api_status))
        .route("/api/top", get(api_top))
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("ai-obs daemon listening on {addr}, db {}", db_path.display());
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
                let _ = state.store.insert_session_sample(&sid, now / 1000, cpu, fp, n);
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

async fn detector_loop(state: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let now = now_ms();
        let procs = tokio::task::spawn_blocking(snapshot_map)
            .await
            .unwrap_or_default();
        let mut findings: Vec<(String, String, Option<String>, Option<i64>, Option<i32>, String)> =
            Vec::new();
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
                sess.orphan_watch.retain(|w| !w.reported || procs.contains_key(&w.pid));

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
    let claude_pid = v.get("claude_pid").and_then(|x| x.as_i64()).map(|x| x as i32);
    {
        let mut corr = st.corr.lock().unwrap();
        let sess = corr.ensure_session(&sid, cwd.as_deref(), claude_pid);
        if claude_pid.is_some() {
            sess.claude_pid = claude_pid;
        }
        let root = sess.project_root.clone();
        let project_id = root.as_deref().and_then(|r| st.store.upsert_project(r).ok());
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
        corr.open_span(
            &sid,
            cwd.as_deref(),
            tool_use_id,
            tool_name,
            command.as_deref(),
            agent_id,
            agent_type,
            &procs,
        );
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

async fn h_sub(State(_st): State<AppState>, Json(_v): Json<Value>) -> Json<Value> {
    // Subagent lifecycle is informational; tool events already carry
    // agent_id/agent_type. Kept as an endpoint for forward-compat.
    Json(json!({}))
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
    tracing::info!("session-end {sid}");
    Json(json!({}))
}

// ---------------- api ----------------

async fn api_status(State(st): State<AppState>) -> Json<Value> {
    let (nsess, tracked) = {
        let corr = st.corr.lock().unwrap();
        (
            corr.sessions.len(),
            corr.sessions.values().map(|s| s.sticky.len()).sum::<usize>(),
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

async fn api_top(State(st): State<AppState>) -> Json<Value> {
    let sessions: Vec<Value> = {
        let corr = st.corr.lock().unwrap();
        let mut rows: Vec<_> = corr.sessions.values().collect();
        rows.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
        rows.iter()
            .map(|s| {
                json!({
                    "session_id": s.id,
                    "project": s.project_root.as_deref()
                        .and_then(|r| r.rsplit('/').next()).unwrap_or("?"),
                    "project_root": s.project_root,
                    "claude_pid": s.claude_pid,
                    "cpu_pct": (s.cpu_pct * 10.0).round() / 10.0,
                    "footprint_mb": s.footprint / 1_000_000,
                    "procs": s.proc_count,
                    "current_tool": s.current_tool,
                    "open_spans": s.open_spans.len(),
                })
            })
            .collect()
    };
    let findings = st
        .store
        .recent_findings(10)
        .unwrap_or_default()
        .into_iter()
        .map(|(ts, kind, sev, msg)| json!({"ts": ts, "kind": kind, "severity": sev, "message": msg}))
        .collect::<Vec<_>>();
    Json(json!({ "sessions": sessions, "findings": findings }))
}
