//! Aggregate queries backing the historical web dashboard
//! (`GET /api/history`, `GET /api/session/{id}`). Runs entirely against a
//! dedicated read-only `Store` connection — see daemon.rs's `dashboard_store`.
//!
//! Date bucketing is by LOCAL calendar day (`date(ts/1000,'unixepoch','localtime')`)
//! per the dashboard spec. Range boundaries (`cur_start`/`cur_end`/`prev_start`/
//! `prev_end`, all `YYYY-MM-DD` strings in local time) are computed once via
//! SQLite's own `date('now','localtime',...)` and then reused as plain bound
//! parameters in every subsequent query, so all queries agree on exactly the
//! same calendar days.

use crate::store::Store;
use anyhow::Result;
use rusqlite::types::ToSql;
use serde_json::{json, Value};
use std::collections::HashMap;

/// Clamp a user-supplied `days` query param to something sane.
pub fn clamp_days(days: Option<i64>) -> i64 {
    days.unwrap_or(30).clamp(1, 3650)
}

struct Bounds {
    cur_start: String,
    cur_end: String,
    prev_start: String,
    /// Day before `cur_start` — the end of the previous window. Kept for
    /// documentation/symmetry with `prev_start`; the KPI/day queries below
    /// infer "previous window" as "in `[prev_start,cur_end]` but not in
    /// `[cur_start,cur_end]`", so this isn't bound as a separate parameter.
    #[allow(dead_code)]
    prev_end: String,
}

fn compute_bounds(store: &Store, days: i64) -> Result<Bounds> {
    let m_cur_start = format!("-{} days", days - 1);
    let m_prev_start = format!("-{} days", 2 * days - 1);
    let m_prev_end = format!("-{} days", days);
    let rows = store.query_json(
        "SELECT date('now','localtime',?1) cur_start,
                date('now','localtime') cur_end,
                date('now','localtime',?2) prev_start,
                date('now','localtime',?3) prev_end",
        &[
            &m_cur_start as &dyn ToSql,
            &m_prev_start as &dyn ToSql,
            &m_prev_end as &dyn ToSql,
        ],
    )?;
    let r = &rows[0];
    Ok(Bounds {
        cur_start: r["cur_start"].as_str().unwrap_or_default().to_string(),
        cur_end: r["cur_end"].as_str().unwrap_or_default().to_string(),
        prev_start: r["prev_start"].as_str().unwrap_or_default().to_string(),
        prev_end: r["prev_end"].as_str().unwrap_or_default().to_string(),
    })
}

fn f(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0)
}
fn i(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Build the full `/api/history` response.
pub fn build_history(store: &Store, days: i64, project: Option<&str>) -> Result<Value> {
    let b = compute_bounds(store, days)?;
    let proj: Option<String> = project.map(|s| s.to_string());
    let now = crate::store::now_ms();

    // ---- kpis + days, llm_usage part ----
    // llm_usage alone can be hundreds of thousands of rows, so it is scanned
    // exactly ONCE (grouped by local day, covering both the current and
    // previous windows) rather than once per metric or once per day — both
    // the per-day bars and the range totals are derived from that single
    // result set in Rust. This dashboard must answer in well under a second.
    let llm_days = store.query_json(
        "SELECT date(u.ts/1000,'unixepoch','localtime') day,
           SUM(u.cost_usd) cost, SUM(u.input_tokens) tokens_in, SUM(u.output_tokens) tokens_out,
           SUM(u.cache_read) cache_read,
           SUM(CASE WHEN u.cost_usd IS NULL THEN 1 ELSE 0 END) unpriced
         FROM llm_usage u JOIN session s ON s.id=u.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(u.ts/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY day",
        &[
            &proj as &dyn ToSql,
            &b.prev_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;
    let mut cur_cost = 0.0f64;
    let mut prev_cost = 0.0f64;
    let mut cur_tokens_in = 0i64;
    let mut cur_tokens_out = 0i64;
    let mut cur_cache_read = 0i64;
    let mut cur_unpriced = 0i64;
    let mut llm_cost_by_day: HashMap<String, f64> = HashMap::new();
    let mut llm_tokens_by_day: HashMap<String, f64> = HashMap::new();
    for r in &llm_days {
        let day = r["day"].as_str().unwrap_or_default().to_string();
        let cost = f(r, "cost");
        let tokens_in = i(r, "tokens_in");
        let tokens_out = i(r, "tokens_out");
        if day.as_str() >= b.cur_start.as_str() && day.as_str() <= b.cur_end.as_str() {
            cur_cost += cost;
            cur_tokens_in += tokens_in;
            cur_tokens_out += tokens_out;
            cur_cache_read += i(r, "cache_read");
            cur_unpriced += i(r, "unpriced");
            llm_cost_by_day.insert(day.clone(), cost);
            llm_tokens_by_day.insert(day, (tokens_in + tokens_out) as f64);
        } else {
            prev_cost += cost;
        }
    }

    let span_kpi_rows = store.query_json(
        "SELECT
           COALESCE(SUM(COALESCE(t.cpu_ns,t.cpu_ns_sampled)),0)/3.6e12 core_hours,
           COALESCE(SUM(t.leaked_count),0) leaked_procs,
           COALESCE(SUM(CASE WHEN t.leaked_count>0 THEN 1 ELSE 0 END),0) leaked_spans
         FROM tool_span t JOIN session s ON s.id=t.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(t.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;
    let finding_kpi_rows = store.query_json(
        "SELECT
           COALESCE(SUM(CASE WHEN f.severity='crit' THEN 1 ELSE 0 END),0) findings_crit,
           COALESCE(SUM(CASE WHEN f.severity='warn' THEN 1 ELSE 0 END),0) findings_warn,
           COUNT(DISTINCT f.session_id) finding_sessions
         FROM finding f LEFT JOIN session s ON s.id=f.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(f.ts/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;
    let (span_k, finding_k) = (&span_kpi_rows[0], &finding_kpi_rows[0]);

    // ---- days (zero-filled bar chart buckets) ----
    // tool_span/session/finding are each scanned once with GROUP BY day, not
    // once per day (the naive per-day correlated-subquery form is O(days)
    // full scans); llm_usage's per-day breakdown was already computed above.
    let span_days = store.query_json(
        "SELECT date(t.started_at/1000,'unixepoch','localtime') day,
           SUM(COALESCE(t.cpu_ns,t.cpu_ns_sampled))/3.6e12 core_hours
         FROM tool_span t JOIN session s ON s.id=t.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(t.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY day",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;
    let session_days = store.query_json(
        "SELECT date(s.started_at/1000,'unixepoch','localtime') day, COUNT(DISTINCT s.id) sessions
         FROM session s LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(s.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY day",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;
    let finding_days = store.query_json(
        "SELECT date(f.ts/1000,'unixepoch','localtime') day, COUNT(*) orphan_findings
         FROM finding f LEFT JOIN session s ON s.id=f.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE f.kind='orphan' AND (?1 IS NULL OR p.name=?1)
           AND date(f.ts/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY day",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;
    let day_rows = store.query_json(
        "WITH RECURSIVE d(day) AS (
           SELECT ?1
           UNION ALL SELECT date(day,'+1 day') FROM d WHERE day < ?2
         )
         SELECT day FROM d ORDER BY day",
        &[&b.cur_start as &dyn ToSql, &b.cur_end as &dyn ToSql],
    )?;
    let by_day = |rows: &[Value], key: &str| -> HashMap<String, f64> {
        rows.iter()
            .map(|r| (r["day"].as_str().unwrap_or_default().to_string(), f(r, key)))
            .collect()
    };
    let cpu_by_day = by_day(&span_days, "core_hours");
    let sessions_by_day = by_day(&session_days, "sessions");
    let orphans_by_day = by_day(&finding_days, "orphan_findings");

    let mut days_out = Vec::new();
    let mut busiest_day = String::new();
    let mut busiest_core_hours = -1.0f64;
    for r in &day_rows {
        let day = r["day"].as_str().unwrap_or_default().to_string();
        let core_hours = *cpu_by_day.get(&day).unwrap_or(&0.0);
        if core_hours > busiest_core_hours {
            busiest_core_hours = core_hours;
            busiest_day = day.clone();
        }
        days_out.push(json!({
            "date": day,
            "cost": round2(*llm_cost_by_day.get(&day).unwrap_or(&0.0)),
            "core_hours": round2(core_hours),
            "tokens": *llm_tokens_by_day.get(&day).unwrap_or(&0.0) as i64,
            "sessions": *sessions_by_day.get(&day).unwrap_or(&0.0) as i64,
            "orphan_findings": *orphans_by_day.get(&day).unwrap_or(&0.0) as i64,
        }));
    }

    // ---- by_project ----
    let by_project = store.query_json(
        "SELECT p.name project, COUNT(DISTINCT u.session_id) sessions,
           COALESCE(SUM(u.input_tokens),0) tokens_in, COALESCE(SUM(u.output_tokens),0) tokens_out,
           COALESCE(SUM(u.cost_usd),0) cost,
           SUM(CASE WHEN u.cost_usd IS NULL THEN 1 ELSE 0 END) unpriced
         FROM llm_usage u JOIN session s ON s.id=u.session_id JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(u.ts/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY p.name ORDER BY cost DESC LIMIT 12",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;

    // ---- by_resource ----
    let by_resource = store.query_json(
        "SELECT p.name project, COUNT(*) calls,
           COALESCE(SUM(COALESCE(t.cpu_ns,t.cpu_ns_sampled)),0)/1e9 cpu_s,
           COALESCE(MAX(t.peak_footprint),0)/1e6 peak_mb,
           COALESCE(SUM(t.leaked_count),0) leaked
         FROM tool_span t JOIN session s ON s.id=t.session_id JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(t.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY p.name ORDER BY cpu_s DESC LIMIT 12",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;

    // ---- heaviest ----
    let heaviest = store.query_json(
        "SELECT t.tool_name tool, COALESCE(t.cmd_digest,'') cmd, COUNT(*) calls,
           COALESCE(SUM(COALESCE(t.cpu_ns,t.cpu_ns_sampled)),0)/1e9 cpu_s,
           COALESCE(MAX(t.peak_footprint),0)/1e6 peak_mb,
           COALESCE(SUM(t.leaked_count),0) leaked
         FROM tool_span t JOIN session s ON s.id=t.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(t.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY t.tool_name, t.cmd_digest ORDER BY cpu_s DESC LIMIT 8",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;

    // ---- by_model ----
    let by_model = store.query_json(
        "SELECT u.model model, COALESCE(SUM(u.input_tokens),0) tokens_in,
           COALESCE(SUM(u.output_tokens),0) tokens_out,
           COALESCE(SUM(u.cache_read),0) cache, COALESCE(SUM(u.cost_usd),0) cost
         FROM llm_usage u JOIN session s ON s.id=u.session_id LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(u.ts/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         GROUP BY u.model ORDER BY cost DESC",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;

    // ---- findings ----
    let findings = store.query_json(
        "SELECT f.ts ts, f.kind kind, f.severity severity, f.message message
         FROM finding f LEFT JOIN session s ON s.id=f.session_id
           LEFT JOIN project p ON p.id=s.project_id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(f.ts/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         ORDER BY f.ts DESC LIMIT 8",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
        ],
    )?;

    // ---- sessions ----
    let sessions = store.query_json(
        "SELECT s.id id, s.started_at started_at, s.ended_at ended_at, p.name project,
           s.git_branch branch, s.pr_number pr_number,
           CAST((COALESCE(s.ended_at, ?4) - s.started_at)/1000 AS INTEGER) duration_s,
           COALESCE(ts.calls,0) calls, COALESCE(ts.cpu_s,0) cpu_s, COALESCE(ts.peak_mb,0) peak_mb,
           COALESCE(u.tokens_out,0) tokens_out, COALESCE(u.cost,0) cost, COALESCE(u.unpriced,0) unpriced,
           s.end_reason end_reason, COALESCE(ts.leaked,0) leaked, COALESCE(ts.failed,0) failed,
           EXISTS(SELECT 1 FROM session_sample ss WHERE ss.session_id = s.id) has_samples
         FROM session s
         LEFT JOIN project p ON p.id = s.project_id
         LEFT JOIN (
           SELECT session_id, COUNT(*) calls, SUM(COALESCE(cpu_ns,cpu_ns_sampled))/1e9 cpu_s,
             MAX(peak_footprint)/1e6 peak_mb, SUM(leaked_count) leaked,
             SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END) failed
           FROM tool_span
           WHERE session_id IN (
             SELECT s2.id FROM session s2 LEFT JOIN project p2 ON p2.id = s2.project_id
             WHERE (?1 IS NULL OR p2.name=?1)
               AND date(s2.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
           )
           GROUP BY session_id
         ) ts ON ts.session_id = s.id
         LEFT JOIN (
           SELECT session_id, SUM(output_tokens) tokens_out, SUM(cost_usd) cost,
             SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) unpriced
           FROM llm_usage
           WHERE session_id IN (
             SELECT s2.id FROM session s2 LEFT JOIN project p2 ON p2.id = s2.project_id
             WHERE (?1 IS NULL OR p2.name=?1)
               AND date(s2.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
           )
           GROUP BY session_id
         ) u ON u.session_id = s.id
         WHERE (?1 IS NULL OR p.name=?1)
           AND date(s.started_at/1000,'unixepoch','localtime') BETWEEN ?2 AND ?3
         ORDER BY s.started_at DESC LIMIT 60",
        &[
            &proj as &dyn ToSql,
            &b.cur_start as &dyn ToSql,
            &b.cur_end as &dyn ToSql,
            &now as &dyn ToSql,
        ],
    )?;
    let session_count = sessions.len();
    let span_count: i64 = sessions.iter().map(|s| i(s, "calls")).sum();

    Ok(json!({
        "range": { "days": days, "start": b.cur_start, "end": b.cur_end },
        "session_count": session_count,
        "span_count": span_count,
        "kpis": {
            "cost_usd": round2(cur_cost),
            "prev_cost_usd": round2(prev_cost),
            "core_hours": round2(f(span_k, "core_hours")),
            "tokens_in": cur_tokens_in,
            "tokens_out": cur_tokens_out,
            "cache_read": cur_cache_read,
            "unpriced_msgs": cur_unpriced,
            "leaked_procs": i(span_k, "leaked_procs"),
            "leaked_spans": i(span_k, "leaked_spans"),
            "findings_crit": i(finding_k, "findings_crit"),
            "findings_warn": i(finding_k, "findings_warn"),
            "finding_sessions": i(finding_k, "finding_sessions"),
            "busiest_day": busiest_day,
        },
        "days": days_out,
        "by_project": by_project,
        "by_resource": by_resource,
        "heaviest": heaviest,
        "by_model": by_model,
        "findings": findings,
        "sessions": sessions,
    }))
}

/// One session_sample row.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    pub t: i64,
    pub cpu_pct: f64,
    pub footprint: f64,
}

/// Downsample `samples` (already ordered by `t`) to at most `max_points` by
/// averaging fixed-size buckets. A no-op when already within budget.
pub fn downsample(samples: &[Sample], max_points: usize) -> Vec<Sample> {
    if max_points == 0 || samples.is_empty() || samples.len() <= max_points {
        return samples.to_vec();
    }
    let bucket = samples.len().div_ceil(max_points);
    let mut out = Vec::with_capacity(samples.len().div_ceil(bucket));
    for chunk in samples.chunks(bucket) {
        let n = chunk.len() as f64;
        let t = chunk.iter().map(|s| s.t).sum::<i64>() / chunk.len() as i64;
        let cpu_pct = chunk.iter().map(|s| s.cpu_pct).sum::<f64>() / n;
        let footprint = chunk.iter().map(|s| s.footprint).sum::<f64>() / n;
        out.push(Sample {
            t,
            cpu_pct,
            footprint,
        });
    }
    out
}

/// `n/2` — the OFFSET used to pick the median of `n` ORDER BY'd rows
/// (upper median for even `n`, exact for odd `n`).
pub fn median_offset(n: usize) -> usize {
    n / 2
}

/// Median of a metric across a slice of values (sorted internally). Returns
/// 0.0 for an empty slice.
fn median_of(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    values[median_offset(values.len())]
}

/// Build the `/api/session/{id}` response. Returns `Ok(None)` if the session
/// doesn't exist.
pub fn build_session(store: &Store, id: &str) -> Result<Option<Value>> {
    let facts_rows = store.query_json(
        "SELECT s.id id, p.name project, p.root project_root, s.git_branch branch,
           s.pr_number pr_number, s.pr_url pr_url, s.claude_pid claude_pid, s.cc_version cc_version,
           s.started_at started_at, s.ended_at ended_at, s.end_reason end_reason,
           COALESCE(ts.calls,0) calls,
           COALESCE(u.tokens_in,0) tokens_in, COALESCE(u.tokens_out,0) tokens_out,
           COALESCE(u.cache,0) cache_read, COALESCE(u.cost,0) cost, COALESCE(u.unpriced,0) unpriced,
           s.project_id project_id
         FROM session s
         LEFT JOIN project p ON p.id = s.project_id
         LEFT JOIN (SELECT session_id, COUNT(*) calls FROM tool_span GROUP BY session_id) ts
           ON ts.session_id = s.id
         LEFT JOIN (
           SELECT session_id, SUM(input_tokens) tokens_in, SUM(output_tokens) tokens_out,
             SUM(cache_read) cache, SUM(cost_usd) cost,
             SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) unpriced
           FROM llm_usage GROUP BY session_id
         ) u ON u.session_id = s.id
         WHERE s.id = ?1",
        &[&id as &dyn ToSql],
    )?;
    let Some(facts) = facts_rows.into_iter().next() else {
        return Ok(None);
    };
    let project_id = facts.get("project_id").and_then(|v| v.as_i64());

    // ---- samples ----
    let sample_rows = store.query_json(
        "SELECT t, cpu_pct, footprint FROM session_sample WHERE session_id=?1 ORDER BY t",
        &[&id as &dyn ToSql],
    )?;
    let samples: Vec<Sample> = sample_rows
        .iter()
        .map(|r| Sample {
            t: i(r, "t"),
            cpu_pct: f(r, "cpu_pct"),
            footprint: f(r, "footprint"),
        })
        .collect();
    let samples_out: Vec<Value> = downsample(&samples, 600)
        .into_iter()
        .map(|s| json!({"t": s.t, "cpu_pct": round2(s.cpu_pct), "footprint": s.footprint as i64}))
        .collect();

    // ---- spans ----
    let total_spans: i64 = store
        .query_json(
            "SELECT COUNT(*) n FROM tool_span WHERE session_id=?1",
            &[&id as &dyn ToSql],
        )?
        .first()
        .map(|r| i(r, "n"))
        .unwrap_or(0);
    let spans = store.query_json(
        "SELECT tool_name tool, COALESCE(cmd_digest,'') cmd, agent_type agent_type,
           started_at started_at, ended_at ended_at,
           COALESCE(cpu_ns,cpu_ns_sampled)/1e9 cpu_s, COALESCE(peak_footprint,0)/1e6 peak_mb,
           ok ok, leaked_count leaked
         FROM tool_span WHERE session_id=?1 ORDER BY started_at LIMIT 200",
        &[&id as &dyn ToSql],
    )?;

    // ---- tree: proc_stat of the heaviest span ----
    let heaviest_span = store.query_json(
        "SELECT id, COALESCE(cmd_digest,'') cmd FROM tool_span WHERE session_id=?1
         ORDER BY COALESCE(cpu_ns,cpu_ns_sampled) DESC LIMIT 1",
        &[&id as &dyn ToSql],
    )?;
    let (tree, tree_cmd) = if let Some(row) = heaviest_span.first() {
        let span_id = i(row, "id");
        let cmd = row["cmd"].as_str().unwrap_or_default().to_string();
        let procs = store.query_json(
            "SELECT depth, comm, name, (COALESCE(cpu_user_ns,0)+COALESCE(cpu_sys_ns,0))/1e9 cpu_s,
               COALESCE(peak_footprint,0)/1e6 peak_mb, orphaned
             FROM proc_stat WHERE span_id=?1 ORDER BY depth, pid",
            &[&span_id as &dyn ToSql],
        )?;
        (procs, cmd)
    } else {
        (Vec::new(), String::new())
    };

    // ---- medians: this project's per-session metrics, all time ----
    let mut this_session = json!({"cost": 0.0, "cpu_s": 0.0, "peak_mb": 0.0, "calls": 0.0});
    let mut medians = json!({"cost": 0.0, "cpu_s": 0.0, "peak_mb": 0.0, "calls": 0.0});
    if let Some(pid) = project_id {
        let per_session = store.query_json(
            "SELECT s2.id id,
               COALESCE((SELECT SUM(cost_usd) FROM llm_usage WHERE session_id=s2.id),0) cost,
               COALESCE((SELECT SUM(COALESCE(cpu_ns,cpu_ns_sampled)) FROM tool_span WHERE session_id=s2.id),0)/1e9 cpu_s,
               COALESCE((SELECT MAX(peak_footprint) FROM tool_span WHERE session_id=s2.id),0)/1e6 peak_mb,
               COALESCE((SELECT COUNT(*) FROM tool_span WHERE session_id=s2.id),0) calls
             FROM session s2 WHERE s2.project_id = ?1",
            &[&pid as &dyn ToSql],
        )?;
        let mut costs: Vec<f64> = per_session.iter().map(|r| f(r, "cost")).collect();
        let mut cpus: Vec<f64> = per_session.iter().map(|r| f(r, "cpu_s")).collect();
        let mut peaks: Vec<f64> = per_session.iter().map(|r| f(r, "peak_mb")).collect();
        let mut calls: Vec<f64> = per_session.iter().map(|r| f(r, "calls")).collect();
        medians = json!({
            "cost": median_of(&mut costs),
            "cpu_s": median_of(&mut cpus),
            "peak_mb": median_of(&mut peaks),
            "calls": median_of(&mut calls),
        });
        if let Some(mine) = per_session.iter().find(|r| r["id"].as_str() == Some(id)) {
            this_session = json!({
                "cost": f(mine, "cost"),
                "cpu_s": f(mine, "cpu_s"),
                "peak_mb": f(mine, "peak_mb"),
                "calls": f(mine, "calls"),
            });
        }
    }

    Ok(Some(json!({
        "facts": {
            "id": facts["id"],
            "project": facts["project"],
            "project_root": facts["project_root"],
            "branch": facts["branch"],
            "pr_number": facts["pr_number"],
            "pr_url": facts["pr_url"],
            "claude_pid": facts["claude_pid"],
            "cc_version": facts["cc_version"],
            "started_at": facts["started_at"],
            "ended_at": facts["ended_at"],
            "end_reason": facts["end_reason"],
            "calls": facts["calls"],
            "tokens_in": facts["tokens_in"],
            "tokens_out": facts["tokens_out"],
            "cache_read": facts["cache_read"],
            "cost": round2(f(&facts, "cost")),
            "unpriced": facts["unpriced"],
        },
        "samples": samples_out,
        "spans": spans,
        "spans_total": total_spans,
        "tree": { "cmd": tree_cmd, "procs": tree },
        "medians": { "project": medians, "session": this_session },
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{LlmUsageRecord, ProcRecord, SpanRecord};

    fn scratch() -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!(
            "ai-obs-history-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let store = Store::open(&db).unwrap();
        (dir, store)
    }

    #[test]
    fn downsample_noop_under_budget() {
        let samples: Vec<Sample> = (0..10)
            .map(|i| Sample {
                t: i,
                cpu_pct: i as f64,
                footprint: (i * 100) as f64,
            })
            .collect();
        let out = downsample(&samples, 600);
        assert_eq!(out, samples);
    }

    #[test]
    fn downsample_averages_buckets() {
        // 1200 points -> bucket size 2 -> 600 points, each the average of a pair.
        let samples: Vec<Sample> = (0..1200)
            .map(|i| Sample {
                t: i,
                cpu_pct: i as f64,
                footprint: 0.0,
            })
            .collect();
        let out = downsample(&samples, 600);
        assert!(out.len() <= 600);
        assert_eq!(out.len(), 600);
        // First bucket averages t=0,1 -> cpu_pct 0.5
        assert!((out[0].cpu_pct - 0.5).abs() < 1e-9);
        assert_eq!(out[0].t, 0); // integer average of 0 and 1 truncates to 0
    }

    #[test]
    fn median_offset_matches_spec() {
        assert_eq!(median_offset(1), 0);
        assert_eq!(median_offset(3), 1);
        assert_eq!(median_offset(4), 2); // upper median for even n
        assert_eq!(median_offset(5), 2);
    }

    #[test]
    fn session_project_medians_against_scratch_db() {
        let (dir, store) = scratch();
        let pid = store.upsert_project("/tmp/proj-median").unwrap();
        // Three sessions in the same project with cost 10, 20, 30 -> median 20.
        for (n, cost) in [("s1", 10.0), ("s2", 20.0), ("s3", 30.0)] {
            store
                .upsert_session(n, Some(pid), None, None, None, 1000)
                .unwrap();
            store
                .insert_llm_usage(&LlmUsageRecord {
                    session_id: n.into(),
                    message_uuid: format!("{n}-u1"),
                    request_id: None,
                    ts: 1000,
                    model: "sonnet".into(),
                    is_sidechain: false,
                    input_tokens: 1,
                    output_tokens: 1,
                    cache_read: 0,
                    cache_creation: 0,
                    cost_usd: Some(cost),
                    cost_source: "computed",
                    agent_id: None,
                })
                .unwrap();
        }
        let result = build_session(&store, "s2").unwrap().unwrap();
        assert_eq!(result["medians"]["project"]["cost"].as_f64().unwrap(), 20.0);
        assert_eq!(result["medians"]["session"]["cost"].as_f64().unwrap(), 20.0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_session_missing_data_does_not_error() {
        // A transcript-only session: registered but with no spans/samples.
        let (dir, store) = scratch();
        store
            .upsert_session("transcript-only", None, None, None, None, 1000)
            .unwrap();
        let result = build_session(&store, "transcript-only").unwrap().unwrap();
        assert_eq!(result["samples"].as_array().unwrap().len(), 0);
        assert_eq!(result["spans"].as_array().unwrap().len(), 0);
        assert_eq!(result["tree"]["procs"].as_array().unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_session_unknown_id_returns_none() {
        let (dir, store) = scratch();
        assert!(build_session(&store, "nope").unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_history_smoke() {
        let (dir, store) = scratch();
        let pid = store.upsert_project("/tmp/proj-hist").unwrap();
        let now = crate::store::now_ms();
        store
            .upsert_session("s1", Some(pid), Some(1), Some("main"), Some("2.0"), now)
            .unwrap();
        store
            .write_span(
                &SpanRecord {
                    session_id: "s1".into(),
                    tool_use_id: Some("t1".into()),
                    agent_id: None,
                    agent_type: None,
                    tool_name: "Bash".into(),
                    cmd_digest: Some("cargo test".into()),
                    started_at: now,
                    ended_at: now + 1000,
                    ok: Some(true),
                    cpu_ns: Some(2_000_000_000),
                    cpu_ns_sampled: 2_000_000_000,
                    peak_footprint: 1 << 20,
                    disk_read: 0,
                    disk_write: 0,
                    proc_count: 1,
                    leaked_count: 0,
                },
                &[ProcRecord {
                    pid: 1,
                    ppid: 0,
                    depth: 0,
                    comm: "cargo".into(),
                    name: "cargo".into(),
                    first_seen: now,
                    last_seen: now + 1000,
                    exited: true,
                    cpu_user_ns: 1_000_000_000,
                    cpu_sys_ns: 1_000_000_000,
                    peak_footprint: 1 << 20,
                    disk_read: 0,
                    disk_write: 0,
                    attribution: "span",
                    orphaned: false,
                }],
            )
            .unwrap();
        store
            .insert_llm_usage(&LlmUsageRecord {
                session_id: "s1".into(),
                message_uuid: "u1".into(),
                request_id: None,
                ts: now,
                model: "sonnet".into(),
                is_sidechain: false,
                input_tokens: 100,
                output_tokens: 50,
                cache_read: 10,
                cache_creation: 0,
                cost_usd: Some(1.5),
                cost_source: "computed",
                agent_id: None,
            })
            .unwrap();
        let out = build_history(&store, 7, None).unwrap();
        assert_eq!(out["days"].as_array().unwrap().len(), 7);
        assert!(out["kpis"]["cost_usd"].as_f64().unwrap() > 0.0);
        assert_eq!(out["sessions"].as_array().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
