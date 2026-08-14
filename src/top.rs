//! `ai-obs top` — collapsible live tree: sessions → agents → tool calls.

use crate::daemon::port;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub fn run(once: bool) -> Result<()> {
    if once {
        return print_once();
    }
    let mut terminal = ratatui::init();
    let res = loop_ui(&mut terminal);
    ratatui::restore();
    res
}

fn fetch() -> Result<serde_json::Value> {
    crate::client::get_json(port(), "/api/top")
}

/// Compact human-readable count: `1.2M`, `48k`, `321`. Shared with `report`.
pub fn fmt_compact(n: i64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1e3)
    } else {
        n.to_string()
    }
}

/// Cost as `$12.34`, with a trailing `+` when some rows had no known price.
fn fmt_cost(cost_usd: f64, unpriced: i64) -> String {
    let suffix = if unpriced > 0 { "+" } else { "" };
    format!("${cost_usd:.2}{suffix}")
}

/// Compact duration: `41s`, `6m12s`, `3h04m`. Drops seconds once hours show.
pub fn fmt_duration(total_secs: f64) -> String {
    let total_secs = total_secs.max(0.0) as i64;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// Idle age as whole minutes: `idle 0m`, `idle 42m`. Deliberately coarse
/// (minutes only, no hours/seconds) — matches the spec for the STATUS
/// column; `fmt_duration` (h/m/s) is used where finer precision matters
/// (span/agent TIME columns).
fn fmt_idle_mins(idle_ms: i64) -> String {
    format!("idle {}m", idle_ms.max(0) / 60_000)
}

/// State label for a session/agent row: `running` or `idle Nm`, with a
/// `\u{b7} N spans` suffix only when there's at least one span — replaces
/// the old "0 spans" placeholder, which read as a status but was really
/// just a (frequently zero, hence meaningless) count.
pub fn fmt_state(running: bool, idle_ms: i64, spans: i64) -> String {
    let base = if running {
        "running".to_string()
    } else {
        fmt_idle_mins(idle_ms)
    };
    if spans > 0 {
        format!(
            "{base} \u{b7} {spans} span{}",
            if spans == 1 { "" } else { "s" }
        )
    } else {
        base
    }
}

/// Session/agent list sort. `Recent` trusts the server's own stable order
/// (started_at desc) and is never client-reordered; the other three are
/// volatile metrics re-sorted at most every [`REORDER_FREEZE_MS`] — see
/// [`compute_session_order`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    Recent,
    Cpu,
    Mem,
    Cost,
}

impl SortMode {
    pub fn next(self) -> Self {
        match self {
            SortMode::Recent => SortMode::Cpu,
            SortMode::Cpu => SortMode::Mem,
            SortMode::Mem => SortMode::Cost,
            SortMode::Cost => SortMode::Recent,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SortMode::Recent => "recent",
            SortMode::Cpu => "cpu",
            SortMode::Mem => "mem",
            SortMode::Cost => "cost",
        }
    }
}

fn sort_metric(session: &serde_json::Value, mode: SortMode) -> f64 {
    match mode {
        SortMode::Recent => 0.0,
        SortMode::Cpu => f64_of(session, "cpu_pct"),
        SortMode::Mem => i64_of(session, "footprint_mb") as f64,
        SortMode::Cost => f64_of(session, "cost_usd"),
    }
}

/// Re-sort at most this often for a volatile sort mode (cpu/mem/cost), so
/// rows don't reshuffle every ~1s refresh tick while the user is navigating.
const REORDER_FREEZE_MS: i64 = 5_000;

fn session_ids(sessions: &[&serde_json::Value]) -> Vec<String> {
    sessions
        .iter()
        .map(|s| s["session_id"].as_str().unwrap_or("?").to_string())
        .collect()
}

fn sorted_refs(sessions: &[serde_json::Value], mode: SortMode) -> Vec<&serde_json::Value> {
    let mut v: Vec<&serde_json::Value> = sessions.iter().collect();
    v.sort_by(|a, b| {
        sort_metric(b, mode)
            .partial_cmp(&sort_metric(a, mode))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    v
}

/// Compute the top-level session display order.
///
/// - `Recent`: always the payload's own order (server-stable, started_at
///   desc) — never resorted here.
/// - `Cpu`/`Mem`/`Cost`: re-sort only when at least [`REORDER_FREEZE_MS`]
///   has elapsed since the last reorder; otherwise reuse `prev_order`
///   (filtered to sessions still present, with any newly-appeared sessions
///   appended in sorted position) so a row already on screen doesn't jump
///   under the cursor between recomputes.
///
/// Returns `(new_order, new_last_reorder_ms)`. Takes plain monotonic
/// milliseconds rather than `Instant` so it's directly unit-testable.
pub fn compute_session_order(
    sessions: &[serde_json::Value],
    prev_order: &[String],
    mode: SortMode,
    now_ms: i64,
    last_reorder_ms: i64,
) -> (Vec<String>, i64) {
    if mode == SortMode::Recent {
        let refs: Vec<&serde_json::Value> = sessions.iter().collect();
        return (session_ids(&refs), now_ms);
    }
    let due = prev_order.is_empty() || now_ms - last_reorder_ms >= REORDER_FREEZE_MS;
    if due {
        return (session_ids(&sorted_refs(sessions, mode)), now_ms);
    }
    let present: HashSet<&str> = sessions
        .iter()
        .filter_map(|s| s["session_id"].as_str())
        .collect();
    let mut order: Vec<String> = prev_order
        .iter()
        .filter(|id| present.contains(id.as_str()))
        .cloned()
        .collect();
    let known: HashSet<&str> = order.iter().map(|s| s.as_str()).collect();
    let newcomers: Vec<serde_json::Value> = sessions
        .iter()
        .filter(|s| {
            s["session_id"]
                .as_str()
                .map(|id| !known.contains(id))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let newcomer_refs = sorted_refs(&newcomers, mode);
    order.extend(session_ids(&newcomer_refs));
    (order, last_reorder_ms)
}

/// Rebuild the `top` payload with its `sessions` array reordered per
/// `order` (session_ids not present in `order` are dropped — shouldn't
/// happen since `compute_session_order` is derived from the same payload,
/// but a stale `order` fails safe by simply hiding the row rather than
/// panicking).
fn reorder_top(top: &serde_json::Value, order: &[String]) -> serde_json::Value {
    let sessions = top["sessions"].as_array().cloned().unwrap_or_default();
    let mut by_id: HashMap<String, serde_json::Value> = sessions
        .into_iter()
        .map(|s| (s["session_id"].as_str().unwrap_or("?").to_string(), s))
        .collect();
    let ordered: Vec<serde_json::Value> = order.iter().filter_map(|id| by_id.remove(id)).collect();
    let mut out = top.clone();
    out["sessions"] = serde_json::Value::Array(ordered);
    out
}

// ---------------- tree flattening (pure, unit-testable) ----------------

/// One flattened row of the tree, ready to render either as a TUI table row
/// or a plain indented text line.
#[derive(Debug, Clone, PartialEq)]
pub struct FlatRow {
    /// Stable id across refreshes: "sess:<id>", "agent:<sid>:<key>",
    /// "span:<sid>:<key>:<span_id_or_idx>".
    pub key: String,
    pub depth: u8,
    pub collapsible: bool,
    pub expanded: bool,
    pub label: String,
    pub pid: String,
    pub cpu: String,
    pub mem: String,
    pub time: String,
    pub tok_in: String,
    pub tok_out: String,
    pub cost: String,
    pub current: String,
    /// Highlight (FAIL / orphaned / high cpu) — rendered in a warn color.
    pub warn: bool,
}

fn s_opt(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn f64_of(v: &serde_json::Value, key: &str) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn i64_of(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key).and_then(|x| x.as_i64()).unwrap_or(0)
}

/// Flatten the `/api/top` JSON payload into display rows, honoring the
/// caller-supplied `expanded` set (keys present == expanded). Pure function
/// of (data, expanded) -> rows; no I/O, no clock reads beyond what's already
/// embedded in the JSON (durations are precomputed server-side).
pub fn flatten(top: &serde_json::Value, expanded: &HashSet<String>) -> Vec<FlatRow> {
    let mut out = Vec::new();
    for sess in top["sessions"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
    {
        let sid = sess["session_id"].as_str().unwrap_or("?").to_string();
        let skey = format!("sess:{sid}");
        let sexpanded = expanded.contains(&skey);
        let tok_in = i64_of(sess, "tokens_in");
        let tok_out = i64_of(sess, "tokens_out");
        let cost = f64_of(sess, "cost_usd");
        let unpriced = i64_of(sess, "unpriced");
        let cpu = f64_of(sess, "cpu_pct");
        let running = sess
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let idle_ms = i64_of(sess, "idle_ms");
        let spans = i64_of(sess, "spans");
        out.push(FlatRow {
            key: skey.clone(),
            depth: 0,
            collapsible: true,
            expanded: sexpanded,
            label: format!(
                "{} {}",
                marker(true, sexpanded),
                sess["project"].as_str().unwrap_or("?")
            ),
            pid: sess["claude_pid"]
                .as_i64()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            cpu: format!("{cpu:.1}"),
            mem: sess["footprint_mb"].to_string(),
            time: fmt_duration(f64_of(sess, "duration_s")),
            tok_in: fmt_compact(tok_in),
            tok_out: fmt_compact(tok_out),
            cost: fmt_cost(cost, unpriced),
            current: fmt_state(running, idle_ms, spans),
            warn: cpu > 300.0,
        });
        if !sexpanded {
            continue;
        }
        for agent in sess["agents"]
            .as_array()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
        {
            let agent_id = s_opt(agent, "agent_id");
            let akey_part = agent_id.clone().unwrap_or_else(|| "main".to_string());
            let akey = format!("agent:{sid}:{akey_part}");
            let aexpanded = expanded.contains(&akey);
            let agent_type = s_opt(agent, "agent_type");
            let title = s_opt(agent, "title");
            // "<agent_type>: <title>" when both are known (e.g. "Explore:
            // Research subagent hook payloads"); otherwise fall back to
            // whichever of the two is known, then a short id — never blank.
            let name = match &agent_id {
                None => "main agent".to_string(),
                Some(aid) => match (&agent_type, &title) {
                    (Some(t), Some(ti)) => format!("{t}: {ti}"),
                    (None, Some(ti)) => ti.clone(),
                    (Some(t), None) => format!("{t} (subagent)"),
                    (None, None) => format!("agent {}", &aid[..aid.len().min(8)]),
                },
            };
            let a_tok_out = i64_of(agent, "tokens_out");
            let a_cost = f64_of(agent, "cost_usd");
            // Only populated when an agent_span row exists (main agent, or a
            // subagent whose SubagentStart the daemon saw).
            let a_time = agent
                .get("duration_s")
                .and_then(|v| v.as_f64())
                .map(fmt_duration)
                .unwrap_or_default();
            let open_spans = agent["open_spans"]
                .as_array()
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let recent_spans = agent["recent_spans"]
                .as_array()
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let a_running = agent
                .get("running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let a_idle_ms = i64_of(agent, "idle_ms");
            let a_spans = agent
                .get("spans")
                .and_then(|v| v.as_i64())
                .unwrap_or((open_spans.len() + recent_spans.len()) as i64);
            out.push(FlatRow {
                key: akey.clone(),
                depth: 1,
                collapsible: true,
                expanded: aexpanded,
                label: format!("  {} {name}", marker(true, aexpanded)),
                pid: String::new(),
                cpu: String::new(),
                mem: String::new(),
                time: a_time,
                tok_in: String::new(),
                tok_out: fmt_compact(a_tok_out),
                cost: fmt_cost(a_cost, 0),
                current: fmt_state(a_running, a_idle_ms, a_spans),
                warn: false,
            });
            if !aexpanded {
                continue;
            }
            // Open (running) spans first, then recent closed spans.
            for (idx, span) in open_spans.iter().enumerate() {
                out.push(span_row(&sid, &akey_part, idx, span, true));
            }
            for (idx, span) in recent_spans.iter().enumerate() {
                out.push(span_row(&sid, &akey_part, idx, span, false));
            }
        }
    }
    out
}

fn span_row(
    sid: &str,
    akey_part: &str,
    idx: usize,
    span: &serde_json::Value,
    running: bool,
) -> FlatRow {
    let tool_name = span["tool_name"].as_str().unwrap_or("?");
    let digest = span["cmd_digest"].as_str();
    let label = match digest {
        Some(d) => format!("{tool_name}({d})"),
        None => tool_name.to_string(),
    };
    let key_id = span["span_id"]
        .as_i64()
        .map(|i| i.to_string())
        .or_else(|| span["tool_use_id"].as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| idx.to_string());
    let ok = span.get("ok").and_then(|v| v.as_bool());
    let orphaned = i64_of(span, "orphaned_count");
    let status = if running {
        "RUNNING".to_string()
    } else if orphaned > 0 {
        format!("orphaned\u{26a0}{orphaned}")
    } else {
        match ok {
            Some(true) => "ok".to_string(),
            Some(false) => "FAIL".to_string(),
            None => "?".to_string(),
        }
    };
    let cpu_s = f64_of(span, "cpu_s");
    let peak_mb = i64_of(span, "peak_mb");
    let pid = span["pid"]
        .as_i64()
        .map(|p| p.to_string())
        .unwrap_or_default();
    FlatRow {
        key: format!(
            "span:{sid}:{akey_part}:{}:{key_id}",
            if running { "open" } else { "closed" }
        ),
        depth: 2,
        collapsible: false,
        expanded: false,
        label: format!("      {label}"),
        pid,
        cpu: format!("{cpu_s:.1}cpu-s"),
        mem: format!("{peak_mb}M"),
        time: fmt_duration(f64_of(span, "duration_s")),
        tok_in: String::new(),
        tok_out: String::new(),
        cost: String::new(),
        current: status.clone(),
        warn: status == "FAIL" || orphaned > 0,
    }
}

fn marker(collapsible: bool, expanded: bool) -> &'static str {
    if !collapsible {
        " "
    } else if expanded {
        "\u{25be}" // ▾
    } else {
        "\u{25b8}" // ▸
    }
}

/// Aggregate totals across every session currently displayed, for the
/// footer summary line.
struct Summary {
    sessions: usize,
    cores: f64,
    gb: f64,
    tok_in: i64,
    tok_out: i64,
    cost: f64,
    unpriced: i64,
    findings: usize,
}

fn summarize(top: &serde_json::Value) -> Summary {
    let sessions = top["sessions"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    let mut sum = Summary {
        sessions: sessions.len(),
        cores: 0.0,
        gb: 0.0,
        tok_in: 0,
        tok_out: 0,
        cost: 0.0,
        unpriced: 0,
        findings: top["findings"].as_array().map(|v| v.len()).unwrap_or(0),
    };
    for s in sessions {
        sum.cores += f64_of(s, "cpu_pct") / 100.0;
        sum.gb += i64_of(s, "footprint_mb") as f64 / 1024.0;
        sum.tok_in += i64_of(s, "tokens_in");
        sum.tok_out += i64_of(s, "tokens_out");
        sum.cost += f64_of(s, "cost_usd");
        sum.unpriced += i64_of(s, "unpriced");
    }
    sum
}

fn fmt_summary_line(sum: &Summary) -> String {
    format!(
        "{} session{} \u{b7} {:.1} cores \u{b7} {:.1} GB \u{b7} {}in/{}out tokens \u{b7} {} \u{b7} {} finding{}",
        sum.sessions,
        if sum.sessions == 1 { "" } else { "s" },
        sum.cores,
        sum.gb,
        fmt_compact(sum.tok_in),
        fmt_compact(sum.tok_out),
        fmt_cost(sum.cost, sum.unpriced),
        sum.findings,
        if sum.findings == 1 { "" } else { "s" },
    )
}

// ---------------- --once: plain indented text ----------------

fn print_once() -> Result<()> {
    let v = fetch()?;
    // Fully expand: every session + agent key present in the payload.
    let mut expanded = HashSet::new();
    for sess in v["sessions"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
    {
        let sid = sess["session_id"].as_str().unwrap_or("?");
        expanded.insert(format!("sess:{sid}"));
        for agent in sess["agents"]
            .as_array()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
        {
            let akey_part = s_opt(agent, "agent_id").unwrap_or_else(|| "main".to_string());
            expanded.insert(format!("agent:{sid}:{akey_part}"));
        }
    }
    let rows = flatten(&v, &expanded);
    println!(
        "{:<34} {:>6} {:>7} {:>8} {:>7} {:>8} {:>8} {:>9}  STATUS/CURRENT",
        "", "PID", "CPU%", "MEM", "TIME", "TOK IN", "TOK OUT", "COST"
    );
    for r in &rows {
        println!(
            "{:<34} {:>6} {:>7} {:>8} {:>7} {:>8} {:>8} {:>9}  {}",
            r.label, r.pid, r.cpu, r.mem, r.time, r.tok_in, r.tok_out, r.cost, r.current
        );
    }
    let sum = summarize(&v);
    println!("{}", fmt_summary_line(&sum));
    for f in v["findings"].as_array().unwrap_or(&vec![]) {
        println!(
            "! [{}] {}",
            f["kind"].as_str().unwrap_or("?"),
            f["message"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

// ---------------- interactive TUI ----------------

struct UiState {
    expanded: HashSet<String>,
    seen_sessions: HashSet<String>,
    selected_key: Option<String>,
    sort_mode: SortMode,
    session_order: Vec<String>,
    last_reorder_ms: i64,
    /// Monotonic clock reference for `compute_session_order`'s `now_ms`
    /// (that function itself is plain-integer and doesn't touch real time —
    /// this is the one place a real `Instant` gets turned into millis).
    clock: Instant,
}

impl UiState {
    fn new() -> Self {
        UiState {
            expanded: HashSet::new(),
            seen_sessions: HashSet::new(),
            selected_key: None,
            sort_mode: SortMode::Recent,
            session_order: Vec::new(),
            last_reorder_ms: 0,
            clock: Instant::now(),
        }
    }

    fn now_ms(&self) -> i64 {
        self.clock.elapsed().as_millis() as i64
    }

    /// Cycle the sort mode and force an immediate reorder on the next
    /// refresh (rather than waiting up to `REORDER_FREEZE_MS`) so switching
    /// modes feels responsive.
    fn cycle_sort(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.last_reorder_ms = i64::MIN / 2;
    }

    /// Recompute (or reuse, per cadence) the session display order for the
    /// latest payload, and return it applied to that payload.
    fn ordered_top(&mut self, top: &serde_json::Value) -> serde_json::Value {
        let sessions = top["sessions"].as_array().cloned().unwrap_or_default();
        let now = self.now_ms();
        let (order, last_reorder_ms) = compute_session_order(
            &sessions,
            &self.session_order,
            self.sort_mode,
            now,
            self.last_reorder_ms,
        );
        self.session_order = order;
        self.last_reorder_ms = last_reorder_ms;
        reorder_top(top, &self.session_order)
    }

    /// Sessions default expanded; agents default collapsed. Apply the
    /// default only the first time a session key is seen so a user's manual
    /// collapse survives subsequent refreshes.
    fn apply_defaults(&mut self, top: &serde_json::Value) {
        for sess in top["sessions"]
            .as_array()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
        {
            let sid = sess["session_id"].as_str().unwrap_or("?");
            let skey = format!("sess:{sid}");
            if self.seen_sessions.insert(skey.clone()) {
                self.expanded.insert(skey);
            }
        }
    }
}

fn loop_ui(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut last = serde_json::json!({"sessions": [], "findings": []});
    let mut err: Option<String>;
    let mut ui = UiState::new();
    loop {
        err = match fetch() {
            Ok(v) => {
                ui.apply_defaults(&v);
                last = v;
                None
            }
            Err(e) => Some(format!("{e:#}")),
        };
        let display_top = ui.ordered_top(&last);
        let rows = flatten(&display_top, &ui.expanded);
        // Clamp selection to an existing row; default to the first row.
        if ui
            .selected_key
            .as_ref()
            .map(|k| !rows.iter().any(|r| &r.key == k))
            .unwrap_or(true)
        {
            ui.selected_key = rows.first().map(|r| r.key.clone());
        }
        let sum = summarize(&last);

        terminal.draw(|f| {
            let chunks = Layout::vertical([
                Constraint::Min(5),
                Constraint::Length(8),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(f.area());

            let header = Row::new(vec![
                "",
                "PID",
                "CPU%",
                "MEM",
                "TIME",
                "TOK IN",
                "TOK OUT",
                "COST",
                "STATUS/CURRENT",
            ])
            .style(Style::default().add_modifier(Modifier::BOLD));
            let selected_idx = ui
                .selected_key
                .as_ref()
                .and_then(|k| rows.iter().position(|r| &r.key == k));
            let table_rows: Vec<Row> = rows
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    let mut style = if r.warn {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default()
                    };
                    if Some(i) == selected_idx {
                        style = style.bg(Color::Rgb(40, 40, 60));
                    }
                    Row::new(vec![
                        r.label.clone(),
                        r.pid.clone(),
                        r.cpu.clone(),
                        r.mem.clone(),
                        r.time.clone(),
                        r.tok_in.clone(),
                        r.tok_out.clone(),
                        r.cost.clone(),
                        r.current.clone(),
                    ])
                    .style(style)
                })
                .collect();
            let table = Table::new(
                table_rows,
                [
                    Constraint::Length(34),
                    Constraint::Length(6),
                    Constraint::Length(7),
                    Constraint::Length(8),
                    Constraint::Length(7),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(9),
                    Constraint::Min(15),
                ],
            )
            .header(header)
            .block(
                Block::default().borders(Borders::ALL).title(format!(
                    " ai-obs — live tree \u{b7} sort: {} ",
                    ui.sort_mode.label()
                )),
            );
            f.render_widget(table, chunks[0]);

            let findings: Vec<Line> = last["findings"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|x| {
                    let sev = x["severity"].as_str().unwrap_or("");
                    let color = match sev {
                        "crit" => Color::Red,
                        "info" => Color::DarkGray,
                        _ => Color::Yellow, // "warn" and any unrecognized severity
                    };
                    Line::styled(
                        format!(
                            "[{}] {}",
                            x["kind"].as_str().unwrap_or("?"),
                            x["message"].as_str().unwrap_or("")
                        ),
                        Style::default().fg(color),
                    )
                })
                .collect();
            let fpanel = Paragraph::new(findings)
                .block(Block::default().borders(Borders::ALL).title(" findings "));
            f.render_widget(fpanel, chunks[1]);

            f.render_widget(Paragraph::new(fmt_summary_line(&sum)), chunks[2]);

            let status = match &err {
                Some(e) => Line::styled(format!(" {e} "), Style::default().fg(Color::Red)),
                None => Line::from(format!(
                    " \u{2191}/\u{2193} move \u{b7} enter/space toggle \u{b7} s sort ({}) \u{b7} q to quit ",
                    ui.sort_mode.label()
                )),
            };
            f.render_widget(Paragraph::new(status), chunks[3]);
        })?;

        if event::poll(Duration::from_millis(1000))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('s') => ui.cycle_sort(),
                    KeyCode::Up | KeyCode::Char('k') => {
                        if let Some(idx) = ui
                            .selected_key
                            .as_ref()
                            .and_then(|key| rows.iter().position(|r| &r.key == key))
                        {
                            if idx > 0 {
                                ui.selected_key = Some(rows[idx - 1].key.clone());
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if let Some(idx) = ui
                            .selected_key
                            .as_ref()
                            .and_then(|key| rows.iter().position(|r| &r.key == key))
                        {
                            if idx + 1 < rows.len() {
                                ui.selected_key = Some(rows[idx + 1].key.clone());
                            }
                        }
                    }
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if let Some(key) = ui.selected_key.clone() {
                            if let Some(r) = rows.iter().find(|r| r.key == key) {
                                if r.collapsible {
                                    if ui.expanded.contains(&key) {
                                        ui.expanded.remove(&key);
                                    } else {
                                        ui.expanded.insert(key);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> serde_json::Value {
        json!({
            "sessions": [{
                "session_id": "s1",
                "project": "ai-obs",
                "claude_pid": 100,
                "duration_s": 90.0,
                "cpu_pct": 145.0,
                "footprint_mb": 1900,
                "current_tool": "Bash(just test)",
                "tokens_in": 12000,
                "tokens_out": 3000,
                "cost_usd": 5.10,
                "unpriced": 0,
                "agents": [
                    {
                        "agent_id": null,
                        "agent_type": null,
                        "cost_usd": 3.0,
                        "tokens_out": 2000,
                        "open_spans": [{
                            "tool_use_id": "tu1",
                            "tool_name": "Bash",
                            "cmd_digest": "just test",
                            "duration_s": 360.0,
                            "cpu_s": 41.2,
                            "peak_mb": 1900,
                            "ok": null,
                            "orphaned_count": 0,
                            "running": true,
                            "pid": 555
                        }],
                        "recent_spans": [{
                            "span_id": 7,
                            "tool_name": "Bash",
                            "cmd_digest": "cargo build",
                            "duration_s": 41.0,
                            "cpu_s": 18.4,
                            "peak_mb": 890,
                            "ok": true,
                            "orphaned_count": 0,
                            "running": false,
                            "pid": null
                        }]
                    },
                    {
                        "agent_id": "testagent1",
                        "agent_type": "code-reviewer",
                        "cost_usd": 2.10,
                        "tokens_out": 900,
                        "open_spans": [],
                        "recent_spans": [],
                        "started_at": 1000,
                        "ended_at": 43000,
                        "duration_s": 42.0
                    }
                ]
            }],
            "findings": []
        })
    }

    #[test]
    fn sessions_expanded_agents_collapsed_by_default() {
        let data = sample();
        let mut expanded = HashSet::new();
        expanded.insert("sess:s1".to_string());
        let rows = flatten(&data, &expanded);
        // session + 2 agent rows, no span rows (agents collapsed).
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].depth, 0);
        assert!(rows[0].label.contains("ai-obs"));
        assert_eq!(rows[1].depth, 1);
        assert!(rows[1].label.contains("main agent"));
        assert_eq!(rows[2].depth, 1);
        assert!(rows[2].label.contains("code-reviewer"));
    }

    #[test]
    fn collapsed_session_hides_everything_below() {
        let data = sample();
        let expanded = HashSet::new(); // session key absent => collapsed
        let rows = flatten(&data, &expanded);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn expanding_agent_reveals_its_spans() {
        let data = sample();
        let mut expanded = HashSet::new();
        expanded.insert("sess:s1".to_string());
        expanded.insert("agent:s1:main".to_string());
        let rows = flatten(&data, &expanded);
        // session + main agent + 1 open span + 1 recent span + subagent row
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[2].depth, 2);
        assert!(rows[2].label.contains("Bash(just test)"));
        assert_eq!(rows[2].current, "RUNNING");
        assert_eq!(rows[3].depth, 2);
        assert!(rows[3].label.contains("Bash(cargo build)"));
        assert_eq!(rows[3].current, "ok");
    }

    #[test]
    fn stable_keys_survive_reordering() {
        let data = sample();
        let mut expanded = HashSet::new();
        expanded.insert("sess:s1".to_string());
        let rows = flatten(&data, &expanded);
        assert_eq!(rows[1].key, "agent:s1:main");
        assert_eq!(rows[2].key, "agent:s1:testagent1");
    }

    #[test]
    fn agent_row_shows_duration_from_agent_span_when_present() {
        let data = sample();
        let mut expanded = HashSet::new();
        expanded.insert("sess:s1".to_string());
        let rows = flatten(&data, &expanded);
        // main agent has no agent_span (no duration_s field) -> blank TIME.
        assert_eq!(rows[1].key, "agent:s1:main");
        assert_eq!(rows[1].time, "");
        // subagent has a 42s agent_span -> TIME shows its duration.
        assert_eq!(rows[2].key, "agent:s1:testagent1");
        assert_eq!(rows[2].time, "42s");
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(fmt_duration(41.0), "41s");
        assert_eq!(fmt_duration(372.0), "6m12s");
        assert_eq!(fmt_duration(3.0 * 3600.0 + 4.0 * 60.0), "3h04m");
    }

    #[test]
    fn summary_line_totals_sessions() {
        let data = sample();
        let sum = summarize(&data);
        assert_eq!(sum.sessions, 1);
        assert!((sum.cores - 1.45).abs() < 1e-9);
        assert_eq!(sum.tok_in, 12000);
        assert_eq!(sum.tok_out, 3000);
    }

    // ---------------- state label formatting ----------------

    #[test]
    fn fmt_state_running_has_no_idle_age() {
        assert_eq!(fmt_state(true, 999_000, 0), "running");
    }

    #[test]
    fn fmt_state_idle_shows_minutes() {
        assert_eq!(fmt_state(false, 0, 0), "idle 0m");
        assert_eq!(fmt_state(false, 5 * 60_000, 0), "idle 5m");
        assert_eq!(fmt_state(false, 90 * 1000, 0), "idle 1m");
    }

    #[test]
    fn fmt_state_omits_span_count_when_zero_but_shows_it_otherwise() {
        // The bug this replaces: "0 spans" read as a meaningless status.
        assert_eq!(fmt_state(true, 0, 0), "running");
        assert_eq!(fmt_state(false, 120_000, 0), "idle 2m");
        assert_eq!(fmt_state(true, 0, 1), "running \u{b7} 1 span");
        assert_eq!(fmt_state(false, 120_000, 3), "idle 2m \u{b7} 3 spans");
    }

    #[test]
    fn agent_title_and_fallback_naming() {
        let data = serde_json::json!({
            "sessions": [{
                "session_id": "s1", "project": "p", "cost_usd": 0.0, "unpriced": 0,
                "tokens_in": 0, "tokens_out": 0,
                "agents": [
                    {
                        "agent_id": "abc123ef00", "agent_type": "Explore",
                        "title": "Research subagent hook payloads",
                        "cost_usd": 0.0, "tokens_out": 0,
                        "open_spans": [], "recent_spans": []
                    },
                    {
                        "agent_id": "def456", "agent_type": null,
                        "title": "Just a title",
                        "cost_usd": 0.0, "tokens_out": 0,
                        "open_spans": [], "recent_spans": []
                    },
                    {
                        "agent_id": "ghi789", "agent_type": "general-purpose",
                        "title": null,
                        "cost_usd": 0.0, "tokens_out": 0,
                        "open_spans": [], "recent_spans": []
                    },
                    {
                        "agent_id": "jkl0123456789", "agent_type": null,
                        "title": null,
                        "cost_usd": 0.0, "tokens_out": 0,
                        "open_spans": [], "recent_spans": []
                    }
                ]
            }],
            "findings": []
        });
        let mut expanded = HashSet::new();
        expanded.insert("sess:s1".to_string());
        let rows = flatten(&data, &expanded);
        // rows[0] is the session; agents follow.
        assert!(rows[1]
            .label
            .contains("Explore: Research subagent hook payloads"));
        assert!(rows[2].label.contains("Just a title"));
        assert!(rows[3].label.contains("general-purpose (subagent)"));
        // Never blank: falls back to a short id when both are unknown.
        assert!(rows[4].label.contains("agent jkl01234"));
    }

    // ---------------- sort mode / reorder cadence ----------------

    fn sess_at(id: &str, cpu: f64) -> serde_json::Value {
        serde_json::json!({"session_id": id, "cpu_pct": cpu, "footprint_mb": 0, "cost_usd": 0.0})
    }

    #[test]
    fn recent_mode_never_reorders() {
        let sessions = vec![sess_at("a", 10.0), sess_at("b", 90.0)];
        let (order, _) = compute_session_order(&sessions, &[], SortMode::Recent, 100_000, 0);
        assert_eq!(order, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn cpu_mode_sorts_descending_on_first_compute() {
        let sessions = vec![sess_at("a", 10.0), sess_at("b", 90.0)];
        let (order, last) = compute_session_order(&sessions, &[], SortMode::Cpu, 0, 0);
        assert_eq!(order, vec!["b".to_string(), "a".to_string()]);
        assert_eq!(last, 0);
    }

    #[test]
    fn volatile_sort_freezes_order_within_the_cadence_window() {
        let sessions = vec![sess_at("a", 10.0), sess_at("b", 90.0)];
        let (order, last) = compute_session_order(&sessions, &[], SortMode::Cpu, 0, 0);
        assert_eq!(order, vec!["b".to_string(), "a".to_string()]);

        // "a" overtakes "b" on cpu, but only 2s have passed (< 5s freeze) ->
        // order must NOT change yet.
        let sessions2 = vec![sess_at("a", 500.0), sess_at("b", 1.0)];
        let (order2, last2) = compute_session_order(&sessions2, &order, SortMode::Cpu, 2_000, last);
        assert_eq!(order2, vec!["b".to_string(), "a".to_string()]);
        assert_eq!(last2, last); // unchanged: no recompute happened

        // Past the freeze window -> resort reflects the new values.
        let (order3, last3) =
            compute_session_order(&sessions2, &order2, SortMode::Cpu, 6_000, last2);
        assert_eq!(order3, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(last3, 6_000);
    }

    #[test]
    fn volatile_sort_appends_newcomers_without_disturbing_frozen_order() {
        let sessions = vec![sess_at("a", 10.0), sess_at("b", 90.0)];
        let (order, last) = compute_session_order(&sessions, &[], SortMode::Cpu, 0, 0);
        assert_eq!(order, vec!["b".to_string(), "a".to_string()]);

        // "c" appears mid-freeze-window; existing order must be preserved,
        // "c" appended (even though it'd sort first by cpu).
        let sessions2 = vec![sess_at("a", 10.0), sess_at("b", 90.0), sess_at("c", 999.0)];
        let (order2, _) = compute_session_order(&sessions2, &order, SortMode::Cpu, 1_000, last);
        assert_eq!(
            order2,
            vec!["b".to_string(), "a".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn reorder_top_reorders_sessions_array_by_id() {
        let data = serde_json::json!({
            "sessions": [sess_at("a", 1.0), sess_at("b", 2.0)],
            "findings": []
        });
        let out = reorder_top(&data, &["b".to_string(), "a".to_string()]);
        let ids: Vec<&str> = out["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["session_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["b", "a"]);
    }

    /// The core anti-jump guarantee: selecting an item by its stable key,
    /// then reordering the underlying sessions (as a volatile sort would),
    /// must keep that same item selected — never silently fall back to
    /// "first row" just because its visual position moved.
    #[test]
    fn selection_by_key_survives_session_reordering() {
        let data = sample();
        let mut expanded = HashSet::new();
        expanded.insert("sess:s1".to_string());
        let rows_before = flatten(&data, &expanded);
        let selected_key = rows_before[2].key.clone(); // the subagent row

        // Simulate a reorder: rebuild the payload with sessions in a
        // different (but here, single-session) order — the interesting
        // case is verified at the compute_session_order level above; this
        // confirms flatten()+key lookup still finds the same logical row
        // after going through reorder_top.
        let reordered = reorder_top(&data, &["s1".to_string()]);
        let rows_after = flatten(&reordered, &expanded);
        let found = rows_after.iter().find(|r| r.key == selected_key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().key, rows_before[2].key);
    }
}
