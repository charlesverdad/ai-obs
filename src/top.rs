//! `ai-obs top` — collapsible live tree: sessions → agents → tool calls.

use crate::daemon::port;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use std::collections::HashSet;
use std::time::Duration;

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
    /// Highlight (FAIL / leaked / high cpu) — rendered in a warn color.
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
            current: sess["current_tool"].as_str().unwrap_or("idle").to_string(),
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
            let name = match &agent_id {
                None => "main agent".to_string(),
                Some(_) => match &agent_type {
                    Some(t) => format!("{t} (subagent)"),
                    None => format!("{akey_part} (subagent)"),
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
            let nspans = open_spans.len() + recent_spans.len();
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
                current: format!("{nspans} span{}", if nspans == 1 { "" } else { "s" }),
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
    let leaked = i64_of(span, "leaked_count");
    let status = if running {
        "RUNNING".to_string()
    } else if leaked > 0 {
        format!("leaked\u{26a0}{leaked}")
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
        warn: status == "FAIL" || leaked > 0,
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
}

impl UiState {
    fn new() -> Self {
        UiState {
            expanded: HashSet::new(),
            seen_sessions: HashSet::new(),
            selected_key: None,
        }
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
        let rows = flatten(&last, &ui.expanded);
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
                Block::default()
                    .borders(Borders::ALL)
                    .title(" ai-obs — live tree "),
            );
            f.render_widget(table, chunks[0]);

            let findings: Vec<Line> = last["findings"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|x| {
                    let sev = x["severity"].as_str().unwrap_or("");
                    let color = if sev == "crit" {
                        Color::Red
                    } else {
                        Color::Yellow
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
                None => Line::from(
                    " \u{2191}/\u{2193} move \u{b7} enter/space toggle \u{b7} q to quit ",
                ),
            };
            f.render_widget(Paragraph::new(status), chunks[3]);
        })?;

        if event::poll(Duration::from_millis(1000))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
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
                            "leaked_count": 0,
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
                            "leaked_count": 0,
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
}
