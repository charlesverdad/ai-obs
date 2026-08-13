//! `ai-obs top` — live ranked view of sessions, plus recent findings.

use crate::daemon::port;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
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

fn print_once() -> Result<()> {
    let v = fetch()?;
    println!(
        "{:<24} {:>7} {:>9} {:>6}  {}",
        "PROJECT", "CPU%", "MEM MB", "PROCS", "CURRENT"
    );
    for s in v["sessions"].as_array().unwrap_or(&vec![]) {
        println!(
            "{:<24} {:>7} {:>9} {:>6}  {}",
            s["project"].as_str().unwrap_or("?"),
            s["cpu_pct"],
            s["footprint_mb"],
            s["procs"],
            s["current_tool"].as_str().unwrap_or("idle")
        );
    }
    for f in v["findings"].as_array().unwrap_or(&vec![]) {
        println!(
            "! [{}] {}",
            f["kind"].as_str().unwrap_or("?"),
            f["message"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

fn loop_ui(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut last = serde_json::json!({"sessions": [], "findings": []});
    let mut err: Option<String> = None;
    loop {
        match fetch() {
            Ok(v) => {
                last = v;
                err = None;
            }
            Err(e) => err = Some(format!("{e:#}")),
        }
        terminal.draw(|f| {
            let chunks = Layout::vertical([
                Constraint::Min(5),
                Constraint::Length(8),
                Constraint::Length(1),
            ])
            .split(f.area());

            let header = Row::new(vec!["PROJECT", "CPU%", "MEM MB", "PROCS", "SPANS", "CURRENT TOOL"])
                .style(Style::default().add_modifier(Modifier::BOLD));
            let rows: Vec<Row> = last["sessions"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|s| {
                    let cpu = s["cpu_pct"].as_f64().unwrap_or(0.0);
                    let style = if cpu > 300.0 {
                        Style::default().fg(Color::Red)
                    } else if cpu > 90.0 {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    };
                    Row::new(vec![
                        s["project"].as_str().unwrap_or("?").to_string(),
                        format!("{cpu:.1}"),
                        s["footprint_mb"].to_string(),
                        s["procs"].to_string(),
                        s["open_spans"].to_string(),
                        s["current_tool"].as_str().unwrap_or("idle").to_string(),
                    ])
                    .style(style)
                })
                .collect();
            let table = Table::new(
                rows,
                [
                    Constraint::Length(24),
                    Constraint::Length(8),
                    Constraint::Length(9),
                    Constraint::Length(6),
                    Constraint::Length(6),
                    Constraint::Min(20),
                ],
            )
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(" ai-obs — live sessions "));
            f.render_widget(table, chunks[0]);

            let findings: Vec<Line> = last["findings"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|x| {
                    let sev = x["severity"].as_str().unwrap_or("");
                    let color = if sev == "crit" { Color::Red } else { Color::Yellow };
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

            let status = match &err {
                Some(e) => Line::styled(format!(" {e} "), Style::default().fg(Color::Red)),
                None => Line::from(" q to quit · refreshes every second "),
            };
            f.render_widget(Paragraph::new(status), chunks[2]);
        })?;

        if event::poll(Duration::from_millis(1000))? {
            if let Event::Key(k) = event::read()? {
                if matches!(k.code, KeyCode::Char('q') | KeyCode::Esc) {
                    return Ok(());
                }
            }
        }
    }
}
