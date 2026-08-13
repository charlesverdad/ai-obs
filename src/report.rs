//! `ai-obs report` — aggregate queries over the store: by project, session,
//! or PR. Reads the database directly; the daemon need not be running.

use crate::store::Store;
use anyhow::Result;
use serde_json::{json, Value};

pub struct ReportOpts {
    pub project: Option<String>,
    pub session: Option<String>,
    pub pr: Option<i64>,
    pub json: bool,
}

pub fn run(opts: &ReportOpts) -> Result<()> {
    let db = crate::store::default_db_path();
    let store = Store::open_readonly(&db)?;

    let mut filter = String::new();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(p) = &opts.project {
        filter.push_str(" AND pr.name = ?1");
        args.push(Box::new(p.clone()));
    } else if let Some(s) = &opts.session {
        filter.push_str(" AND s.id = ?1");
        args.push(Box::new(s.clone()));
    } else if let Some(n) = opts.pr {
        filter.push_str(" AND s.pr_number = ?1");
        args.push(Box::new(n));
    }
    let argrefs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();

    // Per-project rollup: tokens+cost from llm_usage, resources from tool_span.
    let projects = store.query_json(
        &format!(
            "SELECT pr.name project,
                COUNT(DISTINCT s.id) sessions,
                COALESCE(SUM(u.input_tokens),0) input_tokens,
                COALESCE(SUM(u.output_tokens),0) output_tokens,
                COALESCE(SUM(u.cache_read),0) cache_read,
                COALESCE(SUM(u.cache_creation),0) cache_creation,
                ROUND(SUM(COALESCE(u.cost_usd,0)),4) cost_usd,
                SUM(CASE WHEN u.cost_usd IS NULL AND u.message_uuid IS NOT NULL THEN 1 ELSE 0 END) unpriced_messages
             FROM project pr
             JOIN session s ON s.project_id = pr.id
             LEFT JOIN llm_usage u ON u.session_id = s.id
             WHERE 1=1 {filter}
             GROUP BY pr.name ORDER BY cost_usd DESC"
        ),
        &argrefs,
    )?;

    let resources = store.query_json(
        &format!(
            "SELECT pr.name project,
                COUNT(t.id) tool_calls,
                ROUND(SUM(COALESCE(t.cpu_ns, t.cpu_ns_sampled))/1e9, 1) cpu_seconds,
                ROUND(MAX(t.peak_footprint)/1e6) peak_mb,
                SUM(t.orphaned_count) orphaned_procs
             FROM project pr
             JOIN session s ON s.project_id = pr.id
             JOIN tool_span t ON t.session_id = s.id
             WHERE 1=1 {filter}
             GROUP BY pr.name ORDER BY cpu_seconds DESC"
        ),
        &argrefs,
    )?;

    // `top_binary`: the dominant real binary (by cpu_ns, shells excluded)
    // among each (project, tool, digest) group's spans' proc_stat children —
    // same single-grouped-join shape as history.rs's heaviest query (see its
    // comment for why): a `scoped` CTE narrows tool_span to this report's
    // filter once, `bin_agg`/`ranked` aggregate proc_stat per group, and the
    // outer query LEFT JOINs the winner (rn=1) onto the per-group rollup.
    let top_commands = store.query_json(
        &format!(
            "WITH scoped AS (
               SELECT t.id, pr.name project, t.tool_name, t.cmd_digest, t.cpu_ns, t.cpu_ns_sampled, t.peak_footprint
               FROM tool_span t
               JOIN session s ON s.id = t.session_id
               LEFT JOIN project pr ON pr.id = s.project_id
               WHERE 1=1 {filter}
             ),
             bin_agg AS (
               SELECT sc.project, sc.tool_name, sc.cmd_digest, ps.name,
                      SUM(COALESCE(ps.cpu_user_ns,0)+COALESCE(ps.cpu_sys_ns,0)) cpu_ns
               FROM proc_stat ps JOIN scoped sc ON sc.id = ps.span_id
               WHERE ps.name NOT IN ('sh','bash','zsh','dash')
               GROUP BY sc.project, sc.tool_name, sc.cmd_digest, ps.name
             ),
             ranked AS (
               SELECT project, tool_name, cmd_digest, name,
                      ROW_NUMBER() OVER (PARTITION BY project, tool_name, cmd_digest ORDER BY cpu_ns DESC) rn
               FROM bin_agg
             )
             SELECT sc.project project, sc.tool_name, sc.cmd_digest,
                COUNT(*) calls,
                ROUND(SUM(COALESCE(sc.cpu_ns, sc.cpu_ns_sampled))/1e9,1) cpu_seconds,
                ROUND(MAX(sc.peak_footprint)/1e6) peak_mb,
                MAX(r.name) top_binary
             FROM scoped sc
             LEFT JOIN ranked r ON r.project IS sc.project AND r.tool_name = sc.tool_name
               AND r.cmd_digest IS sc.cmd_digest AND r.rn = 1
             GROUP BY sc.project, sc.tool_name, sc.cmd_digest
             ORDER BY cpu_seconds DESC LIMIT 15"
        ),
        &argrefs,
    )?;

    let models = store.query_json(
        &format!(
            "SELECT u.model,
                SUM(u.input_tokens) input_tokens, SUM(u.output_tokens) output_tokens,
                SUM(u.cache_read) cache_read, SUM(u.cache_creation) cache_creation,
                ROUND(SUM(COALESCE(u.cost_usd,0)),4) cost_usd
             FROM llm_usage u JOIN session s ON s.id = u.session_id
             LEFT JOIN project pr ON pr.id = s.project_id
             WHERE 1=1 {filter} GROUP BY u.model ORDER BY cost_usd DESC"
        ),
        &argrefs,
    )?;

    let out = json!({
        "projects": projects,
        "resources": resources,
        "top_commands": top_commands,
        "models": models,
    });

    if opts.json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_markdown(&out);
    }
    Ok(())
}

fn print_markdown(v: &Value) {
    let fmt_tokens = |n: &Value| -> String { crate::top::fmt_compact(n.as_i64().unwrap_or(0)) };

    println!("## Spend by project\n");
    println!("| project | sessions | input | output | cache read | cache write | cost USD |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for r in v["projects"].as_array().unwrap_or(&vec![]) {
        let unpriced = r["unpriced_messages"].as_i64().unwrap_or(0);
        let cost = if unpriced > 0 {
            format!("{} (+{} unpriced msgs)", r["cost_usd"], unpriced)
        } else {
            r["cost_usd"].to_string()
        };
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            r["project"].as_str().unwrap_or("?"),
            r["sessions"],
            fmt_tokens(&r["input_tokens"]),
            fmt_tokens(&r["output_tokens"]),
            fmt_tokens(&r["cache_read"]),
            fmt_tokens(&r["cache_creation"]),
            cost
        );
    }

    println!("\n## Resources by project\n");
    println!("| project | tool calls | CPU s | peak MB | orphaned procs |");
    println!("|---|---:|---:|---:|---:|");
    for r in v["resources"].as_array().unwrap_or(&vec![]) {
        println!(
            "| {} | {} | {} | {} | {} |",
            r["project"].as_str().unwrap_or("?"),
            r["tool_calls"],
            r["cpu_seconds"],
            r["peak_mb"],
            r["orphaned_procs"]
        );
    }

    println!("\n## Heaviest commands\n");
    println!("| project | tool | command | calls | CPU s | peak MB |");
    println!("|---|---|---|---:|---:|---:|");
    for r in v["top_commands"].as_array().unwrap_or(&vec![]) {
        let cmd = r["cmd_digest"].as_str().unwrap_or("-");
        // Append `→ binary` when the sampler caught a dominant child
        // process that differs from the digest's own first word — e.g.
        // `just verify → rustc` — so the row still points at real work
        // even when the digest itself is wrapper noise.
        let top_binary = r["top_binary"].as_str();
        let cmd_display = match top_binary {
            Some(bin) if !bin.is_empty() && Some(bin) != cmd.split_whitespace().next() => {
                format!("{cmd} → {bin}")
            }
            _ => cmd.to_string(),
        };
        println!(
            "| {} | {} | {} | {} | {} | {} |",
            r["project"].as_str().unwrap_or("?"),
            r["tool_name"].as_str().unwrap_or("?"),
            cmd_display,
            r["calls"],
            r["cpu_seconds"],
            r["peak_mb"]
        );
    }

    println!("\n## Tokens by model\n");
    println!("| model | input | output | cache read | cache write | cost USD |");
    println!("|---|---:|---:|---:|---:|---:|");
    for r in v["models"].as_array().unwrap_or(&vec![]) {
        println!(
            "| {} | {} | {} | {} | {} | {} |",
            r["model"].as_str().unwrap_or("?"),
            fmt_tokens(&r["input_tokens"]),
            fmt_tokens(&r["output_tokens"]),
            fmt_tokens(&r["cache_read"]),
            fmt_tokens(&r["cache_creation"]),
            r["cost_usd"]
        );
    }
}
