mod client;
mod correlator;
mod daemon;
mod doctor;
mod history;
mod install;
mod mac;
mod pricing;
mod report;
mod store;
mod tailer;
mod top;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ai-obs",
    version,
    about = "Local-first observability for AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon in the foreground (hook endpoint + sampler + tailer)
    Daemon {
        /// Path to the SQLite database
        #[arg(long)]
        db: Option<std::path::PathBuf>,
    },
    /// Merge ai-obs hooks into ~/.claude/settings.json
    Install {
        /// Show what would change without writing
        #[arg(long)]
        dry_run: bool,
        /// Also install a LaunchAgent so the daemon starts at login
        #[arg(long)]
        launchd: bool,
    },
    /// Remove ai-obs hooks from ~/.claude/settings.json
    Uninstall,
    /// Verify hooks, daemon, timebase and database health
    Doctor,
    /// Live ranked view of sessions by resource use
    Top {
        /// Print one plain-text snapshot instead of the TUI
        #[arg(long)]
        once: bool,
    },
    /// Aggregate report: tokens, cost, CPU, memory — by project, session or PR
    Report {
        /// Filter to one project by name
        #[arg(long)]
        project: Option<String>,
        /// Filter to one session id
        #[arg(long)]
        session: Option<String>,
        /// Filter to one PR number
        #[arg(long)]
        pr: Option<i64>,
        /// Emit JSON instead of markdown
        #[arg(long)]
        json: bool,
    },
    /// SessionStart hook helper (internal): registers the session + claude PID
    #[command(hide = true)]
    SessionStart,
    /// Open the historical web dashboard served by the daemon
    Dashboard,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon { db } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let db = db.unwrap_or_else(store::default_db_path);
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(daemon::run(&db))
        }
        Cmd::Install { dry_run, launchd } => {
            println!("{}", install::install(daemon::port(), dry_run)?);
            if launchd && !dry_run {
                println!("{}", install::install_launchd()?);
            }
            Ok(())
        }
        Cmd::Uninstall => {
            println!("{}", install::uninstall()?);
            Ok(())
        }
        Cmd::Doctor => std::process::exit(doctor::run()),
        Cmd::Top { once } => top::run(once),
        Cmd::Report {
            project,
            session,
            pr,
            json,
        } => report::run(&report::ReportOpts {
            project,
            session,
            pr,
            json,
        }),
        Cmd::SessionStart => session_start(),
        Cmd::Dashboard => dashboard(),
    }
}

/// `ai-obs dashboard`: print the dashboard URL and open it in the default
/// browser. If the daemon isn't reachable, say so instead of opening a dead
/// tab — the dashboard endpoint lives entirely in the daemon process.
fn dashboard() -> anyhow::Result<()> {
    let port = daemon::port();
    let url = format!("http://127.0.0.1:{port}/");
    if client::get_json(port, "/api/status").is_err() {
        println!("ai-obs daemon not reachable on port {port}.");
        println!(
            "Start it with `ai-obs daemon` (or `just daemon`), then run `ai-obs dashboard` again."
        );
        return Ok(());
    }
    println!("{url}");
    let _ = std::process::Command::new("open").arg(&url).status();
    Ok(())
}

/// Runs as a SessionStart command hook. Reads the hook payload from stdin,
/// determines the claude process PID (hooks run as descendants of it), and
/// registers the session with the daemon. Always exits 0 — observability must
/// never break the agent.
fn session_start() -> anyhow::Result<()> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).ok();
    let payload: serde_json::Value = serde_json::from_str(&input).unwrap_or_default();

    let claude_pid = std::env::var("CLAUDE_PID")
        .ok()
        .and_then(|p| p.parse::<i32>().ok())
        .or_else(find_claude_ancestor);

    let body = serde_json::json!({
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "transcript_path": payload.get("transcript_path"),
        "claude_pid": claude_pid,
    });
    // Best-effort; a down daemon must not surface an error into the session.
    let _ = client::post_json(daemon::port(), "/h/session-start", &body);
    Ok(())
}

/// Walk our own ancestry looking for the claude process.
fn find_claude_ancestor() -> Option<i32> {
    let procs = mac::list_processes();
    let by_pid: std::collections::HashMap<i32, &mac::ProcInfo> =
        procs.iter().map(|p| (p.pid, p)).collect();
    let mut pid = std::process::id() as i32;
    for _ in 0..15 {
        let p = by_pid.get(&pid)?;
        if p.comm == "claude" || p.name == "claude" {
            return Some(p.pid);
        }
        if p.ppid <= 1 {
            return None;
        }
        pid = p.ppid;
    }
    None
}
