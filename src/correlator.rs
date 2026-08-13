//! Live state: sessions, open tool spans, tracked process trees.
//!
//! Attribution model (design §5): a process belongs to a session if its PID
//! ancestry passes through the session's claude PID (plus a sticky set so
//! reparented/orphaned processes stay tracked). A process belongs to a tool
//! span if it appeared while that span was open; with more than one span open
//! concurrently it degrades to session-level attribution rather than guessing.

use crate::mac::{self, ProcInfo, ProcUsage};
use crate::store::{ProcRecord, SpanRecord, Store};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const SHELL_COMMS: &[&str] = &["zsh", "bash", "sh", "-zsh", "-bash", "-sh"];

/// Long-lived helpers that are expected to outlive tool calls; not orphans.
pub const ORPHAN_ALLOWLIST: &[&str] = &[
    "rust-analyzer",
    "gopls",
    "tsserver",
    "typescript-langu", // 16-byte comm truncation
    "pyright",
    "pyright-langserv",
    "sourcekit-lsp",
    "clangd",
    "watchman",
    "biomesyncd",
];

#[derive(Clone, Debug)]
pub struct ProcAgg {
    pub info: ProcInfo,
    pub depth: i32,
    pub first_seen: i64,
    pub last_seen: i64,
    pub last_usage: ProcUsage,
    pub peak_footprint: u64,
    pub exited: bool,
}

pub struct Span {
    pub tool_use_id: Option<String>,
    pub tool_name: String,
    pub cmd_digest: Option<String>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub started_at: i64,
    /// Sum of shell child-CPU (ns) across the session's shells at open.
    pub shell_child_base_ns: Option<u64>,
    /// PIDs attributed to this span.
    pub procs: HashMap<i32, ProcAgg>,
    /// True when >1 span was open while this one ran: per-proc attribution
    /// is ambiguous, mark rows 'session'.
    pub ambiguous: bool,
}

pub struct Session {
    pub id: String,
    pub project_root: Option<String>,
    pub project_id: Option<i64>,
    pub claude_pid: Option<i32>,
    #[allow(dead_code)]
    pub git_branch: Option<String>,
    pub started_at: i64,
    /// PIDs ever seen in this session's tree that are still live (or not yet
    /// confirmed exited). Survives reparenting to launchd.
    pub sticky: HashSet<i32>,
    pub open_spans: Vec<Span>,
    /// Session-level process aggregates for procs not inside any span
    /// (or ambiguous). Flushed on session end.
    pub loose_procs: HashMap<i32, ProcAgg>,
    /// Spans closed but with still-live descendants — orphan candidates:
    /// (span_id, pid, comm, closed_at, last footprint, reported).
    pub orphan_watch: Vec<OrphanWatch>,
    /// Previous tick totals for cpu% computation.
    pub prev_cpu_ns: u64,
    pub prev_tick_ms: i64,
    /// Latest computed rates for display.
    pub cpu_pct: f64,
    pub footprint: u64,
    pub proc_count: u32,
    pub current_tool: Option<String>,
}

pub struct OrphanWatch {
    pub span_id: i64,
    pub pid: i32,
    pub comm: String,
    pub cmd_digest: Option<String>,
    pub closed_at: i64,
    pub reported: bool,
}

#[derive(Default)]
pub struct Correlator {
    pub sessions: HashMap<String, Session>,
}

pub struct OpenSpanArgs<'a> {
    pub session_id: &'a str,
    pub cwd: Option<&'a str>,
    pub tool_use_id: Option<String>,
    pub tool_name: String,
    pub command: Option<&'a str>,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub procs: &'a HashMap<i32, ProcInfo>,
}

fn now_ms() -> i64 {
    crate::store::now_ms()
}

/// Normalise a Bash command to a compact, privacy-preserving shape:
/// first two words, executables reduced to basenames, no flags/paths.
pub fn cmd_digest(command: &str) -> String {
    // Only digest the first shell segment: stop at the first separator
    // that would start a new command (;, |, &&, ||, newline).
    let first_segment = split_first_shell_segment(command);
    let mut words = Vec::new();
    for w in first_segment.split_whitespace() {
        // Skip leading env assignments (FOO=bar cmd).
        if words.is_empty() && w.contains('=') && !w.starts_with('/') {
            continue;
        }
        if w.starts_with('-') {
            break;
        }
        let w = w.strip_suffix(';').unwrap_or(w);
        if w.is_empty() {
            break;
        }
        let base = w.rsplit('/').next().unwrap_or(w);
        words.push(base.to_string());
        if words.len() == 2 {
            break;
        }
    }
    if words.is_empty() {
        "sh".to_string()
    } else {
        words.join(" ")
    }
}

/// Split a shell command at the first occurrence of `;`, `|`, `&&`, `||`, or
/// a newline (whichever comes first) and return everything before it.
fn split_first_shell_segment(command: &str) -> &str {
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b';' | b'|' | b'\n' => return &command[..i],
            b'&' if bytes.get(i + 1) == Some(&b'&') => return &command[..i],
            _ => i += 1,
        }
    }
    command
}

impl Correlator {
    pub fn ensure_session(
        &mut self,
        session_id: &str,
        cwd: Option<&str>,
        claude_pid: Option<i32>,
    ) -> &mut Session {
        let sess = self
            .sessions
            .entry(session_id.to_string())
            .or_insert_with(|| Session {
                id: session_id.to_string(),
                project_root: None,
                project_id: None,
                claude_pid: None,
                git_branch: None,
                started_at: now_ms(),
                sticky: HashSet::new(),
                open_spans: Vec::new(),
                loose_procs: HashMap::new(),
                orphan_watch: Vec::new(),
                prev_cpu_ns: 0,
                prev_tick_ms: 0,
                cpu_pct: 0.0,
                footprint: 0,
                proc_count: 0,
                current_tool: None,
            });
        if sess.project_root.is_none() {
            if let Some(c) = cwd {
                sess.project_root = Some(project_root_of(c));
            }
        }
        if sess.claude_pid.is_none() {
            sess.claude_pid = claude_pid;
        }
        sess
    }

    pub fn open_span(&mut self, args: OpenSpanArgs<'_>) {
        let OpenSpanArgs {
            session_id,
            cwd,
            tool_use_id,
            tool_name,
            command,
            agent_id,
            agent_type,
            procs,
        } = args;
        let sess = self.ensure_session(session_id, cwd, None);
        let shell_base = shell_child_ns(sess.claude_pid, procs);
        let already_open = !sess.open_spans.is_empty();
        if already_open {
            for s in &mut sess.open_spans {
                s.ambiguous = true;
            }
        }
        let digest = command.map(cmd_digest);
        sess.current_tool = Some(match &digest {
            Some(d) => format!("{tool_name}({d})"),
            None => tool_name.clone(),
        });
        sess.open_spans.push(Span {
            tool_use_id,
            tool_name,
            cmd_digest: digest,
            agent_id,
            agent_type,
            started_at: now_ms(),
            shell_child_base_ns: shell_base,
            procs: HashMap::new(),
            ambiguous: already_open,
        });
    }

    /// Close the span matching tool_use_id (or the oldest open span when the
    /// id is missing/unknown) and persist it. Returns leaked pids.
    pub fn close_span(
        &mut self,
        store: &Arc<Store>,
        session_id: &str,
        tool_use_id: Option<&str>,
        ok: Option<bool>,
        procs: &HashMap<i32, ProcInfo>,
    ) {
        let Some(sess) = self.sessions.get_mut(session_id) else {
            return;
        };
        let idx = match tool_use_id {
            Some(id) => sess
                .open_spans
                .iter()
                .position(|s| s.tool_use_id.as_deref() == Some(id))
                .or(if sess.open_spans.is_empty() {
                    None
                } else {
                    Some(0)
                }),
            None => {
                if sess.open_spans.is_empty() {
                    None
                } else {
                    Some(0)
                }
            }
        };
        let Some(idx) = idx else { return };
        let mut span = sess.open_spans.remove(idx);
        sess.current_tool = sess.open_spans.last().map(|s| s.tool_name.clone());
        let ended_at = now_ms();

        // Exact CPU: shell child-CPU delta across the span.
        let cpu_ns = match (
            span.shell_child_base_ns,
            shell_child_ns(sess.claude_pid, procs),
        ) {
            (Some(base), Some(now)) => Some(now.saturating_sub(base)),
            _ => None,
        };

        // Final usage read for procs still alive; classify leaks.
        let mut leaked = 0u32;
        let mut peak = 0u64;
        let mut sampled_ns = 0u64;
        let mut disk_r = 0u64;
        let mut disk_w = 0u64;
        let mut rows = Vec::new();
        for (pid, agg) in span.procs.iter_mut() {
            let alive = procs.contains_key(pid);
            if alive {
                if let Some(u) = mac::usage(*pid) {
                    agg.last_usage = u;
                    agg.peak_footprint = agg.peak_footprint.max(u.lifetime_max_footprint);
                    agg.last_seen = ended_at;
                }
            } else {
                agg.exited = true;
            }
            let u = agg.last_usage;
            sampled_ns += u.cpu_user_ns + u.cpu_sys_ns;
            peak = peak.max(agg.peak_footprint);
            disk_r += u.disk_read;
            disk_w += u.disk_write;
            let is_allowed = ORPHAN_ALLOWLIST
                .iter()
                .any(|a| agg.info.comm.starts_with(a));
            if alive && !is_allowed {
                leaked += 1;
            }
            rows.push(ProcRecord {
                pid: *pid,
                ppid: agg.info.ppid,
                depth: agg.depth,
                comm: agg.info.comm.clone(),
                name: agg.info.name.clone(),
                first_seen: agg.first_seen,
                last_seen: agg.last_seen,
                exited: agg.exited,
                cpu_user_ns: u.cpu_user_ns,
                cpu_sys_ns: u.cpu_sys_ns,
                peak_footprint: agg.peak_footprint,
                disk_read: u.disk_read,
                disk_write: u.disk_write,
                attribution: if span.ambiguous { "session" } else { "span" },
                orphaned: alive && !is_allowed,
            });
        }

        let record = SpanRecord {
            session_id: session_id.to_string(),
            tool_use_id: span.tool_use_id.clone(),
            agent_id: span.agent_id.clone(),
            agent_type: span.agent_type.clone(),
            tool_name: span.tool_name.clone(),
            cmd_digest: span.cmd_digest.clone(),
            started_at: span.started_at,
            ended_at,
            ok,
            cpu_ns,
            cpu_ns_sampled: sampled_ns,
            peak_footprint: peak,
            disk_read: disk_r,
            disk_write: disk_w,
            proc_count: span.procs.len() as u32,
            leaked_count: leaked,
        };
        match store.write_span(&record, &rows) {
            Ok(span_id) => {
                for (pid, agg) in span.procs.iter() {
                    if procs.contains_key(pid)
                        && !ORPHAN_ALLOWLIST
                            .iter()
                            .any(|a| agg.info.comm.starts_with(a))
                    {
                        sess.orphan_watch.push(OrphanWatch {
                            span_id,
                            pid: *pid,
                            comm: agg.info.comm.clone(),
                            cmd_digest: span.cmd_digest.clone(),
                            closed_at: ended_at,
                            reported: false,
                        });
                    }
                }
            }
            Err(e) => tracing::error!("write_span failed: {e:#}"),
        }
    }

    /// One sampler tick: enumerate processes, update every session's tree,
    /// attribute new pids to open spans, refresh usage.
    pub fn tick(&mut self, procs: &HashMap<i32, ProcInfo>) {
        let now = now_ms();
        // children map
        let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
        for p in procs.values() {
            children.entry(p.ppid).or_default().push(p.pid);
        }

        for sess in self.sessions.values_mut() {
            let Some(root) = sess.claude_pid else {
                continue;
            };
            // BFS descendants of the claude process (excluding claude itself).
            let mut desc: HashSet<i32> = HashSet::new();
            let mut stack = vec![root];
            let mut depth_of: HashMap<i32, i32> = HashMap::new();
            depth_of.insert(root, 0);
            while let Some(pid) = stack.pop() {
                if let Some(kids) = children.get(&pid) {
                    for &k in kids {
                        if desc.insert(k) {
                            depth_of.insert(k, depth_of.get(&pid).copied().unwrap_or(0) + 1);
                            stack.push(k);
                        }
                    }
                }
            }
            // Sticky union: keep tracking pids that reparented away, drop exited.
            sess.sticky.retain(|pid| procs.contains_key(pid));
            for &pid in &desc {
                sess.sticky.insert(pid);
            }

            let tracked: Vec<i32> = sess.sticky.iter().copied().collect();
            let mut total_cpu_ns = 0u64;
            let mut total_footprint = 0u64;

            // Include the claude process itself in session totals.
            if let Some(u) = mac::usage(root) {
                total_cpu_ns += u.cpu_user_ns + u.cpu_sys_ns;
                total_footprint += u.phys_footprint;
            }

            for pid in tracked {
                let Some(info) = procs.get(&pid) else {
                    continue;
                };
                let Some(u) = mac::usage(pid) else { continue };
                total_cpu_ns += u.cpu_user_ns + u.cpu_sys_ns;
                total_footprint += u.phys_footprint;
                let depth = depth_of.get(&pid).copied().unwrap_or(-1);

                // Already attributed to an open span?
                let mut found = false;
                for span in sess.open_spans.iter_mut() {
                    if let Some(agg) = span.procs.get_mut(&pid) {
                        agg.last_usage = u;
                        agg.last_seen = now;
                        agg.peak_footprint = agg.peak_footprint.max(u.lifetime_max_footprint);
                        found = true;
                        break;
                    }
                }
                if found {
                    continue;
                }
                // New pid: attribute to the most recent open span if its start
                // time is plausible (proc started at/after span open, with 2s
                // slack for clock granularity — pbi_start_tvsec is seconds).
                let start_ms = (info.start_sec as i64) * 1000;
                let target = sess
                    .open_spans
                    .iter_mut()
                    .rev()
                    .find(|s| start_ms >= s.started_at - 2000);
                let agg = ProcAgg {
                    info: info.clone(),
                    depth,
                    first_seen: now,
                    last_seen: now,
                    last_usage: u,
                    peak_footprint: u.lifetime_max_footprint,
                    exited: false,
                };
                match target {
                    Some(span) => {
                        // Skip the persistent shells themselves — they are
                        // infrastructure, not workload.
                        if depth == 1 && SHELL_COMMS.contains(&agg.info.comm.as_str()) {
                            sess.loose_procs.insert(pid, agg);
                        } else {
                            span.procs.insert(pid, agg);
                        }
                    }
                    None => {
                        sess.loose_procs.entry(pid).or_insert(agg);
                    }
                }
            }

            // cpu% from delta
            if sess.prev_tick_ms > 0 && now > sess.prev_tick_ms {
                let dt_ns = ((now - sess.prev_tick_ms) as u64) * 1_000_000;
                let dcpu = total_cpu_ns.saturating_sub(sess.prev_cpu_ns);
                // Note: totals shrink when procs exit; clamp at 0.
                sess.cpu_pct = (dcpu as f64 / dt_ns as f64) * 100.0;
            }
            sess.prev_cpu_ns = total_cpu_ns;
            sess.prev_tick_ms = now;
            sess.footprint = total_footprint;
            sess.proc_count = sess.sticky.len() as u32 + 1;
        }
    }

    /// True when any session has an open span — drives the adaptive rate.
    pub fn any_span_open(&self) -> bool {
        self.sessions.values().any(|s| !s.open_spans.is_empty())
    }

    pub fn end_session(&mut self, store: &Arc<Store>, session_id: &str, reason: Option<&str>) {
        // Close any spans left open, then drop live state.
        let procs = snapshot_map();
        if let Some(sess) = self.sessions.get(session_id) {
            let n = sess.open_spans.len();
            for _ in 0..n {
                self.close_span(store, session_id, None, None, &procs);
            }
        }
        let _ = store.end_session(session_id, now_ms(), reason);
        self.sessions.remove(session_id);
    }
}

/// CPU basis (ns) used to measure the work a span caused: claude's own
/// reaped-child counters (which roll up everything claude has wait4'd,
/// including grandchildren reaped by an intermediate shell) plus, for any
/// still-live direct-child shell, both that shell's own CPU and its reaped-
/// child CPU. The latter covers a persistent shell whose workload hasn't
/// been reaped yet; including the shell's own CPU (not just its children's)
/// keeps the total monotonic across the shell's eventual death and roll-up
/// into claude's child counters.
///
/// This must NOT require any live shell: current Claude Code spawns a
/// transient `zsh -c ...` per Bash call that Claude reaps *before*
/// PostToolUse fires, so at span-close time no shell may exist at all —
/// the "no shell" case used to make this whole function return None,
/// leaving tool_span.cpu_ns permanently NULL for the common case.
///
/// Note: because this rolls up everything claude has reaped, it also
/// absorbs a small amount of CPU from unrelated short-lived helper
/// processes claude spawns and reaps during the span (e.g. hook scripts
/// like rtk). This is accepted noise, not attributable per-span.
fn child_cpu_ns_basis(
    base: Option<ProcUsage>,
    shells: impl Iterator<Item = ProcUsage>,
) -> Option<u64> {
    let base = base?;
    let mut total = base.child_cpu_user_ns + base.child_cpu_sys_ns;
    for u in shells {
        total += u.cpu_user_ns + u.cpu_sys_ns;
        total += u.child_cpu_user_ns + u.child_cpu_sys_ns;
    }
    Some(total)
}

/// Live-snapshot wrapper: reads claude's own usage plus every live direct-
/// child shell's usage, then delegates the arithmetic to
/// [`child_cpu_ns_basis`]. Returns `Some` whenever `usage(claude_pid)`
/// succeeds, regardless of whether any shell is currently alive.
fn shell_child_ns(claude_pid: Option<i32>, procs: &HashMap<i32, ProcInfo>) -> Option<u64> {
    let root = claude_pid?;
    let base = mac::usage(root);
    let shell_usages: Vec<ProcUsage> = procs
        .values()
        .filter(|p| p.ppid == root && SHELL_COMMS.contains(&p.comm.as_str()))
        .filter_map(|p| mac::usage(p.pid))
        .collect();
    child_cpu_ns_basis(base, shell_usages.into_iter())
}

pub fn snapshot_map() -> HashMap<i32, ProcInfo> {
    mac::list_processes()
        .into_iter()
        .map(|p| (p.pid, p))
        .collect()
}

/// Resolve a cwd to its git toplevel (walk up looking for .git), else itself.
pub fn project_root_of(cwd: &str) -> String {
    let mut p = std::path::Path::new(cwd);
    loop {
        if p.join(".git").exists() {
            return p.to_string_lossy().into_owned();
        }
        match p.parent() {
            Some(parent) if parent != p => p = parent,
            _ => return cwd.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_strips_paths_and_flags() {
        assert_eq!(cmd_digest("cargo test --all"), "cargo test");
        assert_eq!(
            cmd_digest("/usr/bin/python3 /tmp/x.py --flag"),
            "python3 x.py"
        );
        assert_eq!(cmd_digest("FOO=1 just verify"), "just verify");
        assert_eq!(cmd_digest("ls -la"), "ls");
        assert_eq!(cmd_digest(""), "sh");
        assert_eq!(
            cmd_digest("~/.local/bin/ai-obs doctor; echo x"),
            "ai-obs doctor"
        );
        assert_eq!(cmd_digest("cargo build && cargo test"), "cargo build");
        assert_eq!(cmd_digest("ls | head"), "ls");
    }

    fn usage_with(cpu_user: u64, cpu_sys: u64, child_user: u64, child_sys: u64) -> ProcUsage {
        ProcUsage {
            cpu_user_ns: cpu_user,
            cpu_sys_ns: cpu_sys,
            child_cpu_user_ns: child_user,
            child_cpu_sys_ns: child_sys,
            ..Default::default()
        }
    }

    #[test]
    fn child_cpu_ns_basis_none_when_claude_usage_missing() {
        assert_eq!(child_cpu_ns_basis(None, std::iter::empty()), None);
    }

    #[test]
    fn child_cpu_ns_basis_works_with_no_live_shells() {
        // Transient-shell case: claude has already reaped the shell, so its
        // own child counters carry the CPU and no live shell is needed.
        let base = usage_with(0, 0, 5_000, 2_000);
        assert_eq!(
            child_cpu_ns_basis(Some(base), std::iter::empty()),
            Some(7_000)
        );
    }

    #[test]
    fn child_cpu_ns_basis_includes_live_shell_own_and_child_cpu() {
        let base = usage_with(0, 0, 1_000, 0);
        let shell = usage_with(100, 50, 200, 300);
        let total = child_cpu_ns_basis(Some(base), std::iter::once(shell));
        // base child (1000) + shell own (100+50) + shell child (200+300)
        assert_eq!(total, Some(1_000 + 150 + 500));
    }

    #[test]
    fn project_root_walks_up() {
        // This test file lives in a git repo; its src dir resolves to the repo root.
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let root = project_root_of(src);
        assert!(std::path::Path::new(&root).join(".git").exists());
    }
}
