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

/// A process that never got attributed to a span (no span was open when it
/// first appeared, or it was a depth-1 shell). Tracked at session level so
/// the orphan sweep can still catch it if it turns out truly detached.
#[derive(Clone, Debug)]
pub struct LooseProc {
    pub agg: ProcAgg,
    pub reported: bool,
}

/// One orphan finding raised from the loose-proc sweep.
pub struct LooseFinding {
    pub pid: i32,
    pub comm: String,
    pub age_ms: i64,
    pub footprint_mb: u64,
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
    pub loose_procs: HashMap<i32, LooseProc>,
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

impl Session {
    /// Sweep `loose_procs` for orphans: still alive, older than 120s (by
    /// first_seen), not allowlisted, and no longer a descendant of the
    /// session's claude process (i.e. reparented away — truly detached,
    /// vs. merely never having been inside an open span). Attribution here
    /// is weaker than the span-based orphan watch (we never saw this proc
    /// open a span), so callers should raise these at a lower severity.
    ///
    /// Marks matched entries `reported` (so they fire once) and prunes dead
    /// pids so `loose_procs` doesn't grow unboundedly over a long session.
    pub fn sweep_loose_orphans(
        &mut self,
        procs: &HashMap<i32, ProcInfo>,
        now: i64,
    ) -> Vec<LooseFinding> {
        self.loose_procs.retain(|pid, _| procs.contains_key(pid));
        let desc = self
            .claude_pid
            .map(|root| descendants_with_depth(root, procs).0)
            .unwrap_or_default();
        let mut findings = Vec::new();
        for (pid, lp) in self.loose_procs.iter_mut() {
            if lp.reported {
                continue;
            }
            let age_ms = now - lp.agg.first_seen;
            if age_ms < 120_000 {
                continue;
            }
            let is_allowed = ORPHAN_ALLOWLIST
                .iter()
                .any(|a| lp.agg.info.comm.starts_with(a));
            if is_allowed {
                continue;
            }
            if desc.contains(pid) {
                continue; // still attached to the claude tree — not detached
            }
            lp.reported = true;
            let footprint_mb = mac::usage(*pid)
                .map(|u| u.phys_footprint / 1_000_000)
                .unwrap_or(0);
            findings.push(LooseFinding {
                pid: *pid,
                comm: lp.agg.info.comm.clone(),
                age_ms,
                footprint_mb,
            });
        }
        findings
    }
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

/// Cap on how much of a single command string we'll ever tokenize. Guards
/// against pathological (megabyte-scale) input without needing to thread a
/// fuel counter through every helper — since each recursive unwrap step
/// only ever operates on a substring of its input (never a copy that grows
/// it), capping the initial input size bounds all downstream work too.
const MAX_DIGEST_INPUT: usize = 64 * 1024;

/// Cap on wrapper-unwrap recursion (nix-shell --run 'sh -c "..."' etc.).
const MAX_UNWRAP_DEPTH: u32 = 5;

/// Normalise a Bash command to a compact, privacy-preserving shape:
/// recursively unwrap wrapper commands (`nix-shell --run`, `sh -c`, `sudo`,
/// `timeout`, `cd x &&`, ...) to reach the innermost real command, then take
/// its first shell segment, first two words, executables reduced to
/// basenames, no flags/paths. Never panics on malformed input (unbalanced
/// quotes, empty strings, non-ASCII, huge strings) — worst case is a
/// best-effort digest.
pub fn cmd_digest(command: &str) -> String {
    let command = truncate_at_char_boundary(command, MAX_DIGEST_INPUT);
    let unwrapped = unwrap_wrappers(command, MAX_UNWRAP_DEPTH);
    digest_words(&unwrapped)
}

fn truncate_at_char_boundary(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Shell-word tokenizer: splits on whitespace, treats a `'...'` or `"..."`
/// run as a single token (quotes stripped, contents kept verbatim including
/// any inner whitespace) so `sh -c 'cargo test --all'` tokenizes to
/// `["sh", "-c", "cargo test --all"]`. No escape processing. An unterminated
/// quote simply consumes to the end of the string instead of erroring —
/// this must never panic on any input.
fn tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut has_cur = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                if has_cur {
                    tokens.push(std::mem::take(&mut cur));
                    has_cur = false;
                }
            }
            '\'' | '"' => {
                has_cur = true;
                for c2 in chars.by_ref() {
                    if c2 == c {
                        break;
                    }
                    cur.push(c2);
                }
            }
            _ => {
                has_cur = true;
                cur.push(c);
            }
        }
    }
    if has_cur {
        tokens.push(cur);
    }
    tokens
}

/// Rejoin a token slice into a command string suitable for feeding back
/// into [`unwrap_wrappers`]/[`tokenize`]. Plain `.join(" ")` would lose the
/// quote grouping of any token that itself contains whitespace (e.g. an
/// already-extracted `sh -c '...'` inner command passed through an outer
/// `sudo`/`time` prefix), silently splitting it into multiple tokens on the
/// next tokenize pass. Requote such tokens so they round-trip as one token.
fn rejoin(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|t| requote(t))
        .collect::<Vec<_>>()
        .join(" ")
}

fn requote(tok: &str) -> String {
    if !tok.chars().any(|c| c.is_whitespace()) {
        return tok.to_string();
    }
    if !tok.contains('\'') {
        format!("'{tok}'")
    } else if !tok.contains('"') {
        format!("\"{tok}\"")
    } else {
        // Contains both quote kinds and whitespace: no clean requoting
        // available. Best effort — a later tokenize() will just split it
        // into multiple tokens instead of one; never panics either way.
        tok.to_string()
    }
}

/// A token that looks like a leading env assignment (`FOO=bar`, `FOO=`),
/// i.e. `NAME=...` where `NAME` is a shell-identifier-shaped prefix.
fn is_env_assignment(tok: &str) -> bool {
    let Some(eq) = tok.find('=') else {
        return false;
    };
    if eq == 0 {
        return false;
    }
    let name = &tok[..eq];
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    first_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Per-wrapper table of short flags that take their value as the *next*
/// token (`xargs -P 4`, `env -u PATH`), as opposed to either taking no
/// value or an attached value (`stdbuf -oL`, which needs no entry here —
/// it's a single token already, not a separate `-o` `L` pair). Matched
/// against the exact flag token, so `-P4`/`-uPATH` (attached forms) don't
/// hit this table and are just skipped as ordinary flags, unchanged.
fn flag_takes_arg(head_base: &str, flag: &str) -> bool {
    matches!(
        (head_base, flag),
        (
            "xargs",
            "-P" | "-n" | "-L" | "-s" | "-I" | "-E" | "-a" | "-d"
        ) | ("env", "-u" | "-S" | "-C" | "-P")
            | ("sudo", "-u" | "-g" | "-p" | "-h")
            | ("nice", "-n")
            | ("timeout", "-k" | "-s")
            | ("caffeinate", "-t" | "-w")
            | ("stdbuf", "-o" | "-e" | "-i")
    )
}

/// Recursively unwrap wrapper commands (`nix-shell --run`, `sh -c`, `sudo`,
/// `timeout`, `env`, ...) down to the innermost real command line. Returns
/// the unwrapped command as a plain (space-joined, quote-stripped) string
/// for [`digest_words`] to segment/truncate as usual. Depth-limited; never
/// panics.
fn unwrap_wrappers(command: &str, depth: u32) -> String {
    if depth == 0 {
        return command.to_string();
    }
    let tokens = tokenize(command);
    if tokens.is_empty() {
        return String::new();
    }
    let mut i = 0;
    while i < tokens.len() && is_env_assignment(&tokens[i]) {
        i += 1;
    }
    if i >= tokens.len() {
        return String::new();
    }
    let head = tokens[i].as_str();
    let head_base = head.rsplit('/').next().unwrap_or(head);

    // Wrappers whose whole point is a quoted inner command line: find the
    // flag that introduces it and recurse on its argument.
    match head_base {
        "nix-shell" => {
            let mut j = i + 1;
            while j < tokens.len() {
                if tokens[j] == "--run" || tokens[j] == "--command" {
                    if let Some(inner) = tokens.get(j + 1) {
                        return unwrap_wrappers(inner, depth - 1);
                    }
                    break;
                }
                j += 1;
            }
            return "nix-shell".to_string();
        }
        "sh" | "bash" | "zsh" | "dash" => {
            let mut j = i + 1;
            while let Some(t) = tokens.get(j) {
                if !t.starts_with('-') {
                    break;
                }
                if t.contains('c') {
                    if let Some(inner) = tokens.get(j + 1) {
                        return unwrap_wrappers(inner, depth - 1);
                    }
                    break;
                }
                j += 1;
            }
            return head_base.to_string();
        }
        _ => {}
    }

    // Prefix wrappers that take the rest of the line as the command to run,
    // after skipping their own flags (and, for `env`, leading VAR=val
    // assignments too).
    let is_prefix_wrapper = matches!(
        head_base,
        "env"
            | "sudo"
            | "time"
            | "timeout"
            | "caffeinate"
            | "stdbuf"
            | "command"
            | "exec"
            | "arch"
            | "nohup"
            | "nice"
            | "xargs"
    );
    if is_prefix_wrapper {
        let mut j = i + 1;
        let mut skipped_duration_for_timeout = head_base != "timeout";
        while let Some(t) = tokens.get(j) {
            if head_base == "env" && is_env_assignment(t) {
                j += 1;
                continue;
            }
            if t.starts_with('-') {
                let consumes_arg = flag_takes_arg(head_base, t);
                j += 1;
                if consumes_arg && tokens.get(j).is_some_and(|a| !a.starts_with('-')) {
                    j += 1;
                }
                continue;
            }
            if head_base == "timeout" && !skipped_duration_for_timeout {
                // First bare token after flags is the duration, not the command.
                skipped_duration_for_timeout = true;
                j += 1;
                continue;
            }
            break;
        }
        if j < tokens.len() {
            let rest = rejoin(&tokens[j..]);
            return unwrap_wrappers(&rest, depth - 1);
        }
        return head_base.to_string();
    }

    // Not a recognised wrapper: reassemble from the first non-env token
    // onward (quotes stripped, whitespace normalised) for `digest_words` to
    // handle as usual.
    tokens[i..].join(" ")
}

/// Apply the final digest rules to an already-unwrapped command: first
/// shell segment, skipping over `cd`/`export`/`set` segments to the next
/// one (when there is one), first two words, executables reduced to
/// basenames.
fn digest_words(command: &str) -> String {
    let mut remaining = command;
    // Bounded by `remaining` strictly shrinking each iteration (a segment
    // plus its separator is consumed), so this always terminates within
    // `command.len()` iterations — the explicit cap is just defense in depth.
    for _ in 0..256 {
        let (seg, rest) = split_off_first_segment(remaining);
        let seg_head_base = seg.split_whitespace().next().map(|w| {
            let w = w.strip_suffix(';').unwrap_or(w);
            w.rsplit('/').next().unwrap_or(w)
        });
        let is_skip_cmd = matches!(seg_head_base, Some("cd") | Some("export") | Some("set"));
        if is_skip_cmd && !rest.is_empty() {
            remaining = rest;
            continue;
        }
        return extract_two_words(seg);
    }
    extract_two_words(remaining)
}

/// Split a shell command at the first occurrence of `;`, `|`, `&&`, or a
/// newline (whichever comes first). Returns `(segment, rest_after_separator)`;
/// `rest` is empty when no separator was found.
fn split_off_first_segment(command: &str) -> (&str, &str) {
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b';' | b'|' | b'\n' => return (&command[..i], &command[i + 1..]),
            b'&' if bytes.get(i + 1) == Some(&b'&') => return (&command[..i], &command[i + 2..]),
            _ => i += 1,
        }
    }
    (command, "")
}

fn extract_two_words(segment: &str) -> String {
    let mut words = Vec::new();
    for w in segment.split_whitespace() {
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

        // Adopt-at-close: catch processes that were spawned and reaped (or
        // just spawned) entirely inside a sampler gap — e.g. the adaptive
        // throttle had backed off to 1 Hz idle and a short-lived process's
        // whole visible window fell inside the ~900ms gap between ticks, so
        // no tick ever attributed it. Walk the *current* snapshot for
        // descendants of the session's claude process that plausibly belong
        // to this span (by kernel start time) and aren't already attributed
        // elsewhere, and fold them in with a fresh usage read.
        if let Some(claude_pid) = sess.claude_pid {
            let attributed: HashSet<i32> = sess
                .open_spans
                .iter()
                .flat_map(|s| s.procs.keys().copied())
                .chain(span.procs.keys().copied())
                .collect();
            let candidates = adopt_candidates(procs, claude_pid, span.started_at, &attributed);
            if !candidates.is_empty() {
                let (_, depth_of) = descendants_with_depth(claude_pid, procs);
                for pid in candidates {
                    let Some(info) = procs.get(&pid) else {
                        continue;
                    };
                    let Some(u) = mac::usage(pid) else {
                        continue;
                    };
                    let depth = depth_of.get(&pid).copied().unwrap_or(-1);
                    let start_ms = (info.start_sec as i64) * 1000;
                    span.procs.insert(
                        pid,
                        ProcAgg {
                            info: info.clone(),
                            depth,
                            first_seen: start_ms,
                            last_seen: ended_at,
                            last_usage: u,
                            peak_footprint: u.lifetime_max_footprint,
                            exited: false,
                        },
                    );
                    sess.loose_procs.remove(&pid);
                }
            }
        }

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

        for sess in self.sessions.values_mut() {
            let Some(root) = sess.claude_pid else {
                continue;
            };
            let (desc, depth_of) = descendants_with_depth(root, procs);
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
                            sess.loose_procs.entry(pid).or_insert_with(|| LooseProc {
                                agg,
                                reported: false,
                            });
                        } else {
                            span.procs.insert(pid, agg);
                        }
                    }
                    None => {
                        sess.loose_procs.entry(pid).or_insert_with(|| LooseProc {
                            agg,
                            reported: false,
                        });
                    }
                }
            }
            // Prune loose procs whose pid vanished from the snapshot, so the
            // map doesn't grow unboundedly over a long session.
            sess.loose_procs.retain(|pid, _| procs.contains_key(pid));

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

/// BFS descendants of `root` in the given snapshot (excluding `root` itself),
/// plus each descendant's depth below `root`. Shared by [`Correlator::tick`]
/// and the adopt-at-close logic in [`Correlator::close_span`].
fn descendants_with_depth(
    root: i32,
    procs: &HashMap<i32, ProcInfo>,
) -> (HashSet<i32>, HashMap<i32, i32>) {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for p in procs.values() {
        children.entry(p.ppid).or_default().push(p.pid);
    }
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
    (desc, depth_of)
}

/// Descendant pids of `root` in the given snapshot (excluding `root`).
#[cfg(test)]
fn descendants(root: i32, procs: &HashMap<i32, ProcInfo>) -> HashSet<i32> {
    descendants_with_depth(root, procs).0
}

/// Pure selection logic for adopt-at-close: which descendants of `claude_pid`
/// in the current snapshot plausibly belong to a span that started at
/// `span_started_at` and haven't already been attributed anywhere else.
///
/// Excludes: pids in `attributed` (already in this or another open span),
/// pids that started before the span opened (with the same 2s clock-
/// granularity slack `tick()` uses), and depth-1 shells (infrastructure, not
/// workload — same as `tick()`'s treatment of new pids).
fn adopt_candidates(
    procs: &HashMap<i32, ProcInfo>,
    claude_pid: i32,
    span_started_at: i64,
    attributed: &HashSet<i32>,
) -> Vec<i32> {
    let (desc, depth_of) = descendants_with_depth(claude_pid, procs);
    desc.into_iter()
        .filter(|pid| !attributed.contains(pid))
        .filter(|pid| {
            procs.get(pid).is_some_and(|info| {
                let start_ms = (info.start_sec as i64) * 1000;
                start_ms >= span_started_at - 2000
            })
        })
        .filter(|pid| {
            let depth = depth_of.get(pid).copied().unwrap_or(-1);
            let comm = procs.get(pid).map(|i| i.comm.as_str()).unwrap_or("");
            !(depth == 1 && SHELL_COMMS.contains(&comm))
        })
        .collect()
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

    // ---- wrapper unwrapping (Part A) ----

    #[test]
    fn digest_unwraps_nix_shell_run() {
        assert_eq!(
            cmd_digest(r#"nix-shell --run "cargo test --workspace""#),
            "cargo test"
        );
        assert_eq!(
            cmd_digest("nix-shell --command 'cargo fmt --check'"),
            "cargo fmt"
        );
        // -p flags before --run don't confuse the scan for --run.
        assert_eq!(
            cmd_digest(r#"nix-shell -p jq --run "jq . file.json""#),
            "jq ."
        );
    }

    #[test]
    fn digest_bare_nix_shell_stays_nix_shell() {
        assert_eq!(cmd_digest("nix-shell"), "nix-shell");
        assert_eq!(cmd_digest("nix-shell -p jq"), "nix-shell");
    }

    #[test]
    fn digest_unwraps_shell_dash_c() {
        assert_eq!(cmd_digest("sh -c 'npm run build'"), "npm run");
        assert_eq!(cmd_digest("bash -c \"cargo build\""), "cargo build");
        assert_eq!(cmd_digest("zsh -c 'ls -la'"), "ls");
        assert_eq!(cmd_digest("bash -lc 'cargo test'"), "cargo test");
    }

    #[test]
    fn digest_skips_leading_env_assignments() {
        assert_eq!(cmd_digest("FOO=bar BAZ=1 cargo build"), "cargo build");
    }

    #[test]
    fn digest_unwraps_env_prefix() {
        assert_eq!(cmd_digest("env FOO=1 cargo build"), "cargo build");
        assert_eq!(cmd_digest("env -i cargo build"), "cargo build");
    }

    #[test]
    fn digest_unwraps_sudo_time_and_combinations() {
        assert_eq!(cmd_digest("sudo cargo build"), "cargo build");
        assert_eq!(cmd_digest("time cargo build"), "cargo build");
        assert_eq!(cmd_digest("FOO=1 sudo -E time cargo build"), "cargo build");
        assert_eq!(cmd_digest("sudo -u root cargo build"), "cargo build");
    }

    #[test]
    fn digest_unwraps_timeout_with_duration() {
        assert_eq!(cmd_digest("timeout 5 cargo test"), "cargo test");
        assert_eq!(cmd_digest("timeout -k 10 30 cargo test"), "cargo test");
        assert_eq!(cmd_digest("timeout 5"), "timeout");
    }

    #[test]
    fn digest_unwraps_caffeinate() {
        assert_eq!(cmd_digest("caffeinate -dims ./long_job.sh"), "long_job.sh");
        assert_eq!(cmd_digest("caffeinate cargo build"), "cargo build");
    }

    #[test]
    fn digest_unwraps_stdbuf_command_exec_arch_nohup_nice() {
        assert_eq!(cmd_digest("stdbuf -oL cargo build"), "cargo build");
        assert_eq!(cmd_digest("command cargo build"), "cargo build");
        assert_eq!(cmd_digest("exec cargo build"), "cargo build");
        assert_eq!(cmd_digest("arch -arm64 cargo build"), "cargo build");
        assert_eq!(cmd_digest("nohup cargo build"), "cargo build");
        assert_eq!(cmd_digest("nice cargo build"), "cargo build");
        assert_eq!(cmd_digest("nice -n 10 cargo build"), "cargo build");
    }

    #[test]
    fn digest_unwraps_xargs() {
        assert_eq!(cmd_digest("xargs rustfmt"), "rustfmt");
        assert_eq!(cmd_digest("xargs -0 rustfmt"), "rustfmt");
        assert_eq!(cmd_digest("xargs"), "xargs");
    }

    #[test]
    fn digest_handles_value_taking_flags_separately() {
        // Regression: a separate-token flag argument (e.g. xargs's `-P 4`)
        // must not be mistaken for the wrapped command itself.
        assert_eq!(cmd_digest("xargs -P 4 cargo build"), "cargo build");
        assert_eq!(cmd_digest("env -u PATH ls"), "ls");
        assert_eq!(cmd_digest("caffeinate -t 3600 ./job.sh"), "job.sh");
        // Other documented value-taking flags, one per wrapper.
        assert_eq!(cmd_digest("xargs -n 1 echo"), "echo");
        assert_eq!(cmd_digest("xargs -I {} rustfmt {}"), "rustfmt {}");
        assert_eq!(cmd_digest("env -S '-a -b' cargo build"), "cargo build");
        assert_eq!(cmd_digest("sudo -p prompt cargo build"), "cargo build");
        assert_eq!(cmd_digest("timeout -k 5 30 cargo test"), "cargo test");
        assert_eq!(cmd_digest("stdbuf -o L cargo build"), "cargo build");
        // Attached-value forms still work unchanged (single token, no
        // separate-arg consumption needed).
        assert_eq!(cmd_digest("stdbuf -oL cargo build"), "cargo build");
    }

    #[test]
    fn digest_value_taking_flag_with_nothing_after_falls_back_gracefully() {
        // `xargs -P` with no argument and no command: no panic, sensible
        // fallback to the wrapper's own name.
        assert_eq!(cmd_digest("xargs -P"), "xargs");
        assert_eq!(cmd_digest("env -u"), "env");
    }

    #[test]
    fn digest_skips_cd_export_set_to_next_segment() {
        assert_eq!(cmd_digest("cd ai-obs && cargo test"), "cargo test");
        assert_eq!(cmd_digest("cd ~/work/x && just verify"), "just verify");
        assert_eq!(cmd_digest("cd x"), "cd x");
        assert_eq!(cmd_digest("export FOO=1 && cargo build"), "cargo build");
        assert_eq!(cmd_digest("set -e && cargo build"), "cargo build");
        // No following segment: nothing to skip to, stays as-is.
        assert_eq!(cmd_digest("export FOO=1"), "export FOO=1");
    }

    #[test]
    fn digest_handles_nested_wrappers() {
        assert_eq!(
            cmd_digest(r#"nix-shell --run "sh -c 'cd ai-obs && cargo test'""#),
            "cargo test"
        );
        assert_eq!(
            cmd_digest("FOO=1 sudo -E nix-shell --run \"timeout 5 cargo build\""),
            "cargo build"
        );
    }

    #[test]
    fn digest_handles_unbalanced_quotes_gracefully() {
        // No closing quote: best-effort digest, must not panic.
        let got = cmd_digest(r#"nix-shell --run "cargo"#);
        assert!(
            got == "cargo" || got == "nix-shell",
            "expected a graceful fallback, got {got:?}"
        );
    }

    #[test]
    fn digest_never_panics_on_adversarial_input() {
        let cases = [
            "",
            "   ",
            ";;;;&&&&||||",
            "'''''''",
            "\"\"\"\"\"\"\"",
            "nix-shell --run",
            "sh -c",
            "sudo",
            "timeout",
            "cd",
            "cd &&",
            "🦀🚀 cargo test --日本語",
            "FOO=1=2=3 cargo build",
            "=cargo build",
        ];
        for c in cases {
            let _ = cmd_digest(c);
        }
        // Deeply nested unwrap chain: must terminate (depth cap) not hang.
        let nested = "sh -c 'sh -c \\'sh -c \\'\\'sh -c \\'\\'\\'cargo test\\'\\'\\'\\'\\'\\'";
        let _ = cmd_digest(nested);
        // 10KB single-line command: must not panic or hang.
        let huge = format!("cargo test {}", "x".repeat(10_000));
        let _ = cmd_digest(&huge);
        // 10KB inside a nix-shell --run quote.
        let huge_wrapped = format!(r#"nix-shell --run "cargo test {}""#, "y".repeat(10_000));
        let _ = cmd_digest(&huge_wrapped);
        // Multi-byte input right at the truncation boundary must not panic
        // on a non-char-boundary slice.
        let boundary = "€".repeat(30_000); // 3 bytes/char, crosses MAX_DIGEST_INPUT
        let _ = cmd_digest(&boundary);
    }

    #[test]
    fn digest_historical_rows_unaffected() {
        // Privacy invariant: we only ever re-digest live commands as they're
        // captured; nothing in the store re-derives cmd_digest from stored
        // data, so old rows keep whatever digest they were written with even
        // if a newer cmd_digest() would produce something different. This
        // test exists as documentation, not as a behavioral check.
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

    fn proc(pid: i32, ppid: i32, comm: &str, start_sec: u64) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            comm: comm.to_string(),
            name: comm.to_string(),
            start_sec,
        }
    }

    #[test]
    fn adopt_candidates_picks_up_missed_descendant() {
        // claude(1) -> shell(2) -> python(3), python started 100ms after the
        // span opened (started_at=10_000ms => start_sec=10). Nothing has
        // attributed pid 3 anywhere yet.
        let procs: HashMap<i32, ProcInfo> = [
            proc(1, 0, "claude", 0),
            proc(2, 1, "zsh", 10),
            proc(3, 2, "python3", 10),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
        let attributed = HashSet::new();
        // pid 2 is a depth-1 shell (excluded); pid 3, the grandchild that was
        // actually missed by the sampler, is adopted.
        let got = adopt_candidates(&procs, 1, 10_000, &attributed);
        assert_eq!(got, vec![3]);
    }

    #[test]
    fn adopt_candidates_excludes_already_attributed() {
        let procs: HashMap<i32, ProcInfo> = [proc(1, 0, "claude", 0), proc(2, 1, "python3", 10)]
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        let mut attributed = HashSet::new();
        attributed.insert(2);
        let got = adopt_candidates(&procs, 1, 10_000, &attributed);
        assert!(got.is_empty());
    }

    #[test]
    fn adopt_candidates_excludes_procs_older_than_span() {
        // pid 2 started well before the span opened (started_at=10_000ms,
        // start_sec=1 => 1_000ms, outside the 2s slack window).
        let procs: HashMap<i32, ProcInfo> = [proc(1, 0, "claude", 0), proc(2, 1, "python3", 1)]
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        let attributed = HashSet::new();
        let got = adopt_candidates(&procs, 1, 10_000, &attributed);
        assert!(got.is_empty());
    }

    #[test]
    fn adopt_candidates_excludes_depth1_shells() {
        let procs: HashMap<i32, ProcInfo> = [proc(1, 0, "claude", 0), proc(2, 1, "zsh", 10)]
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        let attributed = HashSet::new();
        let got = adopt_candidates(&procs, 1, 10_000, &attributed);
        assert!(got.is_empty(), "depth-1 shell should be excluded: {got:?}");
    }

    #[test]
    fn descendants_finds_grandchildren() {
        let procs: HashMap<i32, ProcInfo> = [
            proc(1, 0, "claude", 0),
            proc(2, 1, "zsh", 0),
            proc(3, 2, "python3", 0),
            proc(99, 0, "unrelated", 0),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
        let mut got: Vec<i32> = descendants(1, &procs).into_iter().collect();
        got.sort();
        assert_eq!(got, vec![2, 3]);
    }

    #[test]
    fn project_root_walks_up() {
        // This test file lives in a git repo; its src dir resolves to the repo root.
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let root = project_root_of(src);
        assert!(std::path::Path::new(&root).join(".git").exists());
    }
}
