# Learnings

Terse notes for future agents working in this repo. Keep additions short
and load-bearing — this is not a changelog.

- **mach timebase**: `rusage_info_v4` time fields (`ri_user_time`,
  `ri_system_time`, `ri_child_*_time`) are mach absolute *ticks*, not
  nanoseconds. On Apple Silicon the timebase ratio is 125/3 (~24 MHz), so
  a naive "treat as ns" reading is ~41.67x low. Always convert via
  `mach_timebase_info` (see `mac.rs::ticks_to_ns`), and cross-check against
  `getrusage` — `mac.rs::timebase_self_check` does exactly this and is
  wired into `ai-obs doctor`. If per-process CPU numbers look "plausible
  but off by a constant factor," suspect this first.

- **Other processes' env is unreadable unprivileged on macOS**:
  `KERN_PROCARGS2` strips environment variables for non-root readers, even
  same-uid. Attribution of a subprocess to a Claude session/project must
  go through PID ancestry (`mac::list_processes` + walking `ppid`), never
  through reading env vars.

- **Exact per-tool-call CPU via child-time delta**: `ri_child_user_time` /
  `ri_child_system_time` on the persistent tool shell, sampled before and
  after a tool span, gives exact CPU for reaped descendants — including
  subprocesses that live under 100ms and would be invisible to the
  sampler's own 10 Hz polling.

- **ratatui pin**: ratatui 0.30 requires rustc 1.88; nixpkgs currently pins
  1.86. Stay on ratatui 0.29 in `Cargo.toml` until nixpkgs catches up, or
  the nix build breaks.

- **Hooks**: never return `updatedInput` from any hook — it collides with
  the user's own `rtk` hook. Tool hooks (`PreToolUse`/`PostToolUse`/
  `PostToolUseFailure`) are HTTP hooks posting to the local daemon, not
  command hooks, specifically to avoid a process fork on every tool call.

- **Toolchain**: only use `nix-shell` for building/testing this repo —
  the pinned rustc differs from any system toolchain. `just verify` runs
  the same fmt + clippy (`-D warnings`) + test sequence as CI
  (`.github/workflows/*.yml`, `runs-on: macos-latest`).

- **Transient tool shells**: current Claude Code spawns a fresh `zsh -c
  source snapshot…` per Bash call and reaps it before PostToolUse fires —
  there is no persistent shell to delta against. Exact per-span CPU must be
  based on the claude process's *own* `ri_child_*` counters (wait4 rusage
  rolls up reaped grandchildren recursively), plus any still-live direct
  shell children. Sessions started before hook install have no claude_pid
  (SessionStart never fired) → spans record with sampled CPU only.

- **Redeploying the daemon binary**: never `cp` over `~/.local/bin/ai-obs` in
  place — overwriting the running/registered binary's inode invalidates its
  code signature and launchd refuses to respawn it ("spawn scheduled" forever).
  Always `cp` to a temp name then `mv -f` (new inode), then
  `launchctl kickstart -k gui/$UID/dev.ai-obs.daemon`.

- **Dashboard aggregate queries over `llm_usage` (history.rs)**: this table
  is the dominant cost at real scale (300k+ rows on a live install vs. a few
  hundred in `tool_span`/`session`). `date(ts/1000,'unixepoch','localtime')`
  is *non-deterministic* to SQLite (depends on OS timezone) so it can't back
  an index — `CREATE INDEX ... (date(...))` errors with "non-deterministic
  use of date() in an index". The only lever is minimizing the *number* of
  full-table scans: (1) never write one correlated subquery per output
  metric/day — GROUP BY once and derive every number from that one result
  set in Rust; a naive "one subquery per day" bar-chart query is O(days)
  full scans and single-handedly blew the budget from ~150ms to ~9s; (2)
  when a later query only needs a handful of session_ids (e.g. per-session
  totals for a LIMIT 60 sessions list), filter the `llm_usage` subquery with
  `session_id IN (<narrow set>)` rather than aggregating the whole table —
  `idx_llm_session(session_id, ts)` then turns it into an index lookup
  instead of a scan. Budget roughly one full `llm_usage` scan per ~150-200ms
  at this row count; a `< 1s` target caps you at ~4-5 scans total.

- **`pkill -f "ai-obs daemon"` is not scoped to a scratch process**: the
  live-tested pattern matches *any* process whose command line contains
  that substring, including the real launchd-managed production daemon at
  `~/.local/bin/ai-obs daemon` — even when your own test daemon was started
  under `nix-shell --run "... target/debug/ai-obs daemon"`. This actually
  happened during subagent-span smoke testing: the broad pkill killed the
  production daemon; launchd's `KeepAlive` respawned it within ~1s (same db
  path, WAL-safe reopen, no data loss observed), but it's still a hard-
  constraint violation to avoid. Kill scratch daemons by the PID you
  captured at spawn time (`$!` from the backgrounding command), never by
  `pkill -f` on a substring that also matches the production process.

- **Correction to the note above**: `$!` after backgrounding
  `nix-shell --run "... ai-obs daemon"` captures the PID of the `nix-shell`
  wrapper/subshell, *not* the actual `ai-obs daemon` child process — killing
  that PID can exit cleanly while the daemon keeps running and holding the
  port. Confirmed live during the security-review smoke test: `kill $!`
  "succeeded" (no such process on retry) but `curl` against the scratch port
  still got a response afterward. The reliable way to find the real PID for
  a scratch daemon: `lsof -nP -iTCP:<scratch-port> -sTCP:LISTEN`, or
  `ps aux | grep -F 'target/debug/ai-obs daemon'` (debug-build path is
  never the production binary's `~/.local/bin/ai-obs`) — confirm the port
  and/or binary path before sending the kill.

- **Subagent lifecycle hooks (`SubagentStart`/`SubagentStop`)**: both fire
  with `agent_id`/`agent_type` in the payload alongside the common fields
  (session_id, cwd, hook_event_name); PreToolUse/PostToolUse fired inside
  that subagent carry the same `agent_id`, which is the join key. One HTTP
  hook URL (`/h/sub`) branching on `hook_event_name` covers both events —
  no need for two settings.json entries pointing at different paths. Not
  verified from real traffic (only synthetic smoke-tested payloads): whether
  SubagentStop reliably fires on abnormal termination — hence the
  SessionEnd sweep (`agent_span.end_reason = 'session_end'`) as a backstop
  for subagents whose Stop never arrives.

- **DNS-rebinding guard on a loopback-only daemon**: binding to
  `127.0.0.1` alone does not stop a malicious web page from reaching the
  daemon — a page can get a browser to resolve an attacker-controlled
  hostname to `127.0.0.1` (DNS rebinding) and then `fetch()` it as if it
  were same-origin. The fix is a `Host` header allowlist, not a bind-address
  change: axum `middleware::from_fn` checking `Host` is exactly
  `127.0.0.1:{port}` / `localhost:{port}` / `[::1]:{port}`, 421 otherwise —
  applied to the whole router via `.layer(...)` on the `Router`, after
  `.with_state(...)`. Verify any in-process client (our `client.rs`) and
  hook curl commands still send that literal Host — they do here because
  they target `http://127.0.0.1:{port}/...` directly, but this would have
  broken anything going through a reverse proxy or a different loopback
  alias. Split the header-matching logic into a plain `fn(Option<&str>,
  u16) -> bool` rather than testing the `axum::middleware::Next`-based
  handler directly — building a real `Next` in a unit test needs the full
  tower service stack (not a dependency this repo pulls in), while the pure
  predicate is trivially testable and is what actually encodes the policy.

- **Subagent hook payloads (verified empirically 2026-08-13, CC 2.1.229)**:
  `SubagentStart` carries only `agent_id`, `agent_type`, `cwd`, `prompt_id`,
  `session_id`, `transcript_path`. `SubagentStop` additionally carries
  `agent_transcript_path` (the subagent's own `agent-<id>.jsonl` — a separate
  field from `transcript_path`), `last_assistant_message`, `stop_hook_active`,
  `background_tasks`, `session_crons`, `effort`, `permission_mode`. Hook
  changes in settings.json applied to already-running sessions in practice
  (SubagentStart fired from a session started before install) — don't rely
  on it, but don't assume a restart is required either.

- **`session.end_reason` is NULL far more often than the schema comment
  implies**: on this machine's real production db (13,477 sessions), 100%
  had `end_reason IS NULL` — not just backfilled pre-hook history, ordinary
  recent sessions too (SessionEnd apparently isn't firing/landing reliably
  in practice, separate from the known "daemon down at exit" case). Any
  dashboard logic that treats NULL `end_reason` as "still running" will
  mislabel nearly every session. The fix (`history.rs::derive_status`) is
  evidence-based: a session is "running" only if `last_activity_ms` (max of
  `started_at`, latest `tool_span` activity, latest `llm_usage` activity)
  is within 10 minutes of now; otherwise "inactive", with duration measured
  to `last_activity_ms`, never to `now`. Compute `last_activity_ms` via the
  same narrow, already-`session_id`-filtered GROUP BY joins used for
  calls/cost/etc — adding `MAX(...)` columns to an existing grouped
  subquery is ~free; a naive per-session correlated subquery over
  `llm_usage`/`tool_span` is not (see the dashboard-aggregate-queries note
  above) once used inside the *list* query, though it's fine for the
  single-row `/api/session/{id}` lookup.

- **`cmd_digest` wrapper unwrapping (`correlator.rs`)**: reconstructing a
  "rest of the command line" string by plain `tokens.join(" ")` after a
  prefix wrapper (sudo/time/env/...) strips its own flags silently
  destroys quote grouping on any remaining token that itself came from a
  quoted arg (e.g. an already-extracted `sh -c '...'` payload) — the next
  `tokenize()` pass then splits it back into multiple tokens instead of
  treating it as one, breaking further recursive unwrapping (e.g.
  `sudo nix-shell --run "timeout 5 cargo build"`, where `--run`'s argument
  needs to survive the `sudo`-stripping step intact). Fix: requote any
  token containing whitespace (`'...'`, or `"..."` if the token itself
  contains a single quote) before rejoining — see `rejoin`/`requote`. Only
  needed for strings fed back into `unwrap_wrappers`/`tokenize`, never for
  a terminal return value that `digest_words` will `split_whitespace()`
  directly (requoted text would show up as literal quote characters there).

- **SQLite window functions are available**: the bundled `rusqlite`
  (`features = ["bundled"]`) ships SQLite 3.48 — `ROW_NUMBER() OVER
  (PARTITION BY ... ORDER BY ...)` works fine for "pick the top row per
  group" queries (e.g. dominant-binary-per-digest-group in
  `history.rs`/`report.rs`). Prefer a CTE + window function + single
  `LEFT JOIN` over a per-row correlated subquery — same N+1 concern as the
  llm_usage note above, just against `proc_stat` instead. Use `x IS y` (not
  `x = y`) when joining on a nullable column like `cmd_digest`, since SQL
  `NULL = NULL` is false.

- **Verifying dashboard queries against real data**: `sqlite3 <prod db>
  ".backup '<scratch path>'"` makes a safe, fully-independent read-only
  copy (WAL included) without touching the live db; point a scratch daemon
  at it via `AI_OBS_DB=<copy> AI_OBS_PORT=18xxx`. Timing `/api/history`
  against a ~100MB / 300k-row copy this way found the `top_binary`
  dominant-binary CTE added no measurable overhead (~890ms before and
  after, days=30) — `proc_stat` is small enough that the extra grouped
  join is noise next to the `llm_usage` scan.

- **Task/subagent transcript correlation (verified 2026-08-14 against real
  `~/.claude/projects/**/*.jsonl` on this machine)**: this account's own
  transcripts are written by an Agent-SDK-style harness that names the
  spawn tool `"Agent"`, not the stock Claude Code CLI's `"Task"` — a
  parser meant to work across both must accept either `name`. Two record
  shapes matter, keyed by `tool_use_id`/`tool_use.id`:
  `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_..",
  "name":"Task"|"Agent","input":{"description":"<3-5 word title>"}}]}}` and
  the reply `{"type":"user","message":{"content":[{"type":"tool_result",
  "tool_use_id":"toolu_..","content":[{"type":"text","text":"...agentId:
  <hex-id> (internal ID...)..."}]}]},"toolUseResult":{"agentId":"<hex-id>",
  "description":"..."}}}`. The sibling top-level `toolUseResult.agentId`
  field is a cleaner, structured source than the prose `agentId:` marker in
  the text blob and should be preferred, with the text-scan as a fallback
  (see `tailer.rs::ingest_agent_title`/`extract_agent_id`) — a stock CLI
  transcript may only populate the latter. `sessionId` is present on every
  record type (assistant/user/attachment alike), so correlation doesn't
  need to special-case which record type carries it.

- **Store-side pending-write map for order-independent correlation**: when
  two independent event streams (an HTTP hook vs. the transcript tailer's
  ~3s-lagged poll) both need to populate the same row and either can arrive
  first, don't try to sequence them — give the `Store` a small in-memory
  `Mutex<HashMap<key, value>>` "pending" side table. The write method
  (`Store::set_agent_title`) does `UPDATE ... ; if 0 rows affected, stash
  in pending` and the row-creation method (`Store::open_agent_span`) checks
  pending for its own key right after inserting and applies+removes it.
  Caps the map size (drop-the-whole-map past N) so an event whose match
  never arrives (e.g. a dropped hook) can't leak memory over a long-running
  daemon — losing a handful of not-yet-matched values is fine when the
  consumer already has a fallback (agent_type / short id).

- **`ai-obs top`'s `/api/top` sort must not double as the display order**:
  sorting the session list by a live metric (cpu_pct) server-side, every
  poll, made rows visually reshuffle on their own even though the TUI
  already tracked selection by a stable string key (`sess:`/`agent:`/
  `span:`) rather than row index — the *item* stayed correctly selected,
  but the whole list dancing under it still reads as broken. Fix: the
  server always returns a stable order (`started_at DESC`); a client-side
  sort toggle (`top.rs::compute_session_order`) applies volatile orderings
  (cpu/mem/cost) but only recomputes at most every 5s, reusing the frozen
  order (new sessions appended, gone ones dropped) between recomputes.
  Keep this kind of reordering logic as a pure function of
  `(sessions, prev_order, mode, now_ms, last_reorder_ms)` — plain integers
  for the clock inputs, not `Instant` — so the freeze-cadence behavior is
  directly unit-testable without sleeping in tests.
