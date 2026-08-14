# ai-obs

Local-first observability for Claude Code agents: CPU, memory, tokens, and
cost per tool call, grouped by project.

If you run several Claude Code instances at once, one of them eventually
orphans a process, spins a test loop, or burns tokens on the wrong branch —
and there's no way to tell which session, project, or tool call is
responsible. ai-obs attributes resource use down to the individual tool
call so you can find the culprit instead of guessing from `top`.

## How it works

- HTTP hooks (`PreToolUse`, `PostToolUse`, `PostToolUseFailure`,
  `SubagentStart`, `SubagentStop`, `SessionStart`, `SessionEnd`) push events
  into a local daemon — no per-tool-call forks.
- Subagent lifetimes get their own span (`agent_span`, opened on
  `SubagentStart` and closed on `SubagentStop`), correlated to that
  subagent's own tool calls via the shared `agent_id` — so the dashboard and
  `top` can show a subagent's own duration, not just the tool calls it made.
- A background sampler polls `proc_pid_rusage` for every live process at an
  adaptive rate: 10 Hz while a tool span is open, backing off to 1 Hz when
  idle, self-throttling if its own overhead grows.
- The shell child-CPU delta (`ri_child_user_time` / `ri_child_system_time`
  on the persistent tool shell) gives exact CPU for each tool call,
  including short-lived subprocesses the sampler would otherwise miss.
- A transcript tailer follows each session's JSONL transcript for token
  counts, cost, and PR links.

Everything stays on disk in a local SQLite database — nothing is sent
anywhere.

## Install / usage

Build:

```sh
just release          # uses nix-shell, matches CI
# or, with your own toolchain:
cargo build --release
```

Commands:

```sh
ai-obs install            # merge hooks into ~/.claude/settings.json (backs up first)
ai-obs install --launchd  # also install a LaunchAgent so the daemon starts at login
ai-obs uninstall           # remove ai-obs hook groups
ai-obs daemon               # run the hook endpoint + sampler + tailer in the foreground
ai-obs top                  # live ranked TUI of sessions by resource use (--once for one snapshot)
ai-obs report                # aggregate report: tokens, cost, CPU, memory (--project/--session/--pr, --json)
ai-obs doctor                 # verify timebase, hooks, daemon, and database health
```

Environment variables:

| Variable              | Default              | Purpose                          |
|------------------------|----------------------|-----------------------------------|
| `AI_OBS_PORT`          | `8770`               | Port the daemon listens on / hooks post to |
| `AI_OBS_DB`            | platform data dir     | SQLite database path             |
| `AI_OBS_PROJECTS_DIR`  | `~/.claude/projects`  | Where to find session transcripts |
| `AI_OBS_CONFIG`        | `~/.config/ai-obs/config.toml` | User config file path    |

`ai-obs install` merges hooks into `~/.claude/settings.json` without
touching hooks you already have (it only ever observes; it never returns
`updatedInput` or a permission decision), and backs up the previous file
before writing. It also writes a commented-out default config file to
`~/.config/ai-obs/config.toml` if one doesn't exist yet (never overwrites
one that's already there).

## Configuration

`~/.config/ai-obs/config.toml`, read once at daemon startup. There's no
`toml` dependency in this project, so this is a deliberately tiny
hand-rolled format — one recognized key so far:

```toml
# process names (comm, prefix-matched) the orphan detector never flags,
# merged with the built-in defaults (language servers, caffeinate, ...)
orphan_allowlist = ["caffeinate", "my-long-running-tool"]
```

A missing config file just means built-in defaults only; a malformed one
logs a warning at daemon startup and also falls back to built-in
defaults — a bad config file can never stop the daemon from starting.

### Orphan detector

A process is an "orphan" when it's still alive after its tool call (or its
session, for processes never attributed to a span) has ended and it isn't
allowlisted. Findings are graded by measured burn at detection time, not
just by the fact that they outlived their span:

| Severity | Condition                                |
|----------|-------------------------------------------|
| `info`   | < 5% CPU **and** < 100 MB RSS              |
| `warn`   | 5–50% CPU **or** 100 MB – 1 GB RSS         |
| `crit`   | > 50% CPU (sustained) **or** > 1 GB RSS    |

Each process identity (pid + start time) is reported at most once —
detector passes don't re-emit a finding for a process that's still alive
and already reported. Findings are observational only: ai-obs never kills
or otherwise acts on an orphaned process.

## Privacy

By default, tool commands are stored as normalized digests (e.g. `cargo
test --all --flags /some/path` becomes `cargo test`) — not full command
lines. ai-obs never reads environment variables of other processes; on
macOS that's kernel-enforced (`KERN_PROCARGS2` strips env for non-root
readers), so attribution is done purely through PID ancestry. Nothing
leaves the machine — everything is written to a local SQLite database.

## Requirements

macOS (Apple Silicon or Intel). The design relies on `proc_pid_rusage` and
`libproc`, which are macOS-only APIs, so there is no Linux or Windows
support. See [design/ai-obs-design.html](design/ai-obs-design.html) for the
full design doc.

## Status

Early. Implemented so far: the adaptive sampler, the daemon and its HTTP
hook endpoints, the CLI (`install`/`uninstall`/`daemon`/`top`/`report`/`doctor`),
and the transcript tailer. Anomaly detectors currently log only — they
don't yet alert or act.

## License

MIT.
