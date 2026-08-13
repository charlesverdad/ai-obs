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
