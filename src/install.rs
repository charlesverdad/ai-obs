//! `ai-obs install` — merge our hooks into ~/.claude/settings.json without
//! disturbing anything already there (the user may have other PreToolUse
//! hooks; ours observe only and never return decisions or updatedInput).

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn settings_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude/settings.json")
}

fn http_hook(port: u16, path: &str) -> Value {
    json!({
        "type": "http",
        "url": format!("http://127.0.0.1:{port}/h/{path}"),
        "timeout": 5
    })
}

/// The exact `/h/*` paths any hook group we install ever points at — the
/// full set `is_ours` recognizes by URL. Kept in one place so `our_hooks`
/// and `is_ours` can't drift apart.
const OUR_HOOK_PATHS: [&str; 4] = ["pre", "post", "sub", "end"];

/// The exact URLs `is_ours` treats as ours, for one port.
fn our_urls(port: u16) -> [String; OUR_HOOK_PATHS.len()] {
    OUR_HOOK_PATHS.map(|p| format!("http://127.0.0.1:{port}/h/{p}"))
}

/// The exact `command` hook `is_ours` treats as ours, for one exe path.
fn our_session_start_command(exe: &str) -> String {
    format!("{exe} session-start")
}

/// The hook groups we install: (event, matcher, hook).
fn our_hooks(port: u16, exe: &str) -> Vec<(&'static str, Option<&'static str>, Value)> {
    vec![
        (
            "SessionStart",
            None,
            json!({
                "type": "command",
                "command": our_session_start_command(exe),
                "async": true,
                "timeout": 10
            }),
        ),
        ("PreToolUse", Some("*"), http_hook(port, "pre")),
        ("PostToolUse", Some("*"), http_hook(port, "post")),
        ("PostToolUseFailure", Some("*"), http_hook(port, "post")),
        ("SubagentStart", None, http_hook(port, "sub")),
        ("SubagentStop", None, http_hook(port, "sub")),
        ("SessionEnd", None, http_hook(port, "end")),
    ]
}

/// Exact match only — a loose "contains /h/ and 127.0.0.1" (or "contains
/// the exe path") match would also catch a *foreign* local hook group
/// (e.g. some other tool's `http://127.0.0.1:9999/h/x`, or a command hook
/// that merely mentions our exe path in an argument) and uninstall would
/// delete it. `is_ours` only ever recognizes the literal URLs `our_hooks`
/// generates for this port, and the literal SessionStart command for this
/// exe.
fn is_ours(hook: &Value, port: u16, exe: &str) -> bool {
    if let Some(url) = hook.get("url").and_then(|u| u.as_str()) {
        return our_urls(port).iter().any(|u| u == url);
    }
    if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
        return cmd == our_session_start_command(exe);
    }
    false
}

/// Merge hooks in; returns a human summary. Dry-run supported.
pub fn install(port: u16, dry_run: bool) -> Result<String> {
    let path = settings_path();
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| "{}".into());
    let mut root: Value =
        serde_json::from_str(&text).context("~/.claude/settings.json is not valid JSON")?;
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ai-obs".into());

    let hooks = root
        .as_object_mut()
        .context("settings.json root is not an object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));
    let mut added = Vec::new();
    for (event, matcher, hook) in our_hooks(port, &exe) {
        let arr = hooks
            .as_object_mut()
            .context("hooks is not an object")?
            .entry(event)
            .or_insert_with(|| json!([]));
        let arr = arr.as_array_mut().context("hook event is not an array")?;
        // Skip if any existing group already contains one of our hooks.
        let exists = arr.iter().any(|group| {
            group
                .get("hooks")
                .and_then(|h| h.as_array())
                .map(|hs| hs.iter().any(|h| is_ours(h, port, &exe)))
                .unwrap_or(false)
        });
        if exists {
            continue;
        }
        let mut group = serde_json::Map::new();
        if let Some(m) = matcher {
            group.insert("matcher".into(), json!(m));
        }
        group.insert("hooks".into(), json!([hook]));
        arr.push(Value::Object(group));
        added.push(event);
    }

    if added.is_empty() {
        return Ok("hooks already installed — nothing to do".into());
    }
    let summary = format!("added hooks: {}", added.join(", "));
    if dry_run {
        return Ok(format!("[dry-run] would have {summary}"));
    }
    // Backup, then write atomically.
    let backup = path.with_extension(format!("json.bak-aiobs-{}", crate::store::now_ms()));
    if path.exists() {
        std::fs::copy(&path, &backup).context("backing up settings.json")?;
    }
    let tmp = path.with_extension("json.tmp-aiobs");
    std::fs::write(&tmp, serde_json::to_string_pretty(&root)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(format!(
        "{summary}\nbackup: {}\nnext: run `ai-obs daemon` (or `ai-obs install --launchd` for autostart)",
        backup.display()
    ))
}

/// Uninstall: remove any hook groups that are ours (see [`is_ours`] — exact
/// URL/command match only, so a foreign local hook group is never touched).
/// Same backup + atomic write as [`install`], so an uninstall is as
/// recoverable as an install.
pub fn uninstall() -> Result<String> {
    let path = settings_path();
    let text = std::fs::read_to_string(&path).context("no settings.json")?;
    let mut root: Value = serde_json::from_str(&text)?;
    let port = crate::daemon::port();
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ai-obs".into());
    let mut removed = 0;
    if let Some(hooks) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        for (_event, arr) in hooks.iter_mut() {
            if let Some(arr) = arr.as_array_mut() {
                let before = arr.len();
                arr.retain(|group| {
                    !group
                        .get("hooks")
                        .and_then(|h| h.as_array())
                        .map(|hs| hs.iter().all(|h| is_ours(h, port, &exe)))
                        .unwrap_or(false)
                });
                removed += before - arr.len();
            }
        }
    }
    if removed == 0 {
        return Ok("no ai-obs hook groups found — nothing to do".into());
    }
    // Backup, then write atomically — same recoverability as install().
    let backup = path.with_extension(format!("json.bak-aiobs-{}", crate::store::now_ms()));
    std::fs::copy(&path, &backup).context("backing up settings.json")?;
    let tmp = path.with_extension("json.tmp-aiobs");
    std::fs::write(&tmp, serde_json::to_string_pretty(&root)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(format!(
        "removed {removed} hook group(s)\nbackup: {}",
        backup.display()
    ))
}

/// Write and load a LaunchAgent so the daemon survives reboots.
pub fn install_launchd() -> Result<String> {
    let exe = std::env::current_exe().context("cannot resolve own path")?;
    let home = dirs::home_dir().context("no home dir")?;
    let dir = home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&dir)?;
    let plist = dir.join("dev.ai-obs.daemon.plist");
    let log = home.join(".local/share/ai-obs/daemon.log");
    std::fs::create_dir_all(log.parent().unwrap())?;
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.ai-obs.daemon</string>
  <key>ProgramArguments</key><array>
    <string>{exe}</string><string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>
"#,
        exe = exe.display(),
        log = log.display()
    );
    std::fs::write(&plist, content)?;
    let out = std::process::Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist)
        .output()?;
    let msg = if out.status.success() {
        "launchd agent installed and loaded"
    } else {
        "launchd agent written; `launchctl load` reported an error (may already be loaded)"
    };
    Ok(format!("{msg}: {}", plist.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_is_idempotent_and_preserves_existing() {
        let existing = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]}
                ]
            },
            "model": "opus"
        });
        let mut root = existing.clone();
        let exe = "ai-obs";
        // Simulate the merge body (install() reads from disk; test the logic inline).
        let hooks = root.as_object_mut().unwrap().get_mut("hooks").unwrap();
        let arr = hooks
            .as_object_mut()
            .unwrap()
            .get_mut("PreToolUse")
            .unwrap()
            .as_array_mut()
            .unwrap();
        let ours = http_hook(8770, "pre");
        let exists = arr.iter().any(|g| {
            g["hooks"]
                .as_array()
                .map(|hs| hs.iter().any(|h| is_ours(h, 8770, exe)))
                .unwrap_or(false)
        });
        assert!(!exists);
        arr.push(json!({"matcher": "*", "hooks": [ours]}));
        // rtk hook untouched
        assert_eq!(arr[0]["hooks"][0]["command"], "rtk hook claude");
        assert_eq!(arr.len(), 2);
        // second pass detects ours
        let exists = arr.iter().any(|g| {
            g["hooks"]
                .as_array()
                .map(|hs| hs.iter().any(|h| is_ours(h, 8770, exe)))
                .unwrap_or(false)
        });
        assert!(exists);
    }

    #[test]
    fn our_hooks_include_subagent_lifecycle_events() {
        let hooks = our_hooks(8770, "ai-obs");
        let sub_events: Vec<&str> = hooks
            .iter()
            .filter(|(_, _, h)| {
                h.get("url")
                    .and_then(|u| u.as_str())
                    .map(|u| u.ends_with("/h/sub"))
                    .unwrap_or(false)
            })
            .map(|(event, _, _)| *event)
            .collect();
        assert_eq!(sub_events, vec!["SubagentStart", "SubagentStop"]);
        // No matcher: fires for every agent type, matching install.rs's
        // other unmatched (SessionStart/SessionEnd) hooks.
        for (event, matcher, _) in &hooks {
            if *event == "SubagentStart" || *event == "SubagentStop" {
                assert!(matcher.is_none());
            }
        }
    }

    #[test]
    fn is_ours_matches_and_uninstall_retain_logic_removes_sub_hooks() {
        let exe = "ai-obs";
        let sub_hook = http_hook(8770, "sub");
        assert!(is_ours(&sub_hook, 8770, exe));

        // Simulate uninstall()'s retain: a group is dropped only if every
        // hook in it is ours.
        let mut arr = vec![
            json!({"hooks": [sub_hook.clone()]}),
            json!({"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]}),
        ];
        arr.retain(|group| {
            !group["hooks"]
                .as_array()
                .map(|hs| hs.iter().all(|h| is_ours(h, 8770, exe)))
                .unwrap_or(false)
        });
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0]["command"], "rtk hook claude");
    }

    #[test]
    fn is_ours_rejects_a_foreign_local_hook_on_a_different_port() {
        let exe = "ai-obs";
        // Same shape as our own hooks — an http hook at 127.0.0.1/h/* —
        // but a different tool's daemon on a different port. The old
        // "contains /h/ and 127.0.0.1" match would have swallowed this;
        // the exact-URL match must not.
        let foreign = http_hook(9999, "x");
        assert!(!is_ours(&foreign, 8770, exe));

        // Also reject a command hook that merely mentions our exe path as
        // an argument, rather than being exactly `{exe} session-start`.
        let foreign_cmd =
            json!({"type": "command", "command": format!("some-wrapper {exe} --other-flag")});
        assert!(!is_ours(&foreign_cmd, 8770, exe));
    }

    #[test]
    fn uninstall_retain_logic_preserves_foreign_local_hook_group() {
        let exe = "ai-obs";
        let ours = http_hook(8770, "pre");
        let foreign = http_hook(9999, "x"); // another local tool's own daemon
        let mut arr = vec![
            json!({"matcher": "*", "hooks": [ours]}),
            json!({"matcher": "*", "hooks": [foreign.clone()]}),
        ];
        arr.retain(|group| {
            !group["hooks"]
                .as_array()
                .map(|hs| hs.iter().all(|h| is_ours(h, 8770, exe)))
                .unwrap_or(false)
        });
        // Only the foreign group survives.
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["hooks"][0], foreign);
    }

    #[test]
    fn our_urls_cover_exactly_the_paths_our_hooks_generates() {
        let hooks = our_hooks(8770, "ai-obs");
        let urls: std::collections::HashSet<String> = hooks
            .iter()
            .filter_map(|(_, _, h)| h.get("url").and_then(|u| u.as_str()))
            .map(|s| s.to_string())
            .collect();
        let recognized: std::collections::HashSet<String> = our_urls(8770).into_iter().collect();
        assert_eq!(urls, recognized);
    }
}
