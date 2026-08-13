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

/// The hook groups we install: (event, matcher, hook).
fn our_hooks(port: u16, exe: &str) -> Vec<(&'static str, Option<&'static str>, Value)> {
    vec![
        (
            "SessionStart",
            None,
            json!({
                "type": "command",
                "command": format!("{exe} session-start"),
                "async": true,
                "timeout": 10
            }),
        ),
        ("PreToolUse", Some("*"), http_hook(port, "pre")),
        ("PostToolUse", Some("*"), http_hook(port, "post")),
        ("PostToolUseFailure", Some("*"), http_hook(port, "post")),
        ("SessionEnd", None, http_hook(port, "end")),
    ]
}

fn is_ours(hook: &Value, exe: &str) -> bool {
    if let Some(url) = hook.get("url").and_then(|u| u.as_str()) {
        return url.contains("/h/") && url.contains("127.0.0.1");
    }
    if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
        return cmd.contains("ai-obs session-start") || cmd.contains(exe);
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
                .map(|hs| hs.iter().any(|h| is_ours(h, &exe)))
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

/// Uninstall: remove any hook groups that are ours.
pub fn uninstall() -> Result<String> {
    let path = settings_path();
    let text = std::fs::read_to_string(&path).context("no settings.json")?;
    let mut root: Value = serde_json::from_str(&text)?;
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
                        .map(|hs| hs.iter().all(|h| is_ours(h, &exe)))
                        .unwrap_or(false)
                });
                removed += before - arr.len();
            }
        }
    }
    if removed > 0 {
        std::fs::write(&path, serde_json::to_string_pretty(&root)?)?;
    }
    Ok(format!("removed {removed} hook group(s)"))
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
                .map(|hs| hs.iter().any(|h| is_ours(h, exe)))
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
                .map(|hs| hs.iter().any(|h| is_ours(h, exe)))
                .unwrap_or(false)
        });
        assert!(exists);
    }
}
