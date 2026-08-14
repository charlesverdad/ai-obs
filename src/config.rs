//! User config file for tunables that don't belong hardcoded — currently
//! just the orphan-detector allowlist (`orphan_allowlist`).
//!
//! Location: `~/.config/ai-obs/config.toml` (override via `AI_OBS_CONFIG`,
//! same convention as `AI_OBS_DB`/`AI_OBS_PORT` in `store.rs`/`daemon.rs`).
//! The project has no existing config mechanism and no `toml` dependency —
//! adding one for a single string-list setting isn't worth the extra crate,
//! so this is a hand-rolled parser for a deliberately trivial subset of
//! TOML-ish syntax:
//!
//!   # comments start with '#' and run to end of line (even inside a
//!   # would-be quoted string — keep names free of '#')
//!   orphan_allowlist = ["caffeinate", "my-long-running-tool"]
//!
//! Only that one key is recognized today. Anything else in the file is
//! ignored. A missing file is not an error (defaults only); a *present but
//! malformed* file logs a warning and also falls back to defaults — the
//! daemon must never fail to start over a bad config file.

use std::path::PathBuf;

pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("AI_OBS_CONFIG") {
        return PathBuf::from(p);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config/ai-obs/config.toml")
}

/// Commented-out defaults written by `ai-obs install` when no config file
/// exists yet, so the location and format are discoverable without reading
/// the README.
pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"# ai-obs config.
#
# orphan_allowlist: process names (comm, prefix-matched) that the orphan
# detector never flags, merged with the built-in defaults (language
# servers, caffeinate, ...). Uncomment and edit:
#
# orphan_allowlist = ["caffeinate", "my-long-running-tool"]
"#;

/// Load `orphan_allowlist` from the config file (if any) and merge it with
/// `builtins`, deduplicated. Never fails: a missing file yields `builtins`
/// unchanged; a present-but-malformed file logs a warning and also yields
/// `builtins` unchanged.
pub fn load_merged_orphan_allowlist(builtins: &[&str]) -> Vec<String> {
    load_merged_orphan_allowlist_from(&config_path(), builtins)
}

/// Same as [`load_merged_orphan_allowlist`] but against an explicit path —
/// split out so tests don't need to mutate the process-global
/// `AI_OBS_CONFIG` env var (which would race across parallel test threads).
fn load_merged_orphan_allowlist_from(path: &std::path::Path, builtins: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = builtins.iter().map(|s| s.to_string()).collect();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return out, // no config file present — defaults only
    };
    match parse_orphan_allowlist(&text) {
        Ok(extra) => {
            for name in extra {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "ai-obs config at {} failed to parse ({e}) — using built-in orphan_allowlist only",
                path.display()
            );
        }
    }
    out
}

/// Parse `orphan_allowlist = ["a", "b"]` out of config text. Returns an
/// empty vec (not an error) when the key is simply absent — a file that
/// only sets other future keys, or is empty/all-comments, is valid.
/// Returns `Err` only when the key *is* present but its value isn't a
/// well-formed `[...]` list of double-quoted strings.
fn parse_orphan_allowlist(text: &str) -> Result<Vec<String>, String> {
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("orphan_allowlist") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue; // e.g. some other key that happens to start the same
        };
        let rest = rest.trim();
        let Some(inner) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
            return Err(format!("expected `orphan_allowlist = [...]`, got `{line}`"));
        };
        let mut names = Vec::new();
        for item in inner.split(',') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let Some(name) = item.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
                return Err(format!("expected a quoted string, got `{item}`"));
            };
            if name.is_empty() {
                return Err("empty process name in orphan_allowlist".to_string());
            }
            names.push(name.to_string());
        }
        return Ok(names);
    }
    Ok(Vec::new())
}

/// Write [`DEFAULT_CONFIG_TEMPLATE`] to [`config_path`] if no config file
/// exists yet. Returns `Ok(Some(path))` if it created one, `Ok(None)` if a
/// file was already there (never overwritten). `dry_run` reports what it
/// would do without writing.
pub fn ensure_default_config(dry_run: bool) -> std::io::Result<Option<PathBuf>> {
    let path = config_path();
    if path.exists() {
        return Ok(None);
    }
    if dry_run {
        return Ok(Some(path));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, DEFAULT_CONFIG_TEMPLATE)?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_key_is_empty_not_error() {
        assert_eq!(parse_orphan_allowlist("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_orphan_allowlist("# just a comment\n").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parses_list() {
        let got =
            parse_orphan_allowlist(r#"orphan_allowlist = ["caffeinate", "my-tool"]"#).unwrap();
        assert_eq!(got, vec!["caffeinate".to_string(), "my-tool".to_string()]);
    }

    #[test]
    fn ignores_comments_and_whitespace() {
        let text = "  # comment\n\n  orphan_allowlist = [ \"caffeinate\" , \"x\" ]  # trailing\n";
        let got = parse_orphan_allowlist(text).unwrap();
        assert_eq!(got, vec!["caffeinate".to_string(), "x".to_string()]);
    }

    #[test]
    fn empty_list_is_ok() {
        assert_eq!(
            parse_orphan_allowlist("orphan_allowlist = []").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn malformed_missing_brackets_is_err() {
        assert!(parse_orphan_allowlist("orphan_allowlist = caffeinate").is_err());
    }

    #[test]
    fn malformed_unquoted_item_is_err() {
        assert!(parse_orphan_allowlist("orphan_allowlist = [caffeinate]").is_err());
    }

    #[test]
    fn malformed_never_panics() {
        let cases = [
            "orphan_allowlist = [\"unterminated",
            "orphan_allowlist=",
            "orphan_allowlist = [\"\"]",
            "orphan_allowlist = [,,,]",
            "orphan_allowlist",
            "\0\0\0 orphan_allowlist = [\"x\"]",
        ];
        for c in cases {
            let _ = parse_orphan_allowlist(c);
        }
    }

    #[test]
    fn load_merged_missing_file_returns_builtins_unchanged() {
        let path = std::path::Path::new("/nonexistent/ai-obs-test-config.toml");
        let got = load_merged_orphan_allowlist_from(path, &["a", "b"]);
        assert_eq!(got, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn load_merged_malformed_file_falls_back_to_builtins() {
        let dir = std::env::temp_dir().join(format!("ai-obs-cfg-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "orphan_allowlist = not-a-list").unwrap();
        let got = load_merged_orphan_allowlist_from(&path, &["a"]);
        assert_eq!(got, vec!["a".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_merged_dedups_against_builtins() {
        let dir = std::env::temp_dir().join(format!("ai-obs-cfg-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, r#"orphan_allowlist = ["a", "c"]"#).unwrap();
        let got = load_merged_orphan_allowlist_from(&path, &["a", "b"]);
        assert_eq!(got, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
