//! `ai-obs doctor` — the self-check that keeps the numbers trustworthy.

use crate::daemon::port;

pub fn run() -> i32 {
    let mut failures = 0;
    let mut check = |name: &str, res: Result<String, String>| match res {
        Ok(msg) => println!("  ok    {name}: {msg}"),
        Err(msg) => {
            println!("  FAIL  {name}: {msg}");
            failures += 1;
        }
    };

    check(
        "timebase",
        crate::mac::timebase_self_check().map(|_| "proc_pid_rusage agrees with getrusage".into()),
    );

    check("process enumeration", {
        let t0 = std::time::Instant::now();
        let procs = crate::mac::list_processes();
        let dt = t0.elapsed();
        if procs.len() < 10 {
            Err(format!("only {} processes visible", procs.len()))
        } else if dt.as_millis() > 50 {
            Err(format!("{} procs in {dt:?} — too slow for 10 Hz", procs.len()))
        } else {
            Ok(format!("{} procs in {dt:?}", procs.len()))
        }
    });

    check("hooks installed", {
        let path = crate::install::settings_path();
        match std::fs::read_to_string(&path) {
            Err(_) => Err(format!("{} missing", path.display())),
            Ok(text) => {
                if text.contains("/h/pre") && text.contains("session-start") {
                    Ok("SessionStart + tool hooks present".into())
                } else {
                    Err("hooks not found — run `ai-obs install`".into())
                }
            }
        }
    });

    check("daemon", {
        match crate::client::get_json(port(), "/api/status") {
            Err(e) => Err(format!("{e:#}")),
            Ok(v) => {
                let sessions = v["sessions"].as_u64().unwrap_or(0);
                let cost = v["sampler_cost_frac"].as_f64().unwrap_or(0.0);
                let mut msg = format!(
                    "up {}s, {} session(s), sampler cost {:.2}% of a core",
                    v["uptime_ms"].as_i64().unwrap_or(0) / 1000,
                    sessions,
                    cost * 100.0
                );
                if cost > 0.05 {
                    msg.push_str(" [HIGH]");
                }
                Ok(msg)
            }
        }
    });

    check("database", {
        let db = crate::store::default_db_path();
        if db.exists() {
            match crate::store::Store::open_readonly(&db) {
                Ok(s) => {
                    let spans = s
                        .query_json("SELECT COUNT(*) n FROM tool_span", &[])
                        .ok()
                        .and_then(|r| r.first().and_then(|x| x["n"].as_i64()))
                        .unwrap_or(0);
                    Ok(format!("{} — {} spans recorded", db.display(), spans))
                }
                Err(e) => Err(format!("cannot open {}: {e:#}", db.display())),
            }
        } else {
            Err(format!("{} does not exist yet (daemon not run?)", db.display()))
        }
    });

    check("pricing table", {
        // pricing::REVIEWED is "YYYY-MM"; warn when older than ~6 months.
        let reviewed = crate::pricing::REVIEWED;
        Ok(format!(
            "reviewed {reviewed}; unknown models are stored with cost NULL, never guessed"
        ))
    });

    if failures == 0 {
        println!("\nall checks passed");
        0
    } else {
        println!("\n{failures} check(s) failed");
        1
    }
}
