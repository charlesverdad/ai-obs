//! Local token→USD pricing. Used only when Claude Code's own priced telemetry
//! is unavailable; rows record cost_source='computed' so nobody mistakes an
//! estimate for the authoritative number. Unknown models get cost NULL, never
//! a guess.

/// USD per million tokens: (model substring, input, output).
/// Cache pricing follows the standard multipliers: read = 0.1x input,
/// 5-minute cache write = 1.25x input.
/// Last reviewed: 2026-08. `ai-obs doctor` warns when this file's review date
/// is more than 6 months old.
pub const REVIEWED: &str = "2026-08";

const TABLE: &[(&str, f64, f64)] = &[
    ("opus", 15.0, 75.0),
    ("sonnet", 3.0, 15.0),
    ("haiku", 1.0, 5.0),
];

pub fn cost_usd(
    model: &str,
    input: i64,
    output: i64,
    cache_read: i64,
    cache_creation: i64,
) -> Option<f64> {
    let m = model.to_ascii_lowercase();
    let (_, inp, out) = TABLE.iter().find(|(k, _, _)| m.contains(k))?;
    let per = 1.0 / 1_000_000.0;
    Some(
        input as f64 * inp * per
            + output as f64 * out * per
            + cache_read as f64 * inp * 0.1 * per
            + cache_creation as f64 * inp * 1.25 * per,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_models_priced() {
        let c = cost_usd("claude-sonnet-5", 1_000_000, 0, 0, 0).unwrap();
        assert!((c - 3.0).abs() < 1e-9);
        let c = cost_usd("claude-opus-5[1m]", 0, 1_000_000, 0, 0).unwrap();
        assert!((c - 75.0).abs() < 1e-9);
    }

    #[test]
    fn unknown_model_is_none_not_zero() {
        assert!(cost_usd("claude-fable-5", 1000, 1000, 0, 0).is_none());
    }

    #[test]
    fn cache_multipliers() {
        // 1M cache-read on sonnet = 0.1 * $3
        let c = cost_usd("sonnet", 0, 0, 1_000_000, 0).unwrap();
        assert!((c - 0.30).abs() < 1e-9);
        let c = cost_usd("sonnet", 0, 0, 0, 1_000_000).unwrap();
        assert!((c - 3.75).abs() < 1e-9);
    }
}
