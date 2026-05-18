//! Parsers for human-readable resource strings used in `AppSpec`.

use crate::error::{Result, RuntimeError};

/// Parse a memory string like `"256MB"`, `"1.5GiB"`, `"512K"` into bytes.
///
/// Recognises both decimal (k, M, G, T) and binary (Ki, Mi, Gi, Ti) prefixes,
/// case-insensitive. A trailing `b` / `B` is optional. No suffix means bytes.
pub(crate) fn parse_memory(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::InvalidResource {
            field: "memory",
            value: raw.to_owned(),
            reason: "empty",
        });
    }

    // Split into numeric prefix and unit suffix.
    let (num_str, unit_str) = split_number_unit(trimmed);
    let value: f64 = num_str.parse().map_err(|_| RuntimeError::InvalidResource {
        field: "memory",
        value: raw.to_owned(),
        reason: "not a number",
    })?;
    if !value.is_finite() || value < 0.0 {
        return Err(RuntimeError::InvalidResource {
            field: "memory",
            value: raw.to_owned(),
            reason: "must be a non-negative finite number",
        });
    }

    let multiplier = memory_multiplier(unit_str).ok_or(RuntimeError::InvalidResource {
        field: "memory",
        value: raw.to_owned(),
        reason: "unknown unit",
    })?;

    // Allow lossy float<->int conversion: memory sizes fit comfortably in
    // an f64 mantissa for any realistic input.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let bytes = (value * multiplier as f64) as u64;
    Ok(bytes)
}

/// Parse a CPU string like `"0.5"`, `"2"`, `"100m"` into a cgroup
/// `cpu.shares` value (the OCI spec's portable name; libcontainer
/// maps it to cgroup v2's `cpu.weight` automatically).
///
/// `1.0` → 1024 shares (the cgroup default, equivalent to weight 100).
/// `0.5` → 512 (half priority). `2.0` → 2048 (double priority). `100m`
/// is shorthand for `0.1`. Shares are a **relative weight** between
/// apps, not a hard cap — an app with shares 512 takes half the CPU
/// of an app with 1024 only while both are saturating the same core;
/// otherwise it gets whatever's idle. This is the "instance-wide
/// bugpot, fair-share contention" model that replaced the prior
/// `cpu.max` hardcap behaviour.
///
/// Floor at 2 (cgroup v2's minimum); ceiling at 262144 (the largest
/// shares value that maps to a valid cgroup v2 weight ≤ 10000).
pub(crate) fn parse_cpu(raw: &str) -> Result<u64> {
    /// cgroup v1 cpu.shares for "1.0 CPU's worth". libcontainer
    /// rescales to cgroup v2 cpu.weight per the OCI conversion
    /// formula; 1024 maps to weight 100, which is the cgroup v2
    /// default.
    const SHARES_PER_CPU: f64 = 1024.0;
    const MIN_SHARES: u64 = 2;
    const MAX_SHARES: u64 = 262_144;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::InvalidResource {
            field: "cpu",
            value: raw.to_owned(),
            reason: "empty",
        });
    }

    let cpus: f64 = if let Some(stripped) = trimmed
        .strip_suffix('m')
        .or_else(|| trimmed.strip_suffix('M'))
    {
        stripped
            .parse::<f64>()
            .map_err(|_| RuntimeError::InvalidResource {
                field: "cpu",
                value: raw.to_owned(),
                reason: "not a number",
            })?
            / 1000.0
    } else {
        trimmed
            .parse::<f64>()
            .map_err(|_| RuntimeError::InvalidResource {
                field: "cpu",
                value: raw.to_owned(),
                reason: "not a number",
            })?
    };

    if !cpus.is_finite() || cpus <= 0.0 {
        return Err(RuntimeError::InvalidResource {
            field: "cpu",
            value: raw.to_owned(),
            reason: "must be > 0",
        });
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let raw_shares = (cpus * SHARES_PER_CPU).round() as u64;
    Ok(raw_shares.clamp(MIN_SHARES, MAX_SHARES))
}

fn split_number_unit(s: &str) -> (&str, &str) {
    let idx = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(idx);
    (num.trim(), unit.trim())
}

fn memory_multiplier(unit: &str) -> Option<u64> {
    // Normalise.
    let u = unit.trim().to_ascii_uppercase();
    // Strip optional trailing 'B' (e.g. KB, MB, MiB → KiB → handled below)
    // We accept both decimal (K, M, G, T) and binary (Ki, Mi, Gi, Ti) units.
    let stripped = u.strip_suffix('B').unwrap_or(&u);
    match stripped {
        "" => Some(1),
        "K" => Some(1_000),
        "M" => Some(1_000_000),
        "G" => Some(1_000_000_000),
        "T" => Some(1_000_000_000_000),
        "KI" => Some(1 << 10),
        "MI" => Some(1 << 20),
        "GI" => Some(1 << 30),
        "TI" => Some(1 << 40),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_bytes_no_unit() {
        assert_eq!(parse_memory("1024").unwrap(), 1024);
    }

    #[test]
    fn memory_decimal_units() {
        assert_eq!(parse_memory("1KB").unwrap(), 1_000);
        assert_eq!(parse_memory("256MB").unwrap(), 256_000_000);
        assert_eq!(parse_memory("1GB").unwrap(), 1_000_000_000);
    }

    #[test]
    fn memory_binary_units() {
        assert_eq!(parse_memory("1KiB").unwrap(), 1024);
        assert_eq!(parse_memory("256MiB").unwrap(), 256 * 1024 * 1024);
        assert_eq!(parse_memory("1GiB").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn memory_case_insensitive_and_whitespace() {
        assert_eq!(parse_memory(" 2 mb ").unwrap(), 2_000_000);
        assert_eq!(parse_memory("2gib").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn memory_rejects_garbage() {
        assert!(parse_memory("nope").is_err());
        assert!(parse_memory("-1MB").is_err());
        assert!(parse_memory("1XB").is_err());
        assert!(parse_memory("").is_err());
    }

    #[test]
    fn cpu_default_neutral_priority() {
        // "1.0" = 1024 shares = cgroup v2 weight 100 (the default).
        // Apps without an explicit cpu setting end up here.
        assert_eq!(parse_cpu("1.0").unwrap(), 1024);
        assert_eq!(parse_cpu("1").unwrap(), 1024);
    }

    #[test]
    fn cpu_double_priority() {
        assert_eq!(parse_cpu("2").unwrap(), 2048);
    }

    #[test]
    fn cpu_half_priority() {
        assert_eq!(parse_cpu("0.5").unwrap(), 512);
    }

    #[test]
    fn cpu_millis_are_milli_cpus() {
        // 100m = 0.1 CPU's worth = 102.4 shares, rounded to 102.
        assert_eq!(parse_cpu("100m").unwrap(), 102);
    }

    #[test]
    fn cpu_clamps_below_kernel_floor() {
        // 0.001 = 1.024 raw shares; cgroup v2 weight floor is 2.
        assert_eq!(parse_cpu("0.001").unwrap(), 2);
    }

    #[test]
    fn cpu_rejects_garbage() {
        assert!(parse_cpu("nope").is_err());
        assert!(parse_cpu("0").is_err());
        assert!(parse_cpu("-1").is_err());
    }
}
