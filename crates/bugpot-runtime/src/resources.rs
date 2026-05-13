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
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
    let bytes = (value * multiplier as f64) as u64;
    Ok(bytes)
}

/// Parse a CPU string like `"0.5"`, `"2"`, `"100m"` into `(quota_us, period_us)`.
///
/// Returns the cgroup `cpu.quota` and `cpu.period` in microseconds.
///
/// We use a fixed period of `100_000` microseconds (the cgroup default) and
/// scale quota accordingly. `100m` (milli-cpus) == 0.1 CPU.
pub(crate) fn parse_cpu(raw: &str) -> Result<(i64, u64)> {
    const PERIOD_US: u64 = 100_000;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::InvalidResource {
            field: "cpu",
            value: raw.to_owned(),
            reason: "empty",
        });
    }

    let cpus: f64 = if let Some(stripped) =
        trimmed.strip_suffix('m').or_else(|| trimmed.strip_suffix('M'))
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

    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    let quota = (cpus * PERIOD_US as f64).round() as i64;
    Ok((quota, PERIOD_US))
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
    fn cpu_full_cores() {
        let (quota, period) = parse_cpu("2").unwrap();
        assert_eq!(period, 100_000);
        assert_eq!(quota, 200_000);
    }

    #[test]
    fn cpu_fractional() {
        let (quota, _) = parse_cpu("0.5").unwrap();
        assert_eq!(quota, 50_000);
    }

    #[test]
    fn cpu_millis() {
        let (quota, _) = parse_cpu("100m").unwrap();
        assert_eq!(quota, 10_000);
    }

    #[test]
    fn cpu_rejects_garbage() {
        assert!(parse_cpu("nope").is_err());
        assert!(parse_cpu("0").is_err());
        assert!(parse_cpu("-1").is_err());
    }
}
