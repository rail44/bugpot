//! `/proc/meminfo` parsing for the controller's memory-pressure
//! handler. Kept here rather than in `bugpot-metrics` because the only
//! consumer is the frozen-app eviction loop, and the pressure signal
//! it derives is internal to the controller's lifecycle decisions
//! (not an operator-facing metric).

/// Parse `MemAvailable` (in bytes) from `/proc/meminfo`. Returns
/// `None` if the file can't be read or the field is missing — callers
/// should skip the tick rather than treat an absent reading as
/// "no pressure". Linux-only path; on a non-Linux dev host this
/// returns `None` and the memory pressure loop is a no-op.
pub(crate) fn read_mem_available() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_mem_available(&raw)
}

fn parse_mem_available(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            // `MemAvailable:   123456 kB` — split on whitespace, take
            // the number, multiply by 1024.
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())?;
            return Some(kb * 1024);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mem_available_finds_value_and_converts_kb_to_bytes() {
        let sample = "MemTotal:        1014820 kB\nMemFree:          123456 kB\nMemAvailable:     200000 kB\nBuffers:           12345 kB\n";
        assert_eq!(parse_mem_available(sample), Some(200_000 * 1024));
    }

    #[test]
    fn parse_mem_available_returns_none_when_field_missing() {
        let sample = "MemTotal: 1024 kB\nMemFree: 512 kB\n";
        assert!(parse_mem_available(sample).is_none());
    }

    #[test]
    fn parse_mem_available_tolerates_extra_whitespace() {
        let sample = "MemAvailable:\t  500 kB\n";
        assert_eq!(parse_mem_available(sample), Some(500 * 1024));
    }
}
