//! Cgroup v2 stats reading for live containers.
//!
//! Reads `memory.current` and `cpu.stat` from the running container's
//! cgroup directory, after resolving the directory by reading
//! `/proc/<pid>/cgroup`. The numbers feed
//! `bugpot_app_memory_bytes` and `bugpot_app_cpu_microseconds_total`
//! via the controller's `emit_resource_metrics`.
//!
//! Cgroup v1 hosts silently return `None` — bugpot expects v2.

use std::fs;
use std::path::{Path, PathBuf};

/// Resolve the cgroup v2 path of `pid` by reading `/proc/<pid>/cgroup`.
/// Returns `None` when the file is missing (process gone) or the
/// expected `0::/...` line is absent (cgroup v1 host).
pub(crate) fn cgroup_path_for_pid(pid: u32) -> Option<PathBuf> {
    let body = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_cgroup_v2_path(&body).map(|rel| {
        let mut p = PathBuf::from("/sys/fs/cgroup");
        let trimmed = rel.trim_start_matches('/');
        if !trimmed.is_empty() {
            p.push(trimmed);
        }
        p
    })
}

/// Parse the cgroup v2 line (`"0::/foo/bar"`) out of the content of
/// `/proc/<pid>/cgroup`. Cgroup v1 lines (`"4:cpu:/..."`) are ignored.
fn parse_cgroup_v2_path(s: &str) -> Option<String> {
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            return Some(rest.to_owned());
        }
    }
    None
}

pub(crate) fn read_memory_bytes(cgroup: &Path) -> Option<u64> {
    let text = fs::read_to_string(cgroup.join("memory.current")).ok()?;
    text.trim().parse().ok()
}

pub(crate) fn read_cpu_usec(cgroup: &Path) -> Option<u64> {
    let text = fs::read_to_string(cgroup.join("cpu.stat")).ok()?;
    parse_cpu_usec(&text)
}

/// Parse the `usage_usec <n>` field out of the cgroup v2 `cpu.stat`
/// file body. Other fields (`user_usec`, `system_usec`, throttling
/// stats) are ignored.
fn parse_cpu_usec(stat_content: &str) -> Option<u64> {
    for line in stat_content.lines() {
        if let Some(rest) = line.strip_prefix("usage_usec ") {
            return rest.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cgroup_v2_picks_unified_line() {
        // Real-world `/proc/<pid>/cgroup` on a cgroup-v2-unified host.
        let body = "0::/system.slice/bugpot-x.service\n";
        assert_eq!(
            parse_cgroup_v2_path(body),
            Some("/system.slice/bugpot-x.service".to_string()),
        );
    }

    #[test]
    fn parse_cgroup_v2_ignores_v1_lines() {
        // Hybrid mode: v1 controllers come first, v2 is the line with "0::".
        let body = "\
13:misc:/\n\
12:cpuset:/\n\
11:cpu,cpuacct:/foo\n\
0::/unified/path\n";
        assert_eq!(
            parse_cgroup_v2_path(body),
            Some("/unified/path".to_string())
        );
    }

    #[test]
    fn parse_cgroup_v2_absent_returns_none() {
        // v1-only host has no `0::` line.
        let body = "1:cpu:/foo\n2:memory:/foo\n";
        assert!(parse_cgroup_v2_path(body).is_none());
    }

    #[test]
    fn parse_cpu_usec_finds_usage_field() {
        let body = "\
usage_usec 123456789\n\
user_usec 100000000\n\
system_usec 23456789\n\
nr_periods 0\n";
        assert_eq!(parse_cpu_usec(body), Some(123_456_789));
    }

    #[test]
    fn parse_cpu_usec_missing_field_returns_none() {
        let body = "user_usec 1\nsystem_usec 1\n";
        assert!(parse_cpu_usec(body).is_none());
    }
}
