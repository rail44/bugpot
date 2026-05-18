//! nftables ruleset generation + thin shell-out wrapper around `nft`.
//!
//! Why shell out instead of `rustables` / `nftables-rs`:
//!   - `rustables` exposes the low-level netlink ABI; rule construction is
//!     verbose and brittle across kernel versions.
//!   - Generating a textual ruleset is trivially testable (no kernel needed).
//!   - The runtime overhead of `nft -f -` is negligible for our use (a handful
//!     of calls per app lifecycle plus per-DNS-resolve set updates).
//!
//! Layout (one inet table `bugpot`, atomic load):
//!   - `set allow4 { type ipv4_addr . ipv4_addr; flags timeout; }`
//!     populated dynamically by [`add_allow`].
//!   - chain `forward` (hook forward, priority filter):
//!     - accept conntrack established/related
//!     - accept bridge → bridge DNS endpoint on udp/tcp 53
//!     - drop outbound to 53 / 853 / `DoH` 443 toward non-bridge resolvers
//!     - accept if `(saddr . daddr)` ∈ allow4
//!     - drop
//!   - chain `input` (hook input): only the bridge-side DNS port is exposed to
//!     containers — covers the case where the DNS listener is bound to the
//!     bridge IP.

use std::fmt::Write;
use std::net::Ipv4Addr;
use std::process::Stdio;

use ipnet::Ipv4Net;
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct NftConfig {
    pub table: String,
    pub bridge: String,
    pub subnet: Ipv4Net,
    pub bridge_ip: Ipv4Addr,
    pub dns_port: u16,
    pub allow_ttl_secs: u32,
}

/// Build the textual ruleset that bootstraps the table, chains, and sets.
///
/// The output is meant for `nft -f -`. It first flushes any prior `bugpot`
/// table (idempotent on first run, replaces on reload). The three
/// sub-renderers below carry the per-section policy; this fn just
/// concatenates them in the order `nft` consumes them (table → set →
/// forward chain → input chain).
#[must_use]
pub fn render_bootstrap(cfg: &NftConfig) -> String {
    let mut out = String::new();
    render_table_and_set(&mut out, cfg);
    render_forward_chain(&mut out, cfg);
    render_input_chain(&mut out, cfg);
    out
}

/// Atomic-replace the `inet <table>` table and declare the `allow4`
/// timeout set inside it.
fn render_table_and_set(out: &mut String, cfg: &NftConfig) {
    // Flush prior state. `add table` is a no-op if it already exists; `delete`
    // then `add` is the standard atomic-replace idiom.
    let _ = writeln!(out, "add table inet {}", cfg.table);
    let _ = writeln!(out, "delete table inet {}", cfg.table);
    let _ = writeln!(out, "add table inet {}", cfg.table);

    // Allow set: (src, dst) tuple with timeout.
    let _ = writeln!(
        out,
        "add set inet {table} allow4 {{ type ipv4_addr . ipv4_addr; flags timeout; timeout {ttl}s; }}",
        table = cfg.table,
        ttl = cfg.allow_ttl_secs,
    );
}

/// Forward chain (default drop) — the rule that enforces the
/// allow-set gate for traffic leaving the bridge plus the
/// pre-`allow4` external-DNS / `DoT` shoulder drops.
fn render_forward_chain(out: &mut String, cfg: &NftConfig) {
    let _ = writeln!(
        out,
        "add chain inet {table} forward {{ type filter hook forward priority filter; policy drop; }}",
        table = cfg.table,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} forward ct state established,related accept",
        table = cfg.table,
    );
    // Block egress to *external* DNS over UDP / TCP and DoT. Containers may
    // only talk to the bridge DNS endpoint (allowed in `input`). DoH on
    // tcp/443 is not blocked at L4 (looks like ordinary HTTPS); it is denied
    // implicitly because the bridge DNS never resolves DoH bootstrap names,
    // so DoH server IPs never enter `allow4`, and the final allow-set check
    // drops them.
    let _ = writeln!(
        out,
        "add rule inet {table} forward ip saddr {subnet} udp dport {{ 53, 853 }} drop",
        table = cfg.table,
        subnet = cfg.subnet,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} forward ip saddr {subnet} tcp dport {{ 53, 853 }} drop",
        table = cfg.table,
        subnet = cfg.subnet,
    );
    // The actual gate: only `(src, dst)` pairs the DNS path has populated.
    let _ = writeln!(
        out,
        "add rule inet {table} forward ip saddr . ip daddr @allow4 accept",
        table = cfg.table,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} forward ip saddr {subnet} log prefix \"bugpot-drop \" drop",
        table = cfg.table,
        subnet = cfg.subnet,
    );
}

/// Input chain — allows the bridge DNS port from inside the subnet
/// plus conntrack-related replies (so host-initiated connections to
/// containers, e.g. bugpot-router → app, receive their responses).
/// Everything else originating from the bridge subnet is dropped, so
/// containers cannot probe the host's other services.
fn render_input_chain(out: &mut String, cfg: &NftConfig) {
    let _ = writeln!(
        out,
        "add chain inet {table} input {{ type filter hook input priority filter; policy accept; }}",
        table = cfg.table,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} input iifname \"{bridge}\" ct state established,related accept",
        table = cfg.table,
        bridge = cfg.bridge,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} input iifname \"{bridge}\" ip daddr {bridge_ip} udp dport {dns} accept",
        table = cfg.table,
        bridge = cfg.bridge,
        bridge_ip = cfg.bridge_ip,
        dns = cfg.dns_port,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} input iifname \"{bridge}\" ip daddr {bridge_ip} tcp dport {dns} accept",
        table = cfg.table,
        bridge = cfg.bridge,
        bridge_ip = cfg.bridge_ip,
        dns = cfg.dns_port,
    );
    let _ = writeln!(
        out,
        "add rule inet {table} input iifname \"{bridge}\" ip saddr {subnet} drop",
        table = cfg.table,
        bridge = cfg.bridge,
        subnet = cfg.subnet,
    );
}

/// Render the command that adds `(src, dst)` to the allow set with the
/// table's default timeout. Exposed for testing; runtime uses [`add_allow`].
#[must_use]
pub fn render_add_allow(table: &str, src: Ipv4Addr, dst: Ipv4Addr) -> String {
    format!("add element inet {table} allow4 {{ {src} . {dst} }}")
}

/// Minimal subset of `nft -j list set` JSON, just enough to enumerate
/// `(src, dst)` pairs from the `allow4` set. Each `nftables` array
/// entry is an object with a single tagging key (`metainfo`, `set`,
/// `table`, etc.); we only care about `set` blocks and ignore the
/// rest via `#[serde(default)]`.
#[derive(Debug, Deserialize)]
struct NftListOutput {
    nftables: Vec<NftListBlock>,
}

#[derive(Debug, Deserialize)]
struct NftListBlock {
    #[serde(default)]
    set: Option<NftSet>,
}

#[derive(Debug, Deserialize)]
struct NftSet {
    #[serde(default)]
    elem: Vec<NftElemEntry>,
}

#[derive(Debug, Deserialize)]
struct NftElemEntry {
    elem: NftElem,
}

#[derive(Debug, Deserialize)]
struct NftElem {
    val: NftElemVal,
}

#[derive(Debug, Deserialize)]
struct NftElemVal {
    /// For our `type ipv4_addr . ipv4_addr` set, this is the
    /// `[src, dst]` pair as strings.
    concat: Vec<String>,
}

/// Enumerate every `(src, dst)` pair currently in the `allow4` set of
/// `table`.
///
/// Returns `Ok(vec![])` for an empty set; an error only when `nft`
/// itself fails to run or its JSON output drifts from the schema we
/// know about.
pub async fn list_allow_set(table: &str) -> anyhow::Result<Vec<(Ipv4Addr, Ipv4Addr)>> {
    let output = Command::new("nft")
        .args(["-j", "list", "set", "inet", table, "allow4"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawn nft: {e}"))?;
    anyhow::ensure!(
        output.status.success(),
        "nft -j list set failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let parsed: NftListOutput = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("parse nft -j output: {e}"))?;

    let mut out = Vec::new();
    for block in parsed.nftables {
        let Some(set) = block.set else { continue };
        for entry in set.elem {
            if entry.elem.val.concat.len() < 2 {
                continue;
            }
            let Ok(src) = entry.elem.val.concat[0].parse::<Ipv4Addr>() else {
                continue;
            };
            let Ok(dst) = entry.elem.val.concat[1].parse::<Ipv4Addr>() else {
                continue;
            };
            out.push((src, dst));
        }
    }
    Ok(out)
}

/// Drop every `(src, *)` entry from `allow4` whose source is `src`.
/// Used when releasing an endpoint so the next app to take that IP
/// inherits no leftover allow-list state.
///
/// `nft` cannot delete elements by sub-key, so we list the set first
/// and emit a per-element `delete element` script. Both the list and
/// the delete may fail; the error is propagated so the caller can
/// decide whether to surface or swallow it. Entries TTL-expire after
/// `allow_ttl_secs`, so the typical caller (endpoint release) logs +
/// drops the error and lets the TTL handle eventual cleanup.
pub async fn flush_src(table: &str, src: Ipv4Addr) -> anyhow::Result<()> {
    let entries = list_allow_set(table).await?;
    let mut script = String::new();
    for (s, d) in entries {
        if s == src {
            let _ = writeln!(script, "delete element inet {table} allow4 {{ {s} . {d} }}");
        }
    }
    if script.is_empty() {
        return Ok(());
    }
    run_script(&script).await
}

/// Run an nft script via `nft -f -`. Captures stderr in the error.
pub async fn run_script(script: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn nft: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let out = child.wait_with_output().await?;
    anyhow::ensure!(
        out.status.success(),
        "nft failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// Add a single `(src, dst)` allow entry.
pub async fn add_allow(table: &str, src: Ipv4Addr, dst: Ipv4Addr) -> anyhow::Result<()> {
    run_script(&render_add_allow(table, src, dst)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> NftConfig {
        NftConfig {
            table: "bugpot".into(),
            bridge: "bugpot0".into(),
            subnet: "172.20.0.0/24".parse().unwrap(),
            bridge_ip: "172.20.0.1".parse().unwrap(),
            dns_port: 5353,
            allow_ttl_secs: 60,
        }
    }

    #[test]
    fn bootstrap_contains_required_pieces() {
        let s = render_bootstrap(&cfg());
        // Atomic-replace idiom.
        assert!(s.contains("add table inet bugpot"));
        assert!(s.contains("delete table inet bugpot"));
        // Allow set with the right type + timeout.
        assert!(s.contains("type ipv4_addr . ipv4_addr"));
        assert!(s.contains("timeout 60s"));
        // Default-drop forward.
        assert!(s.contains("hook forward"));
        assert!(s.contains("policy drop"));
        // External resolver block (udp 53/853 + tcp 53/853). Tcp/443 (DoH)
        // is blocked implicitly by the allow-set gate, not by an L4 rule.
        assert!(s.contains("udp dport { 53, 853 } drop"));
        assert!(s.contains("tcp dport { 53, 853 } drop"));
        assert!(!s.contains("allow4_doh_skip"), "dead set was removed");
        // The allow-set gate.
        assert!(s.contains("ip saddr . ip daddr @allow4 accept"));
        // Bridge-DNS input rule pinned to the bridge IP + port.
        assert!(s.contains("iifname \"bugpot0\""));
        assert!(s.contains("ip daddr 172.20.0.1"));
        assert!(s.contains("dport 5353"));
        // Conntrack reply rule on input — without this the router cannot
        // talk to apps over the bridge.
        assert!(s.contains("input iifname \"bugpot0\" ct state established,related accept"));
    }

    #[test]
    fn add_allow_text() {
        let s = render_add_allow(
            "bugpot",
            "172.20.0.10".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
        );
        assert_eq!(
            s,
            "add element inet bugpot allow4 { 172.20.0.10 . 1.2.3.4 }"
        );
    }

    /// Pure parser test for the JSON shape emitted by
    /// `nft -j list set inet <table> allow4`.
    ///
    /// Generated by capturing real `nft -j` output (nftables 1.0.9)
    /// after seeding the set with three `(src, dst)` pairs.
    #[test]
    fn parses_nft_list_set_json() {
        let body = r#"{
            "nftables": [
                {"metainfo": {"version": "1.0.9", "release_name": "x", "json_schema_version": 1}},
                {"set": {
                    "family": "inet", "name": "allow4", "table": "bugpot",
                    "type": ["ipv4_addr", "ipv4_addr"],
                    "handle": 1, "flags": ["timeout"], "timeout": 60,
                    "elem": [
                        {"elem": {"val": {"concat": ["172.20.0.2", "1.2.3.4"]}, "expires": 59}},
                        {"elem": {"val": {"concat": ["172.20.0.3", "9.8.7.6"]}, "expires": 59}},
                        {"elem": {"val": {"concat": ["172.20.0.2", "5.6.7.8"]}, "expires": 59}}
                    ]
                }}
            ]
        }"#;
        let parsed: NftListOutput = serde_json::from_str(body).unwrap();
        let mut pairs = Vec::new();
        for block in parsed.nftables {
            if let Some(set) = block.set {
                for entry in set.elem {
                    pairs.push((
                        entry.elem.val.concat[0].clone(),
                        entry.elem.val.concat[1].clone(),
                    ));
                }
            }
        }
        assert_eq!(
            pairs,
            vec![
                ("172.20.0.2".to_owned(), "1.2.3.4".to_owned()),
                ("172.20.0.3".to_owned(), "9.8.7.6".to_owned()),
                ("172.20.0.2".to_owned(), "5.6.7.8".to_owned()),
            ]
        );
    }

    /// Empty set: `elem` is omitted in the JSON. Must parse to zero
    /// entries, not error.
    #[test]
    fn parses_empty_set() {
        let body = r#"{
            "nftables": [
                {"set": {"family": "inet", "name": "allow4", "table": "bugpot",
                         "type": ["ipv4_addr", "ipv4_addr"]}}
            ]
        }"#;
        let parsed: NftListOutput = serde_json::from_str(body).unwrap();
        let count: usize = parsed
            .nftables
            .into_iter()
            .filter_map(|b| b.set)
            .map(|s| s.elem.len())
            .sum();
        assert_eq!(count, 0);
    }

    /// Pipe the bootstrap script through `nft -c -f -` (check-only mode) so
    /// that purely-textual mistakes — like a rule referencing a set that
    /// hasn't been declared yet — are caught at test time.
    ///
    /// `nft -c` still opens a netlink socket to populate its cache, so it
    /// requires `CAP_NET_ADMIN`. When the test is run as a non-privileged
    /// user we treat that as inconclusive rather than as a failure. Ignored
    /// by default; run with `sudo -E cargo test -- --ignored` for real
    /// validation, or with `cargo test -- --ignored` to confirm the script
    /// at least makes it past the parser.
    #[test]
    #[ignore = "needs the `nft` binary; run with `cargo test -- --ignored`"]
    fn bootstrap_parses_under_nft_check() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let script = render_bootstrap(&cfg());

        let mut child = match Command::new("nft")
            .args(["-c", "-f", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("`nft` not available, skipping ({e})");
                return;
            }
        };
        child
            .stdin
            .as_mut()
            .expect("nft stdin")
            .write_all(script.as_bytes())
            .expect("write nft script");
        let out = child.wait_with_output().expect("wait nft");
        if out.status.success() {
            return;
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("Operation not permitted") {
            eprintln!("nft -c needs CAP_NET_ADMIN; treating as inconclusive");
            return;
        }
        panic!("nft -c rejected the bootstrap script:\n{stderr}\n--- script ---\n{script}");
    }
}
