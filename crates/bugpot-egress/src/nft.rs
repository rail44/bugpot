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
/// table (idempotent on first run, replaces on reload).
#[must_use]
pub fn render_bootstrap(cfg: &NftConfig) -> String {
    let mut out = String::new();
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

    // forward chain, default drop for traffic leaving the bridge.
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

    // input chain: allow the bridge DNS port from inside the subnet plus
    // any conntrack-related reply (so host-initiated connections to
    // containers, e.g. bugpot-router → app, receive their responses).
    // Everything else originating from the bridge subnet is dropped, so
    // containers cannot probe the host's other services.
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

    out
}

/// Render the command that adds `(src, dst)` to the allow set with the
/// table's default timeout. Exposed for testing; runtime uses [`add_allow`].
#[must_use]
pub fn render_add_allow(table: &str, src: Ipv4Addr, dst: Ipv4Addr) -> String {
    format!("add element inet {table} allow4 {{ {src} . {dst} }}")
}

/// Render the command that deletes every `(src, *)` entry for a given app —
/// used when releasing an endpoint.
#[must_use]
pub fn render_flush_src(table: &str, _src: Ipv4Addr) -> String {
    // nft can't filter set elements by sub-key, so we just flush the set
    // (entries are short-lived under TTL anyway). Caller may choose to be
    // surgical with `nft list set` + per-element delete; we keep it simple.
    format!("flush set inet {table} allow4")
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
        assert_eq!(s, "add element inet bugpot allow4 { 172.20.0.10 . 1.2.3.4 }");
    }

    #[test]
    fn flush_src_text() {
        let s = render_flush_src("bugpot", "172.20.0.10".parse().unwrap());
        assert_eq!(s, "flush set inet bugpot allow4");
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
        panic!(
            "nft -c rejected the bootstrap script:\n{stderr}\n--- script ---\n{script}"
        );
    }
}
