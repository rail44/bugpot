//! Bridge + veth + netns provisioning via shell-out to `ip(8)`.
//!
//! Why shell-out:
//!   - `rtnetlink` works but each operation (add link, set master, addr,
//!     up, move-to-netns) is many lines and version-sensitive.
//!   - `ip` is universally available on Linux hosts and tests can stub the
//!     command list (see [`render_setup_bridge`] / [`render_attach_endpoint`]).
//!   - All of these are root-only anyway; the shell boundary is not the
//!     bottleneck.
//!
//! Naming:
//!   - veth host side: `vh-<short_id>` (≤ 15 bytes, IFNAMSIZ-1)
//!   - veth peer when created (host netns): `vc-<short_id>` — must not
//!     collide with the host's existing interfaces (in particular real
//!     `eth0`); renamed to `eth0` only after being moved into the
//!     container's netns.
//!   - veth container side (final): `eth0` (inside the netns)
//!   - netns name: `bugpot-<name>` → bind-mounted at
//!     `/var/run/netns/bugpot-<name>` by `ip netns add`.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Stdio;

use ipnet::Ipv4Net;
use tokio::process::Command;

const NS_PREFIX: &str = "bugpot-";

/// Each step is one `ip` invocation. Kept as `Vec<&str>` so tests can assert
/// the full command line.
pub(crate) type IpCmd = Vec<String>;

#[derive(Debug)]
pub struct EndpointPlan {
    pub host_veth: String,
    /// Temporary name for the container side of the veth pair while it
    /// still lives in the host netns (before being moved into the
    /// container's netns). Picked to avoid colliding with the host's own
    /// interfaces (notably real `eth0`).
    pub tmp_ns_veth: String,
    /// Final name of the container-side interface, inside the netns.
    pub ns_veth: String,
    pub ns_name: String,
    pub ns_path: PathBuf,
    pub container_ip: Ipv4Addr,
    pub subnet_prefix: u8,
}

impl EndpointPlan {
    #[must_use]
    pub fn new(name: &str, container_ip: Ipv4Addr, subnet: Ipv4Net) -> Self {
        let short = short_name(name);
        let ns_name = format!("{NS_PREFIX}{name}");
        Self {
            host_veth: format!("vh-{short}"),
            tmp_ns_veth: format!("vc-{short}"),
            ns_veth: "eth0".to_string(),
            ns_path: PathBuf::from(format!("/var/run/netns/{ns_name}")),
            ns_name,
            container_ip,
            subnet_prefix: subnet.prefix_len(),
        }
    }
}

/// 12-char-max stable shortening of an app name for use in interface
/// names (IFNAMSIZ = 16 incl. NUL → host iface `vh-` + 12 = 15 bytes).
fn short_name(name: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // Truncate to 12 hex chars (48 bits — collision is acceptable; names
    // are short-lived per-host, and a clash will surface as `ip link
    // add` failure on the second app rather than as silent corruption).
    let s = format!("{h:016x}");
    s[..12].to_string()
}

#[must_use]
pub fn render_setup_bridge(bridge: &str, bridge_ip: Ipv4Addr, subnet: Ipv4Net) -> Vec<IpCmd> {
    vec![
        // The bridge may already exist after a restart; callers treat
        // EEXIST-ish failures as soft. We render the canonical create sequence.
        s(&["ip", "link", "add", bridge, "type", "bridge"]),
        s(&[
            "ip",
            "addr",
            "add",
            &format!("{bridge_ip}/{}", subnet.prefix_len()),
            "dev",
            bridge,
        ]),
        s(&["ip", "link", "set", bridge, "up"]),
        // Allow forwarding inside the kernel (the nftables chain has its own
        // policy; this just turns on the global switch).
        s(&[
            "sysctl",
            "-w",
            "net.ipv4.ip_forward=1",
        ]),
    ]
}

#[must_use]
pub fn render_attach_endpoint(bridge: &str, plan: &EndpointPlan) -> Vec<IpCmd> {
    let host = &plan.host_veth;
    let ns = &plan.ns_name;
    let tmp = &plan.tmp_ns_veth;
    let final_name = &plan.ns_veth;
    let addr_in_ns = format!("{}/{}", plan.container_ip, plan.subnet_prefix);
    vec![
        s(&["ip", "netns", "add", ns]),
        // Create the veth pair under a non-colliding peer name; rename
        // it to `eth0` only after it has been moved into the container's
        // netns, so the host's real `eth0` (if any) stays intact.
        s(&[
            "ip", "link", "add", host, "type", "veth", "peer", "name", tmp,
        ]),
        s(&["ip", "link", "set", host, "master", bridge]),
        s(&["ip", "link", "set", host, "up"]),
        s(&["ip", "link", "set", tmp, "netns", ns]),
        s(&["ip", "-n", ns, "link", "set", tmp, "name", final_name]),
        s(&["ip", "-n", ns, "addr", "add", &addr_in_ns, "dev", final_name]),
        s(&["ip", "-n", ns, "link", "set", final_name, "up"]),
        s(&["ip", "-n", ns, "link", "set", "lo", "up"]),
    ]
}

#[must_use]
pub fn render_detach_endpoint(plan: &EndpointPlan) -> Vec<IpCmd> {
    vec![
        // Deleting the netns also tears down the veth peer that lives in it;
        // the host side disappears when the bridge port is removed.
        s(&["ip", "link", "del", &plan.host_veth]),
        s(&["ip", "netns", "del", &plan.ns_name]),
    ]
}

fn s(parts: &[&str]) -> IpCmd {
    parts.iter().map(|p| (*p).to_string()).collect()
}

/// List the app ids of all `bugpot-*` netns present on the host.
///
/// Returns just the suffix after `bugpot-` (i.e. the app id), since
/// callers match these against loaded `AppSpec` names. Missing `ip` or
/// no matching netns both produce an empty result.
pub async fn list_app_namespaces() -> anyhow::Result<Vec<String>> {
    let output = Command::new("ip")
        .args(["netns", "list"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawn `ip netns list`: {e}"))?;
    anyhow::ensure!(
        output.status.success(),
        "`ip netns list` failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(parse_app_namespaces(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_app_namespaces(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| {
            // Each line is `<name>` or `<name> (id: <n>)` — we only want
            // the leading whitespace-delimited token.
            l.split_whitespace().next()
        })
        .filter_map(|name| name.strip_prefix(NS_PREFIX))
        .map(str::to_owned)
        .collect()
}

/// Read the IPv4 address of `eth0` inside the netns `bugpot-<name>`.
/// `Ok(None)` when the interface exists but carries no inet address; an
/// error when the netns or interface itself is gone.
pub async fn read_eth0_ipv4(name: &str) -> anyhow::Result<Option<Ipv4Addr>> {
    let ns = format!("{NS_PREFIX}{name}");
    let output = Command::new("ip")
        .args(["-n", &ns, "-4", "addr", "show", "eth0"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("spawn `ip -n {ns} addr show eth0`: {e}"))?;
    anyhow::ensure!(
        output.status.success(),
        "`ip -n {ns} -4 addr show eth0` failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(parse_inet_addr(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_inet_addr(s: &str) -> Option<Ipv4Addr> {
    // `ip addr show` output:
    //   2: eth0@if5: <UP,LOWER_UP> mtu 1500 ...
    //       inet 172.20.0.2/24 scope global eth0
    //          valid_lft forever preferred_lft forever
    for line in s.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("inet ")
            && let Some(cidr) = rest.split_whitespace().next()
            && let Some((ip, _prefix)) = cidr.split_once('/')
            && let Ok(addr) = ip.parse::<Ipv4Addr>()
        {
            return Some(addr);
        }
    }
    None
}

/// Run a single `ip` command. Returns an error including the command line
/// and the program's stderr on non-zero exit.
async fn run_one_cmd(cmd: &IpCmd) -> anyhow::Result<()> {
    let (head, tail) = cmd.split_first().ok_or_else(|| anyhow::anyhow!("empty cmd"))?;
    let status = Command::new(head)
        .args(tail)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn {head}: {e}"))?
        .wait_with_output()
        .await?;
    anyhow::ensure!(
        status.status.success(),
        "command {cmd:?} failed: {}",
        String::from_utf8_lossy(&status.stderr).trim()
    );
    Ok(())
}

/// Run a sequence of `ip` commands. Bails on the first non-zero exit
/// with the failing command included for diagnosis.
pub async fn run_cmds(cmds: Vec<IpCmd>) -> anyhow::Result<()> {
    for cmd in cmds {
        run_one_cmd(&cmd).await?;
    }
    Ok(())
}

/// Best-effort detach: runs every detach command independently,
/// ignoring failures.
///
/// Tolerates the "target does not exist" case from a partial prior
/// cleanup. Used by `Egress::allocate_endpoint` to reclaim a leaked
/// netns from a failed `release_endpoint`, and by
/// `cleanup_orphan_endpoint` so a missing veth doesn't block deleting
/// the netns.
pub async fn force_detach_endpoint(plan: &EndpointPlan) {
    for cmd in render_detach_endpoint(plan) {
        if let Err(e) = run_one_cmd(&cmd).await {
            tracing::debug!(?cmd, error = %e, "force-detach step failed; continuing");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_setup_is_canonical() {
        let cmds = render_setup_bridge(
            "bugpot0",
            "172.20.0.1".parse().unwrap(),
            "172.20.0.0/24".parse().unwrap(),
        );
        assert_eq!(cmds[0], vec!["ip", "link", "add", "bugpot0", "type", "bridge"]);
        assert_eq!(
            cmds[1],
            vec!["ip", "addr", "add", "172.20.0.1/24", "dev", "bugpot0"]
        );
        assert_eq!(cmds[2], vec!["ip", "link", "set", "bugpot0", "up"]);
    }

    #[test]
    fn endpoint_plan_is_stable_per_name() {
        let p1 = EndpointPlan::new(
            "myapp",
            "172.20.0.10".parse().unwrap(),
            "172.20.0.0/24".parse().unwrap(),
        );
        let p2 = EndpointPlan::new(
            "myapp",
            "172.20.0.10".parse().unwrap(),
            "172.20.0.0/24".parse().unwrap(),
        );
        assert_eq!(p1.host_veth, p2.host_veth);
        assert_eq!(p1.ns_name, "bugpot-myapp");
        assert!(p1.host_veth.len() <= 15, "iface name must fit IFNAMSIZ");
    }

    #[test]
    fn attach_commands_target_bridge_and_netns() {
        let plan = EndpointPlan::new(
            "myapp",
            "172.20.0.10".parse().unwrap(),
            "172.20.0.0/24".parse().unwrap(),
        );
        let cmds = render_attach_endpoint("bugpot0", &plan);
        // netns add comes first so subsequent moves can target it.
        assert_eq!(cmds[0][1], "netns");
        // host side ends up mastered by the bridge.
        assert!(cmds
            .iter()
            .any(|c| c.windows(2).any(|w| w == ["master", "bugpot0"])));
        // container IP is configured *inside* the netns.
        assert!(cmds.iter().any(|c| c.contains(&"172.20.0.10/24".to_string())
            && c.iter().any(|s| s == "-n")));
        // The veth pair MUST NOT be created with peer name `eth0` in the
        // host netns — that would collide with the host's real eth0.
        // It is renamed to eth0 only after being moved into the container
        // netns.
        assert!(
            !cmds.iter().any(|c| c.windows(2).any(|w| w == ["peer", "name"])
                && c.iter().any(|s| s == "eth0")),
            "veth peer must not be named eth0 while in host netns"
        );
        assert!(
            cmds.iter()
                .any(|c| c.windows(2).any(|w| w == ["set", &plan.tmp_ns_veth])
                    && c.iter().any(|s| s == "name")
                    && c.contains(&"eth0".to_string())),
            "rename to eth0 must happen inside the netns"
        );
    }

    #[test]
    fn parse_app_namespaces_filters_to_bugpot_prefix() {
        let out = "bugpot-alpha\nbugpot-beta (id: 1)\nother-ns\nbugpot-with-dashes\n";
        let mut got = parse_app_namespaces(out);
        got.sort();
        assert_eq!(got, vec!["alpha", "beta", "with-dashes"]);
    }

    #[test]
    fn parse_app_namespaces_handles_empty() {
        assert!(parse_app_namespaces("").is_empty());
    }

    #[test]
    fn parse_inet_addr_picks_v4() {
        let out = "2: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    \
            inet 172.20.0.2/24 scope global eth0\n       \
            valid_lft forever preferred_lft forever\n";
        assert_eq!(
            parse_inet_addr(out),
            Some("172.20.0.2".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn parse_inet_addr_missing_when_no_address() {
        let out = "2: eth0@if5: <BROADCAST,MULTICAST> mtu 1500\n";
        assert_eq!(parse_inet_addr(out), None);
    }

    #[test]
    fn detach_removes_host_iface_and_netns() {
        let plan = EndpointPlan::new(
            "myapp",
            "172.20.0.10".parse().unwrap(),
            "172.20.0.0/24".parse().unwrap(),
        );
        let cmds = render_detach_endpoint(&plan);
        assert!(cmds.iter().any(|c| c[0..3] == ["ip", "link", "del"]));
        assert!(cmds.iter().any(|c| c[0..3] == ["ip", "netns", "del"]));
    }
}
