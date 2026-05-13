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
//!   - netns name: `bugpot-<app_id>` → bind-mounted at
//!     `/var/run/netns/bugpot-<app_id>` by `ip netns add`.

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
    pub fn new(app_id: &str, container_ip: Ipv4Addr, subnet: Ipv4Net) -> Self {
        let short = short_id(app_id);
        let ns_name = format!("{NS_PREFIX}{app_id}");
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

/// 12-char-max stable shortening of an app id for use in interface names
/// (IFNAMSIZ = 16 incl. NUL → host iface `vh-` + 12 = 15 bytes).
fn short_id(app_id: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset
    for b in app_id.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    // Truncate to 12 hex chars (48 bits — collision is acceptable; app_ids
    // are short-lived per-host names, and a clash will surface as `ip link
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

/// Run a sequence of `ip` commands. Errors are returned with the failing
/// command included for diagnosis.
pub async fn run_cmds(cmds: Vec<IpCmd>) -> anyhow::Result<()> {
    for cmd in cmds {
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
    }
    Ok(())
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
    fn endpoint_plan_is_stable_per_app_id() {
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
