//! IPv4 allocator for the bridge subnet.
//!
//! - Reserves `.1` for the bridge / DNS endpoint, `.255` (broadcast in `/24`)
//!   and the network address.
//! - Hands out the next free host address, re-using released addresses.
//! - Pure data structure, no network side effects.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

#[derive(Debug)]
pub struct IpAllocator {
    subnet: Ipv4Net,
    bridge_ip: Ipv4Addr,
    in_use: HashSet<Ipv4Addr>,
}

impl IpAllocator {
    pub fn new(subnet: Ipv4Net, bridge_ip: Ipv4Addr) -> anyhow::Result<Self> {
        anyhow::ensure!(
            subnet.contains(&bridge_ip),
            "bridge IP {bridge_ip} not in subnet {subnet}"
        );
        Ok(Self {
            subnet,
            bridge_ip,
            in_use: HashSet::new(),
        })
    }

    /// Allocate the next free address. Errors when the subnet is exhausted.
    pub fn allocate(&mut self) -> anyhow::Result<Ipv4Addr> {
        for ip in self.subnet.hosts() {
            if ip == self.bridge_ip {
                continue;
            }
            if self.in_use.insert(ip) {
                return Ok(ip);
            }
        }
        anyhow::bail!("subnet {} exhausted", self.subnet)
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        self.in_use.remove(&ip);
    }

    /// Mark `ip` as already taken without going through `allocate`. Used at
    /// startup to seed the in-use set with addresses recovered from the
    /// kernel (live netns from a previous bugpot instance).
    pub fn mark_used(&mut self, ip: Ipv4Addr) {
        self.in_use.insert(ip);
    }

    #[must_use]
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        self.in_use.contains(&ip)
    }

    #[must_use]
    pub const fn bridge_ip(&self) -> Ipv4Addr {
        self.bridge_ip
    }

    #[must_use]
    pub const fn subnet(&self) -> Ipv4Net {
        self.subnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> IpAllocator {
        let net: Ipv4Net = "172.20.0.0/24".parse().unwrap();
        IpAllocator::new(net, "172.20.0.1".parse().unwrap()).unwrap()
    }

    #[test]
    fn skips_bridge_ip_and_returns_sequentially() {
        let mut a = fixture();
        let first = a.allocate().unwrap();
        let second = a.allocate().unwrap();
        assert_eq!(first, "172.20.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(second, "172.20.0.3".parse::<Ipv4Addr>().unwrap());
        assert_ne!(first, a.bridge_ip());
    }

    #[test]
    fn release_makes_address_reusable() {
        let mut a = fixture();
        let ip = a.allocate().unwrap();
        assert!(a.is_allocated(ip));
        a.release(ip);
        assert!(!a.is_allocated(ip));
        // Lowest free host is `.2` again because `.2` was released.
        assert_eq!(a.allocate().unwrap(), ip);
    }

    #[test]
    fn exhaustion_errors() {
        let net: Ipv4Net = "10.0.0.0/30".parse().unwrap();
        // /30 has hosts .1 and .2 only; bridge takes .1, so one allocation max.
        let mut a = IpAllocator::new(net, "10.0.0.1".parse().unwrap()).unwrap();
        let _ = a.allocate().unwrap();
        assert!(a.allocate().is_err());
    }

    #[test]
    fn rejects_bridge_outside_subnet() {
        let net: Ipv4Net = "172.20.0.0/24".parse().unwrap();
        assert!(IpAllocator::new(net, "10.0.0.1".parse().unwrap()).is_err());
    }
}
