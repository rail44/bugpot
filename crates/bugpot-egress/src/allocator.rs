//! IPv4 allocator for the bridge subnet.
//!
//! - Reserves `.1` for the bridge / DNS endpoint, `.255` (broadcast in `/24`)
//!   and the network address.
//! - Hands out the lowest free host address, re-using released addresses.
//! - Pure data structure, no network side effects.
//!
//! Implementation: holds the **free** set (rather than the in-use set) in a
//! `BTreeSet<Ipv4Addr>`. `pop_first` gives O(log N) allocate and preserves
//! the "lowest free first" semantics tests rely on. Initialisation cost
//! grows with the subnet size (one insert per host), bounded at startup;
//! after that no per-allocation scan is needed regardless of subnet width.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

#[derive(Debug)]
pub struct IpAllocator {
    subnet: Ipv4Net,
    bridge_ip: Ipv4Addr,
    free: BTreeSet<Ipv4Addr>,
}

impl IpAllocator {
    pub fn new(subnet: Ipv4Net, bridge_ip: Ipv4Addr) -> anyhow::Result<Self> {
        anyhow::ensure!(
            subnet.contains(&bridge_ip),
            "bridge IP {bridge_ip} not in subnet {subnet}"
        );
        let mut free = BTreeSet::new();
        for ip in subnet.hosts() {
            if ip != bridge_ip {
                free.insert(ip);
            }
        }
        Ok(Self {
            subnet,
            bridge_ip,
            free,
        })
    }

    /// Allocate the lowest free address. Errors when the subnet is exhausted.
    pub fn allocate(&mut self) -> anyhow::Result<Ipv4Addr> {
        self.free
            .pop_first()
            .ok_or_else(|| anyhow::anyhow!("subnet {} exhausted", self.subnet))
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        // Defence-in-depth: never put the bridge IP or an address
        // outside the subnet back into rotation, no matter what the
        // caller hands us.
        if ip != self.bridge_ip && self.subnet.contains(&ip) {
            self.free.insert(ip);
        }
    }

    /// Mark `ip` as already taken without going through `allocate`. Used at
    /// startup to seed the in-use set with addresses recovered from the
    /// kernel (live netns from a previous bugpot instance).
    pub fn mark_used(&mut self, ip: Ipv4Addr) {
        self.free.remove(&ip);
    }

    #[must_use]
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        ip != self.bridge_ip && self.subnet.contains(&ip) && !self.free.contains(&ip)
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

    #[test]
    fn is_allocated_classifies_special_addresses() {
        let mut a = fixture();
        // Bridge: never reported as allocated by the allocator (it is
        // permanently reserved, not "given out").
        assert!(!a.is_allocated(a.bridge_ip()));
        // Out-of-subnet: never reported as allocated.
        assert!(!a.is_allocated("10.0.0.1".parse().unwrap()));
        // Fresh state: every host address is free.
        assert!(!a.is_allocated("172.20.0.2".parse().unwrap()));
        // After allocate the address is reported as allocated.
        let ip = a.allocate().unwrap();
        assert!(a.is_allocated(ip));
    }

    #[test]
    fn release_ignores_bridge_and_out_of_subnet() {
        let mut a = fixture();
        // Releasing the bridge IP or a stray address must not put it
        // into rotation — defence-in-depth against a caller bug.
        a.release(a.bridge_ip());
        a.release("10.0.0.1".parse().unwrap());
        let first = a.allocate().unwrap();
        // First handout is still .2, not .1.
        assert_eq!(first, "172.20.0.2".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn allocate_is_amortised_constant_at_subnet_scale() {
        // Regression guard for the algorithmic-complexity rewrite: at
        // /22 (about 1k hosts) the old linear-scan allocator did ~1M
        // hash probes for a full drain. The BTreeSet path completes
        // well under a tenth of a second; we only assert it finishes
        // and returns the expected count.
        let net: Ipv4Net = "10.0.0.0/22".parse().unwrap();
        let mut a = IpAllocator::new(net, "10.0.0.1".parse().unwrap()).unwrap();
        let mut count = 0;
        while a.allocate().is_ok() {
            count += 1;
        }
        // /22 has 1022 host addresses; minus the bridge IP we expect 1021.
        assert_eq!(count, 1021);
    }
}
