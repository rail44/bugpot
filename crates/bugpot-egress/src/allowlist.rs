//! Per-app allowlist matching for domains and CIDR blocks.
//!
//! Rules in an allowlist string are auto-classified:
//!   - `*.example.com` → wildcard domain (matches `a.example.com`, `b.c.example.com`,
//!     but **not** `example.com`).
//!   - `example.com` → exact domain (or any subdomain of it, e.g. `api.example.com`).
//!     This mirrors common "egress allowlist" UX (Cilium FQDN policy default,
//!     iron-proxy "host" rule).
//!   - `1.2.3.0/24` or `10.0.0.0/8` → IPv4 CIDR (used for direct-IP matching).
//!   - `1.2.3.4` → IPv4 host (`/32`).
//!
//! Trailing dots and case are normalised on parse.

use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Matches `domain` exactly, or any subdomain of it.
    Domain(String),
    /// Matches strict subdomains of `domain` (e.g. `*.example.com` does not
    /// match `example.com`).
    Wildcard(String),
    /// Matches IPs inside the CIDR (used by the direct-IP allow path; DNS
    /// resolution never needs this branch).
    Cidr(Ipv4Net),
}

/// Compiled per-app allowlist.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<Rule>,
}

impl Allowlist {
    /// Parse a list of raw strings into rules. Empty / blank entries are
    /// skipped; unparseable entries return an error so misconfiguration is
    /// caught at app-deploy time.
    pub fn parse<I, S>(raw: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut rules = Vec::new();
        for entry in raw {
            let entry = entry.as_ref().trim();
            if entry.is_empty() {
                continue;
            }
            rules.push(Rule::parse(entry)?);
        }
        Ok(Self { rules })
    }

    /// Check whether a domain name (e.g. from a DNS query) is allowed by any
    /// rule. CIDR rules are ignored on this path.
    #[must_use]
    pub fn matches_domain(&self, name: &str) -> bool {
        let name = normalise_name(name);
        self.rules.iter().any(|r| match r {
            Rule::Domain(d) => name == *d || is_subdomain_of(d, &name),
            Rule::Wildcard(d) => is_subdomain_of(d, &name),
            Rule::Cidr(_) => false,
        })
    }

    /// Check whether a literal IPv4 address is allowed by any CIDR rule.
    /// Domain rules are ignored on this path.
    #[must_use]
    pub fn matches_ip(&self, ip: Ipv4Addr) -> bool {
        self.rules.iter().any(|r| match r {
            Rule::Cidr(net) => net.contains(&ip),
            Rule::Domain(_) | Rule::Wildcard(_) => false,
        })
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

impl Rule {
    fn parse(s: &str) -> anyhow::Result<Self> {
        // CIDR / IP forms contain '/' or are valid IPv4 literals.
        if s.contains('/') {
            let net: Ipv4Net = s
                .parse()
                .map_err(|e| anyhow::anyhow!("bad CIDR {s:?}: {e}"))?;
            return Ok(Self::Cidr(net));
        }
        if let Ok(ip) = Ipv4Addr::from_str(s) {
            return Ok(Self::Cidr(Ipv4Net::new(ip, 32).expect("/32 always valid")));
        }
        if let Some(rest) = s.strip_prefix("*.") {
            let d = normalise_name(rest);
            anyhow::ensure!(!d.is_empty(), "wildcard with empty suffix: {s:?}");
            return Ok(Self::Wildcard(d));
        }
        anyhow::ensure!(
            s.chars().all(is_domain_char),
            "unsupported allowlist entry: {s:?}"
        );
        Ok(Self::Domain(normalise_name(s)))
    }
}

const fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

fn normalise_name(s: &str) -> String {
    let s = s.trim_end_matches('.');
    s.to_ascii_lowercase()
}

/// `true` iff `name` is a strict subdomain of `parent` — `name` is
/// longer than `parent`, ends with `parent`, and the boundary byte
/// is a `.`. The exact-match case is handled by the call site
/// (`Rule::Domain` adds `name == parent`, `Rule::Wildcard` doesn't).
fn is_subdomain_of(parent: &str, name: &str) -> bool {
    name.len() > parent.len()
        && name.ends_with(parent)
        && name.as_bytes()[name.len() - parent.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_rule_form() {
        let al = Allowlist::parse([
            "api.openai.com",
            "*.googleapis.com",
            "10.0.0.0/8",
            "192.168.1.1",
        ])
        .unwrap();
        assert_eq!(al.rules().len(), 4);
        assert!(matches!(al.rules()[0], Rule::Domain(ref d) if d == "api.openai.com"));
        assert!(matches!(al.rules()[1], Rule::Wildcard(ref d) if d == "googleapis.com"));
        assert!(matches!(al.rules()[2], Rule::Cidr(_)));
        assert!(matches!(al.rules()[3], Rule::Cidr(n) if n.prefix_len() == 32));
    }

    #[test]
    fn matches_exact_and_subdomain() {
        let al = Allowlist::parse(["example.com"]).unwrap();
        assert!(al.matches_domain("example.com"));
        assert!(al.matches_domain("api.example.com"));
        assert!(al.matches_domain("Api.Example.Com")); // case-insensitive
        assert!(al.matches_domain("api.example.com.")); // trailing dot tolerated
        assert!(!al.matches_domain("notexample.com"));
        assert!(!al.matches_domain("example.com.evil.io"));
    }

    #[test]
    fn wildcard_is_strict_subdomain() {
        let al = Allowlist::parse(["*.googleapis.com"]).unwrap();
        assert!(al.matches_domain("storage.googleapis.com"));
        assert!(al.matches_domain("a.b.googleapis.com"));
        assert!(!al.matches_domain("googleapis.com"));
        assert!(!al.matches_domain("evil-googleapis.com"));
    }

    #[test]
    fn cidr_matches_ip_only() {
        let al = Allowlist::parse(["10.0.0.0/8", "1.2.3.4"]).unwrap();
        assert!(al.matches_ip("10.1.2.3".parse().unwrap()));
        assert!(al.matches_ip("1.2.3.4".parse().unwrap()));
        assert!(!al.matches_ip("11.0.0.1".parse().unwrap()));
        // Domain query must not be allowed by a CIDR-only allowlist.
        assert!(!al.matches_domain("10.0.0.1"));
    }

    #[test]
    fn empty_and_blank_entries_skipped() {
        let al = Allowlist::parse(["", "  ", "api.openai.com"]).unwrap();
        assert_eq!(al.rules().len(), 1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Allowlist::parse(["not a domain!!"]).is_err());
        assert!(Allowlist::parse(["1.2.3.4/99"]).is_err());
        assert!(Allowlist::parse(["*."]).is_err());
    }

    #[test]
    fn ip_only_allowlist_blocks_domains() {
        let al = Allowlist::parse(["10.0.0.0/8"]).unwrap();
        assert!(!al.matches_domain("example.com"));
    }
}
