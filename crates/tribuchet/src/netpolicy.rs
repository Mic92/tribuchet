//! Flow policy for the fixed-output build network (`[fod-network]` in
//! worker.toml): an ordered rule list matched against the destination
//! of each new outbound flow, first match wins, plus a default action.
//!
//! Only destinations are matched (the sandbox is the only source), and
//! rules are IP-based on purpose: hostname rules would be enforced on
//! whatever the name resolves to at connect time and are trivially
//! bypassed by a build resolving names itself. DNS forwarding to the
//! host resolver is handled separately by presto-pasta and is not
//! affected by these rules.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// `[fod-network]` section of worker.toml.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NetPolicy {
    /// Action when no rule matches.
    #[serde(default)]
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Any,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Rule {
    pub action: Action,
    #[serde(default)]
    pub proto: Proto,
    /// Destination match: "any", "private", a single IP, or CIDR
    /// ("192.0.2.0/24", "2001:db8::/32").
    /// Host loopback is unreachable regardless (presto-pasta default).
    #[serde(default)]
    pub dst: Dst,
    /// Destination ports: single ("443") or range ("8000-8999");
    /// empty means any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
}

impl NetPolicy {
    /// Decide a new flow to `ip:port` with IP protocol number `proto`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn allows(&self, proto: u8, ip: IpAddr, port: u16) -> bool {
        let action = self
            .rules
            .iter()
            .find(|r| r.matches(proto, ip, port))
            .map_or(self.default, |r| r.action);
        action == Action::Allow
    }
}

impl Rule {
    fn matches(&self, proto: u8, ip: IpAddr, port: u16) -> bool {
        let proto_ok = match self.proto {
            Proto::Any => true,
            Proto::Tcp => proto == 6,
            Proto::Udp => proto == 17,
        };
        proto_ok
            && self.dst.matches(ip)
            && (self.ports.is_empty() || self.ports.iter().any(|r| r.contains(port)))
    }
}

/// Destination address matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dst {
    #[default]
    Any,
    /// Non-public destinations: loopback, RFC 1918, link-local, ULA,
    /// CGNAT, multicast, ...
    Private,
    Cidr {
        ip: IpAddr,
        prefix: u8,
    },
}

impl Dst {
    fn matches(self, ip: IpAddr) -> bool {
        // ::ffff:a.b.c.d is a.b.c.d for `private` and IPv4 CIDRs.
        let ip = ip.to_canonical();
        match self {
            Self::Any => true,
            Self::Private => !is_public(ip),
            Self::Cidr { ip: net, prefix } => cidr_contains(net, prefix, ip),
        }
    }
}

/// Same classification as `presto_pasta::FlowDst::is_public`,
/// duplicated here so the policy stays testable on non-Linux hosts.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
                // 100.64.0.0/10, RFC 6598 shared address space.
                || (ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64))
        }
        IpAddr::V6(ip) => {
            let seg0 = ip.segments()[0];
            !(ip.is_loopback()
                || ip.is_multicast()
                || ip.is_unspecified()
                // fc00::/7 unique local, fe80::/10 link-local.
                || seg0 & 0xfe00 == 0xfc00
                || seg0 & 0xffc0 == 0xfe80)
        }
    }
}

fn cidr_contains(net: IpAddr, prefix: u8, ip: IpAddr) -> bool {
    fn masked(ip: u128, bits: u32, prefix: u8) -> u128 {
        let shift = bits - u32::from(prefix);
        // prefix == 0 would shift by the full width; that means "match all".
        if shift >= bits { 0 } else { ip >> shift }
    }
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            masked(u32::from(net).into(), 32, prefix) == masked(u32::from(ip).into(), 32, prefix)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            masked(net.into(), 128, prefix) == masked(ip.into(), 128, prefix)
        }
        _ => false,
    }
}

impl FromStr for Dst {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" => return Ok(Self::Any),
            "private" => return Ok(Self::Private),
            _ => {}
        }
        let (addr, prefix) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let ip: IpAddr = addr
            .parse()
            .map_err(|e| format!("bad destination {s:?}: {e}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => match p.parse::<u8>() {
                Ok(p) if p <= max => p,
                _ => return Err(format!("bad prefix length in {s:?}")),
            },
        };
        Ok(Self::Cidr { ip, prefix })
    }
}

impl fmt::Display for Dst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Private => f.write_str("private"),
            Self::Cidr { ip, prefix } => write!(f, "{ip}/{prefix}"),
        }
    }
}

/// Inclusive destination port range, written as "443" or "8000-8999".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(self, port: u16) -> bool {
        (self.start..=self.end).contains(&port)
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (start, end) = match s.split_once('-') {
            Some((a, b)) => (a, b),
            None => (s, s),
        };
        let parse = |p: &str| {
            p.trim()
                .parse::<u16>()
                .map_err(|e| format!("bad port range {s:?}: {e}"))
        };
        let (start, end) = (parse(start)?, parse(end)?);
        if start > end {
            return Err(format!("bad port range {s:?}: start > end"));
        }
        Ok(Self { start, end })
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

// TOML representation of Dst and PortRange is their string form.
macro_rules! serde_via_str {
    ($ty:ty, $expecting:literal) => {
        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(|e| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(&s),
                        &format!("{}: {e}", $expecting).as_str(),
                    )
                })
            }
        }
    };
}
serde_via_str!(Dst, "a destination matcher");
serde_via_str!(PortRange, "a port or port range");

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(toml: &str) -> NetPolicy {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn default_policy_allows_everything() {
        let p = NetPolicy::default();
        assert!(p.allows(6, "93.184.216.34".parse().unwrap(), 443));
        assert!(p.allows(17, "::1".parse().unwrap(), 53));
    }

    #[test]
    fn first_match_wins_and_default_applies() {
        let p = policy(
            r#"
            default = "deny"

            [[rules]]
            action = "allow"
            proto = "tcp"
            dst = "192.0.2.0/24"
            ports = ["443", "8000-8999"]

            [[rules]]
            action = "deny"
            dst = "192.0.2.7"
            "#,
        );
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        // first rule matches before the specific deny
        assert!(p.allows(6, ip, 443));
        assert!(p.allows(6, ip, 8500));
        // wrong port, wrong proto, or outside the CIDR fall through
        assert!(!p.allows(6, ip, 80));
        assert!(!p.allows(17, ip, 443));
        assert!(!p.allows(6, "192.0.3.1".parse().unwrap(), 443));
    }

    #[test]
    fn keywords_and_v6_cidrs() {
        let p = policy(
            r#"
            [[rules]]
            action = "deny"
            dst = "private"

            [[rules]]
            action = "deny"
            proto = "tcp"
            dst = "2001:db8::/32"
            ports = ["25"]
            "#,
        );
        assert!(!p.allows(6, "10.1.2.3".parse().unwrap(), 80));
        assert!(!p.allows(6, "127.0.0.1".parse().unwrap(), 80));
        assert!(!p.allows(6, "fd00::1".parse().unwrap(), 80));
        // IPv4-mapped IPv6 addresses classify by their embedded IPv4.
        assert!(!p.allows(6, "::ffff:10.1.2.3".parse().unwrap(), 80));
        assert!(!p.allows(6, "::ffff:127.0.0.1".parse().unwrap(), 80));
        assert!(p.allows(6, "::ffff:93.184.216.34".parse().unwrap(), 80));
        assert!(!p.allows(6, "2001:db8::5".parse().unwrap(), 25));
        assert!(p.allows(6, "2001:db8::5".parse().unwrap(), 443));
        assert!(p.allows(6, "93.184.216.34".parse().unwrap(), 80));
    }

    #[test]
    fn bad_values_are_rejected() {
        for toml in [
            r#"[[rules]]
               action = "deny"
               dst = "not-an-ip""#,
            r#"[[rules]]
               action = "deny"
               dst = "10.0.0.0/33""#,
            r#"[[rules]]
               action = "deny"
               ports = ["80-70"]"#,
        ] {
            assert!(toml::from_str::<NetPolicy>(toml).is_err(), "{toml}");
        }
    }
}
