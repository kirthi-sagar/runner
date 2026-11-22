//! Network boundary: block private/link-local egress from job sandboxes.
//!
//! Phase 4 enforcement is an nftables ruleset: drop RFC 1918, link-local,
//! and ULA destinations; allow only DNS (UDP 53) and public HTTPS
//! (TCP 443); drop everything else. eBPF attachment at the veth/TAP is the
//! hardening follow-up for Tier-1 microVMs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// In-process eBPF egress program (no external `nftables` CLI needed).
pub use super::ebpf::EgressFilterProgram;

/// Reserved private ranges (RFC 1918).
pub const RFC1918_CIDRS: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
/// Link-local / cloud-metadata range.
pub const LINK_LOCAL_CIDR: &str = "169.254.0.0/16";
/// IPv6 unique-local range (RFC 4193 `fc00::/7`, covering both the
/// `fc00::/8` centrally-assigned and `fd00::/8` locally-assigned halves).
pub const ULA_CIDR: &str = "fc00::/7";
/// Allowed egress: DNS.
pub const ALLOW_DNS_PORT: u16 = 53;
/// Allowed egress: public HTTPS.
pub const ALLOW_HTTPS_PORT: u16 = 443;

/// True if the address falls in `10/8`, `172.16/12`, or `192.168/16`.
pub fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (o[1] & 0xf0) == 16) || (o[0] == 192 && o[1] == 168)
}

/// True for link-local `169.254/16` (also the cloud metadata endpoint).
pub fn is_link_local(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 169 && o[1] == 254
}

/// True for IPv6 unique-local `fc00::/7`.
pub fn is_ula(ip: Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

/// True when outbound traffic to `ip` must be dropped.
pub fn is_blocked_egress(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            is_rfc1918(v4) || is_link_local(v4) || v4.is_loopback() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => is_ula(v6) || v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Render nftables egress-drop rules for the sandbox output chain.
pub fn nftables_egress_rules() -> String {
    RFC1918_CIDRS
        .iter()
        .map(|cidr| format!("ip daddr {cidr} drop"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Render the full sandbox output-chain ruleset: drop private ranges,
/// allow DNS + public HTTPS only, drop the rest.
pub fn nftables_sandbox_ruleset() -> String {
    format!(
        "chain runner_egress {{\n\
         \x20 type filter hook output priority 0; policy accept;\n\
         \x20 ip daddr {{ {rfc1918}, {link_local} }} drop\n\
         \x20 ip6 daddr {{ {ula} }} drop\n\
         \x20 ct state established,related accept\n\
         \x20 udp dport {dns} accept\n\
         \x20 tcp dport {https} accept\n\
         \x20 drop\n\
         }}",
        rfc1918 = RFC1918_CIDRS.join(", "),
        link_local = LINK_LOCAL_CIDR,
        ula = ULA_CIDR,
        dns = ALLOW_DNS_PORT,
        https = ALLOW_HTTPS_PORT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn classifies_private_ranges() {
        for ip in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
        ] {
            assert!(is_rfc1918(Ipv4Addr::from_str(ip).unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "192.167.0.1",
            "140.82.112.4",
        ] {
            assert!(!is_rfc1918(Ipv4Addr::from_str(ip).unwrap()), "{ip}");
        }
    }

    #[test]
    fn blocks_link_local_ula_and_loopback() {
        assert!(is_blocked_egress(
            IpAddr::from_str("169.254.169.254").unwrap()
        ));
        assert!(is_blocked_egress(IpAddr::from_str("fd00::1").unwrap()));
        assert!(is_blocked_egress(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(is_blocked_egress(IpAddr::from_str("::1").unwrap()));
        assert!(!is_blocked_egress(
            IpAddr::from_str("140.82.112.4").unwrap()
        ));
        assert!(!is_blocked_egress(IpAddr::from_str("8.8.8.8").unwrap()));
    }

    #[test]
    fn ruleset_allows_only_dns_and_https() {
        let rules = nftables_sandbox_ruleset();
        assert!(rules.contains("10.0.0.0/8"));
        assert!(rules.contains("169.254.0.0/16"));
        assert!(rules.contains("fc00::/7"));
        assert!(rules.contains("udp dport 53 accept"));
        assert!(rules.contains("tcp dport 443 accept"));
    }
}
