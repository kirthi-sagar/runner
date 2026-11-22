//! Portable WFP rule contract: types, builder, matchers, and arbitration.
//!
//! Everything in this module compiles on every platform with zero
//! Windows dependencies. The builder derives the sandbox egress
//! ruleset from the shared [`crate::network`] contract:
//!
//! * Drop RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) — IPv4.
//! * Drop link-local / cloud-metadata `169.254/16` — IPv4.
//! * Drop IPv6 unique-local `fc00::/7`.
//! * Allow only UDP 53 (DNS) and TCP 443 (public HTTPS).
//! * Default-drop everything else.
//!
//! Rules carry precomputed WFP mask values (the `FWP_V4_ADDR_AND_MASK` /
//! `FWP_V6_ADDR_AND_MASK` form WFP conditions take). The unit tests prove
//! those literals equal the parsed [`crate::network`] CIDR strings,
//! so a contract edit fails tests instead of silently drifting. The
//! builder itself is infallible by construction: a security boundary
//! must not have a runtime parse failure mode.
//!
//! Mappings from these portable types to real WFP layer GUIDs and
//! session flags live in the parent module's `api` submodule
//! (`#[cfg(windows)]`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::network;

/// ALE layer a rule attaches to (portable; layer GUIDs resolve under
/// `#[cfg(windows)]` in the parent `api` module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpLayer {
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V4`: outbound IPv4 connect path.
    AleAuthConnectV4,
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V6`: outbound IPv6 connect path.
    AleAuthConnectV6,
}

/// Filter action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAction {
    /// `FWP_ACTION_BLOCK`.
    Block,
    /// `FWP_ACTION_PERMIT`.
    Permit,
}

/// Transport protocol for port conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpProtocol {
    /// TCP (IP protocol 6).
    Tcp,
    /// UDP (IP protocol 17).
    Udp,
}

impl WfpProtocol {
    /// IP protocol number, as matched by `FWPM_CONDITION_IP_PROTOCOL`.
    pub fn number(self) -> u8 {
        match self {
            WfpProtocol::Tcp => 6,
            WfpProtocol::Udp => 17,
        }
    }
}

/// Remote-address condition in WFP mask form.
///
/// IPv4 form is the `FWP_V4_ADDR_MASK` pair (address and mask in
/// network byte order); IPv6 form is the `FWP_V6_ADDR_MASK` pair
/// (16-byte address and 16-byte mask).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpAddressCondition {
    /// IPv4 network: big-endian address and mask.
    V4 {
        /// Network address (`addr & mask`).
        addr: u32,
        /// Prefix mask.
        mask: u32,
    },
    /// IPv6 network: 16-byte address and mask.
    V6 {
        /// Network address (`addr & mask` per byte).
        addr: [u8; 16],
        /// Prefix mask.
        mask: [u8; 16],
    },
}

impl WfpAddressCondition {
    /// True when `ip` falls inside this network (family must match).
    pub fn matches(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (WfpAddressCondition::V4 { addr, mask }, IpAddr::V4(v4)) => {
                (u32::from_be_bytes(v4.octets()) & mask) == addr
            }
            (WfpAddressCondition::V6 { addr, mask }, IpAddr::V6(v6)) => {
                let octets = v6.octets();
                (0..16).all(|i| (octets[i] & mask[i]) == addr[i])
            }
            _ => false,
        }
    }
}

/// Remote-port condition: protocol plus destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WfpPortCondition {
    /// Transport protocol.
    pub protocol: WfpProtocol,
    /// Destination port.
    pub port: u16,
}

/// Weight for private-range block rules: highest, so denies always
/// arbitrate ahead of the DNS/HTTPS allowlist.
pub const WEIGHT_BLOCK_PRIVATE: u64 = 0x1000;
/// Weight for DNS/HTTPS permit rules: above the default drop.
pub const WEIGHT_PERMIT_ALLOWLIST: u64 = 0x100;
/// Weight for the default-drop rules: lowest, matched last.
pub const WEIGHT_DEFAULT_DROP: u64 = 0x1;

/// One ALE connect filter rule.
///
/// WFP arbitrates by weight on the ALE auth layers: the highest-weight
/// matching filter decides. Deny-before-allow ordering is therefore
/// weight-enforced ([`WEIGHT_BLOCK_PRIVATE`] > [`WEIGHT_PERMIT_ALLOWLIST`]
/// > [`WEIGHT_DEFAULT_DROP`]), never position-dependent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFilterRule {
    /// Human-readable filter name (WFP display data).
    pub name: &'static str,
    /// ALE layer this filter attaches to.
    pub layer: WfpLayer,
    /// Action taken when the rule matches.
    pub action: WfpAction,
    /// Arbitration weight: highest matching weight wins.
    pub weight: u64,
    /// Remote-address condition, if any.
    pub address: Option<WfpAddressCondition>,
    /// Remote-port condition, if any.
    pub port: Option<WfpPortCondition>,
}

impl WfpFilterRule {
    /// True when this rule matches an outbound connection to `ip`
    /// over `protocol`/`port`. Rules only match their own layer's
    /// address family.
    pub fn matches(&self, ip: IpAddr, protocol: WfpProtocol, port: u16) -> bool {
        let family_ok = matches!(
            (self.layer, ip),
            (WfpLayer::AleAuthConnectV4, IpAddr::V4(_))
                | (WfpLayer::AleAuthConnectV6, IpAddr::V6(_))
        );
        family_ok
            && self.address.is_none_or(|cond| cond.matches(ip))
            && self
                .port
                .is_none_or(|cond| cond.protocol == protocol && cond.port == port)
    }
}

/// Parse `"a.b.c.d/p"` into big-endian `(network_addr, mask)`.
/// Returns `None` on malformed input or a prefix wider than 32.
pub fn parse_v4_cidr(cidr: &str) -> Option<(u32, u32)> {
    let (addr_text, prefix_text) = cidr.split_once('/')?;
    let addr: Ipv4Addr = addr_text.parse().ok()?;
    let prefix: u8 = prefix_text.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = v4_prefix_mask(prefix);
    Some((u32::from_be_bytes(addr.octets()) & mask, mask))
}

/// Parse `"xxxx::/p"` into `(network_bytes, mask_bytes)`.
/// Returns `None` on malformed input or a prefix wider than 128.
pub fn parse_v6_cidr(cidr: &str) -> Option<([u8; 16], [u8; 16])> {
    let (addr_text, prefix_text) = cidr.split_once('/')?;
    let addr: Ipv6Addr = addr_text.parse().ok()?;
    let prefix: u8 = prefix_text.parse().ok()?;
    if prefix > 128 {
        return None;
    }
    let mask = v6_prefix_mask(prefix);
    let octets = addr.octets();
    let mut net = [0u8; 16];
    for (i, byte) in net.iter_mut().enumerate() {
        *byte = octets[i] & mask[i];
    }
    Some((net, mask))
}

/// Big-endian IPv4 mask for a prefix length (saturates past 32).
pub fn v4_prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        !0u32 << (32 - prefix)
    }
}

/// 16-byte IPv6 mask for a prefix length (saturates past 128).
pub fn v6_prefix_mask(prefix: u8) -> [u8; 16] {
    let mut mask = [0u8; 16];
    let full = (prefix.min(128) / 8) as usize;
    for byte in mask.iter_mut().take(full) {
        *byte = 0xff;
    }
    if full < 16 {
        let rem = prefix.min(128) % 8;
        if rem > 0 {
            mask[full] = !0u8 << (8 - rem);
        }
    }
    mask
}

/// Dynamic-session display name for the sandbox egress filter set.
pub const SESSION_NAME: &str = "runner-sandbox-egress";
/// Dynamic-session description.
pub const SESSION_DESCRIPTION: &str =
    "runner job sandbox: drop private egress, allow DNS + HTTPS only";

/// A dynamic WFP session plus its sandbox egress filter set.
///
/// The session is always dynamic (`FWPM_SESSION_FLAG_DYNAMIC`): if the
/// runner process dies, the kernel tears the session and all its
/// filters down, so rules can never leak past the job (see the
/// Windows-only `api::session_flags`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpSession {
    /// Session display name.
    pub name: &'static str,
    /// Session description.
    pub description: &'static str,
    /// Always true: dynamic session, fail-safe kernel teardown.
    pub dynamic: bool,
    /// Egress filter rules, built from the [`network`] contract.
    pub rules: Vec<WfpFilterRule>,
}

impl WfpSession {
    /// Build the sandbox egress session from the shared contract.
    pub fn sandbox_egress() -> Self {
        WfpSession {
            name: SESSION_NAME,
            description: SESSION_DESCRIPTION,
            dynamic: true,
            rules: sandbox_egress_rules(),
        }
    }

    /// Rules attached to one ALE layer.
    pub fn rules_for_layer(&self, layer: WfpLayer) -> Vec<&WfpFilterRule> {
        self.rules.iter().filter(|r| r.layer == layer).collect()
    }
}

/// Build the sandbox egress ruleset from the shared [`network`]
/// contract: drop RFC 1918, link-local, and ULA; allow only DNS
/// (UDP 53) and public HTTPS (TCP 443); default-drop both families.
///
/// Address literals below are the precomputed WFP mask values; the
/// unit tests prove each equals the parsed [`network`] CIDR string.
pub fn sandbox_egress_rules() -> Vec<WfpFilterRule> {
    vec![
        // --- IPv4: drop RFC 1918 + link-local (highest weight) ---
        WfpFilterRule {
            name: "runner: block 10.0.0.0/8",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Block,
            weight: WEIGHT_BLOCK_PRIVATE,
            address: Some(WfpAddressCondition::V4 {
                addr: 0x0a00_0000,
                mask: 0xff00_0000,
            }),
            port: None,
        },
        WfpFilterRule {
            name: "runner: block 172.16.0.0/12",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Block,
            weight: WEIGHT_BLOCK_PRIVATE,
            address: Some(WfpAddressCondition::V4 {
                addr: 0xac10_0000,
                mask: 0xfff0_0000,
            }),
            port: None,
        },
        WfpFilterRule {
            name: "runner: block 192.168.0.0/16",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Block,
            weight: WEIGHT_BLOCK_PRIVATE,
            address: Some(WfpAddressCondition::V4 {
                addr: 0xc0a8_0000,
                mask: 0xffff_0000,
            }),
            port: None,
        },
        WfpFilterRule {
            name: "runner: block 169.254.0.0/16",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Block,
            weight: WEIGHT_BLOCK_PRIVATE,
            address: Some(WfpAddressCondition::V4 {
                addr: 0xa9fe_0000,
                mask: 0xffff_0000,
            }),
            port: None,
        },
        // --- IPv4: allow DNS + HTTPS only ---
        WfpFilterRule {
            name: "runner: allow UDP DNS",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Permit,
            weight: WEIGHT_PERMIT_ALLOWLIST,
            address: None,
            port: Some(WfpPortCondition {
                protocol: WfpProtocol::Udp,
                port: network::ALLOW_DNS_PORT,
            }),
        },
        WfpFilterRule {
            name: "runner: allow TCP HTTPS",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Permit,
            weight: WEIGHT_PERMIT_ALLOWLIST,
            address: None,
            port: Some(WfpPortCondition {
                protocol: WfpProtocol::Tcp,
                port: network::ALLOW_HTTPS_PORT,
            }),
        },
        // --- IPv4: default drop (lowest weight) ---
        WfpFilterRule {
            name: "runner: default drop v4",
            layer: WfpLayer::AleAuthConnectV4,
            action: WfpAction::Block,
            weight: WEIGHT_DEFAULT_DROP,
            address: None,
            port: None,
        },
        // --- IPv6: drop ULA ---
        WfpFilterRule {
            name: "runner: block fc00::/7",
            layer: WfpLayer::AleAuthConnectV6,
            action: WfpAction::Block,
            weight: WEIGHT_BLOCK_PRIVATE,
            address: Some(WfpAddressCondition::V6 {
                addr: [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                mask: [0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            }),
            port: None,
        },
        // --- IPv6: allow DNS + HTTPS only ---
        WfpFilterRule {
            name: "runner: allow UDP DNS",
            layer: WfpLayer::AleAuthConnectV6,
            action: WfpAction::Permit,
            weight: WEIGHT_PERMIT_ALLOWLIST,
            address: None,
            port: Some(WfpPortCondition {
                protocol: WfpProtocol::Udp,
                port: network::ALLOW_DNS_PORT,
            }),
        },
        WfpFilterRule {
            name: "runner: allow TCP HTTPS",
            layer: WfpLayer::AleAuthConnectV6,
            action: WfpAction::Permit,
            weight: WEIGHT_PERMIT_ALLOWLIST,
            address: None,
            port: Some(WfpPortCondition {
                protocol: WfpProtocol::Tcp,
                port: network::ALLOW_HTTPS_PORT,
            }),
        },
        // --- IPv6: default drop ---
        WfpFilterRule {
            name: "runner: default drop v6",
            layer: WfpLayer::AleAuthConnectV6,
            action: WfpAction::Block,
            weight: WEIGHT_DEFAULT_DROP,
            address: None,
            port: None,
        },
    ]
}

/// Arbitrate `rules` for one outbound connection the way WFP does:
/// the highest-weight matching rule decides. Fail-closed: with no
/// matching rule the verdict is [`WfpAction::Block`] (unreachable in
/// the built ruleset, whose default-drop rules match everything).
pub fn arbitrate(
    rules: &[WfpFilterRule],
    ip: IpAddr,
    protocol: WfpProtocol,
    port: u16,
) -> WfpAction {
    let mut best: Option<&WfpFilterRule> = None;
    for rule in rules {
        if rule.matches(ip, protocol, port)
            && best.is_none_or(|b: &WfpFilterRule| rule.weight > b.weight)
        {
            best = Some(rule);
        }
    }
    best.map(|r| r.action).unwrap_or(WfpAction::Block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn v4(text: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(text).unwrap())
    }

    fn v6(text: &str) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from_str(text).unwrap())
    }

    #[test]
    fn v4_cidr_parsing_matches_contract_ranges() {
        // Parsed literals equal the precomputed WFP mask values.
        assert_eq!(
            parse_v4_cidr(network::RFC1918_CIDRS[0]),
            Some((0x0a00_0000, 0xff00_0000))
        );
        assert_eq!(
            parse_v4_cidr(network::RFC1918_CIDRS[1]),
            Some((0xac10_0000, 0xfff0_0000))
        );
        assert_eq!(
            parse_v4_cidr(network::RFC1918_CIDRS[2]),
            Some((0xc0a8_0000, 0xffff_0000))
        );
        assert_eq!(
            parse_v4_cidr(network::LINK_LOCAL_CIDR),
            Some((0xa9fe_0000, 0xffff_0000))
        );
        // Malformed input fails instead of producing a wrong mask.
        assert_eq!(parse_v4_cidr("10.0.0.0/33"), None);
        assert_eq!(parse_v4_cidr("10.0.0.0"), None);
        assert_eq!(parse_v4_cidr("not-an-ip/8"), None);

        // WFP mask matching agrees with the network contract classifiers,
        // including the 172.16/12 nibble boundaries.
        let rfc1918: Vec<_> = network::RFC1918_CIDRS
            .iter()
            .map(|c| parse_v4_cidr(c).unwrap())
            .collect();
        let link_local = parse_v4_cidr(network::LINK_LOCAL_CIDR).unwrap();
        for text in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "8.8.8.8",
            "172.15.255.255",
            "172.32.0.1",
            "192.167.0.1",
            "140.82.112.4",
            "169.254.169.254",
        ] {
            let addr = Ipv4Addr::from_str(text).unwrap();
            let masked = rfc1918.iter().any(|(net, mask)| {
                WfpAddressCondition::V4 {
                    addr: *net,
                    mask: *mask,
                }
                .matches(IpAddr::V4(addr))
            });
            assert_eq!(masked, network::is_rfc1918(addr), "{text}");
            let ll = WfpAddressCondition::V4 {
                addr: link_local.0,
                mask: link_local.1,
            }
            .matches(IpAddr::V4(addr));
            assert_eq!(ll, network::is_link_local(addr), "{text}");
        }
    }

    #[test]
    fn v6_cidr_parsing_matches_ula() {
        let (net, mask) = parse_v6_cidr(network::ULA_CIDR).unwrap();
        assert_eq!(net[0], 0xfc);
        assert!(net[1..].iter().all(|b| *b == 0));
        assert_eq!(mask[0], 0xfe);
        assert!(mask[1..].iter().all(|b| *b == 0));
        assert_eq!(parse_v6_cidr("fd00::/129"), None);
        assert_eq!(parse_v6_cidr("fd00::"), None);

        let cond = WfpAddressCondition::V6 { addr: net, mask };
        for text in ["fd00::1", "fc12:34::56", "fe80::1", "2001:db8::1", "::1"] {
            let addr = Ipv6Addr::from_str(text).unwrap();
            assert_eq!(
                cond.matches(IpAddr::V6(addr)),
                network::is_ula(addr),
                "{text}"
            );
        }
    }

    #[test]
    fn sandbox_ruleset_covers_contract() {
        let rules = sandbox_egress_rules();
        // 4 v4 blocks + 2 v4 permits + 1 v4 default + 1 v6 block +
        // 2 v6 permits + 1 v6 default.
        assert_eq!(rules.len(), 11);

        // Every block rule's mask equals the parsed contract CIDR.
        let contract_v4 = [
            network::RFC1918_CIDRS[0],
            network::RFC1918_CIDRS[1],
            network::RFC1918_CIDRS[2],
            network::LINK_LOCAL_CIDR,
        ];
        let blocks_v4: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.layer == WfpLayer::AleAuthConnectV4
                    && r.action == WfpAction::Block
                    && r.address.is_some()
            })
            .collect();
        assert_eq!(blocks_v4.len(), 4);
        for (rule, cidr) in blocks_v4.iter().zip(contract_v4.iter()) {
            let (net, mask) = parse_v4_cidr(cidr).unwrap();
            assert_eq!(
                rule.address,
                Some(WfpAddressCondition::V4 { addr: net, mask }),
                "{}",
                rule.name
            );
        }
        let block_v6: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.layer == WfpLayer::AleAuthConnectV6
                    && r.action == WfpAction::Block
                    && r.address.is_some()
            })
            .collect();
        assert_eq!(block_v6.len(), 1);
        let (net6, mask6) = parse_v6_cidr(network::ULA_CIDR).unwrap();
        assert_eq!(
            block_v6[0].address,
            Some(WfpAddressCondition::V6 {
                addr: net6,
                mask: mask6
            })
        );

        // Permits reference the contract ports, one per layer.
        for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6] {
            let permits: Vec<_> = rules
                .iter()
                .filter(|r| r.layer == layer && r.action == WfpAction::Permit)
                .collect();
            assert_eq!(permits.len(), 2, "{layer:?}");
            assert!(permits.iter().any(|r| r.port
                == Some(WfpPortCondition {
                    protocol: WfpProtocol::Udp,
                    port: network::ALLOW_DNS_PORT,
                })));
            assert!(permits.iter().any(|r| r.port
                == Some(WfpPortCondition {
                    protocol: WfpProtocol::Tcp,
                    port: network::ALLOW_HTTPS_PORT,
                })));
        }

        // Defaults are unconditional blocks, one per layer.
        for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6] {
            let defaults: Vec<_> = rules
                .iter()
                .filter(|r| {
                    r.layer == layer
                        && r.action == WfpAction::Block
                        && r.address.is_none()
                        && r.port.is_none()
                })
                .collect();
            assert_eq!(defaults.len(), 1, "{layer:?}");
        }
    }

    #[test]
    fn weights_enforce_deny_before_allow() {
        const {
            assert!(WEIGHT_BLOCK_PRIVATE > WEIGHT_PERMIT_ALLOWLIST);
            assert!(WEIGHT_PERMIT_ALLOWLIST > WEIGHT_DEFAULT_DROP);
        }
        let rules = sandbox_egress_rules();
        for rule in &rules {
            match (rule.action, rule.address.is_some()) {
                (WfpAction::Block, true) => assert_eq!(rule.weight, WEIGHT_BLOCK_PRIVATE),
                (WfpAction::Permit, _) => assert_eq!(rule.weight, WEIGHT_PERMIT_ALLOWLIST),
                (WfpAction::Block, false) => assert_eq!(rule.weight, WEIGHT_DEFAULT_DROP),
            }
        }
    }

    #[test]
    fn arbitration_verdicts() {
        use WfpProtocol::{Tcp, Udp};
        let rules = sandbox_egress_rules();
        // Private destinations drop even on allowlisted ports.
        assert_eq!(
            arbitrate(&rules, v4("10.0.0.5"), Tcp, 443),
            WfpAction::Block
        );
        assert_eq!(
            arbitrate(&rules, v4("172.16.9.9"), Udp, 53),
            WfpAction::Block
        );
        assert_eq!(
            arbitrate(&rules, v4("169.254.169.254"), Tcp, 80),
            WfpAction::Block
        );
        assert_eq!(arbitrate(&rules, v6("fd00::1"), Udp, 53), WfpAction::Block);
        // Public DNS + HTTPS permit.
        assert_eq!(arbitrate(&rules, v4("8.8.8.8"), Udp, 53), WfpAction::Permit);
        assert_eq!(
            arbitrate(&rules, v4("140.82.112.4"), Tcp, 443),
            WfpAction::Permit
        );
        assert_eq!(
            arbitrate(&rules, v6("2606:4700:4700::1111"), Udp, 53),
            WfpAction::Permit
        );
        // Everything else default-drops.
        assert_eq!(arbitrate(&rules, v4("1.1.1.1"), Tcp, 80), WfpAction::Block);
        assert_eq!(arbitrate(&rules, v4("8.8.8.8"), Tcp, 53), WfpAction::Block);
        // Family isolation: v4 block rules never match v6 traffic, so
        // an IPv4-mapped address on the v6 layer falls through to the
        // v6 allowlist instead of the v4 10/8 block.
        let mapped = v6("::ffff:10.0.0.1");
        assert!(rules
            .iter()
            .filter(|r| r.layer == WfpLayer::AleAuthConnectV4
                && r.action == WfpAction::Block
                && r.address.is_some())
            .all(|r| !r.matches(mapped, Tcp, 443)));
        assert_eq!(arbitrate(&rules, mapped, Tcp, 443), WfpAction::Permit);
        // Fail-closed with no matching rule.
        assert_eq!(arbitrate(&[], v4("8.8.8.8"), Udp, 53), WfpAction::Block);
    }

    #[test]
    fn session_is_dynamic_with_layer_split() {
        let session = WfpSession::sandbox_egress();
        assert_eq!(session.name, SESSION_NAME);
        assert!(session.dynamic);
        assert_eq!(session.rules_for_layer(WfpLayer::AleAuthConnectV4).len(), 7);
        assert_eq!(session.rules_for_layer(WfpLayer::AleAuthConnectV6).len(), 4);
    }

    #[test]
    fn protocol_numbers_match_ip_assignments() {
        assert_eq!(WfpProtocol::Tcp.number(), 6);
        assert_eq!(WfpProtocol::Udp.number(), 17);
    }
}
