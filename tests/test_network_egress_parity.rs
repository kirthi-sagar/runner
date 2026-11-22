//! Cross-platform egress parity: the WFP rule engine, the eBPF
//! bytecode (actually executed by `evaluate_packet`, not mirrored),
//! and the shared `network` contract must yield identical verdicts
//! on every vector.
//!
//! The oracle is the contract's full verdict: blocked address → Drop
//! (`is_blocked_egress`); public address → Pass only for UDP 53 / TCP
//! 443, Drop otherwise. Loopback and unspecified addresses are out of
//! scope: `is_blocked_egress` covers them but neither engine carries
//! loopback rules (pre-existing classifier-only property).

use runner::sandbox::ebpf::{evaluate_packet, BpfVerdict, EgressFilterProgram};
use runner::sandbox::network;
use runner::sandbox::wfp::{arbitrate, sandbox_egress_rules, WfpAction, WfpProtocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Full-contract verdict: blocked ranges drop; public addresses pass
/// only on the DNS/HTTPS allowlist.
fn oracle(ip: IpAddr, proto: WfpProtocol, port: u16) -> BpfVerdict {
    if network::is_blocked_egress(ip) {
        return BpfVerdict::Drop;
    }
    match (proto, port) {
        (WfpProtocol::Udp, network::ALLOW_DNS_PORT)
        | (WfpProtocol::Tcp, network::ALLOW_HTTPS_PORT) => BpfVerdict::Pass,
        _ => BpfVerdict::Drop,
    }
}

/// Minimal IPv4 packet with tunable IHL (options shift the transport).
fn v4_packet(dst: Ipv4Addr, proto: u8, dport: u16, ihl_words: u8) -> Vec<u8> {
    let hlen = ihl_words as usize * 4;
    let mut pkt = vec![0u8; hlen + 4];
    pkt[0] = 0x40 | (ihl_words & 0x0f);
    pkt[9] = proto;
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[hlen + 2..hlen + 4].copy_from_slice(&dport.to_be_bytes());
    pkt
}

/// Minimal IPv6 packet (no extension headers; transport at 40).
fn v6_packet(dst: Ipv6Addr, proto: u8, dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 44];
    pkt[0] = 0x60;
    pkt[6] = proto;
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[42..44].copy_from_slice(&dport.to_be_bytes());
    pkt
}

/// IPv6 with one Hop-by-Hop header and a tunable source port (the
/// source port is what a misordered walk would dispatch on).
fn v6_packet_hbh(dst: Ipv6Addr, proto: u8, sport: u16, dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 52];
    pkt[0] = 0x60;
    pkt[6] = 0; // Hop-by-Hop
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40] = proto;
    pkt[41] = 0; // Hdr Ext Len 0 -> 8 bytes
    pkt[48..50].copy_from_slice(&sport.to_be_bytes());
    pkt[50..52].copy_from_slice(&dport.to_be_bytes());
    pkt
}

/// IPv6 with a first-fragment header (offset 0 carries transport).
fn v6_packet_frag(dst: Ipv6Addr, proto: u8, dport: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 52];
    pkt[0] = 0x60;
    pkt[6] = 44; // Fragment
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40] = proto;
    pkt[41] = 0;
    // Bytes 42..44 (frag offset/res/M) stay 0: first fragment.
    pkt[50..52].copy_from_slice(&dport.to_be_bytes());
    pkt
}

fn wfp_proto(proto: u8) -> WfpProtocol {
    match proto {
        6 => WfpProtocol::Tcp,
        17 => WfpProtocol::Udp,
        _ => panic!("parity matrix uses TCP/UDP only, got {proto}"),
    }
}

/// Assert three-way verdict equality for one vector; returns the
/// shared verdict for the agreement tally.
fn check_vector(
    program: &EgressFilterProgram,
    ip_text: &str,
    proto: u8,
    port: u16,
    packet: &[u8],
    shape: &str,
) -> BpfVerdict {
    let ip = IpAddr::from_str(ip_text).unwrap();
    let wfp_protocol = wfp_proto(proto);
    let expected = oracle(ip, wfp_protocol, port);
    let rules = sandbox_egress_rules();
    let wfp = match arbitrate(&rules, ip, wfp_protocol, port) {
        WfpAction::Block => BpfVerdict::Drop,
        WfpAction::Permit => BpfVerdict::Pass,
    };
    let ebpf = evaluate_packet(program, packet);
    let context = format!("{ip_text} proto={proto} port={port} shape={shape}");
    assert_eq!(wfp, expected, "WFP diverged: {context}");
    assert_eq!(ebpf, expected, "eBPF diverged: {context}");
    assert_eq!(wfp, ebpf, "engines disagree: {context}");
    expected
}

#[test]
fn egress_parity_across_engines_and_contract() {
    let program = EgressFilterProgram::new();
    // (address, is_public): privates and ULA drop on every port;
    // boundary negatives and public addresses follow the allowlist.
    let addresses = [
        // RFC 1918, all three ranges plus edges.
        ("10.0.0.1", false),
        ("10.255.255.254", false),
        ("172.16.0.1", false),
        ("172.31.255.254", false),
        ("192.168.0.1", false),
        ("192.168.255.254", false),
        // Link-local / cloud metadata.
        ("169.254.0.1", false),
        ("169.254.169.254", false),
        // IPv6 ULA, both halves of fc00::/7.
        ("fd00::1", false),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ("fc00::1", false),
        ("fc12:34::56", false),
        // CIDR boundary negatives: just outside the blocked ranges.
        ("172.15.255.255", true),
        ("172.32.0.1", true),
        ("192.167.0.1", true),
        ("11.0.0.1", true),
        // Public IPv4.
        ("8.8.8.8", true),
        ("1.1.1.1", true),
        ("140.82.112.4", true),
        // Public IPv6 (fe80::/10 is link-local, not ULA: the contract
        // treats it as public in all three engines consistently).
        ("2001:db8::1", true),
        ("2606:4700:4700::1111", true),
        ("fe80::1", true),
    ];
    // Allowed ports pass on public IPs; everything else drops. The
    // cross-protocol pairs (TCP 53, UDP 443) pin proto+port matching.
    let ports = [
        (17u8, 53u16),
        (6, 443),
        (6, 80),
        (6, 8080),
        (6, 22),
        (6, 25),
        (6, 3389),
        (6, 53),
        (17, 443),
    ];
    let mut total = 0;
    let mut agreed = 0;
    for (ip_text, public) in addresses {
        let ip = IpAddr::from_str(ip_text).unwrap();
        assert_eq!(
            !network::is_blocked_egress(ip),
            public,
            "matrix mislabeled: {ip_text}"
        );
        for (proto, port) in ports {
            let packet = match ip {
                IpAddr::V4(v4) => v4_packet(v4, proto, port, 5),
                IpAddr::V6(v6) => v6_packet(v6, proto, port),
            };
            check_vector(&program, ip_text, proto, port, &packet, "plain");
            total += 1;
            agreed += 1;
        }
    }
    assert_eq!((agreed, total), (198, 198));
}

#[test]
fn egress_parity_with_ip_options_and_ext_headers() {
    let program = EgressFilterProgram::new();
    // IPv4 options shift the transport header (IHL 6).
    let v4_shapes = [
        ("10.0.0.1", 6u8, 443u16),
        ("8.8.8.8", 6, 443),
        ("1.1.1.1", 6, 80),
        ("169.254.169.254", 17, 53),
    ];
    for (ip_text, proto, port) in v4_shapes {
        let IpAddr::V4(dst) = IpAddr::from_str(ip_text).unwrap() else {
            panic!("v4 shape needs a v4 address: {ip_text}");
        };
        let packet = v4_packet(dst, proto, port, 6);
        check_vector(&program, ip_text, proto, port, &packet, "ihl-options");
    }
    // IPv6 Hop-by-Hop and Fragment headers shift the transport.
    let v6_plain_ext = [
        ("2606:4700:4700::1111", 6u8, 443u16),
        ("2001:db8::1", 6, 80),
        ("fd00::1", 6, 443),
    ];
    for (ip_text, proto, port) in v6_plain_ext {
        let IpAddr::V6(dst) = IpAddr::from_str(ip_text).unwrap() else {
            panic!("v6 shape needs a v6 address: {ip_text}");
        };
        let packet = v6_packet_hbh(dst, proto, 0, port);
        check_vector(&program, ip_text, proto, port, &packet, "hbh");
        let packet = v6_packet_frag(dst, proto, port);
        check_vector(&program, ip_text, proto, port, &packet, "frag");
    }
    // Adversarial shapes for the walk fix: a source port whose high
    // byte collides with a transport protocol number must not steer
    // dispatch — UDP/443 and TCP/53 stay dropped.
    let IpAddr::V6(collide) = IpAddr::from_str("2001:db8::1").unwrap() else {
        unreachable!();
    };
    let packet = v6_packet_hbh(collide, 17, 0x0600, 443);
    check_vector(
        &program,
        "2001:db8::1",
        17,
        443,
        &packet,
        "hbh-sport-collision",
    );
    let packet = v6_packet_hbh(collide, 6, 0x1100, 53);
    check_vector(
        &program,
        "2001:db8::1",
        6,
        53,
        &packet,
        "hbh-sport-collision",
    );
}
