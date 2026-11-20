//! eBPF program tests: instruction encoding, range filtering,
//! port whitelist, and unprivileged attach probe.

use runner::sandbox::ebpf::{alu64_imm, jmp_imm, ld_abs, op, probe_ebpf, EgressFilterProgram};

#[test]
fn instruction_encodings_match_isa() {
    assert_eq!(alu64_imm(0x50, 0, 0).code, op::ALU64_IMM_AND);
    assert_eq!(jmp_imm(0x10, 0, 0, 0).code, op::JMP_IMM_JEQ);
    assert_eq!(ld_abs(op::LD_ABS_W, 16).imm, 16);
    assert_eq!(ld_abs(op::LD_ABS_B, 0).code, op::LD_ABS_B);
}

#[test]
fn program_filters_ipv4_ranges() {
    let insns = EgressFilterProgram::new().to_instructions().unwrap();
    let imms: Vec<i32> = insns.iter().map(|i| i.imm).collect();
    // Masked network constants for 10/8, 172.16/12, 192.168/16, 169.254/16.
    for net in [
        0x0a00_0000i32,
        0xac10_0000u32 as i32,
        0xc0a8_0000u32 as i32,
        0xa9fe_0000u32 as i32,
    ] {
        assert!(imms.contains(&net), "missing net {net:#x}");
    }
    // Destination word loads at IPv4 offset 16.
    let dst_loads = insns
        .iter()
        .filter(|i| i.code == op::LD_ABS_W && i.imm == 16)
        .count();
    assert_eq!(dst_loads, 4);
}

#[test]
fn program_filters_ipv6_ula() {
    let insns = EgressFilterProgram::new().to_instructions().unwrap();
    let has_ula = insns.iter().any(|i| i.code == op::LD_ABS_B && i.imm == 24)
        && insns
            .iter()
            .any(|i| i.code == op::ALU64_IMM_AND && i.imm == 0xfe);
    assert!(has_ula);
}

#[test]
fn port_whitelist_covers_dns_and_https() {
    let insns = EgressFilterProgram::new().to_instructions().unwrap();
    for port in [53i32, 443i32] {
        assert!(
            insns
                .iter()
                .any(|i| i.code == op::JMP_IMM_JEQ && i.imm == port),
            "missing port {port}"
        );
    }
    // Both families load ports indirectly (offset in R1 + 2): v4
    // via IHL, v6 via the extension-header walk — plus one
    // fragment-offset word per walk stage.
    assert_eq!(
        insns
            .iter()
            .filter(|i| i.code == op::LD_IND_H && i.src_reg == 1 && i.imm == 2)
            .count(),
        8
    );
    assert!(
        !insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 42),
        "fixed 40-byte v6 assumption must be gone"
    );
    assert!(
        !insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 22),
        "fixed 20-byte v4 assumption must be gone"
    );
}

#[test]
fn probe_returns_clean_boolean_unprivileged() {
    // Must not panic regardless of kernel policy; both outcomes are valid.
    let _supported: bool = probe_ebpf();
}

#[test]
fn ipv6_walk_emits_bounded_stages() {
    use runner::sandbox::ebpf::MAX_V6_EXTENSIONS;
    let insns = EgressFilterProgram::new().to_instructions().unwrap();
    // One dispatch per walkable next-header value, per stage. Imm 0
    // appears twice per stage (Hop-by-Hop dispatch + fragment-first
    // check), hence 8.
    for (proto, count) in [(0i32, 8), (43, 4), (44, 4), (60, 4)] {
        assert_eq!(
            insns
                .iter()
                .filter(|i| i.code == op::JMP_IMM_JEQ && i.imm == proto)
                .count(),
            count as usize,
            "dispatch for next-header {proto}"
        );
    }
    // One fragment-offset mask per stage (non-first fragments drop).
    assert_eq!(
        insns
            .iter()
            .filter(|i| i.code == op::ALU64_IMM_AND && i.imm == 0xfff8)
            .count(),
        MAX_V6_EXTENSIONS
    );
    // Indirect byte loads walk the chain (next-header + Hdr Ext Len).
    assert!(
        insns.iter().filter(|i| i.code == op::LD_IND_B).count() >= MAX_V6_EXTENSIONS * 2,
        "walk must read next-header and length bytes indirectly"
    );
    // The walk starts at the 40-byte base header.
    assert!(
        insns
            .iter()
            .any(|i| i.code == op::MOV64_IMM && i.dst_reg == 1 && i.imm == 40),
        "R1 must start at 40"
    );
}

/// Test-only semantic mirror of the emitted v6 path: version, ULA
/// drop, then the same 4-stage walk the bytecode performs. The test
/// above pins the emitted instructions; this pins their meaning.
fn v6_verdict(packet: &[u8]) -> bool {
    fn dport_at(packet: &[u8], off: usize) -> Option<u16> {
        packet
            .get(off + 2..off + 4)
            .map(|w| u16::from_be_bytes([w[0], w[1]]))
    }
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return false;
    }
    if packet[24] & 0xfe == 0xfc {
        return false;
    }
    let mut off = 40usize;
    let mut next = packet[6];
    for _ in 0..4 {
        match next {
            6 => return dport_at(packet, off) == Some(443),
            17 => return dport_at(packet, off) == Some(53),
            0 | 43 | 60 => {
                if packet.len() < off + 2 {
                    return false;
                }
                let ext_len = packet[off + 1] as usize;
                next = packet[off];
                off += (ext_len + 1) * 8;
            }
            44 => {
                if packet.len() < off + 4 {
                    return false;
                }
                let word = u16::from_be_bytes([packet[off + 2], packet[off + 3]]);
                if word & 0xfff8 != 0 {
                    return false;
                }
                next = packet[off];
                off += 8;
            }
            _ => return false,
        }
    }
    // Terminal dispatch after the fourth advance (mirrors walk_term).
    match next {
        6 => dport_at(packet, off) == Some(443),
        17 => dport_at(packet, off) == Some(53),
        _ => false,
    }
}

/// One extension header: type number + body bytes (next-header byte
/// backfilled by the builder).
enum V6Ext {
    Hbh(u8),
    Routing(u8),
    Fragment(u16),
    DstOpts(u8),
    Esp,
}

impl V6Ext {
    fn number(&self) -> u8 {
        match self {
            V6Ext::Hbh(_) => 0,
            V6Ext::Routing(_) => 43,
            V6Ext::Fragment(_) => 44,
            V6Ext::DstOpts(_) => 60,
            V6Ext::Esp => 50,
        }
    }

    fn body_len(&self) -> usize {
        match self {
            V6Ext::Hbh(len) | V6Ext::Routing(len) | V6Ext::DstOpts(len) => (*len as usize + 1) * 8,
            V6Ext::Fragment(_) | V6Ext::Esp => 8,
        }
    }

    fn fill_body(&self, body: &mut [u8]) {
        match self {
            V6Ext::Hbh(len) | V6Ext::Routing(len) | V6Ext::DstOpts(len) => body[1] = *len,
            V6Ext::Fragment(word) => body[2..4].copy_from_slice(&word.to_be_bytes()),
            V6Ext::Esp => {}
        }
    }
}

/// Minimal IPv6 packet: base header + extension chain + 4 transport
/// bytes (sport zeroed, dport set). Next-header bytes threaded.
fn v6_packet(exts: &[V6Ext], dport: u16, dst_first: u8, proto: u8) -> Vec<u8> {
    let total: usize = 40 + exts.iter().map(V6Ext::body_len).sum::<usize>() + 4;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x60;
    pkt[24] = dst_first;
    // Thread next-headers: base points at the first extension (or the
    // transport proto), each extension at its follower.
    let mut followers: Vec<u8> = exts.iter().map(V6Ext::number).collect();
    followers.push(proto);
    pkt[6] = followers[0];
    let mut off = 40usize;
    for (i, ext) in exts.iter().enumerate() {
        let len = ext.body_len();
        pkt[off] = followers[i + 1];
        ext.fill_body(&mut pkt[off..off + len]);
        off += len;
    }
    pkt[total - 2..total].copy_from_slice(&dport.to_be_bytes());
    pkt
}

#[test]
fn v6_model_matches_chains_drops_and_malformed() {
    use V6Ext::*;
    // No extensions: plain TCP 443 allows, wrong port drops.
    assert!(v6_verdict(&v6_packet(&[], 443, 0x20, 6)));
    assert!(v6_verdict(&v6_packet(&[], 53, 0x20, 17)));
    assert!(!v6_verdict(&v6_packet(&[], 80, 0x20, 6)));
    // Single headers of each walkable type shift the port correctly.
    assert!(v6_verdict(&v6_packet(&[Hbh(0)], 443, 0x20, 6)));
    assert!(v6_verdict(&v6_packet(&[Routing(2)], 53, 0x20, 17)));
    assert!(v6_verdict(&v6_packet(&[DstOpts(1)], 443, 0x20, 6)));
    assert!(v6_verdict(&v6_packet(&[Fragment(0)], 443, 0x20, 6)));
    // A fixed-offset-42 reader would misread every chained case: the
    // word at 42 is header bytes here, not the port.
    let chained = v6_packet(&[Hbh(0)], 443, 0x20, 6);
    assert_ne!(u16::from_be_bytes([chained[42], chained[43]]), 443);
    // Two-header chain resolves through both stages.
    assert!(v6_verdict(&v6_packet(&[Hbh(0), DstOpts(0)], 443, 0x20, 6)));
    // Fifth extension exceeds the bound: drop.
    assert!(!v6_verdict(&v6_packet(
        &[Hbh(0), Hbh(0), Hbh(0), Hbh(0), Hbh(0)],
        443,
        0x20,
        6
    )));
    // Four headers still resolve.
    assert!(v6_verdict(&v6_packet(
        &[Hbh(0), Hbh(0), Hbh(0), Hbh(0)],
        443,
        0x20,
        6
    )));
    // Non-first fragment (offset 1 == 8 bytes in): drop.
    assert!(!v6_verdict(&v6_packet(&[Fragment(0x0008)], 443, 0x20, 6)));
    // ESP and unknown headers: drop (nothing walkable past them).
    assert!(!v6_verdict(&v6_packet(&[Esp], 443, 0x20, 6)));
    // ULA destination drops regardless of ports.
    assert!(!v6_verdict(&v6_packet(&[Hbh(0)], 443, 0xfd, 6)));
    // Truncated chain drops instead of reading past the end.
    let mut short = v6_packet(&[Hbh(0)], 443, 0x20, 6);
    short.truncate(41);
    assert!(!v6_verdict(&short));
}
