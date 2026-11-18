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
    // IPv4 ports load indirectly (IHL-derived offset in R1 + 2);
    // IPv6 ports keep the fixed offset-42 absolute load.
    assert_eq!(
        insns
            .iter()
            .filter(|i| i.code == op::LD_IND_H && i.src_reg == 1 && i.imm == 2)
            .count(),
        2
    );
    assert!(insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 42));
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
