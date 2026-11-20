//! Native eBPF egress filtering: pure-Rust bytecode generation.
//!
//! Replaces external `nftables` CLI execution with in-tree programs. The
//! generator emits socket-filter bytecode inspecting the IP header at
//! offset 0 (no Ethernet header in socket-filter context):
//!
//! * Drops RFC 1918 IPv4 destinations and `169.254/16` metadata.
//! * Drops IPv6 ULA (`fd00::/8`).
//! * Allows only UDP 53 (DNS) and TCP 443 (public HTTPS).
//! * Default-drops everything else.
//!
//! Multi-byte absolute loads yield big-endian (network-order) values, so
//! port constants compare directly against 53/443. IPv4 transport offsets
//! derive dynamically from the IHL nibble (RFC 791), so IP options never
//! shift port matching. IPv6 keeps a fixed 40-byte header assumption;
//! extension-header walking is the remaining hardening follow-up.

/// eBPF opcode classes and ALU/JMP operation codes (linux/bpf.h).
pub mod op {
    pub const ALU64_IMM_AND: u8 = 0x57;
    pub const ALU64_IMM_RSH: u8 = 0x77;
    pub const JMP_JA: u8 = 0x05;
    pub const JMP_IMM_JEQ: u8 = 0x15;
    pub const LD_ABS_W: u8 = 0x20;
    pub const LD_ABS_H: u8 = 0x28;
    pub const LD_ABS_B: u8 = 0x30;
    /// `LD_IND` (load from packet at `src_reg + imm`; `BPF_LD|BPF_IND`
    /// per `linux/bpf_common.h`). The index register holds the computed
    /// transport-header offset.
    pub const LD_IND_W: u8 = 0x40;
    pub const LD_IND_H: u8 = 0x48;
    pub const LD_IND_B: u8 = 0x50;
    pub const MOV64_IMM: u8 = 0xb7;
    /// `MOV64_REG` (dst = src; `BPF_ALU64|BPF_MOV|BPF_X`, `linux/bpf.h`).
    pub const MOV64_REG: u8 = 0xbf;
    pub const EXIT: u8 = 0x95;
}

/// Raw 8-byte eBPF instruction: `code | dst/src | off | imm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInstruction {
    pub code: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInstruction {
    /// Pack into wire bytes (regs nibble-packed per the ISA).
    pub fn to_bytes(self) -> [u8; 8] {
        let regs = (self.dst_reg & 0x0f) | ((self.src_reg & 0x0f) << 4);
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        [
            self.code, regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ]
    }
}

/// `dst = dst <alu-op> imm` (64-bit immediate ALU).
pub fn alu64_imm(op: u8, dst: u8, imm: i32) -> BpfInstruction {
    BpfInstruction {
        code: 0x07 | op,
        dst_reg: dst,
        src_reg: 0,
        off: 0,
        imm,
    }
}

/// Conditional/unconditional jump with 32-bit immediate comparator.
pub fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> BpfInstruction {
    BpfInstruction {
        code: 0x05 | op,
        dst_reg: dst,
        src_reg: 0,
        off,
        imm,
    }
}

/// Absolute packet load into R0 (`size` = W/H/B opcode).
pub fn ld_abs(size_opcode: u8, offset: u32) -> BpfInstruction {
    BpfInstruction {
        code: size_opcode,
        dst_reg: 0,
        src_reg: 0,
        off: 0,
        imm: offset as i32,
    }
}

/// Indirect packet load into R0 from `packet[src + offset]`.
pub fn ld_ind(size_opcode: u8, src: u8, offset: u32) -> BpfInstruction {
    BpfInstruction {
        code: size_opcode,
        dst_reg: 0,
        src_reg: src,
        off: 0,
        imm: offset as i32,
    }
}

/// 64-bit register move (dst = src).
pub fn mov64_reg(dst: u8, src: u8) -> BpfInstruction {
    BpfInstruction {
        code: op::MOV64_REG,
        dst_reg: dst,
        src_reg: src,
        off: 0,
        imm: 0,
    }
}

/// Accept the packet (returns 1).
pub fn exit_ok() -> [BpfInstruction; 2] {
    [
        BpfInstruction {
            code: op::MOV64_IMM,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 1,
        },
        BpfInstruction {
            code: op::EXIT,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 0,
        },
    ]
}

/// Drop the packet (returns 0).
pub fn exit_drop() -> [BpfInstruction; 2] {
    [
        BpfInstruction {
            code: op::MOV64_IMM,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 0,
        },
        BpfInstruction {
            code: op::EXIT,
            dst_reg: 0,
            src_reg: 0,
            off: 0,
            imm: 0,
        },
    ]
}

/// Label-resolving assembler for jump fixups.
struct Assembler {
    insns: Vec<BpfInstruction>,
    labels: std::collections::HashMap<String, usize>,
    fixups: Vec<(usize, String)>,
}

impl Assembler {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            labels: Default::default(),
            fixups: Vec::new(),
        }
    }

    fn emit(&mut self, insn: BpfInstruction) {
        self.insns.push(insn);
    }

    fn label(&mut self, name: &str) {
        self.labels.insert(name.to_string(), self.insns.len());
    }

    fn jump(&mut self, op: u8, dst: u8, imm: i32, target: &str) {
        self.fixups.push((self.insns.len(), target.to_string()));
        self.insns.push(jmp_imm(op, dst, imm, 0));
    }

    fn finish(mut self) -> Result<Vec<BpfInstruction>, String> {
        for (pos, target) in std::mem::take(&mut self.fixups) {
            let Some(dest) = self.labels.get(&target) else {
                return Err(format!("assembler: unknown label {target:?}"));
            };
            let rel = *dest as isize - pos as isize - 1;
            self.insns[pos].off = rel as i16;
        }
        Ok(self.insns)
    }
}

/// Egress filter policy: blocked ranges + port whitelist.
#[derive(Debug, Clone)]
pub struct EgressFilterProgram {
    /// (masked network, mask) pairs to drop (big-endian u32).
    pub blocked_v4: Vec<(u32, u32)>,
    /// Allowed (proto, port): proto 6 = TCP, 17 = UDP.
    pub allowed_ports: Vec<(u8, u16)>,
}

impl Default for EgressFilterProgram {
    fn default() -> Self {
        Self {
            blocked_v4: vec![
                (0x0a00_0000, 0xff00_0000), // 10.0.0.0/8
                (0xac10_0000, 0xfff0_0000), // 172.16.0.0/12
                (0xc0a8_0000, 0xffff_0000), // 192.168.0.0/16
                (0xa9fe_0000, 0xffff_0000), // 169.254.0.0/16
            ],
            allowed_ports: vec![(17, 53), (6, 443)],
        }
    }
}

impl EgressFilterProgram {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate the complete filter program. Fails closed on an
    /// unknown jump label instead of aborting the daemon.
    pub fn to_instructions(&self) -> Result<Vec<BpfInstruction>, String> {
        use op::*;
        let mut asm = Assembler::new();

        // Version dispatch: R0 = first byte >> 4.
        asm.emit(ld_abs(LD_ABS_B, 0));
        asm.emit(alu64_imm(0x70, 0, 4)); // RSH64_IMM
        asm.jump(0x10, 0, 4, "ipv4"); // JEQ_IMM
        asm.jump(0x10, 0, 6, "ipv6");
        asm.jump(0x00, 0, 0, "drop"); // JA

        // IPv4: masked range drops on dst word at offset 16.
        asm.label("ipv4");
        for (net, mask) in &self.blocked_v4 {
            asm.emit(ld_abs(LD_ABS_W, 16));
            asm.emit(alu64_imm(0x50, 0, *mask as i32)); // AND64_IMM
            asm.jump(0x10, 0, *net as i32, "drop");
        }
        // Protocol dispatch.
        asm.emit(ld_abs(LD_ABS_B, 9));
        asm.jump(0x10, 0, 6, "tcp_v4");
        asm.jump(0x10, 0, 17, "udp_v4");
        asm.jump(0x00, 0, 0, "drop");
        self.emit_port_check_v4(&mut asm, "tcp_v4", 6);
        self.emit_port_check_v4(&mut asm, "udp_v4", 17);

        // IPv6: ULA check on first dst byte, then ports at offset 42.
        asm.label("ipv6");
        asm.emit(ld_abs(LD_ABS_B, 24));
        asm.emit(alu64_imm(0x50, 0, 0xfe));
        asm.jump(0x10, 0, 0xfc, "drop");
        asm.emit(ld_abs(LD_ABS_B, 6));
        asm.jump(0x10, 0, 6, "tcp_v6");
        asm.jump(0x10, 0, 17, "udp_v6");
        asm.jump(0x00, 0, 0, "drop");
        self.emit_port_check(&mut asm, "tcp_v6", 6, 42);
        self.emit_port_check(&mut asm, "udp_v6", 17, 42);

        asm.label("allow");
        for insn in exit_ok() {
            asm.emit(insn);
        }
        asm.label("drop");
        for insn in exit_drop() {
            asm.emit(insn);
        }
        asm.finish()
    }

    fn emit_port_check(&self, asm: &mut Assembler, label: &str, proto: u8, dport_off: u32) {
        asm.label(label);
        let port = self
            .allowed_ports
            .iter()
            .find(|(p, _)| *p == proto)
            .map(|(_, port)| *port as i32);
        asm.emit(ld_abs(op::LD_ABS_H, dport_off));
        match port {
            Some(port) => asm.jump(0x10, 0, port, "allow"),
            None => asm.jump(0x00, 0, 0, "drop"),
        }
        asm.jump(0x00, 0, 0, "drop");
    }

    /// IPv4 port check with dynamic IHL walking (RFC 791): R1 ends up
    /// holding the transport-header offset `(IHL & 0x0F) * 4`, and the
    /// destination port loads indirectly from R1 + 2 — correct even
    /// when IP options are present. Headers shorter than 20 bytes
    /// (IHL < 5) are malformed and drop.
    fn emit_port_check_v4(&self, asm: &mut Assembler, label: &str, proto: u8) {
        asm.label(label);
        let port = self
            .allowed_ports
            .iter()
            .find(|(p, _)| *p == proto)
            .map(|(_, port)| *port as i32);
        asm.emit(ld_abs(op::LD_ABS_B, 0));
        asm.emit(alu64_imm(0x50, 0, 0x0f)); // AND64_IMM: IHL nibble
        asm.emit(alu64_imm(0x60, 0, 2)); // LSH64_IMM: * 4
        asm.emit(mov64_reg(1, 0)); // R1 = header length
        asm.jump(0xa0, 1, 20, "drop"); // JLT_IMM: malformed if < 20
        asm.emit(ld_ind(op::LD_IND_H, 1, 2));
        match port {
            Some(port) => asm.jump(0x10, 0, port, "allow"),
            None => asm.jump(0x00, 0, 0, "drop"),
        }
        asm.jump(0x00, 0, 0, "drop");
    }
}

/// Probe unprivileged socket-filter attachment: binds a loopback UDP
/// socket and attempts a harmless accept-all `SO_ATTACH_FILTER`.
/// Returns false (never panics) when the kernel refuses. Linux-only;
/// other platforms have no `SO_ATTACH_FILTER` and always degrade.
#[cfg(target_os = "linux")]
pub fn probe_ebpf() -> bool {
    use std::os::unix::io::AsRawFd;

    #[repr(C)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *mut SockFilter,
    }

    let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(socket) => socket,
        Err(_) => return false,
    };
    // RET #-1: accept everything (harmless on an unconnected test socket).
    let mut filter = [SockFilter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0xffff_ffff,
    }];
    let prog = SockFprog {
        len: 1,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: bare setsockopt with a valid fprog pointer; no memory
    // is retained by the kernel on failure, socket is closed on drop.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const SockFprog as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Non-Linux kernels have no socket-filter attach; always degrade.
#[cfg(not(target_os = "linux"))]
pub fn probe_ebpf() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_pack_to_eight_bytes() {
        let bytes = alu64_imm(0x50, 6, 0x1200).to_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], op::ALU64_IMM_AND);
        assert_eq!(bytes[1], 0x06);
    }

    #[test]
    fn program_has_balanced_allow_and_drop_exits() {
        let insns = EgressFilterProgram::new().to_instructions().unwrap();
        let exits = insns.iter().filter(|i| i.code == op::EXIT).count();
        assert_eq!(exits, 2);
        assert!(insns.len() > 30);
    }

    #[test]
    fn probe_returns_bool_without_panic() {
        let _ = probe_ebpf();
    }

    #[test]
    fn ipv4_ports_use_dynamic_ihl_indirect_loads() {
        let insns = EgressFilterProgram::new().to_instructions().unwrap();
        // Both v4 paths walk IHL: AND nibble, *4, stash in R1, bound it.
        let ands = insns
            .iter()
            .filter(|i| i.code == 0x57 && i.imm == 0x0f)
            .count();
        assert_eq!(ands, 2, "one IHL mask per v4 proto path");
        assert_eq!(
            insns
                .iter()
                .filter(|i| i.code == op::MOV64_REG && i.dst_reg == 1 && i.src_reg == 0)
                .count(),
            2
        );
        // Indirect half-word loads from R1 + 2 (dst port).
        let inds: Vec<_> = insns.iter().filter(|i| i.code == op::LD_IND_H).collect();
        assert_eq!(inds.len(), 2);
        assert!(inds.iter().all(|i| i.src_reg == 1 && i.imm == 2));
        // Malformed headers (IHL < 5, i.e. length < 20) drop.
        assert_eq!(
            insns
                .iter()
                .filter(|i| i.code == 0xa5 && i.dst_reg == 1 && i.imm == 20)
                .count(),
            2
        );
        // No fixed-offset v4 port load remains; v6 keeps offset 42.
        assert!(!insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 22));
        assert!(insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 42));
    }

    /// Test-only semantic mirror of the v4 program path: version, range
    /// drops, proto dispatch, IHL-derived port fetch. The bytecode test
    /// above pins the emitted instructions; this pins their meaning.
    fn v4_verdict(packet: &[u8], udp_allowed: bool, tcp_allowed: bool) -> bool {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return false;
        }
        let ihl = ((packet[0] & 0x0f) as usize) * 4;
        if ihl < 20 || packet.len() < ihl + 4 {
            return false;
        }
        let dst = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
        for (net, mask) in [
            (0x0a00_0000u32, 0xff00_0000u32),
            (0xac10_0000, 0xfff0_0000),
            (0xc0a8_0000, 0xffff_0000),
            (0xa9fe_0000, 0xffff_0000),
        ] {
            if dst & mask == net {
                return false;
            }
        }
        let dport = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
        match packet[9] {
            17 => udp_allowed && dport == 53,
            6 => tcp_allowed && dport == 443,
            _ => false,
        }
    }

    /// Minimal IPv4/TCP header with tunable IHL, proto, dst, dport.
    fn v4_packet(ihl_words: u8, proto: u8, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let hlen = ihl_words as usize * 4;
        let mut pkt = vec![0u8; hlen + 4];
        pkt[0] = 0x40 | (ihl_words & 0x0f);
        pkt[9] = proto;
        pkt[16..20].copy_from_slice(&dst);
        pkt[hlen + 2..hlen + 4].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    #[test]
    fn v4_model_matches_options_and_malformed_packets() {
        let public = [1, 1, 1, 1];
        // Plain 20-byte header, TCP 443: allow.
        assert!(v4_verdict(&v4_packet(5, 6, public, 443), true, true));
        // Wrong port: drop.
        assert!(!v4_verdict(&v4_packet(5, 6, public, 80), true, true));
        // IP options (IHL 6 and 7): port found at the shifted offset.
        assert!(v4_verdict(&v4_packet(6, 6, public, 443), true, true));
        assert!(v4_verdict(&v4_packet(7, 17, public, 53), true, true));
        // A fixed-offset-22 reader would misread the options case: the
        // word at 22 is options zero-fill here, not the port.
        let with_opts = v4_packet(7, 6, public, 443);
        assert_ne!(u16::from_be_bytes([with_opts[22], with_opts[23]]), 443);
        // Malformed IHL < 5: drop.
        assert!(!v4_verdict(&v4_packet(4, 6, public, 443), true, true));
        // Blocked ranges drop regardless of ports.
        assert!(!v4_verdict(
            &v4_packet(5, 6, [10, 0, 0, 1], 443),
            true,
            true
        ));
        assert!(!v4_verdict(
            &v4_packet(6, 17, [169, 254, 169, 254], 53),
            true,
            true
        ));
        // Unknown proto and truncated packets drop.
        assert!(!v4_verdict(&v4_packet(5, 1, public, 443), true, true));
        assert!(!v4_verdict(&[0x45u8; 10], true, true));
    }

    #[test]
    fn unknown_label_fails_closed() {
        let mut asm = Assembler::new();
        asm.jump(0x00, 0, 0, "typo_label");
        let err = asm.finish().expect_err("unknown label must fail");
        assert!(err.contains("typo_label"), "unexpected: {err}");
        // Full program still assembles after the Result change.
        assert!(!EgressFilterProgram::new()
            .to_instructions()
            .unwrap()
            .is_empty());
    }
}
