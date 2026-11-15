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
//! port constants compare directly against 53/443. The program assumes a
//! fixed 20-byte IPv4 header and no IPv6 extension headers (documented
//! fast path; full header-chain walking is the hardening follow-up).

/// eBPF opcode classes and ALU/JMP operation codes (linux/bpf.h).
pub mod op {
    pub const ALU64_IMM_AND: u8 = 0x57;
    pub const ALU64_IMM_RSH: u8 = 0x77;
    pub const JMP_JA: u8 = 0x05;
    pub const JMP_IMM_JEQ: u8 = 0x15;
    pub const LD_ABS_W: u8 = 0x20;
    pub const LD_ABS_H: u8 = 0x28;
    pub const LD_ABS_B: u8 = 0x30;
    pub const MOV64_IMM: u8 = 0xb7;
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

    fn finish(mut self) -> Vec<BpfInstruction> {
        for (pos, target) in std::mem::take(&mut self.fixups) {
            let dest = *self.labels.get(&target).expect("assembler label");
            let rel = dest as isize - pos as isize - 1;
            self.insns[pos].off = rel as i16;
        }
        self.insns
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

    /// Generate the complete filter program.
    pub fn to_instructions(&self) -> Vec<BpfInstruction> {
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
        self.emit_port_check(&mut asm, "tcp_v4", 6, 22);
        self.emit_port_check(&mut asm, "udp_v4", 17, 22);

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
}

/// Probe unprivileged socket-filter attachment: binds a loopback UDP
/// socket and attempts a harmless accept-all `SO_ATTACH_FILTER`.
/// Returns false (never panics) when the kernel refuses.
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
        let insns = EgressFilterProgram::new().to_instructions();
        let exits = insns.iter().filter(|i| i.code == op::EXIT).count();
        assert_eq!(exits, 2);
        assert!(insns.len() > 30);
    }

    #[test]
    fn probe_returns_bool_without_panic() {
        let _ = probe_ebpf();
    }
}
