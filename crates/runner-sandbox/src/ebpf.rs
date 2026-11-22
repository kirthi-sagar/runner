//! Native eBPF egress filtering: pure-Rust bytecode generation.
//!
//! Replaces external `nftables` CLI execution with in-tree programs. The
//! generator emits socket-filter bytecode inspecting the IP header at
//! offset 0 (no Ethernet header in socket-filter context):
//!
//! * Drops RFC 1918 IPv4 destinations and `169.254/16` metadata.
//! * Drops IPv6 ULA (`fc00::/7`).
//! * Allows only UDP 53 (DNS) and TCP 443 (public HTTPS).
//! * Default-drops everything else.
//!
//! Multi-byte absolute loads yield big-endian (network-order) values, so
//! port constants compare directly against 53/443. IPv4 transport offsets
//! derive dynamically from the IHL nibble (RFC 791), so IP options never
//! shift port matching. IPv6 walks up to [`MAX_V6_EXTENSIONS`] extension
//! headers (RFC 8200 §4) the same way — Hop-by-Hop, Routing, Fragment,
//! Destination Options — so header chaining never shifts port matching
//! either. Anything the walker cannot parse drops.

/// eBPF opcode classes and ALU/JMP operation codes (linux/bpf.h).
pub mod op {
    /// `BPF_ALU|BPF_AND|BPF_K`: 32-bit AND, upper bits zeroed.
    pub const ALU_IMM_AND: u8 = 0x54;
    pub const ALU64_IMM_AND: u8 = 0x57;
    pub const ALU64_IMM_RSH: u8 = 0x77;
    pub const JMP_JA: u8 = 0x05;
    pub const JMP_IMM_JEQ: u8 = 0x15;
    /// `BPF_JMP32|BPF_JEQ|BPF_K`: 32-bit equality compare.
    pub const JMP32_IMM_JEQ: u8 = 0x16;
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

/// `dst = (u32)dst <alu-op> (u32)imm`, upper 32 bits zeroed
/// (32-bit immediate ALU).
pub fn alu32_imm(op: u8, dst: u8, imm: i32) -> BpfInstruction {
    BpfInstruction {
        code: 0x04 | op,
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

/// 32-bit conditional jump: compares `(u32)dst` against `(u32)imm`.
pub fn jmp32_imm(op: u8, dst: u8, imm: i32, off: i16) -> BpfInstruction {
    BpfInstruction {
        code: 0x06 | op,
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

/// 64-bit register-register ALU (dst op= src), e.g. ADD64_REG.
pub fn alu64_reg(op: u8, dst: u8, src: u8) -> BpfInstruction {
    BpfInstruction {
        code: 0x0f | op,
        dst_reg: dst,
        src_reg: src,
        off: 0,
        imm: 0,
    }
}

/// 64-bit immediate move (dst = imm).
pub fn mov64_imm(dst: u8, imm: i32) -> BpfInstruction {
    BpfInstruction {
        code: op::MOV64_IMM,
        dst_reg: dst,
        src_reg: 0,
        off: 0,
        imm,
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

    fn jump32(&mut self, op: u8, dst: u8, imm: i32, target: &str) {
        self.fixups.push((self.insns.len(), target.to_string()));
        self.insns.push(jmp32_imm(op, dst, imm, 0));
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

/// Maximum IPv6 extension headers walked before dropping (unrolled
/// stages; a fifth header means the transport offset stays unresolved).
pub const MAX_V6_EXTENSIONS: usize = 4;

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

        // IPv4: masked range drops on dst word at offset 16. The
        // 32-bit domain is load-bearing here, not a peephole: 64-bit
        // JMP immediates are sign-extended, so a 64-bit JEQ against a
        // high-bit net (172.16/12, 192.168/16, 169.254/16) compares
        // the zero-extended load against 0xFFFF_FFFF_<net> and can
        // never match — a fail-open. AND32 + JEQ32 keep the compare in
        // the 32-bit domain, the same approach as the kernel's
        // classic→eBPF converter for 32-bit packet data.
        asm.label("ipv4");
        for (net, mask) in &self.blocked_v4 {
            asm.emit(ld_abs(LD_ABS_W, 16));
            asm.emit(alu32_imm(0x50, 0, *mask as i32)); // AND_IMM
            asm.jump32(0x10, 0, *net as i32, "drop"); // JEQ32_IMM
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
        self.emit_v6_walk(&mut asm);
        self.emit_port_check(&mut asm, "tcp_v6", 6);
        self.emit_port_check(&mut asm, "udp_v6", 17);

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

    /// IPv6 port check at the walked transport offset: R1 holds the
    /// header offset (placed by [`Self::emit_v6_walk`]) and the
    /// destination port loads indirectly from R1 + 2.
    fn emit_port_check(&self, asm: &mut Assembler, label: &str, proto: u8) {
        asm.label(label);
        let port = self
            .allowed_ports
            .iter()
            .find(|(p, _)| *p == proto)
            .map(|(_, port)| *port as i32);
        asm.emit(ld_ind(op::LD_IND_H, 1, 2));
        match port {
            Some(port) => asm.jump(0x10, 0, port, "allow"),
            None => asm.jump(0x00, 0, 0, "drop"),
        }
        asm.jump(0x00, 0, 0, "drop");
    }

    /// IPv6 extension-header walk (RFC 8200 §4), unrolled into
    /// [`MAX_V6_EXTENSIONS`] advancing stages plus one terminal
    /// dispatch (no backward jumps: socket-filter BPF is straight-line
    /// by design). R1 carries the current header offset (starts at
    /// 40), R0 the current header's type, R2 walk scratch. Each stage
    /// dispatches TCP (6)/UDP (17) to the port checks, advances over
    /// Hop-by-Hop (0), Routing (43), and Destination Options (60) by
    /// `(Hdr Ext Len + 1) * 8`, and over first-fragments (44, zero
    /// frag offset) by 8. Anything else — ESP/AH/unknown headers,
    /// non-first fragments (no transport header to check), truncated
    /// reads (OOB loads yield 0, which never matches a port), or a
    /// fifth extension — drops. Fail-closed: whatever the walker
    /// cannot parse never reaches `allow`.
    ///
    /// The next-header read order is load-bearing: every extension
    /// header's byte 0 is its Next field, so the following header's
    /// type must be captured at the CURRENT R1 before advancing —
    /// reading R1+0 after the advance would fetch the next header's
    /// first payload byte (a source port for transport headers) and
    /// dispatch on attacker-controlled data.
    fn emit_v6_walk(&self, asm: &mut Assembler) {
        asm.emit(mov64_imm(1, 40)); // R1 = base header length
        asm.emit(ld_abs(op::LD_ABS_B, 6)); // R0 = first next-header
        for stage in 0..MAX_V6_EXTENSIONS {
            let next = if stage + 1 < MAX_V6_EXTENSIONS {
                format!("walk{}", stage + 1)
            } else {
                // Last stage advances onto the terminal dispatch, so a
                // full 4-header chain still resolves its transport.
                "walk_term".to_string()
            };
            asm.label(&format!("walk{stage}"));
            asm.jump(0x10, 0, 6, "tcp_v6"); // JEQ_IMM
            asm.jump(0x10, 0, 17, "udp_v6");
            asm.jump(0x10, 0, 0, &format!("extv{stage}")); // Hop-by-Hop
            asm.jump(0x10, 0, 43, &format!("extv{stage}")); // Routing
            asm.jump(0x10, 0, 60, &format!("extv{stage}")); // Dest Options
            asm.jump(0x10, 0, 44, &format!("extf{stage}")); // Fragment
            asm.jump(0x00, 0, 0, "drop"); // JA: ESP/AH/unknown
                                          // Variable-length header: capture the following
                                          // header's type at R1+0 first (R2 scratch — the
                                          // length math needs R0), then R1 += (Hdr Ext
                                          // Len + 1) * 8 and restore R0 for dispatch.
            asm.label(&format!("extv{stage}"));
            asm.emit(ld_ind(op::LD_IND_B, 1, 0));
            asm.emit(mov64_reg(2, 0)); // R2 = following header type
            asm.emit(ld_ind(op::LD_IND_B, 1, 1));
            asm.emit(alu64_imm(0x00, 0, 1)); // ADD64_IMM
            asm.emit(alu64_imm(0x60, 0, 3)); // LSH64_IMM: * 8
            asm.emit(alu64_reg(0x00, 1, 0)); // ADD64_REG: R1 += R0
            asm.emit(mov64_reg(0, 2)); // R0 = following header type
            asm.jump(0x00, 0, 0, &next); // JA
                                         // Fragment: fixed 8 bytes, but only zero-offset first
                                         // fragments carry a transport header (bytes R1+2..R1+3 hold
                                         // the 13-bit offset in the top bits; mask 0xFFF8).
                                         // The immediate R1 add preserves R0, so the
                                         // pre-advance next-header read needs no scratch.
            asm.label(&format!("extf{stage}"));
            asm.emit(ld_ind(op::LD_IND_H, 1, 2));
            asm.emit(alu64_imm(0x50, 0, 0xfff8)); // AND64_IMM
            asm.jump(0x10, 0, 0, &format!("fragok{stage}"));
            asm.jump(0x00, 0, 0, "drop"); // JA: non-first fragment
            asm.label(&format!("fragok{stage}"));
            asm.emit(ld_ind(op::LD_IND_B, 1, 0)); // R0 = following type
            asm.emit(alu64_imm(0x00, 1, 8)); // ADD64_IMM: R1 += 8
            asm.jump(0x00, 0, 0, &next); // JA
        }
        // Terminal dispatch after the fourth advance: transport
        // protocols resolve, a fifth extension (or anything else)
        // drops.
        asm.label("walk_term");
        asm.jump(0x10, 0, 6, "tcp_v6"); // JEQ_IMM
        asm.jump(0x10, 0, 17, "udp_v6");
        asm.jump(0x00, 0, 0, "drop"); // JA
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

/// Verdict of in-memory bytecode evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfVerdict {
    /// Packet dropped (program returned 0).
    Drop,
    /// Packet passed (program returned nonzero).
    Pass,
}

/// Interpreter step cap. The generated program is straight-line
/// (~100 instructions, no backward jumps), so exhaustion means a
/// corrupt program — fail closed.
const EVAL_MAX_STEPS: usize = 4096;

/// eBPF general registers (R0-R9).
const EVAL_NUM_REGS: usize = 10;

/// Evaluate `program` against a raw packet buffer in memory by
/// interpreting the generated bytecode with kernel socket-filter
/// semantics: 64-bit ALU/JMP immediates are sign-extended (the
/// kernel's classic→eBPF converter states this contract explicitly
/// when routing 32-bit compares through zero-extended tmp
/// registers), 32-bit ALU/JMP stay in the 32-bit domain with upper
/// bits zeroed, and jumps are relative to the next instruction
/// (RFC 9669 §4).
///
/// Fail-closed throughout: assembly errors, unknown opcodes,
/// register/descriptor violations, step exhaustion, and falling off
/// the program end all yield [`BpfVerdict::Drop`]. Out-of-bounds
/// packet loads yield 0 and continue (the codebase's documented
/// socket-filter model): a zero can never match a blocked net, a
/// protocol, or an allowlisted port, so every truncated-read path
/// still ends at `drop` — verdict-equivalent to terminating.
pub fn evaluate_packet(program: &EgressFilterProgram, packet: &[u8]) -> BpfVerdict {
    let insns = match program.to_instructions() {
        Ok(insns) => insns,
        Err(_) => return BpfVerdict::Drop,
    };
    let mut regs = [0u64; EVAL_NUM_REGS];
    let mut pc = 0usize;
    for _ in 0..EVAL_MAX_STEPS {
        let Some(insn) = insns.get(pc) else {
            return BpfVerdict::Drop;
        };
        let dst = insn.dst_reg as usize;
        let src = insn.src_reg as usize;
        if dst >= EVAL_NUM_REGS || src >= EVAL_NUM_REGS {
            return BpfVerdict::Drop;
        }
        match insn.code {
            op::EXIT => {
                return if regs[0] as u32 == 0 {
                    BpfVerdict::Drop
                } else {
                    BpfVerdict::Pass
                };
            }
            op::MOV64_IMM => {
                regs[dst] = insn.imm as i64 as u64;
                pc += 1;
            }
            op::MOV64_REG => {
                regs[dst] = regs[src];
                pc += 1;
            }
            _ => match insn.code & 0x07 {
                // BPF_LD: absolute/indirect packet loads into R0.
                0x00 => {
                    let size = match insn.code {
                        op::LD_ABS_W | op::LD_IND_W => 4,
                        op::LD_ABS_H | op::LD_IND_H => 2,
                        op::LD_ABS_B | op::LD_IND_B => 1,
                        _ => return BpfVerdict::Drop,
                    };
                    let indirect = matches!(insn.code, op::LD_IND_W | op::LD_IND_H | op::LD_IND_B);
                    let base = if indirect { regs[src] } else { 0 };
                    regs[0] = load_be(packet, base.wrapping_add(insn.imm as u64), size);
                    pc += 1;
                }
                // BPF_ALU: 32-bit immediate ops, upper bits zeroed.
                0x04 => {
                    if insn.code & 0x08 != 0 {
                        return BpfVerdict::Drop;
                    }
                    let imm32 = insn.imm as u32;
                    let result = match insn.code & 0xf0 {
                        0x00 => (regs[dst] as u32).wrapping_add(imm32),
                        0x50 => (regs[dst] as u32) & imm32,
                        0x60 => (regs[dst] as u32).wrapping_shl(imm32),
                        0x70 => (regs[dst] as u32).wrapping_shr(imm32),
                        _ => return BpfVerdict::Drop,
                    };
                    regs[dst] = result as u64;
                    pc += 1;
                }
                // BPF_JMP: 64-bit jumps over a sign-extended immediate.
                0x05 => {
                    if insn.code & 0x08 != 0 {
                        return BpfVerdict::Drop;
                    }
                    let imm = insn.imm as i64 as u64;
                    let taken = match insn.code & 0xf0 {
                        0x00 => true,             // JA
                        0x10 => regs[dst] == imm, // JEQ
                        0xa0 => regs[dst] < imm,  // JLT (unsigned)
                        _ => return BpfVerdict::Drop,
                    };
                    let Some(next) = jump_target(pc, insn.off, taken) else {
                        return BpfVerdict::Drop;
                    };
                    pc = next;
                }
                // BPF_JMP32: 32-bit compares (JA32's imm-target form is
                // never emitted).
                0x06 => {
                    if insn.code & 0x08 != 0 {
                        return BpfVerdict::Drop;
                    }
                    let taken = match insn.code & 0xf0 {
                        0x10 => (regs[dst] as u32) == (insn.imm as u32), // JEQ32
                        _ => return BpfVerdict::Drop,
                    };
                    let Some(next) = jump_target(pc, insn.off, taken) else {
                        return BpfVerdict::Drop;
                    };
                    pc = next;
                }
                // BPF_ALU64: 64-bit ops over a sign-extended immediate,
                // plus register ADD.
                0x07 => {
                    if insn.code & 0x08 == 0 {
                        let imm = insn.imm as i64 as u64;
                        match insn.code & 0xf0 {
                            0x00 => regs[dst] = regs[dst].wrapping_add(imm),
                            0x50 => regs[dst] &= imm,
                            0x60 => regs[dst] = regs[dst].wrapping_shl(imm as u32),
                            0x70 => regs[dst] = regs[dst].wrapping_shr(imm as u32),
                            _ => return BpfVerdict::Drop,
                        }
                    } else {
                        match insn.code & 0xf0 {
                            0x00 => regs[dst] = regs[dst].wrapping_add(regs[src]),
                            _ => return BpfVerdict::Drop,
                        }
                    }
                    pc += 1;
                }
                _ => return BpfVerdict::Drop,
            },
        }
    }
    BpfVerdict::Drop
}

/// Big-endian packet load; out-of-bounds yields 0 (see
/// [`evaluate_packet`]).
fn load_be(packet: &[u8], off: u64, size: usize) -> u64 {
    let Ok(off) = usize::try_from(off) else {
        return 0;
    };
    let end = off.saturating_add(size);
    if end > packet.len() {
        return 0;
    }
    let mut value = 0u64;
    for (i, byte) in packet[off..end].iter().enumerate() {
        value |= (*byte as u64) << ((size - 1 - i) * 8);
    }
    value
}

/// Next program counter for a conditional jump (`off` is relative to
/// the following instruction); `None` when the target underflows.
fn jump_target(pc: usize, off: i16, taken: bool) -> Option<usize> {
    if !taken {
        return pc.checked_add(1);
    }
    usize::try_from(pc as i64 + 1 + i64::from(off)).ok()
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
        // Indirect half-word loads from R1 + 2: two v4 dst ports
        // (IHL-derived), two v6 dst ports (walk-derived), and four
        // fragment-offset words (one per walk stage).
        let inds: Vec<_> = insns.iter().filter(|i| i.code == op::LD_IND_H).collect();
        assert_eq!(inds.len(), 8);
        assert!(inds.iter().all(|i| i.src_reg == 1 && i.imm == 2));
        // Malformed headers (IHL < 5, i.e. length < 20) drop.
        assert_eq!(
            insns
                .iter()
                .filter(|i| i.code == 0xa5 && i.dst_reg == 1 && i.imm == 20)
                .count(),
            2
        );
        // No fixed-offset port load remains on either path (v4 used 22,
        // v6 used 42 before the walk).
        assert!(!insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 22));
        assert!(!insns.iter().any(|i| i.code == op::LD_ABS_H && i.imm == 42));
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

    #[test]
    fn range_compares_use_32bit_domain() {
        // Guards the sign-extension fix: 64-bit JEQ against high-bit
        // nets can never match, so all four range checks must stay in
        // the 32-bit domain.
        let insns = EgressFilterProgram::new().to_instructions().unwrap();
        let and32 = insns.iter().filter(|i| i.code == op::ALU_IMM_AND).count();
        let jeq32 = insns.iter().filter(|i| i.code == op::JMP32_IMM_JEQ).count();
        assert_eq!((and32, jeq32), (4, 4));
    }

    #[test]
    fn evaluator_agrees_with_v4_mirror() {
        // The bytecode, actually executed, must match the semantic
        // mirror on every combination — including the high-bit ranges
        // a 64-bit JEQ would fail open on.
        let program = EgressFilterProgram::new();
        let dsts = [
            [10, 0, 0, 1],
            [10, 255, 255, 254],
            [172, 16, 5, 4],
            [172, 31, 255, 254],
            [172, 15, 0, 1],
            [172, 32, 0, 1],
            [192, 168, 1, 1],
            [192, 167, 1, 1],
            [169, 254, 169, 254],
            [8, 8, 8, 8],
            [1, 1, 1, 1],
        ];
        let mut vectors = 0;
        for dst in dsts {
            for proto in [6u8, 17] {
                for dport in [53u16, 443, 80] {
                    for ihl in [5u8, 6] {
                        let pkt = v4_packet(ihl, proto, dst, dport);
                        let expected = v4_verdict(&pkt, true, true);
                        let verdict = evaluate_packet(&program, &pkt);
                        assert_eq!(
                            verdict == BpfVerdict::Pass,
                            expected,
                            "dst={dst:?} proto={proto} dport={dport} ihl={ihl}"
                        );
                        vectors += 1;
                    }
                }
            }
        }
        assert_eq!(vectors, 132);
    }

    /// Minimal IPv6 header with tunable dst, next header, and dport
    /// (no extension headers; transport at offset 40).
    fn v6_packet(dst: [u8; 16], proto: u8, dport: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60;
        pkt[6] = proto;
        pkt[24..40].copy_from_slice(&dst);
        pkt[42..44].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    /// IPv6 with one Hop-by-Hop options header (8 bytes, ext-len 0).
    fn v6_packet_hbh(dst: [u8; 16], proto: u8, dport: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 52];
        pkt[0] = 0x60;
        pkt[6] = 0; // Hop-by-Hop
        pkt[24..40].copy_from_slice(&dst);
        pkt[40] = proto;
        pkt[41] = 0; // Hdr Ext Len 0 -> 8 bytes
        pkt[50..52].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    /// IPv6 with a first-fragment header (offset 0 carries transport).
    fn v6_packet_frag(dst: [u8; 16], proto: u8, dport: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 52];
        pkt[0] = 0x60;
        pkt[6] = 44; // Fragment
        pkt[24..40].copy_from_slice(&dst);
        pkt[40] = proto;
        pkt[41] = 0;
        // Bytes 42..44 (frag offset/res/M) stay 0: first fragment.
        pkt[50..52].copy_from_slice(&dport.to_be_bytes());
        pkt
    }

    #[test]
    fn evaluator_v6_vectors() {
        use BpfVerdict::{Drop, Pass};
        let program = EgressFilterProgram::new();
        let public = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let fd = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let fc = [0xfc, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        // ULA drops on any port, both halves of fc00::/7.
        assert_eq!(evaluate_packet(&program, &v6_packet(fd, 6, 443)), Drop);
        assert_eq!(evaluate_packet(&program, &v6_packet(fd, 17, 53)), Drop);
        assert_eq!(evaluate_packet(&program, &v6_packet(fc, 6, 443)), Drop);
        // Public allowlist passes; anything else drops.
        assert_eq!(evaluate_packet(&program, &v6_packet(public, 6, 443)), Pass);
        assert_eq!(evaluate_packet(&program, &v6_packet(public, 17, 53)), Pass);
        assert_eq!(evaluate_packet(&program, &v6_packet(public, 6, 80)), Drop);
        assert_eq!(evaluate_packet(&program, &v6_packet(public, 6, 53)), Drop);
        assert_eq!(evaluate_packet(&program, &v6_packet(public, 58, 443)), Drop);
        // Extension headers resolve the shifted transport offset.
        assert_eq!(
            evaluate_packet(&program, &v6_packet_hbh(public, 6, 443)),
            Pass
        );
        assert_eq!(
            evaluate_packet(&program, &v6_packet_hbh(public, 6, 80)),
            Drop
        );
        assert_eq!(evaluate_packet(&program, &v6_packet_hbh(fd, 6, 443)), Drop);
        assert_eq!(
            evaluate_packet(&program, &v6_packet_frag(public, 17, 53)),
            Pass
        );
        assert_eq!(
            evaluate_packet(&program, &v6_packet_frag(public, 6, 22)),
            Drop
        );
        // Non-first fragments carry no transport header: drop.
        let mut non_first = v6_packet_frag(public, 6, 443);
        non_first[42] = 0x08; // frag offset 1 (top 13 bits nonzero)
        assert_eq!(evaluate_packet(&program, &non_first), Drop);
    }

    #[test]
    fn evaluator_malformed_packets_drop() {
        use BpfVerdict::Drop;
        let program = EgressFilterProgram::new();
        assert_eq!(evaluate_packet(&program, &[]), Drop);
        assert_eq!(evaluate_packet(&program, &[0x45u8; 10]), Drop);
        assert_eq!(
            evaluate_packet(&program, &v4_packet(4, 6, [1, 1, 1, 1], 443)),
            Drop
        );
        let mut bad_version = v4_packet(5, 6, [1, 1, 1, 1], 443);
        bad_version[0] = 0x50;
        assert_eq!(evaluate_packet(&program, &bad_version), Drop);
        // Truncated transport header: the port load reads past the end.
        assert_eq!(
            evaluate_packet(&program, &v4_packet(5, 6, [1, 1, 1, 1], 443)[..22]),
            Drop
        );
    }
}
