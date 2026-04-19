//! Programmatic construction of Artik [`Program`]s.
//!
//! The Fase 2 Circom lifting pass needs to emit Artik bytecode while
//! walking a function AST. Writing the raw `Instr` list by hand is
//! viable (tests in [`executor::tests`] do it) but gets tedious for
//! real programs, especially with forward jumps. This module provides
//! a small builder with:
//!
//! - Automatic register / signal / witness-slot id allocation.
//! - A label mechanism for forward jumps (`place` fills in an offset
//!   that is only known once later instructions are emitted).
//! - Ergonomic `emit_*` helpers for common shapes (field ops, int
//!   ops, conversions) that both allocate a fresh destination
//!   register and emit the instruction in one call.
//!
//! Example usage — lift `function sq(x) { return x * x; }`:
//!
//! ```ignore
//! use artik::builder::ProgramBuilder;
//! use artik::FieldFamily;
//!
//! let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
//! let x_sig = b.alloc_signal();           // caller binds x to signal 0
//! let slot = b.alloc_witness_slot();      // caller reads slot 0
//! let x = b.read_signal(x_sig);
//! let sq = b.fmul(x, x);
//! b.write_witness(slot, sq);
//! b.ret();
//! let prog = b.finish();
//! ```
//!
//! After `finish()`, round-trip the program through
//! [`bytecode::encode`](crate::bytecode::encode) +
//! [`bytecode::decode`](crate::bytecode::decode) to run the validator.

use crate::header::FieldFamily;
use crate::ir::{ElemT, Instr, IntBinOp, IntW, Reg};
use crate::program::{FieldConstEntry, Program};

/// An opaque handle to a yet-to-be-placed location in the instruction
/// stream. Obtained via [`ProgramBuilder::new_label`]; materialized
/// into a byte offset by [`ProgramBuilder::place`].
#[derive(Debug, Clone, Copy)]
pub struct Label(u32);

/// Fluent builder for [`Program`].
///
/// All methods take `&mut self`. The builder owns a growing `Vec<Instr>`
/// and a `Vec<FieldConstEntry>`; `finish()` consumes the builder and
/// returns the assembled `Program` with jump targets patched.
pub struct ProgramBuilder {
    family: FieldFamily,
    body: Vec<Instr>,
    const_pool: Vec<FieldConstEntry>,
    next_reg: u32,
    next_signal: u32,
    next_slot: u32,
    /// For each [`Label`], the instruction index where it was placed
    /// (index into `body`, not a byte offset — byte offsets are only
    /// computed in `finish`).
    label_positions: Vec<Option<u32>>,
    /// Pending patches: `(instruction_index, label_id)` — jump targets
    /// that still need to be resolved from instruction index to byte
    /// offset at `finish()` time.
    pending_jumps: Vec<PendingJump>,
}

struct PendingJump {
    /// Index into `body` of the Jump / JumpIf whose `target` we must patch.
    instr_index: u32,
    /// Which label this jump targets.
    label: u32,
}

impl ProgramBuilder {
    /// Start a new builder for the given field family. The builder
    /// has zero registers, signals, slots, constants, or instructions
    /// on entry — allocate them as you go.
    pub fn new(family: FieldFamily) -> Self {
        Self {
            family,
            body: Vec::new(),
            const_pool: Vec::new(),
            next_reg: 0,
            next_signal: 0,
            next_slot: 0,
            label_positions: Vec::new(),
            pending_jumps: Vec::new(),
        }
    }

    // ── Namespace allocation ──────────────────────────────────────────

    /// Allocate a fresh register. Returns a monotonically increasing
    /// index; the builder bumps `frame_size` automatically.
    pub fn alloc_reg(&mut self) -> Reg {
        let r = self.next_reg;
        self.next_reg += 1;
        r
    }

    /// Allocate a fresh input signal id. The caller is expected to
    /// supply these values as the `signals: &[FieldElement<F>]` slice
    /// when invoking the executor.
    pub fn alloc_signal(&mut self) -> u32 {
        let s = self.next_signal;
        self.next_signal += 1;
        s
    }

    /// Allocate a fresh witness slot id. The caller is expected to
    /// provide a `witness_slots: &mut [FieldElement<F>]` slice of at
    /// least `slot + 1` elements when invoking the executor.
    pub fn alloc_witness_slot(&mut self) -> u32 {
        let s = self.next_slot;
        self.next_slot += 1;
        s
    }

    /// Intern a constant into the pool and return its id. `bytes` is
    /// little-endian canonical encoding (up to the field family's
    /// max). Smaller values are zero-padded on decode.
    pub fn intern_const(&mut self, bytes: Vec<u8>) -> u32 {
        let id = self.const_pool.len() as u32;
        self.const_pool.push(FieldConstEntry { bytes });
        id
    }

    // ── Raw emission ──────────────────────────────────────────────────

    /// Append a raw instruction. Prefer the typed helpers below for
    /// common patterns — they both allocate and emit in one call.
    pub fn emit(&mut self, instr: Instr) {
        self.body.push(instr);
    }

    // ── Label mechanism ───────────────────────────────────────────────

    /// Create a new unplaced label. The returned handle can be passed
    /// to `jump_to` / `jump_if_to` before the target site is emitted;
    /// calling `place(label)` afterwards fills in the offset at
    /// `finish()` time.
    pub fn new_label(&mut self) -> Label {
        let id = self.label_positions.len() as u32;
        self.label_positions.push(None);
        Label(id)
    }

    /// Mark the current position in the instruction stream as the
    /// target of `label`. Must be called exactly once per label; the
    /// position is the instruction index of the *next* instruction
    /// that will be emitted.
    pub fn place(&mut self, label: Label) {
        let pos = self.body.len() as u32;
        self.label_positions[label.0 as usize] = Some(pos);
    }

    /// Emit an unconditional jump to `label`. The target is left as a
    /// sentinel (0) and patched at `finish()` time.
    pub fn jump_to(&mut self, label: Label) {
        let instr_index = self.body.len() as u32;
        self.body.push(Instr::Jump { target: 0 });
        self.pending_jumps.push(PendingJump {
            instr_index,
            label: label.0,
        });
    }

    /// Emit a conditional jump to `label`. `cond` must be an Int-typed
    /// register (typically U8 — any non-zero branches).
    pub fn jump_if_to(&mut self, cond: Reg, label: Label) {
        let instr_index = self.body.len() as u32;
        self.body.push(Instr::JumpIf { cond, target: 0 });
        self.pending_jumps.push(PendingJump {
            instr_index,
            label: label.0,
        });
    }

    // ── High-level emission helpers ───────────────────────────────────

    /// Emit `ReadSignal` and return the destination register.
    pub fn read_signal(&mut self, signal_id: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::ReadSignal { dst, signal_id });
        dst
    }

    /// Emit `PushConst` and return the destination register.
    pub fn push_const(&mut self, const_id: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::PushConst { dst, const_id });
        dst
    }

    /// Emit `WriteWitness`. No register is returned (it is a sink).
    pub fn write_witness(&mut self, slot_id: u32, src: Reg) {
        self.emit(Instr::WriteWitness { slot_id, src });
    }

    /// Emit `Return`. No register is returned.
    pub fn ret(&mut self) {
        self.emit(Instr::Return);
    }

    /// Emit `Trap { code }`. No register is returned.
    pub fn trap(&mut self, code: u16) {
        self.emit(Instr::Trap { code });
    }

    // ── Field ops ────────────────────────────────────────────────────

    pub fn fadd(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FAdd { dst, a, b });
        dst
    }

    pub fn fsub(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FSub { dst, a, b });
        dst
    }

    pub fn fmul(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FMul { dst, a, b });
        dst
    }

    pub fn fdiv(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FDiv { dst, a, b });
        dst
    }

    pub fn finv(&mut self, src: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FInv { dst, src });
        dst
    }

    pub fn feq(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FEq { dst, a, b });
        dst
    }

    // ── Integer ops ──────────────────────────────────────────────────

    pub fn ibin(&mut self, op: IntBinOp, w: IntW, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::IBin { op, w, dst, a, b });
        dst
    }

    pub fn inot(&mut self, w: IntW, src: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::INot { w, dst, src });
        dst
    }

    pub fn rotl32(&mut self, src: Reg, n: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::Rotl32 { dst, src, n });
        dst
    }

    pub fn rotr32(&mut self, src: Reg, n: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::Rotr32 { dst, src, n });
        dst
    }

    pub fn rotl8(&mut self, src: Reg, n: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::Rotl8 { dst, src, n });
        dst
    }

    // ── Conversions ─────────────────────────────────────────────────

    pub fn int_from_field(&mut self, w: IntW, src: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::IntFromField { w, dst, src });
        dst
    }

    pub fn field_from_int(&mut self, src: Reg, w: IntW) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FieldFromInt { dst, src, w });
        dst
    }

    // ── Arrays ──────────────────────────────────────────────────────

    pub fn alloc_array(&mut self, len: u32, elem: ElemT) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::AllocArray { dst, len, elem });
        dst
    }

    pub fn load_arr(&mut self, arr: Reg, idx: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::LoadArr { dst, arr, idx });
        dst
    }

    pub fn store_arr(&mut self, arr: Reg, idx: Reg, val: Reg) {
        self.emit(Instr::StoreArr { arr, idx, val });
    }

    // ── Finalize ────────────────────────────────────────────────────

    /// Consume the builder and produce a [`Program`], patching all
    /// pending jump targets into the byte offsets they ultimately
    /// land at. Returns an error if any label was referenced but
    /// never placed.
    pub fn finish(mut self) -> Result<Program, BuilderError> {
        // Pass 1: compute the byte offset of each instruction index.
        // Since encoded_size depends only on the instruction variant
        // (not its operands), we can walk the final body once.
        let mut index_to_offset: Vec<u32> = Vec::with_capacity(self.body.len() + 1);
        let mut acc: u32 = 0;
        for ins in &self.body {
            index_to_offset.push(acc);
            acc = acc.saturating_add(ins.encoded_size());
        }
        // Sentinel — offset *past* the last instruction. Useful if a
        // caller places a label at the end of the program to mean
        // "fall through to the end", though we don't emit one here.
        index_to_offset.push(acc);

        // Pass 2: patch pending jumps with the resolved byte offsets.
        for pending in &self.pending_jumps {
            let target_index = self
                .label_positions
                .get(pending.label as usize)
                .and_then(|p| *p)
                .ok_or(BuilderError::UnplacedLabel(pending.label))?;
            let target_offset = *index_to_offset
                .get(target_index as usize)
                .ok_or(BuilderError::UnplacedLabel(pending.label))?;
            match self.body.get_mut(pending.instr_index as usize) {
                Some(Instr::Jump { target }) | Some(Instr::JumpIf { target, .. }) => {
                    *target = target_offset;
                }
                _ => {
                    // The builder only records pending patches for Jump
                    // / JumpIf sites, so hitting another opcode here
                    // means the body was mutated behind the builder's
                    // back. Treat as a programmer error.
                    return Err(BuilderError::NonJumpAtPatchSite(pending.instr_index));
                }
            }
        }

        Ok(Program::new(
            self.family,
            self.next_reg,
            std::mem::take(&mut self.const_pool),
            std::mem::take(&mut self.body),
        ))
    }
}

/// Errors that can arise from misuse of the builder API. All of them
/// indicate a bug in the lifting pass; none of them are expected to
/// fire on correct input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// A label was referenced by [`ProgramBuilder::jump_to`] or
    /// [`ProgramBuilder::jump_if_to`] but never had [`ProgramBuilder::place`]
    /// called on it.
    UnplacedLabel(u32),
    /// A pending-jump slot resolved to an instruction that was not a
    /// Jump or JumpIf — indicates the builder's internal state was
    /// corrupted (should be unreachable).
    NonJumpAtPatchSite(u32),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnplacedLabel(id) => write!(f, "Artik builder label {id} was never placed"),
            Self::NonJumpAtPatchSite(idx) => {
                write!(f, "Artik builder patch site {idx} is not a jump")
            }
        }
    }
}

impl std::error::Error for BuilderError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{decode, encode};
    use crate::executor::{execute, ArtikContext};
    use memory::field::{Bn254Fr, FieldElement};

    type F = Bn254Fr;
    type FE = FieldElement<F>;

    fn run(prog: &Program, signals: &[FE], slots: &mut [FE]) {
        let mut ctx = ArtikContext::<F>::new(signals, slots);
        execute(prog, &mut ctx).expect("execute");
    }

    fn roundtrip(prog: Program) -> Program {
        let bytes = encode(&prog);
        decode(&bytes, Some(FieldFamily::BnLike256)).expect("decode")
    }

    #[test]
    fn builder_square_program() {
        // function sq(x) { return x * x; }  — witness lift.
        let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
        let x_sig = b.alloc_signal();
        let out_slot = b.alloc_witness_slot();
        let x = b.read_signal(x_sig);
        let sq = b.fmul(x, x);
        b.write_witness(out_slot, sq);
        b.ret();
        let prog = roundtrip(b.finish().unwrap());

        let mut slots = [FE::zero()];
        run(&prog, &[FE::from_u64(9)], &mut slots);
        assert_eq!(slots[0], FE::from_u64(81));
    }

    #[test]
    fn builder_forward_jump_resolves_to_return() {
        // function skip(cond, x) {
        //     if (cond) { skip past return-of-double-x; }
        //     write witness[0] = x * 2;
        //     return;
        // }
        let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
        let cond_sig = b.alloc_signal();
        let x_sig = b.alloc_signal();
        let slot = b.alloc_witness_slot();
        let end = b.new_label();

        let cond_f = b.read_signal(cond_sig);
        let cond = b.int_from_field(IntW::U8, cond_f);
        let x = b.read_signal(x_sig);
        let two_x = b.fadd(x, x);
        b.jump_if_to(cond, end);
        b.write_witness(slot, two_x);
        b.place(end);
        b.ret();

        let prog = roundtrip(b.finish().unwrap());

        // cond=0 → write runs.
        let sig = [FE::zero(), FE::from_u64(21)];
        let mut slots = [FE::zero()];
        run(&prog, &sig, &mut slots);
        assert_eq!(slots[0], FE::from_u64(42));

        // cond=1 → write skipped, slot stays at initial value.
        let sig = [FE::from_u64(1), FE::from_u64(21)];
        let mut slots = [FE::from_u64(999)];
        run(&prog, &sig, &mut slots);
        assert_eq!(slots[0], FE::from_u64(999));
    }

    #[test]
    fn builder_unplaced_label_errors() {
        let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
        let lbl = b.new_label();
        b.jump_to(lbl);
        b.ret();
        // `lbl` never placed.
        let err = b.finish().unwrap_err();
        assert_eq!(err, BuilderError::UnplacedLabel(0));
    }

    #[test]
    fn builder_intern_const_roundtrip() {
        let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
        let slot = b.alloc_witness_slot();
        // A canonical field constant of value 42 (BN-like, 32 bytes LE).
        let cid = b.intern_const(vec![42]);
        let r = b.push_const(cid);
        b.write_witness(slot, r);
        b.ret();
        let prog = roundtrip(b.finish().unwrap());

        let mut slots = [FE::zero()];
        run(&prog, &[], &mut slots);
        assert_eq!(slots[0], FE::from_u64(42));
    }
}
