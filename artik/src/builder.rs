//! Programmatic construction of Artik [`Program`]s.
//!
//! The circom witness-lift pass emits Artik bytecode while walking a
//! function AST. Writing the raw `Instr` list by hand is viable (the
//! executor tests do it) but gets tedious for real programs, especially
//! with forward jumps and multiple subprograms. This module provides a
//! builder with:
//!
//! - Automatic register / signal / witness-slot id allocation.
//! - A label mechanism for forward jumps (`place` fills in an offset
//!   that is only known once later instructions are emitted).
//! - Ergonomic `emit_*` helpers for common shapes (field ops, int
//!   ops, conversions) that both allocate a fresh destination
//!   register and emit the instruction in one call.
//! - Multi-subprogram support: [`ProgramBuilder::reserve_subprogram`]
//!   hands out a callable id (so a caller can emit a `Call` to a
//!   subprogram whose body is not built yet), and
//!   [`ProgramBuilder::begin_subprogram`] /
//!   [`ProgramBuilder::end_subprogram`] switch which subprogram the
//!   emission helpers target. A builder that never reserves a
//!   subprogram produces exactly one entry subprogram — identical to
//!   the single-body programs every current producer emits.
//!
//! Example usage — lift `function sq(x) { return x * x; }`:
//!
//! ```ignore
//! use artik::builder::ProgramBuilder;
//! use memory::FieldFamily;
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

use memory::FieldFamily;

use crate::ir::{ElemT, Instr, IntBinOp, IntW, Reg, RegType};
use crate::program::{FieldConstEntry, Program, Subprogram};

/// An opaque handle to a yet-to-be-placed location in the instruction
/// stream. Obtained via [`ProgramBuilder::new_label`]; materialized
/// into a byte offset by [`ProgramBuilder::place`]. Labels are
/// subprogram-local.
#[derive(Debug, Clone, Copy)]
pub struct Label(u32);

struct PendingJump {
    /// Index into the subprogram body of the Jump / JumpIf whose
    /// `target` we must patch.
    instr_index: u32,
    /// Which label this jump targets.
    label: u32,
}

/// Mutable per-subprogram emission state. Registers, the instruction
/// body, the label table, and pending jumps are all subprogram-local;
/// the constant pool and signal / witness-slot namespaces are
/// program-global and live on [`ProgramBuilder`].
struct SubInProgress {
    params: Vec<RegType>,
    returns: Vec<RegType>,
    body: Vec<Instr>,
    next_reg: u32,
    label_positions: Vec<Option<u32>>,
    pending_jumps: Vec<PendingJump>,
}

impl SubInProgress {
    fn new(params: Vec<RegType>, returns: Vec<RegType>) -> Self {
        // Parameter values are delivered into registers
        // `0..params.len()` by the executor on entry to the call, so
        // freshly allocated registers must start past them.
        let next_reg = params.len() as u32;
        Self {
            params,
            returns,
            body: Vec::new(),
            next_reg,
            label_positions: Vec::new(),
            pending_jumps: Vec::new(),
        }
    }
}

/// Captured state of the active subprogram, usable as a rollback point
/// for speculative emission (e.g. a loop-unroll attempt that may bail).
/// Produced by [`ProgramBuilder::snapshot`] and consumed by
/// [`ProgramBuilder::restore`]. A snapshot is only valid while the same
/// subprogram is active.
#[derive(Debug, Clone, Copy)]
pub struct BuilderSnapshot {
    active: usize,
    body_len: usize,
    const_pool_len: usize,
    next_reg: u32,
    next_signal: u32,
    next_slot: u32,
    label_positions_len: usize,
    pending_jumps_len: usize,
}

/// Fluent builder for [`Program`].
///
/// All emission methods target the *active* subprogram (the entry
/// subprogram until [`Self::begin_subprogram`] switches it). `finish()`
/// consumes the builder, resolves every subprogram's jump targets, and
/// returns the assembled `Program`.
pub struct ProgramBuilder {
    family: FieldFamily,
    const_pool: Vec<FieldConstEntry>,
    next_signal: u32,
    next_slot: u32,
    subs: Vec<SubInProgress>,
    active: usize,
}

impl ProgramBuilder {
    /// Start a new builder for the given field family. The builder has
    /// one subprogram — the entry (id 0), with no parameters or
    /// returns — and zero registers, signals, slots, constants, or
    /// instructions. Allocate them as you go.
    pub fn new(family: FieldFamily) -> Self {
        Self {
            family,
            const_pool: Vec::new(),
            next_signal: 0,
            next_slot: 0,
            subs: vec![SubInProgress::new(Vec::new(), Vec::new())],
            active: 0,
        }
    }

    #[inline]
    fn cur(&self) -> &SubInProgress {
        // `active` is 0 on construction and only ever set to an index
        // returned by `reserve_subprogram` (always in range), so this
        // index is an internal invariant, not caller-controlled.
        &self.subs[self.active]
    }

    #[inline]
    fn cur_mut(&mut self) -> &mut SubInProgress {
        &mut self.subs[self.active]
    }

    // ── Subprogram management ─────────────────────────────────────────

    /// Reserve a callable subprogram id with the given signature
    /// without building its body yet. The id can be used as the
    /// `func_id` of a [`Self::call`] emitted from any subprogram —
    /// including one built *before* this subprogram's body — so the
    /// lift can emit a call at the point it discovers the callee and
    /// fill in the callee body afterwards. Does not change the active
    /// subprogram.
    pub fn reserve_subprogram(&mut self, params: Vec<RegType>, returns: Vec<RegType>) -> u32 {
        let id = self.subs.len() as u32;
        self.subs.push(SubInProgress::new(params, returns));
        id
    }

    /// Make `id` the active subprogram, returning the previously active
    /// id so the caller can restore it with [`Self::end_subprogram`].
    /// `id` must come from [`Self::reserve_subprogram`] (or be 0, the
    /// entry).
    pub fn begin_subprogram(&mut self, id: u32) -> u32 {
        let prev = self.active as u32;
        debug_assert!((id as usize) < self.subs.len());
        self.active = id as usize;
        prev
    }

    /// Restore the active subprogram to `prev` (the value returned by
    /// the matching [`Self::begin_subprogram`]).
    pub fn end_subprogram(&mut self, prev: u32) {
        debug_assert!((prev as usize) < self.subs.len());
        self.active = prev as usize;
    }

    /// The currently active subprogram id. Subprogram 0 is the entry;
    /// any other id is a reserved callee whose body is being built.
    pub fn active_subprogram(&self) -> u32 {
        self.active as u32
    }

    // ── Namespace allocation ──────────────────────────────────────────

    /// Allocate a fresh register in the active subprogram. Returns a
    /// monotonically increasing index; the subprogram's frame size
    /// grows automatically.
    pub fn alloc_reg(&mut self) -> Reg {
        let r = self.cur().next_reg;
        self.cur_mut().next_reg += 1;
        r
    }

    /// Current register count of the active subprogram — same as its
    /// `next_reg`. The lift uses this as a frame-size proxy when
    /// deciding whether to bail out of a partial unroll attempt.
    pub fn next_reg(&self) -> u32 {
        self.cur().next_reg
    }

    /// Snapshot the active subprogram's emission state so a speculative
    /// attempt (e.g. unrolling a loop) can be rolled back on failure
    /// without leaving partial instructions or register allocations
    /// behind. Restore via [`Self::restore`].
    pub fn snapshot(&self) -> BuilderSnapshot {
        let s = self.cur();
        BuilderSnapshot {
            active: self.active,
            body_len: s.body.len(),
            const_pool_len: self.const_pool.len(),
            next_reg: s.next_reg,
            next_signal: self.next_signal,
            next_slot: self.next_slot,
            label_positions_len: s.label_positions.len(),
            pending_jumps_len: s.pending_jumps.len(),
        }
    }

    /// Roll back to a previously-captured [`BuilderSnapshot`]. All
    /// instructions, constants, labels, and pending jumps emitted
    /// since the snapshot are discarded; id counters revert. The
    /// snapshot must have been taken with the same subprogram active.
    pub fn restore(&mut self, snapshot: BuilderSnapshot) {
        debug_assert_eq!(
            snapshot.active, self.active,
            "snapshot taken under a different active subprogram"
        );
        self.const_pool.truncate(snapshot.const_pool_len);
        self.next_signal = snapshot.next_signal;
        self.next_slot = snapshot.next_slot;
        let s = self.cur_mut();
        s.body.truncate(snapshot.body_len);
        s.next_reg = snapshot.next_reg;
        s.label_positions.truncate(snapshot.label_positions_len);
        s.pending_jumps.truncate(snapshot.pending_jumps_len);
    }

    /// Allocate a fresh input signal id. Signals are only meaningful in
    /// the entry subprogram (the validator rejects signal access
    /// elsewhere). The caller supplies these as the
    /// `signals: &[FieldElement<F>]` slice when invoking the executor.
    pub fn alloc_signal(&mut self) -> u32 {
        let s = self.next_signal;
        self.next_signal += 1;
        s
    }

    /// Allocate a fresh witness slot id. Witness slots are only
    /// meaningful in the entry subprogram. The caller provides a
    /// `witness_slots: &mut [FieldElement<F>]` slice of at least
    /// `slot + 1` elements when invoking the executor.
    pub fn alloc_witness_slot(&mut self) -> u32 {
        let s = self.next_slot;
        self.next_slot += 1;
        s
    }

    /// Intern a constant into the program-global pool and return its
    /// id. `bytes` is little-endian canonical encoding (up to the
    /// field family's max). Smaller values are zero-padded on decode.
    pub fn intern_const(&mut self, bytes: Vec<u8>) -> u32 {
        let id = self.const_pool.len() as u32;
        self.const_pool.push(FieldConstEntry { bytes });
        id
    }

    // ── Raw emission ──────────────────────────────────────────────────

    /// Append a raw instruction to the active subprogram. Prefer the
    /// typed helpers below for common patterns.
    pub fn emit(&mut self, instr: Instr) {
        self.cur_mut().body.push(instr);
    }

    // ── Label mechanism ───────────────────────────────────────────────

    /// Create a new unplaced label in the active subprogram. Labels do
    /// not cross subprogram boundaries.
    pub fn new_label(&mut self) -> Label {
        let s = self.cur_mut();
        let id = s.label_positions.len() as u32;
        s.label_positions.push(None);
        Label(id)
    }

    /// Mark the current position in the active subprogram's stream as
    /// the target of `label`. Call exactly once per label.
    pub fn place(&mut self, label: Label) {
        let s = self.cur_mut();
        let pos = s.body.len() as u32;
        s.label_positions[label.0 as usize] = Some(pos);
    }

    /// Emit an unconditional jump to `label`. The target is left as a
    /// sentinel (0) and patched at `finish()` time.
    pub fn jump_to(&mut self, label: Label) {
        let s = self.cur_mut();
        let instr_index = s.body.len() as u32;
        s.body.push(Instr::Jump { target: 0 });
        s.pending_jumps.push(PendingJump {
            instr_index,
            label: label.0,
        });
    }

    /// Emit a conditional jump to `label`. `cond` must be an Int-typed
    /// register (typically U8 — any non-zero branches).
    pub fn jump_if_to(&mut self, cond: Reg, label: Label) {
        let s = self.cur_mut();
        let instr_index = s.body.len() as u32;
        s.body.push(Instr::JumpIf { cond, target: 0 });
        s.pending_jumps.push(PendingJump {
            instr_index,
            label: label.0,
        });
    }

    // ── High-level emission helpers ───────────────────────────────────

    /// Emit `ReadSignal` and return the destination register. Only
    /// valid in the entry subprogram.
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
    /// Only valid in the entry subprogram.
    pub fn write_witness(&mut self, slot_id: u32, src: Reg) {
        self.emit(Instr::WriteWitness { slot_id, src });
    }

    /// Emit a `Return` with no return values (the entry subprogram, or
    /// a callee that communicates only through arrays).
    pub fn ret(&mut self) {
        self.emit(Instr::Return { srcs: Vec::new() });
    }

    /// Emit a `Return` carrying the given source registers. The count
    /// and categories must match the active subprogram's declared
    /// return list.
    pub fn ret_vals(&mut self, srcs: &[Reg]) {
        self.emit(Instr::Return {
            srcs: srcs.to_vec(),
        });
    }

    /// Emit a `Call` to subprogram `func_id` with `args` (registers in
    /// the active subprogram). One destination register is allocated
    /// per entry in `ret_types`; the destinations are returned in
    /// order. `func_id` is typically a [`Self::reserve_subprogram`]
    /// result.
    pub fn call(&mut self, func_id: u32, args: &[Reg], ret_types: &[RegType]) -> Vec<Reg> {
        let rets: Vec<Reg> = (0..ret_types.len()).map(|_| self.alloc_reg()).collect();
        self.emit(Instr::Call {
            func_id,
            args: args.to_vec(),
            rets: rets.clone(),
        });
        rets
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

    /// `dst (Int U8) = 1 if a < b else 0`, comparing canonical
    /// representatives as unsigned integers in `[0, p)` — field
    /// precision, no fixed-width truncation.
    pub fn fcmplt(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FCmpLt { dst, a, b });
        dst
    }

    /// Truncated unsigned division on the canonical representative.
    /// Both operands are field cells; result is a field cell carrying
    /// `floor(a / b)`. Traps at execute time on `b == 0`.
    pub fn fidiv(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FIDiv { dst, a, b });
        dst
    }

    /// Unsigned remainder on the canonical representative.
    pub fn firem(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FIRem { dst, a, b });
        dst
    }

    /// Right-shift the canonical representative by a compile-time
    /// constant amount (≤ 253).
    pub fn fshr(&mut self, src: Reg, amount: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FShr { dst, src, amount });
        dst
    }

    /// `2 ^ amount` in the field — the field-precision lowering of
    /// circom's `1 << amount`. `amount` is a runtime Field register;
    /// the result is a correct residue for the active backend prime.
    pub fn fpow2(&mut self, amount: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FPow2 { dst, amount });
        dst
    }

    /// AND the canonical representative with a const-pool mask.
    pub fn fand(&mut self, src: Reg, mask_const_id: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FAnd {
            dst,
            src,
            mask_const_id,
        });
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

    /// Read the array handle in `arr` as a U32 int so it can be
    /// stashed in a heap slot across a branch and reconstructed with
    /// [`Self::array_from_id`].
    pub fn array_id(&mut self, arr: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::ArrayId { dst, arr });
        dst
    }

    /// Reconstruct an array handle from a U32 int produced by
    /// [`Self::array_id`]. `elem` must match the original array's
    /// element category.
    pub fn array_from_id(&mut self, id: Reg, elem: ElemT) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::ArrayFromId { dst, id, elem });
        dst
    }

    // ── Finalize ────────────────────────────────────────────────────

    /// Consume the builder and produce a [`Program`], patching every
    /// subprogram's pending jump targets into the byte offsets they
    /// land at. A builder that never reserved a subprogram yields a
    /// single entry subprogram — the same shape `Program::new`
    /// produces. Returns an error if any label was referenced but
    /// never placed.
    pub fn finish(mut self) -> Result<Program, BuilderError> {
        let mut subprograms = Vec::with_capacity(self.subs.len());
        for sub in std::mem::take(&mut self.subs) {
            subprograms.push(Self::resolve_sub(sub)?);
        }
        Ok(Program::from_subprograms(
            self.family,
            std::mem::take(&mut self.const_pool),
            subprograms,
        ))
    }

    /// Resolve one subprogram's pending jumps (instruction index →
    /// byte offset within that subprogram's standalone stream) and
    /// finalize it into a [`Subprogram`].
    fn resolve_sub(mut sub: SubInProgress) -> Result<Subprogram, BuilderError> {
        // Pass 1: byte offset of each instruction index. `encoded_size`
        // depends on the instruction (including its operand list, for
        // the variable-length Call / Return), so walk the final body.
        let mut index_to_offset: Vec<u32> = Vec::with_capacity(sub.body.len() + 1);
        let mut acc: u32 = 0;
        for ins in &sub.body {
            index_to_offset.push(acc);
            acc = acc.saturating_add(ins.encoded_size());
        }
        // Sentinel — offset past the last instruction, in case a label
        // is placed at the very end ("fall through to the end").
        index_to_offset.push(acc);

        // Pass 2: patch pending jumps with the resolved byte offsets.
        for pending in &sub.pending_jumps {
            let target_index = sub
                .label_positions
                .get(pending.label as usize)
                .and_then(|p| *p)
                .ok_or(BuilderError::UnplacedLabel(pending.label))?;
            let target_offset = *index_to_offset
                .get(target_index as usize)
                .ok_or(BuilderError::UnplacedLabel(pending.label))?;
            match sub.body.get_mut(pending.instr_index as usize) {
                Some(Instr::Jump { target }) | Some(Instr::JumpIf { target, .. }) => {
                    *target = target_offset;
                }
                _ => {
                    // The builder only records pending patches for Jump
                    // / JumpIf sites, so any other opcode here means the
                    // body was mutated behind the builder's back.
                    return Err(BuilderError::NonJumpAtPatchSite(pending.instr_index));
                }
            }
        }

        Ok(Subprogram {
            frame_size: sub.next_reg,
            params: std::mem::take(&mut sub.params),
            returns: std::mem::take(&mut sub.returns),
            body: std::mem::take(&mut sub.body),
        })
    }
}

/// Errors that can arise from misuse of the builder API. All of them
/// indicate a bug in the lifting pass; none are expected on correct
/// input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// A label was referenced by [`ProgramBuilder::jump_to`] or
    /// [`ProgramBuilder::jump_if_to`] but never had
    /// [`ProgramBuilder::place`] called on it.
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

    #[test]
    fn builder_reserve_and_call_subprogram() {
        // Entry calls a reserved `square(x)` subprogram. The callee id
        // is handed out before its body exists, so the Call in the
        // entry can reference it; the callee body is filled in after.
        let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
        let sq = b.reserve_subprogram(vec![RegType::Field], vec![RegType::Field]);

        // Entry body (active = 0).
        let x_sig = b.alloc_signal();
        let slot = b.alloc_witness_slot();
        let x = b.read_signal(x_sig);
        let rets = b.call(sq, &[x], &[RegType::Field]);
        b.write_witness(slot, rets[0]);
        b.ret();

        // Callee body: param is register 0.
        let prev = b.begin_subprogram(sq);
        let p = b.fmul(0, 0);
        b.ret_vals(&[p]);
        b.end_subprogram(prev);

        let prog = roundtrip(b.finish().unwrap());
        let mut slots = [FE::zero()];
        run(&prog, &[FE::from_u64(6)], &mut slots);
        assert_eq!(slots[0], FE::from_u64(36));
    }
}
