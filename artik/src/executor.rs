//! Artik interpreter — executes a decoded, validated [`Program`]
//! against a caller-provided [`ArtikContext`].
//!
//! The executor is intentionally minimal. It does not allocate on the
//! heap after setup (arrays are bump-allocated into a single `Vec`,
//! registers live in one flat frame) and it never shares state with
//! the main Achronyme VM. Signals are read-only; witness slots are the
//! only output channel.
//!
//! # Trap model
//!
//! The bytecode validator catches *structural* errors before a program
//! ever reaches the interpreter. The executor only needs to handle
//! *data-dependent* failures:
//!
//! - [`ArtikError::FieldDivByZero`] — `FDiv`/`FInv` on zero.
//! - [`ArtikError::ArrayIndexOutOfBounds`] — dynamic index past `len`.
//! - [`ArtikError::SignalOutOfBounds`] / [`ArtikError::WitnessSlotOutOfBounds`]
//!   — signal or slot index beyond what the caller supplied.
//! - [`ArtikError::UndefinedRegister`] — a read hit a register that had
//!   no prior write on the executed path. (The validator only enforces
//!   category consistency across *writes*; dynamic branches can still
//!   leave a slot unassigned.)
//! - [`ArtikError::ExecTrap`] — explicit [`Instr::Trap`] fires.
//! - [`ArtikError::BudgetExhausted`] — loop guard.
//!
//! All cases abort cleanly; the caller's witness buffer is left in
//! whatever state the partial execution produced. It is the caller's
//! responsibility to discard the proof attempt on any `Err`.

use std::collections::HashMap;

use memory::field::{FieldBackend, FieldElement, PrimeId};

use crate::error::ArtikError;
use crate::header::FieldFamily;
use crate::ir::{ElemT, Instr, IntBinOp, IntW};
use crate::program::Program;

/// Default cap for the interpreter's instruction counter. Chosen large
/// enough for realistic witness programs (one SHA-256 round is ~64
/// instructions; a full block ~4K; a SHA-256 over a 64-byte message
/// fits comfortably under 32K). Callers that need more should use
/// [`execute_with_budget`].
pub const DEFAULT_BUDGET: u64 = 8_000_000;

/// Cumulative cap on array cells allocated across a single
/// [`execute`] call. 16M cells corresponds to ~512 MB for BN-like
/// field arrays (32 B per element) or ~128 MB for U32 arrays. A
/// program can still carve that up across many [`Instr::AllocArray`]
/// calls, but it cannot exceed the sum.
pub const MAX_ARRAY_MEMORY_CELLS: u64 = 1 << 24;

/// Read-only signals + mutable witness slots the Artik program will
/// touch. The executor never reads outside these two slices and never
/// shares them with other callers.
pub struct ArtikContext<'a, F: FieldBackend> {
    pub signals: &'a [FieldElement<F>],
    pub witness_slots: &'a mut [FieldElement<F>],
}

impl<'a, F: FieldBackend> ArtikContext<'a, F> {
    pub fn new(signals: &'a [FieldElement<F>], witness_slots: &'a mut [FieldElement<F>]) -> Self {
        Self {
            signals,
            witness_slots,
        }
    }
}

/// A single register's contents. `Undef` is the initial state for every
/// register; reading it is a trap.
#[derive(Clone)]
enum Cell<F: FieldBackend> {
    Undef,
    Field(FieldElement<F>),
    Int(u64),
    Array(u32),
}

/// An array allocated during execution. Kept width-tagged so the
/// Load/Store semantics are obvious.
enum ArrayBuf<F: FieldBackend> {
    Field(Vec<FieldElement<F>>),
    Int { w: IntW, data: Vec<u64> },
}

impl<F: FieldBackend> ArrayBuf<F> {
    fn len(&self) -> u32 {
        match self {
            Self::Field(v) => v.len() as u32,
            Self::Int { data, .. } => data.len() as u32,
        }
    }
}

/// Run `prog` with the default instruction budget.
pub fn execute<F: FieldBackend>(
    prog: &Program,
    ctx: &mut ArtikContext<'_, F>,
) -> Result<(), ArtikError> {
    execute_with_budget(prog, ctx, DEFAULT_BUDGET)
}

/// Run `prog` and abort after `budget` instructions. Guards against
/// non-terminating loops in malicious or buggy bytecode.
pub fn execute_with_budget<F: FieldBackend>(
    prog: &Program,
    ctx: &mut ArtikContext<'_, F>,
    budget: u64,
) -> Result<(), ArtikError> {
    // Field family compat check — the bytecode declares one family and
    // the caller picks a backend; reject early if they do not match.
    check_family_compat::<F>(prog.header.family)?;

    let mut state = State::<F>::new(prog)?;

    let mut ran: u64 = 0;
    loop {
        if ran >= budget {
            return Err(ArtikError::BudgetExhausted { ran });
        }
        ran += 1;

        // A PC that falls off the end of the program (including an
        // empty body) is a validator gap, not a panic — adversarial
        // bytecode could hit this by omitting the final `Halt`. Surface
        // as `InvalidJumpTarget` so the caller sees a clean error.
        if (state.pc as usize) >= prog.body.len() {
            return Err(ArtikError::InvalidJumpTarget { target: state.pc });
        }
        let instr = &prog.body[state.pc as usize];
        match step(instr, &mut state, ctx, prog)? {
            Flow::Next => state.pc += 1,
            Flow::JumpTo(idx) => state.pc = idx,
            Flow::Halt => return Ok(()),
        }
    }
}

/// Per-step control-flow signal. The interpreter loop in
/// [`execute_with_budget`] consumes this to advance its PC.
enum Flow {
    /// Move to the next instruction (PC += 1).
    Next,
    /// Jump to a resolved instruction index.
    JumpTo(u32),
    /// `Return` fired — exit the loop cleanly.
    Halt,
}

/// Executor state kept across instructions. Registers + arrays + PC +
/// a byte-offset-to-index map that lets us resolve `Jump`/`JumpIf`
/// targets (which are byte offsets in the encoded stream).
struct State<F: FieldBackend> {
    cells: Vec<Cell<F>>,
    arrays: Vec<ArrayBuf<F>>,
    offset_to_index: HashMap<u32, u32>,
    /// Total cells allocated across all arrays so far. Incremented on
    /// every [`Instr::AllocArray`] and checked against
    /// [`MAX_ARRAY_MEMORY_CELLS`] before the allocation is accepted.
    array_cells_used: u64,
    pc: u32,
}

impl<F: FieldBackend> State<F> {
    fn new(prog: &Program) -> Result<Self, ArtikError> {
        // Validator already enforces this, but re-check here so the
        // executor never trusts a caller-built `Program` that bypassed
        // decode. Defense in depth against direct Program construction.
        if prog.frame_size > crate::ir::MAX_FRAME_SIZE {
            return Err(ArtikError::FrameTooLarge {
                frame_size: prog.frame_size,
                max: crate::ir::MAX_FRAME_SIZE,
            });
        }
        let frame = prog.frame_size as usize;
        let mut offset_to_index = HashMap::with_capacity(prog.body.len());
        let mut offset: u32 = 0;
        for (idx, instr) in prog.body.iter().enumerate() {
            offset_to_index.insert(offset, idx as u32);
            offset = offset.saturating_add(instr.encoded_size());
        }
        Ok(Self {
            cells: vec![Cell::Undef; frame],
            arrays: Vec::new(),
            offset_to_index,
            array_cells_used: 0,
            pc: 0,
        })
    }

    fn read_field(&self, reg: u32) -> Result<&FieldElement<F>, ArtikError> {
        match self.cells.get(reg as usize) {
            Some(Cell::Field(v)) => Ok(v),
            Some(Cell::Undef) => Err(ArtikError::UndefinedRegister { reg }),
            Some(_) => Err(ArtikError::WrongCellKind { reg }),
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: self.cells.len() as u32,
            }),
        }
    }

    fn read_int(&self, reg: u32) -> Result<u64, ArtikError> {
        match self.cells.get(reg as usize) {
            Some(Cell::Int(v)) => Ok(*v),
            Some(Cell::Undef) => Err(ArtikError::UndefinedRegister { reg }),
            Some(_) => Err(ArtikError::WrongCellKind { reg }),
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: self.cells.len() as u32,
            }),
        }
    }

    fn read_array(&self, reg: u32) -> Result<u32, ArtikError> {
        match self.cells.get(reg as usize) {
            Some(Cell::Array(h)) => Ok(*h),
            Some(Cell::Undef) => Err(ArtikError::UndefinedRegister { reg }),
            Some(_) => Err(ArtikError::WrongCellKind { reg }),
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: self.cells.len() as u32,
            }),
        }
    }

    fn write(&mut self, reg: u32, cell: Cell<F>) -> Result<(), ArtikError> {
        match self.cells.get_mut(reg as usize) {
            Some(slot) => {
                *slot = cell;
                Ok(())
            }
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: self.cells.len() as u32,
            }),
        }
    }

    fn resolve_jump(&self, target: u32) -> Result<u32, ArtikError> {
        self.offset_to_index
            .get(&target)
            .copied()
            .ok_or(ArtikError::InvalidJumpTarget { target })
    }
}

fn step<F: FieldBackend>(
    instr: &Instr,
    state: &mut State<F>,
    ctx: &mut ArtikContext<'_, F>,
    prog: &Program,
) -> Result<Flow, ArtikError> {
    match instr {
        // ── Control flow ────────────────────────────────────────────
        Instr::Return => Ok(Flow::Halt),
        Instr::Trap { code } => Err(ArtikError::ExecTrap { code: *code }),
        Instr::Jump { target } => Ok(Flow::JumpTo(state.resolve_jump(*target)?)),
        Instr::JumpIf { cond, target } => {
            // Any non-zero in the low byte of the int cell is truthy,
            // matching the `FEq`/`CmpLt`/`CmpEq` encoding of 0 or 1.
            let c = state.read_int(*cond)?;
            if c != 0 {
                Ok(Flow::JumpTo(state.resolve_jump(*target)?))
            } else {
                Ok(Flow::Next)
            }
        }

        // ── Constants & signals ────────────────────────────────────
        Instr::PushConst { dst, const_id } => {
            let entry =
                prog.const_pool
                    .get(*const_id as usize)
                    .ok_or(ArtikError::InvalidConstId {
                        const_id: *const_id,
                    })?;
            let fe = decode_const_fe::<F>(&entry.bytes).ok_or(ArtikError::BadConstBytes {
                const_id: *const_id,
            })?;
            state.write(*dst, Cell::Field(fe))?;
            Ok(Flow::Next)
        }
        Instr::ReadSignal { dst, signal_id } => {
            let fe = ctx.signals.get(*signal_id as usize).copied().ok_or(
                ArtikError::SignalOutOfBounds {
                    signal_id: *signal_id,
                    len: ctx.signals.len() as u32,
                },
            )?;
            state.write(*dst, Cell::Field(fe))?;
            Ok(Flow::Next)
        }
        Instr::WriteWitness { slot_id, src } => {
            let fe = *state.read_field(*src)?;
            let slots_len = ctx.witness_slots.len() as u32;
            let slot = ctx.witness_slots.get_mut(*slot_id as usize).ok_or(
                ArtikError::WitnessSlotOutOfBounds {
                    slot_id: *slot_id,
                    len: slots_len,
                },
            )?;
            *slot = fe;
            Ok(Flow::Next)
        }

        // ── Field ops ──────────────────────────────────────────────
        Instr::FAdd { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            state.write(*dst, Cell::Field(a.add(&b)))?;
            Ok(Flow::Next)
        }
        Instr::FSub { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            state.write(*dst, Cell::Field(a.sub(&b)))?;
            Ok(Flow::Next)
        }
        Instr::FMul { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            state.write(*dst, Cell::Field(a.mul(&b)))?;
            Ok(Flow::Next)
        }
        Instr::FDiv { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            let v = a.div(&b).ok_or(ArtikError::FieldDivByZero)?;
            state.write(*dst, Cell::Field(v))?;
            Ok(Flow::Next)
        }
        Instr::FInv { dst, src } => {
            let s = *state.read_field(*src)?;
            let v = s.inv().ok_or(ArtikError::FieldDivByZero)?;
            state.write(*dst, Cell::Field(v))?;
            Ok(Flow::Next)
        }
        Instr::FEq { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            let out: u64 = if a == b { 1 } else { 0 };
            state.write(*dst, Cell::Int(out))?;
            Ok(Flow::Next)
        }

        // ── Integer ops ────────────────────────────────────────────
        Instr::IBin { op, w, dst, a, b } => {
            let av = state.read_int(*a)?;
            let bv = state.read_int(*b)?;
            let out = apply_bin(*op, *w, av, bv);
            state.write(*dst, Cell::Int(out))?;
            Ok(Flow::Next)
        }
        Instr::INot { w, dst, src } => {
            let v = state.read_int(*src)?;
            let mask = w.mask();
            state.write(*dst, Cell::Int((!v) & mask))?;
            Ok(Flow::Next)
        }
        Instr::Rotl32 { dst, src, n } => {
            let v = state.read_int(*src)? as u32;
            let shift = (state.read_int(*n)? & 31) as u32;
            state.write(*dst, Cell::Int(v.rotate_left(shift) as u64))?;
            Ok(Flow::Next)
        }
        Instr::Rotr32 { dst, src, n } => {
            let v = state.read_int(*src)? as u32;
            let shift = (state.read_int(*n)? & 31) as u32;
            state.write(*dst, Cell::Int(v.rotate_right(shift) as u64))?;
            Ok(Flow::Next)
        }
        Instr::Rotl8 { dst, src, n } => {
            let v = state.read_int(*src)? as u8;
            let shift = (state.read_int(*n)? & 7) as u32;
            state.write(*dst, Cell::Int(v.rotate_left(shift) as u64))?;
            Ok(Flow::Next)
        }

        // ── Conversions ───────────────────────────────────────────
        // `IntFromField` is an unsigned truncation to `width` bits —
        // we take the low 64-bit limb of the canonical representation
        // and mask. For values that fit in `width` bits (typical for
        // SHA-256 u32 signals) this is exact; for full 256-bit field
        // elements it is truncation. Signed interpretation of an I64
        // conversion is the caller's responsibility.
        Instr::IntFromField { w, dst, src } => {
            let fe = *state.read_field(*src)?;
            let limbs = fe.to_canonical();
            state.write(*dst, Cell::Int(limbs[0] & w.mask()))?;
            Ok(Flow::Next)
        }
        // `FieldFromInt` with `I64` treats the raw u64 as a two's
        // complement signed value and maps negative inputs to
        // `p - |v|` via `from_i64`. All other widths zero-extend.
        Instr::FieldFromInt { dst, src, w } => {
            let v = state.read_int(*src)?;
            let fe = match w {
                IntW::I64 => FieldElement::<F>::from_i64(v as i64),
                _ => FieldElement::<F>::from_u64(v & w.mask()),
            };
            state.write(*dst, Cell::Field(fe))?;
            Ok(Flow::Next)
        }

        // ── Arrays ─────────────────────────────────────────────────
        Instr::AllocArray { dst, len, elem } => {
            // Cumulative runtime check: the validator caps each
            // individual `len`, but a loop that allocates many arrays
            // can still add up. Reject the whole execution cleanly.
            let prospective = state.array_cells_used.saturating_add(*len as u64);
            if prospective > MAX_ARRAY_MEMORY_CELLS {
                return Err(ArtikError::ArrayMemoryExceeded {
                    cells: prospective,
                    max: MAX_ARRAY_MEMORY_CELLS,
                });
            }
            state.array_cells_used = prospective;

            let handle = state.arrays.len() as u32;
            let buf = match elem {
                ElemT::Field => ArrayBuf::Field(vec![FieldElement::<F>::zero(); *len as usize]),
                ElemT::IntU8 => ArrayBuf::Int {
                    w: IntW::U8,
                    data: vec![0; *len as usize],
                },
                ElemT::IntU32 => ArrayBuf::Int {
                    w: IntW::U32,
                    data: vec![0; *len as usize],
                },
                ElemT::IntU64 => ArrayBuf::Int {
                    w: IntW::U64,
                    data: vec![0; *len as usize],
                },
                ElemT::IntI64 => ArrayBuf::Int {
                    w: IntW::I64,
                    data: vec![0; *len as usize],
                },
            };
            state.arrays.push(buf);
            state.write(*dst, Cell::Array(handle))?;
            Ok(Flow::Next)
        }
        Instr::LoadArr { dst, arr, idx } => {
            let handle = state.read_array(*arr)?;
            let idx_v = state.read_int(*idx)?;
            let buf = state
                .arrays
                .get(handle as usize)
                .ok_or(ArtikError::WrongCellKind { reg: *arr })?;
            let cell = load_array(buf, idx_v)?;
            state.write(*dst, cell)?;
            Ok(Flow::Next)
        }
        Instr::StoreArr { arr, idx, val } => {
            let handle = state.read_array(*arr)?;
            let idx_v = state.read_int(*idx)?;
            // Defensive lookup: clone the source cell via `.get()`
            // rather than direct indexing so the executor stays
            // non-panicking even if a caller hands it a Program that
            // skipped `decode` / `validate`.
            let src = state
                .cells
                .get(*val as usize)
                .ok_or(ArtikError::RegisterOutOfRange {
                    reg: *val,
                    frame_size: state.cells.len() as u32,
                })?
                .clone();
            let buf = state
                .arrays
                .get_mut(handle as usize)
                .ok_or(ArtikError::WrongCellKind { reg: *arr })?;
            store_array(buf, idx_v, src, *val)?;
            Ok(Flow::Next)
        }
    }
}

fn load_array<F: FieldBackend>(buf: &ArrayBuf<F>, idx: u64) -> Result<Cell<F>, ArtikError> {
    let len = buf.len();
    if idx >= len as u64 {
        return Err(ArtikError::ArrayIndexOutOfBounds { idx, len });
    }
    let i = idx as usize;
    Ok(match buf {
        ArrayBuf::Field(v) => Cell::Field(v[i]),
        ArrayBuf::Int { data, .. } => Cell::Int(data[i]),
    })
}

fn store_array<F: FieldBackend>(
    buf: &mut ArrayBuf<F>,
    idx: u64,
    val: Cell<F>,
    val_reg: u32,
) -> Result<(), ArtikError> {
    let len = buf.len();
    if idx >= len as u64 {
        return Err(ArtikError::ArrayIndexOutOfBounds { idx, len });
    }
    let i = idx as usize;
    match (buf, val) {
        (ArrayBuf::Field(v), Cell::Field(fe)) => {
            v[i] = fe;
            Ok(())
        }
        (ArrayBuf::Int { w, data }, Cell::Int(raw)) => {
            data[i] = raw & w.mask();
            Ok(())
        }
        (_, Cell::Undef) => Err(ArtikError::UndefinedRegister { reg: val_reg }),
        _ => Err(ArtikError::WrongCellKind { reg: val_reg }),
    }
}

/// Apply an [`IntBinOp`] to two width-tagged u64 operands. All ops are
/// wrapping in the given width. `Shl`/`Shr` reduce the shift amount
/// modulo the width (matching Rust's `wrapping_shl` semantics for the
/// underlying primitive type).
fn apply_bin(op: IntBinOp, w: IntW, a: u64, b: u64) -> u64 {
    let mask = w.mask();
    let a = a & mask;
    let b = b & mask;
    match op {
        IntBinOp::Add => a.wrapping_add(b) & mask,
        IntBinOp::Sub => a.wrapping_sub(b) & mask,
        IntBinOp::Mul => a.wrapping_mul(b) & mask,
        IntBinOp::And => (a & b) & mask,
        IntBinOp::Or => (a | b) & mask,
        IntBinOp::Xor => (a ^ b) & mask,
        IntBinOp::Shl => shl_w(w, a, b),
        IntBinOp::Shr => shr_w(w, a, b),
        IntBinOp::CmpLt => {
            // I64 is signed; others unsigned. Boolean result is 0 or 1.
            let lt = match w {
                IntW::I64 => (a as i64) < (b as i64),
                _ => a < b,
            };
            if lt {
                1
            } else {
                0
            }
        }
        IntBinOp::CmpEq => {
            if a == b {
                1
            } else {
                0
            }
        }
    }
}

fn shl_w(w: IntW, a: u64, b: u64) -> u64 {
    match w {
        IntW::U8 => (a as u8).wrapping_shl(b as u32) as u64,
        IntW::U32 => (a as u32).wrapping_shl(b as u32) as u64,
        IntW::U64 => a.wrapping_shl(b as u32),
        IntW::I64 => (a as i64).wrapping_shl(b as u32) as u64,
    }
}

fn shr_w(w: IntW, a: u64, b: u64) -> u64 {
    match w {
        IntW::U8 => (a as u8).wrapping_shr(b as u32) as u64,
        IntW::U32 => (a as u32).wrapping_shr(b as u32) as u64,
        IntW::U64 => a.wrapping_shr(b as u32),
        IntW::I64 => ((a as i64).wrapping_shr(b as u32)) as u64,
    }
}

/// Decode a const-pool entry into a field element. The bytes are
/// stored length-prefixed and zero-padded up to the backend's canonical
/// size (32 bytes for BN-like, 8 for Goldilocks). The backend's
/// `from_le_bytes` requires exactly 32 bytes for its reject-above-p
/// check, so we pad here.
fn decode_const_fe<F: FieldBackend>(bytes: &[u8]) -> Option<FieldElement<F>> {
    let mut buf = [0u8; 32];
    if bytes.len() > 32 {
        return None;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    F::from_le_bytes(&buf).map(FieldElement::<F>::from_repr)
}

/// Reject a mismatch between the bytecode's declared field family and
/// the prime the backend implements. The mapping is: every 254/255/256
/// -bit prime shares `BnLike256`, Goldilocks has its own family, and
/// M31 is reserved for v2.
fn check_family_compat<F: FieldBackend>(declared: FieldFamily) -> Result<(), ArtikError> {
    let expected = match F::PRIME_ID {
        PrimeId::Bn254
        | PrimeId::Bls12_381
        | PrimeId::Grumpkin
        | PrimeId::Pallas
        | PrimeId::Vesta
        | PrimeId::Secp256r1
        | PrimeId::Bls12_377 => FieldFamily::BnLike256,
        PrimeId::Goldilocks => FieldFamily::Goldilocks64,
    };
    if declared == expected {
        Ok(())
    } else {
        Err(ArtikError::FieldFamilyMismatch {
            declared: declared as u8,
            expected: expected as u8,
        })
    }
}

// ============================================================================
// Unit tests — per-opcode semantics + SHA-256 rotation vectors.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{decode, encode};
    use crate::ir::{ElemT, IntBinOp, IntW};
    use crate::program::{FieldConstEntry, Program};
    use memory::field::Bn254Fr;

    type F = Bn254Fr;
    type FE = FieldElement<F>;

    fn run_bn(prog: &Program, signals: &[FE], slots: &mut [FE]) -> Result<(), ArtikError> {
        let mut ctx = ArtikContext::<F>::new(signals, slots);
        execute(prog, &mut ctx)
    }

    fn roundtrip(prog: Program) -> Program {
        let bytes = encode(&prog);
        decode(&bytes, Some(FieldFamily::BnLike256)).expect("decode")
    }

    // ── Field arithmetic ────────────────────────────────────────────

    #[test]
    fn square_signal() {
        // out = signal[0] * signal[0]
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::FMul { dst: 1, a: 0, b: 0 },
            Instr::WriteWitness { slot_id: 0, src: 1 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, Vec::new(), body));
        let sig = [FE::from_u64(7)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(49));
    }

    #[test]
    fn field_add_sub_mul_div() {
        // Push const 6, const 2, compute (6+2)*2 - 6/2 = 13.
        let pool = vec![
            FieldConstEntry { bytes: vec![6] },
            FieldConstEntry { bytes: vec![2] },
        ];
        let body = vec![
            Instr::PushConst {
                dst: 0,
                const_id: 0,
            },
            Instr::PushConst {
                dst: 1,
                const_id: 1,
            },
            Instr::FAdd { dst: 2, a: 0, b: 1 }, // 8
            Instr::FMul { dst: 3, a: 2, b: 1 }, // 16
            Instr::FDiv { dst: 4, a: 0, b: 1 }, // 3
            Instr::FSub { dst: 5, a: 3, b: 4 }, // 13
            Instr::WriteWitness { slot_id: 0, src: 5 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, pool, body));
        let mut slots = [FE::zero()];
        run_bn(&prog, &[], &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(13));
    }

    #[test]
    fn field_div_by_zero_traps() {
        let pool = vec![FieldConstEntry { bytes: vec![0] }];
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::PushConst {
                dst: 1,
                const_id: 0,
            },
            Instr::FDiv { dst: 2, a: 0, b: 1 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 3, pool, body));
        let sig = [FE::from_u64(42)];
        let mut slots = [];
        let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
        assert_eq!(err, ArtikError::FieldDivByZero);
    }

    #[test]
    fn field_eq_produces_boolean_int() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::ReadSignal {
                dst: 1,
                signal_id: 1,
            },
            Instr::FEq { dst: 2, a: 0, b: 1 },
            Instr::FieldFromInt {
                dst: 3,
                src: 2,
                w: IntW::U8,
            },
            Instr::WriteWitness { slot_id: 0, src: 3 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));

        // equal
        let sig = [FE::from_u64(42), FE::from_u64(42)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(1));

        // not equal
        let sig = [FE::from_u64(42), FE::from_u64(41)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::zero());
    }

    // ── Integer arithmetic ─────────────────────────────────────────

    fn int_prog(body: Vec<Instr>, frame_size: u32) -> Program {
        roundtrip(Program::new(
            FieldFamily::BnLike256,
            frame_size,
            Vec::new(),
            body,
        ))
    }

    fn run_int(prog: &Program, sig_u32: u32) -> FE {
        let sig = [FE::from_u64(sig_u32 as u64)];
        let mut slots = [FE::zero()];
        run_bn(prog, &sig, &mut slots).unwrap();
        slots[0]
    }

    #[test]
    fn ibin_u32_add_wraps() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 1,
                src: 0,
            },
            Instr::IBin {
                op: IntBinOp::Add,
                w: IntW::U32,
                dst: 2,
                a: 1,
                b: 1,
            },
            Instr::FieldFromInt {
                dst: 3,
                src: 2,
                w: IntW::U32,
            },
            Instr::WriteWitness { slot_id: 0, src: 3 },
            Instr::Return,
        ];
        let prog = int_prog(body, 4);
        // 0x8000_0000 + 0x8000_0000 == 0 (mod 2^32)
        let out = run_int(&prog, 0x8000_0000);
        assert_eq!(out, FE::zero());
    }

    #[test]
    fn ibin_u8_xor_masks() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U8,
                dst: 1,
                src: 0,
            },
            Instr::IBin {
                op: IntBinOp::Xor,
                w: IntW::U8,
                dst: 2,
                a: 1,
                b: 1,
            },
            Instr::FieldFromInt {
                dst: 3,
                src: 2,
                w: IntW::U8,
            },
            Instr::WriteWitness { slot_id: 0, src: 3 },
            Instr::Return,
        ];
        let prog = int_prog(body, 4);
        let out = run_int(&prog, 0xAB);
        assert_eq!(out, FE::zero());
    }

    #[test]
    fn inot_u32_inverts_low_32_bits() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 1,
                src: 0,
            },
            Instr::INot {
                w: IntW::U32,
                dst: 2,
                src: 1,
            },
            Instr::FieldFromInt {
                dst: 3,
                src: 2,
                w: IntW::U32,
            },
            Instr::WriteWitness { slot_id: 0, src: 3 },
            Instr::Return,
        ];
        let prog = int_prog(body, 4);
        let out = run_int(&prog, 0);
        assert_eq!(out, FE::from_u64(0xFFFF_FFFF));
    }

    #[test]
    fn cmplt_u32_boolean() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 1,
                src: 0,
            },
            Instr::ReadSignal {
                dst: 2,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 3,
                src: 2,
            },
            Instr::IBin {
                op: IntBinOp::CmpLt,
                w: IntW::U32,
                dst: 4,
                a: 1,
                b: 3,
            },
            Instr::FieldFromInt {
                dst: 5,
                src: 4,
                w: IntW::U8,
            },
            Instr::WriteWitness { slot_id: 0, src: 5 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));
        let sig = [FE::from_u64(3), FE::from_u64(7)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(1));
    }

    // ── Rotations (RFC 4634 / SHA-256 ρ₀ sanity vectors) ───────────

    /// Hardware reference: SHA-256 small sigma 0, σ₀(x) = ROTR7(x) ⊕
    /// ROTR18(x) ⊕ SHR3(x). We compute σ₀(0x12345678) two ways — with
    /// Artik rotations and natively — and require them to agree.
    fn sha256_sigma0_native(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[test]
    fn rotr32_matches_native() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 1,
                src: 0,
            },
            Instr::ReadSignal {
                dst: 2,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 3,
                src: 2,
            },
            Instr::Rotr32 {
                dst: 4,
                src: 1,
                n: 3,
            },
            Instr::FieldFromInt {
                dst: 5,
                src: 4,
                w: IntW::U32,
            },
            Instr::WriteWitness { slot_id: 0, src: 5 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));
        let test_values: [(u32, u32); 5] = [
            (0x12345678, 7),
            (0xDEADBEEF, 13),
            (0xFFFFFFFF, 1),
            (0x00000001, 31),
            (0x80000000, 17),
        ];
        for (x, n) in test_values {
            let sig = [FE::from_u64(x as u64), FE::from_u64(n as u64)];
            let mut slots = [FE::zero()];
            run_bn(&prog, &sig, &mut slots).unwrap();
            assert_eq!(
                slots[0],
                FE::from_u64(x.rotate_right(n) as u64),
                "rotr32({x:#010x}, {n}) mismatch"
            );
        }
    }

    #[test]
    fn sha256_sigma0_full_pipeline() {
        // Construct σ₀ from 3 rotations + 2 xors in Artik.
        //
        //   t1 = rotr32(x, 7)
        //   t2 = rotr32(x, 18)
        //   t3 = shr_u32(x, 3)
        //   out = t1 ^ t2 ^ t3
        let body = vec![
            // Read x (sig 0) and decode to u32.
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 1,
                src: 0,
            },
            // Read shift amounts 7, 18, 3 as u32.
            Instr::ReadSignal {
                dst: 2,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 3,
                src: 2,
            },
            Instr::ReadSignal {
                dst: 4,
                signal_id: 2,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 5,
                src: 4,
            },
            Instr::ReadSignal {
                dst: 6,
                signal_id: 3,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 7,
                src: 6,
            },
            Instr::Rotr32 {
                dst: 8,
                src: 1,
                n: 3,
            },
            Instr::Rotr32 {
                dst: 9,
                src: 1,
                n: 5,
            },
            Instr::IBin {
                op: IntBinOp::Shr,
                w: IntW::U32,
                dst: 10,
                a: 1,
                b: 7,
            },
            Instr::IBin {
                op: IntBinOp::Xor,
                w: IntW::U32,
                dst: 11,
                a: 8,
                b: 9,
            },
            Instr::IBin {
                op: IntBinOp::Xor,
                w: IntW::U32,
                dst: 12,
                a: 11,
                b: 10,
            },
            Instr::FieldFromInt {
                dst: 13,
                src: 12,
                w: IntW::U32,
            },
            Instr::WriteWitness {
                slot_id: 0,
                src: 13,
            },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 14, Vec::new(), body));

        for &x in &[
            0x12345678u32,
            0x00000000,
            0xFFFFFFFF,
            0xDEADBEEF,
            0x80000001,
        ] {
            let sig = [
                FE::from_u64(x as u64),
                FE::from_u64(7),
                FE::from_u64(18),
                FE::from_u64(3),
            ];
            let mut slots = [FE::zero()];
            run_bn(&prog, &sig, &mut slots).unwrap();
            let expected = sha256_sigma0_native(x);
            assert_eq!(
                slots[0],
                FE::from_u64(expected as u64),
                "σ₀({x:#010x}) mismatch: got {:?}, want {expected:#010x}",
                slots[0]
            );
        }
    }

    #[test]
    fn rotl8_wraps_modulo_8() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U8,
                dst: 1,
                src: 0,
            },
            Instr::ReadSignal {
                dst: 2,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U8,
                dst: 3,
                src: 2,
            },
            Instr::Rotl8 {
                dst: 4,
                src: 1,
                n: 3,
            },
            Instr::FieldFromInt {
                dst: 5,
                src: 4,
                w: IntW::U8,
            },
            Instr::WriteWitness { slot_id: 0, src: 5 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));
        // rotl8(0xA5, 11) == rotl8(0xA5, 3) since rot wraps mod 8.
        let sig = [FE::from_u64(0xA5), FE::from_u64(11)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        let expected = 0xA5u8.rotate_left(3) as u64;
        assert_eq!(slots[0], FE::from_u64(expected));
    }

    // ── Arrays + loops ─────────────────────────────────────────────

    #[test]
    fn array_allocate_store_load() {
        // arr : Field[2]
        // arr[0] = sig[0]; arr[1] = sig[1];
        // witness[0] = arr[1] + arr[0]
        let body = vec![
            Instr::AllocArray {
                dst: 0,
                len: 2,
                elem: ElemT::Field,
            },
            // idx0 = IntFromField(0)
            Instr::ReadSignal {
                dst: 1,
                signal_id: 2, // sig[2] == 0
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 2,
                src: 1,
            },
            Instr::ReadSignal {
                dst: 3,
                signal_id: 0,
            },
            Instr::StoreArr {
                arr: 0,
                idx: 2,
                val: 3,
            },
            Instr::ReadSignal {
                dst: 4,
                signal_id: 3, // sig[3] == 1
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 5,
                src: 4,
            },
            Instr::ReadSignal {
                dst: 6,
                signal_id: 1,
            },
            Instr::StoreArr {
                arr: 0,
                idx: 5,
                val: 6,
            },
            Instr::LoadArr {
                dst: 7,
                arr: 0,
                idx: 5,
            },
            Instr::LoadArr {
                dst: 8,
                arr: 0,
                idx: 2,
            },
            Instr::FAdd { dst: 9, a: 7, b: 8 },
            Instr::WriteWitness { slot_id: 0, src: 9 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 10, Vec::new(), body));
        let sig = [
            FE::from_u64(7),
            FE::from_u64(35),
            FE::zero(),
            FE::from_u64(1),
        ];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(42));
    }

    #[test]
    fn array_oob_traps() {
        let body = vec![
            Instr::AllocArray {
                dst: 0,
                len: 1,
                elem: ElemT::IntU32,
            },
            // idx 5 via sig
            Instr::ReadSignal {
                dst: 1,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 2,
                src: 1,
            },
            Instr::LoadArr {
                dst: 3,
                arr: 0,
                idx: 2,
            },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));
        let sig = [FE::from_u64(5)];
        let mut slots = [];
        let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
        assert!(matches!(
            err,
            ArtikError::ArrayIndexOutOfBounds { idx: 5, len: 1 }
        ));
    }

    // ── Control flow (jumps, budgets, traps) ───────────────────────

    #[test]
    fn jump_if_taken_and_not_taken() {
        // Two-instruction program is not enough to exercise jumps
        // safely across encoded offsets, so we hand-build a loop-free
        // program: JumpIf skips one FAdd when cond != 0. We rely on
        // knowing the encoded target (by walking the instruction list).
        //
        // Layout:
        //   [0] ReadSignal dst=0 sig=0       ; x
        //   [1] ReadSignal dst=1 sig=1       ; cond
        //   [2] IntFromField U8 dst=2 src=1
        //   [3] FAdd dst=3 a=0 b=0           ; x + x
        //   [4] JumpIf cond=2 target=<off>   ; if cond skip WriteWitness 0
        //   [5] WriteWitness slot=0 src=3
        //   [6] Return
        //
        // If cond==1, we jump past WriteWitness to Return, leaving
        // slot 0 untouched. If cond==0, WriteWitness runs.

        // Compute byte offset of Return (instr 6).
        let lead: Vec<Instr> = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::ReadSignal {
                dst: 1,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U8,
                dst: 2,
                src: 1,
            },
            Instr::FAdd { dst: 3, a: 0, b: 0 },
            Instr::JumpIf {
                cond: 2,
                target: 0, // placeholder
            },
            Instr::WriteWitness { slot_id: 0, src: 3 },
            Instr::Return,
        ];
        let mut offset = 0u32;
        let mut offs = Vec::new();
        for ins in &lead {
            offs.push(offset);
            offset += ins.encoded_size();
        }
        let return_offset = offs[6];

        let mut body = lead;
        if let Instr::JumpIf { target, .. } = &mut body[4] {
            *target = return_offset;
        }

        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));

        // cond = 1 → skip WriteWitness, slot stays at initial value.
        let sig = [FE::from_u64(7), FE::from_u64(1)];
        let mut slots = [FE::from_u64(999)];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(999));

        // cond = 0 → run WriteWitness, slot becomes 14.
        let sig = [FE::from_u64(7), FE::from_u64(0)];
        let mut slots = [FE::from_u64(999)];
        run_bn(&prog, &sig, &mut slots).unwrap();
        assert_eq!(slots[0], FE::from_u64(14));
    }

    #[test]
    fn budget_exhausted_on_tight_loop() {
        // Jump { target = 0 } creates an infinite loop back to the
        // first instruction. Budget must fire with the accurate
        // instructions-ran count.
        let body = vec![
            Instr::Jump { target: 0 },
            Instr::Return, // unreachable
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 0, Vec::new(), body));
        let mut ctx = ArtikContext::<F>::new(&[], &mut []);
        let err = execute_with_budget(&prog, &mut ctx, 10).unwrap_err();
        assert_eq!(err, ArtikError::BudgetExhausted { ran: 10 });
    }

    #[test]
    fn trap_instruction_fires_exec_trap() {
        let body = vec![Instr::Trap { code: 0x01 }, Instr::Return];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 0, Vec::new(), body));
        let err = run_bn(&prog, &[], &mut []).unwrap_err();
        assert_eq!(err, ArtikError::ExecTrap { code: 0x01 });
    }

    #[test]
    fn signal_out_of_bounds_traps() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 10,
            },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), body));
        let sig = [FE::from_u64(1)];
        let mut slots = [];
        let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
        assert_eq!(
            err,
            ArtikError::SignalOutOfBounds {
                signal_id: 10,
                len: 1,
            }
        );
    }

    #[test]
    fn witness_slot_out_of_bounds_traps() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::WriteWitness { slot_id: 5, src: 0 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), body));
        let sig = [FE::from_u64(1)];
        let mut slots = [FE::zero(), FE::zero()];
        let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
        assert_eq!(
            err,
            ArtikError::WitnessSlotOutOfBounds { slot_id: 5, len: 2 }
        );
    }

    // ── Differential-by-proxy: external cryptographic vectors ─────

    /// `FInv` on 7 mod BN254_Fr must match the canonical value used by
    /// iden3 / circom witness calculators. This is the cheapest
    /// credible "differential vs CVM" check we can run without pulling
    /// the external tool in as a dep.
    #[test]
    fn finv_7_matches_external_vector() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::FInv { dst: 1, src: 0 },
            Instr::WriteWitness { slot_id: 0, src: 1 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 2, Vec::new(), body));
        let sig = [FE::from_u64(7)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        let expected = FE::from_decimal_str(
            "3126891838834182174606629392179610726935480628630862049099743455225115499374",
        )
        .unwrap();
        assert_eq!(slots[0], expected);
    }

    /// SHA-256 `Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)` computed
    /// through Artik must match the native composition on u32 inputs.
    #[test]
    fn sha256_ch_function_matches_native() {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 1,
                src: 0,
            },
            Instr::ReadSignal {
                dst: 2,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 3,
                src: 2,
            },
            Instr::ReadSignal {
                dst: 4,
                signal_id: 2,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 5,
                src: 4,
            },
            Instr::IBin {
                op: IntBinOp::And,
                w: IntW::U32,
                dst: 6,
                a: 1,
                b: 3,
            },
            Instr::INot {
                w: IntW::U32,
                dst: 7,
                src: 1,
            },
            Instr::IBin {
                op: IntBinOp::And,
                w: IntW::U32,
                dst: 8,
                a: 7,
                b: 5,
            },
            Instr::IBin {
                op: IntBinOp::Xor,
                w: IntW::U32,
                dst: 9,
                a: 6,
                b: 8,
            },
            Instr::FieldFromInt {
                dst: 10,
                src: 9,
                w: IntW::U32,
            },
            Instr::WriteWitness {
                slot_id: 0,
                src: 10,
            },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 11, Vec::new(), body));

        fn ch(x: u32, y: u32, z: u32) -> u32 {
            (x & y) ^ (!x & z)
        }

        for (x, y, z) in [
            (0x6a09e667u32, 0xbb67ae85, 0x3c6ef372),
            (0xFFFFFFFF, 0x00000000, 0xAAAAAAAA),
            (0x12345678, 0x9ABCDEF0, 0x0F0F0F0F),
        ] {
            let sig = [
                FE::from_u64(x as u64),
                FE::from_u64(y as u64),
                FE::from_u64(z as u64),
            ];
            let mut slots = [FE::zero()];
            run_bn(&prog, &sig, &mut slots).unwrap();
            assert_eq!(
                slots[0],
                FE::from_u64(ch(x, y, z) as u64),
                "Ch({x:#010x},{y:#010x},{z:#010x}) mismatch"
            );
        }
    }

    /// Regression: a program whose final instruction flows to Next
    /// (no Halt/Return) must not panic — it should surface a clean
    /// `InvalidJumpTarget` instead of indexing past the end of
    /// `prog.body`. Discovered by fuzz_artik_exec on adversarial
    /// bytecode that passed validation but omitted the tail Halt.
    #[test]
    fn pc_past_end_returns_error_not_panic() {
        // PushConst 0 then fall off the end — no Halt/Return.
        let prog = roundtrip(Program::new(
            FieldFamily::BnLike256,
            1,
            vec![crate::program::FieldConstEntry { bytes: vec![0u8] }],
            vec![Instr::PushConst {
                dst: 0,
                const_id: 0,
            }],
        ));
        let err = run_bn(&prog, &[], &mut []).unwrap_err();
        assert!(
            matches!(err, ArtikError::InvalidJumpTarget { target: 1 }),
            "expected InvalidJumpTarget, got {err:?}"
        );
    }

    #[test]
    fn undefined_register_read_traps() {
        // r0 never written; WriteWitness reads it.
        let body = vec![Instr::WriteWitness { slot_id: 0, src: 0 }, Instr::Return];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), body));
        let mut slots = [FE::zero()];
        let err = run_bn(&prog, &[], &mut slots).unwrap_err();
        assert_eq!(err, ArtikError::UndefinedRegister { reg: 0 });
    }

    // ── Resource limits (DoS resistance) ───────────────────────────

    #[test]
    fn frame_too_large_rejected_by_validator() {
        // `decode` calls `validate`. A hand-built program declaring a
        // frame of `MAX_FRAME_SIZE + 1` must fail validation.
        use crate::ir::MAX_FRAME_SIZE;
        let body = vec![Instr::Return];
        let prog = Program::new(FieldFamily::BnLike256, MAX_FRAME_SIZE + 1, Vec::new(), body);
        let bytes = encode(&prog);
        let err = decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
        assert!(matches!(
            err,
            ArtikError::FrameTooLarge {
                frame_size,
                max,
            } if frame_size == MAX_FRAME_SIZE + 1 && max == MAX_FRAME_SIZE
        ));
    }

    #[test]
    fn alloc_array_too_large_rejected_by_validator() {
        use crate::ir::MAX_ARRAY_LEN;
        let body = vec![
            Instr::AllocArray {
                dst: 0,
                len: MAX_ARRAY_LEN + 1,
                elem: ElemT::IntU32,
            },
            Instr::Return,
        ];
        let prog = Program::new(FieldFamily::BnLike256, 1, Vec::new(), body);
        let bytes = encode(&prog);
        let err = decode(&bytes, Some(FieldFamily::BnLike256)).unwrap_err();
        assert!(matches!(
            err,
            ArtikError::ArrayTooLarge {
                len,
                max,
            } if len == MAX_ARRAY_LEN + 1 && max == MAX_ARRAY_LEN
        ));
    }

    #[test]
    fn cumulative_array_memory_budget_enforced_at_runtime() {
        // Each AllocArray is below MAX_ARRAY_LEN, but many of them
        // together cross the runtime memory budget. The loop runs
        // until `ArrayMemoryExceeded` fires; without this guard, a
        // malicious bytecode would OOM the host.
        //
        // Layout: a single AllocArray re-executed in a tight loop.
        //   [0] AllocArray dst=0 len=MAX_ARRAY_LEN elem=IntU8
        //   [1] Jump target=0
        let lead = vec![
            Instr::AllocArray {
                dst: 0,
                len: crate::ir::MAX_ARRAY_LEN,
                elem: ElemT::IntU8,
            },
            Instr::Jump { target: 0 },
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), lead));
        let err = run_bn(&prog, &[], &mut []).unwrap_err();
        match err {
            ArtikError::ArrayMemoryExceeded { cells, max } => {
                assert_eq!(max, MAX_ARRAY_MEMORY_CELLS);
                assert!(cells > MAX_ARRAY_MEMORY_CELLS);
            }
            other => panic!("expected ArrayMemoryExceeded, got {other:?}"),
        }
    }

    // ── Extra semantic gaps uncovered during audit ────────────────

    #[test]
    fn shr_i64_is_arithmetic_shift() {
        // A 64-bit bit pattern with the high bit set must sign-extend
        // under right shift in I64 width, matching hardware SAR.
        //
        // Note: `IntFromField` truncates to the low 64 bits of the
        // canonical field representation (documented behavior). Pass
        // the two's-complement bit pattern of -8 as a field element
        // directly; `from_i64(-8)` would NOT round-trip, because the
        // low limb of `p - 8` is not `0xFFFF_FFFF_FFFF_FFF8`.
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::I64,
                dst: 1,
                src: 0,
            },
            Instr::ReadSignal {
                dst: 2,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::I64,
                dst: 3,
                src: 2,
            },
            Instr::IBin {
                op: IntBinOp::Shr,
                w: IntW::I64,
                dst: 4,
                a: 1,
                b: 3,
            },
            Instr::FieldFromInt {
                dst: 5,
                src: 4,
                w: IntW::I64,
            },
            Instr::WriteWitness { slot_id: 0, src: 5 },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 6, Vec::new(), body));

        let neg8_bits: u64 = (-8i64) as u64;
        let sig = [FE::from_u64(neg8_bits), FE::from_u64(1)];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        // SAR on the raw bit pattern produces -4 in two's complement
        // (0xFFFF_FFFF_FFFF_FFFC). `FieldFromInt I64` then maps the
        // negative interpretation back to `p - 4`.
        assert_eq!(slots[0], FE::from_i64(-4));
    }

    #[test]
    fn int_array_store_load_roundtrips_values() {
        // Fill an IntU32 array with [0xAAAA_AAAA, 0x5555_5555] and
        // read them back; the masking in store_array / the width-tag
        // on the buf must not corrupt the value.
        let body = vec![
            Instr::AllocArray {
                dst: 0,
                len: 2,
                elem: ElemT::IntU32,
            },
            // idx0, idx1 from signals 2, 3.
            Instr::ReadSignal {
                dst: 1,
                signal_id: 2,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 2,
                src: 1,
            },
            Instr::ReadSignal {
                dst: 3,
                signal_id: 3,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 4,
                src: 3,
            },
            // val0, val1 from signals 0, 1.
            Instr::ReadSignal {
                dst: 5,
                signal_id: 0,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 6,
                src: 5,
            },
            Instr::ReadSignal {
                dst: 7,
                signal_id: 1,
            },
            Instr::IntFromField {
                w: IntW::U32,
                dst: 8,
                src: 7,
            },
            Instr::StoreArr {
                arr: 0,
                idx: 2,
                val: 6,
            },
            Instr::StoreArr {
                arr: 0,
                idx: 4,
                val: 8,
            },
            // Load back and XOR them so we get a single witness slot.
            Instr::LoadArr {
                dst: 9,
                arr: 0,
                idx: 2,
            },
            Instr::LoadArr {
                dst: 10,
                arr: 0,
                idx: 4,
            },
            Instr::IBin {
                op: IntBinOp::Xor,
                w: IntW::U32,
                dst: 11,
                a: 9,
                b: 10,
            },
            Instr::FieldFromInt {
                dst: 12,
                src: 11,
                w: IntW::U32,
            },
            Instr::WriteWitness {
                slot_id: 0,
                src: 12,
            },
            Instr::Return,
        ];
        let prog = roundtrip(Program::new(FieldFamily::BnLike256, 13, Vec::new(), body));
        let sig = [
            FE::from_u64(0xAAAA_AAAA),
            FE::from_u64(0x5555_5555),
            FE::zero(),
            FE::from_u64(1),
        ];
        let mut slots = [FE::zero()];
        run_bn(&prog, &sig, &mut slots).unwrap();
        // 0xAAAA_AAAA ^ 0x5555_5555 == 0xFFFF_FFFF
        assert_eq!(slots[0], FE::from_u64(0xFFFF_FFFF));
    }
}
