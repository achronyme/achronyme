//! Artik IR — the instruction set for the witness VM.
//!
//! Roughly 25 opcodes, register-based, SSA-style. Each instruction has a
//! fixed layout and is serialized as an opcode tag byte followed by its
//! operands. Operand widths are chosen conservatively (u32 for registers,
//! jump targets, and indices; u16 for small enums/codes) so a single
//! program can cover reasonable circuit sizes without needing dynamic
//! encoding.
//!
//! The IR is intentionally minimal: no GC, no heap, no tagged values at
//! runtime. Type consistency for each register is enforced at validation
//! time by walking the instruction stream.
//!
//! # Static limits
//!
//! The [`MAX_FRAME_SIZE`] and [`MAX_ARRAY_LEN`] constants bound what
//! the validator will accept from a bytecode file. They prevent
//! adversarial programs from forcing the executor to allocate tens of
//! gigabytes before any real work starts.

/// Upper bound on the register frame a single Artik program may
/// declare. Limits worst-case allocation to about `MAX_FRAME_SIZE *
/// size_of::<Cell<F>>()` bytes up front — a few MB on BN-like
/// backends, which comfortably fits Poseidon-16 with hundreds of
/// rounds, SHA-256 compression + message schedule, Pedersen 8×254,
/// and EdDSA verification.
pub const MAX_FRAME_SIZE: u32 = 1 << 16;

/// Upper bound on the length of a single `AllocArray`. Caps one call
/// at ~1M cells. Multiple `AllocArray` calls are then caught by the
/// cumulative runtime limit (see `executor::MAX_ARRAY_MEMORY_CELLS`).
pub const MAX_ARRAY_LEN: u32 = 1 << 20;

/// A register index. Artik uses an SSA-style register file where each
/// register is assigned at most once per function (enforced at the IR
/// emitter, not here). Validation ensures every read sees a prior write
/// with a compatible type.
pub type Reg = u32;

mod types;

pub use types::{ElemT, IntBinOp, IntW, RegType};

/// Opcode tag — the first byte of each encoded instruction.
#[repr(u8)]
pub enum OpTag {
    // Control flow
    Jump = 0x01,
    JumpIf = 0x02,
    Return = 0x03,
    Trap = 0x04,
    Call = 0x05,

    // Constants & signals
    PushConst = 0x10,
    ReadSignal = 0x11,
    WriteWitness = 0x12,

    // Field ops
    FAdd = 0x20,
    FSub = 0x21,
    FMul = 0x22,
    FDiv = 0x23,
    FInv = 0x24,
    FEq = 0x25,
    /// `dst (Field) = floor(a / b)` on the canonical representative.
    /// Operands stay as Field cells; the canonical rep is interpreted
    /// as an unsigned 256-bit integer < p. Traps on `b == 0`.
    FIDiv = 0x26,
    /// `dst (Field) = a mod b` on the canonical representative.
    /// Same operand semantics as FIDiv. Traps on `b == 0`.
    FIRem = 0x27,
    /// `dst (Field) = src >> amount` on the canonical representative.
    /// `amount` is a compile-time constant ≤ 253. Result is always a
    /// valid canonical rep because `(x < p) >> n ≤ x < p`.
    FShr = 0x28,
    /// `dst (Field) = src AND mask`, mask loaded from the const pool.
    /// Result is always a valid canonical rep because `(x < p) AND m ≤ x < p`.
    FAnd = 0x29,
    /// `dst (Field) = 2 ^ amount` in the field (i.e. `(1 << amount) mod
    /// p`), where `amount` is a runtime Field register. Computed by
    /// repeated squaring of the field element `2`, so the result is the
    /// correct residue for the active backend's prime and the work is
    /// bounded by the canonical representative's bit width — no machine
    /// width is involved. This is the field-precision lowering of
    /// circom's `1 << n`, distinct from the fixed-width integer shift
    /// used for 32-bit bit-packing gadgets.
    FPow2 = 0x2A,
    /// `dst (Int U8) = 1 if a < b else 0`, comparing the operands'
    /// canonical representatives as unsigned integers in `[0, p)`.
    /// Field-precision ordered compare — distinct from the fixed-width
    /// `IBin { CmpLt }` used for 32/64-bit gadgets, which truncates
    /// values that legitimately reach `2^64` (e.g. `b[i] + borrow` in
    /// circomlib's bigint `long_sub` at n=64).
    FCmpLt = 0x2B,

    // Integer ops
    IBin = 0x30,
    INot = 0x31,
    Rotl32 = 0x32,
    Rotr32 = 0x33,
    Rotl8 = 0x34,

    // Conversion
    IntFromField = 0x40,
    FieldFromInt = 0x41,

    // Array
    AllocArray = 0x50,
    LoadArr = 0x51,
    StoreArr = 0x52,
    /// `dst (Int U32) = handle index of the array in `arr``. Lets a
    /// branch-merge stash a runtime-selected array handle in a heap
    /// int slot (the array analogue of the scalar slot merge).
    ArrayId = 0x53,
    /// `dst (Array) = the array whose handle index is `id``. Traps if
    /// `id` is not a live handle. Inverse of `ArrayId`.
    ArrayFromId = 0x54,
}

impl OpTag {
    pub const MAX: u8 = 0x55;

    pub fn from_u8(v: u8) -> Option<Self> {
        use OpTag::*;
        match v {
            0x01 => Some(Jump),
            0x02 => Some(JumpIf),
            0x03 => Some(Return),
            0x04 => Some(Trap),
            0x05 => Some(Call),
            0x10 => Some(PushConst),
            0x11 => Some(ReadSignal),
            0x12 => Some(WriteWitness),
            0x20 => Some(FAdd),
            0x21 => Some(FSub),
            0x22 => Some(FMul),
            0x23 => Some(FDiv),
            0x24 => Some(FInv),
            0x25 => Some(FEq),
            0x26 => Some(FIDiv),
            0x27 => Some(FIRem),
            0x28 => Some(FShr),
            0x29 => Some(FAnd),
            0x2A => Some(FPow2),
            0x2B => Some(FCmpLt),
            0x30 => Some(IBin),
            0x31 => Some(INot),
            0x32 => Some(Rotl32),
            0x33 => Some(Rotr32),
            0x34 => Some(Rotl8),
            0x40 => Some(IntFromField),
            0x41 => Some(FieldFromInt),
            0x50 => Some(AllocArray),
            0x51 => Some(LoadArr),
            0x52 => Some(StoreArr),
            0x53 => Some(ArrayId),
            0x54 => Some(ArrayFromId),
            _ => None,
        }
    }
}

/// Artik instruction.
///
/// Stored as an enum in memory (one `u64`+ payload per variant) and
/// serialized compactly with opcode + operand bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instr {
    // ── Control flow ────────────────────────────────────────────────
    Jump {
        target: u32,
    },
    JumpIf {
        cond: Reg,
        target: u32,
    },
    /// Pop the current call frame. `srcs` names the registers in the
    /// returning frame that hold this subprogram's return values; the
    /// executor copies them into the caller's destination registers
    /// recorded at the `Call` site. The entry subprogram has no caller,
    /// so it returns with an empty `srcs` and execution halts.
    Return {
        srcs: Vec<Reg>,
    },
    /// Call subprogram `func_id`. `args` are registers in the calling
    /// frame copied cell-for-cell into the callee's parameter
    /// registers `0..args.len()`; `rets` are registers in the calling
    /// frame that receive the callee's return values on `Return`.
    /// Array cells carry a handle into the program-global array store,
    /// so array arguments and returns cross frames with no backing
    /// copy.
    Call {
        func_id: u32,
        args: Vec<Reg>,
        rets: Vec<Reg>,
    },
    Trap {
        code: u16,
    },

    // ── Constants & signals ────────────────────────────────────────
    PushConst {
        dst: Reg,
        const_id: u32,
    },
    ReadSignal {
        dst: Reg,
        signal_id: u32,
    },
    WriteWitness {
        slot_id: u32,
        src: Reg,
    },

    // ── Field ops ──────────────────────────────────────────────────
    FAdd {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FSub {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FMul {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FDiv {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FInv {
        dst: Reg,
        src: Reg,
    },
    FEq {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FIDiv {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FIRem {
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    FShr {
        dst: Reg,
        src: Reg,
        amount: u32,
    },
    FAnd {
        dst: Reg,
        src: Reg,
        mask_const_id: u32,
    },
    FPow2 {
        dst: Reg,
        amount: Reg,
    },
    FCmpLt {
        dst: Reg,
        a: Reg,
        b: Reg,
    },

    // ── Integer ops ────────────────────────────────────────────────
    IBin {
        op: IntBinOp,
        w: IntW,
        dst: Reg,
        a: Reg,
        b: Reg,
    },
    INot {
        w: IntW,
        dst: Reg,
        src: Reg,
    },
    Rotl32 {
        dst: Reg,
        src: Reg,
        n: Reg,
    },
    Rotr32 {
        dst: Reg,
        src: Reg,
        n: Reg,
    },
    Rotl8 {
        dst: Reg,
        src: Reg,
        n: Reg,
    },

    // ── Conversion ─────────────────────────────────────────────────
    IntFromField {
        w: IntW,
        dst: Reg,
        src: Reg,
    },
    FieldFromInt {
        dst: Reg,
        src: Reg,
        w: IntW,
    },

    // ── Array ──────────────────────────────────────────────────────
    AllocArray {
        dst: Reg,
        len: u32,
        elem: ElemT,
    },
    LoadArr {
        dst: Reg,
        arr: Reg,
        idx: Reg,
    },
    StoreArr {
        arr: Reg,
        idx: Reg,
        val: Reg,
    },
    ArrayId {
        dst: Reg,
        arr: Reg,
    },
    ArrayFromId {
        dst: Reg,
        id: Reg,
        elem: ElemT,
    },
}

impl Instr {
    /// Number of bytes this instruction occupies in the encoded stream,
    /// including its opcode tag. Used by the executor to translate jump
    /// targets (byte offsets) into indices into the decoded `body`.
    pub fn encoded_size(&self) -> u32 {
        match self {
            // tag + u8 count + 4 bytes per return-source register.
            Instr::Return { srcs } => 1 + 1 + 4 * srcs.len() as u32,
            // tag + func_id(4) + u8 arg count + 4·args + u8 ret count
            // + 4·rets.
            Instr::Call { args, rets, .. } => {
                1 + 4 + 1 + 4 * args.len() as u32 + 1 + 4 * rets.len() as u32
            }
            Instr::Trap { .. } => 1 + 2,
            Instr::Jump { .. } => 1 + 4,
            Instr::JumpIf { .. } => 1 + 4 + 4,
            Instr::PushConst { .. } | Instr::ReadSignal { .. } | Instr::WriteWitness { .. } => {
                1 + 4 + 4
            }
            Instr::FInv { .. } | Instr::ArrayId { .. } | Instr::FPow2 { .. } => 1 + 4 + 4,
            Instr::FAdd { .. }
            | Instr::FSub { .. }
            | Instr::FMul { .. }
            | Instr::FDiv { .. }
            | Instr::FEq { .. }
            | Instr::FCmpLt { .. }
            | Instr::FIDiv { .. }
            | Instr::FIRem { .. }
            | Instr::FShr { .. }
            | Instr::FAnd { .. }
            | Instr::Rotl32 { .. }
            | Instr::Rotr32 { .. }
            | Instr::Rotl8 { .. }
            | Instr::LoadArr { .. }
            | Instr::StoreArr { .. } => 1 + 4 + 4 + 4,
            Instr::IBin { .. } => 1 + 1 + 1 + 4 + 4 + 4,
            Instr::INot { .. } | Instr::IntFromField { .. } | Instr::FieldFromInt { .. } => {
                1 + 1 + 4 + 4
            }
            Instr::AllocArray { .. } | Instr::ArrayFromId { .. } => 1 + 1 + 4 + 4,
        }
    }
}
