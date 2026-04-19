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

/// A register index. Artik uses an SSA-style register file where each
/// register is assigned at most once per function (enforced at the IR
/// emitter, not here). Validation ensures every read sees a prior write
/// with a compatible type.
pub type Reg = u32;

/// Integer width for bit-exact ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntW {
    U8 = 0,
    U32 = 1,
    U64 = 2,
    I64 = 3,
}

impl IntW {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::U8),
            1 => Some(Self::U32),
            2 => Some(Self::U64),
            3 => Some(Self::I64),
            _ => None,
        }
    }

    /// Mask applied to wrapping arithmetic outputs in this width.
    pub fn mask(self) -> u64 {
        match self {
            Self::U8 => 0xFF,
            Self::U32 => 0xFFFF_FFFF,
            Self::U64 | Self::I64 => u64::MAX,
        }
    }
}

/// Element type for arrays allocated inside Artik.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ElemT {
    Field = 0,
    IntU8 = 1,
    IntU32 = 2,
    IntU64 = 3,
    IntI64 = 4,
}

impl ElemT {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Field),
            1 => Some(Self::IntU8),
            2 => Some(Self::IntU32),
            3 => Some(Self::IntU64),
            4 => Some(Self::IntI64),
            _ => None,
        }
    }
}

/// Type category carried by a register. Validation tracks one of these
/// per register and rejects reuse with a different category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegType {
    Field,
    Int(IntW),
    /// Handle to an array. `elem` is the element category; registers of
    /// this type cannot participate in field/int arithmetic.
    Array(ElemT),
}

/// Integer binary operation subcategory. Used with `Instr::IBin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IntBinOp {
    Add = 0,
    Sub = 1,
    Mul = 2,
    And = 3,
    Or = 4,
    Xor = 5,
    Shl = 6,
    Shr = 7,
    CmpLt = 8,
    CmpEq = 9,
}

impl IntBinOp {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Add),
            1 => Some(Self::Sub),
            2 => Some(Self::Mul),
            3 => Some(Self::And),
            4 => Some(Self::Or),
            5 => Some(Self::Xor),
            6 => Some(Self::Shl),
            7 => Some(Self::Shr),
            8 => Some(Self::CmpLt),
            9 => Some(Self::CmpEq),
            _ => None,
        }
    }

    /// Does this op produce a boolean (0 or 1) regardless of operand width?
    pub fn is_boolean(self) -> bool {
        matches!(self, Self::CmpLt | Self::CmpEq)
    }
}

/// Opcode tag — the first byte of each encoded instruction.
#[repr(u8)]
pub enum OpTag {
    // Control flow
    Jump = 0x01,
    JumpIf = 0x02,
    Return = 0x03,
    Trap = 0x04,

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
}

impl OpTag {
    pub const MAX: u8 = 0x52;

    pub fn from_u8(v: u8) -> Option<Self> {
        use OpTag::*;
        match v {
            0x01 => Some(Jump),
            0x02 => Some(JumpIf),
            0x03 => Some(Return),
            0x04 => Some(Trap),
            0x10 => Some(PushConst),
            0x11 => Some(ReadSignal),
            0x12 => Some(WriteWitness),
            0x20 => Some(FAdd),
            0x21 => Some(FSub),
            0x22 => Some(FMul),
            0x23 => Some(FDiv),
            0x24 => Some(FInv),
            0x25 => Some(FEq),
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
    Return,
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
}

impl Instr {
    /// Number of bytes this instruction occupies in the encoded stream,
    /// including its opcode tag. Used by the executor to translate jump
    /// targets (byte offsets) into indices into the decoded `body`.
    pub fn encoded_size(&self) -> u32 {
        match self {
            Instr::Return => 1,
            Instr::Trap { .. } => 1 + 2,
            Instr::Jump { .. } => 1 + 4,
            Instr::JumpIf { .. } => 1 + 4 + 4,
            Instr::PushConst { .. } | Instr::ReadSignal { .. } | Instr::WriteWitness { .. } => {
                1 + 4 + 4
            }
            Instr::FInv { .. } => 1 + 4 + 4,
            Instr::FAdd { .. }
            | Instr::FSub { .. }
            | Instr::FMul { .. }
            | Instr::FDiv { .. }
            | Instr::FEq { .. }
            | Instr::Rotl32 { .. }
            | Instr::Rotr32 { .. }
            | Instr::Rotl8 { .. }
            | Instr::LoadArr { .. }
            | Instr::StoreArr { .. } => 1 + 4 + 4 + 4,
            Instr::IBin { .. } => 1 + 1 + 1 + 4 + 4 + 4,
            Instr::INot { .. } | Instr::IntFromField { .. } | Instr::FieldFromInt { .. } => {
                1 + 1 + 4 + 4
            }
            Instr::AllocArray { .. } => 1 + 1 + 4 + 4,
        }
    }
}
