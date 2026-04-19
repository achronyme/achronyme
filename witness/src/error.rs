//! Error types for Artik bytecode decoding, validation, and execution.

use std::fmt;

/// Errors raised by the Artik subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtikError {
    // ── Decode / validation ─────────────────────────────────────────
    /// The bytecode header is malformed or carries an unsupported tag.
    BadHeader(&'static str),
    /// The bytecode was truncated — a read ran past the end of the buffer.
    UnexpectedEof { needed: usize, remaining: usize },
    /// An opcode tag is out of range.
    UnknownOpcode(u8),
    /// An `IntBinOp` sub-discriminant is out of range.
    UnknownIntBinOp(u8),
    /// An `IntW` tag is out of range.
    UnknownIntWidth(u8),
    /// An `ElemT` tag is out of range.
    UnknownElemTag(u8),
    /// A `FieldFamily` tag is out of range.
    UnknownFieldFamily(u8),
    /// The bytecode's declared field family does not match the executor's.
    FieldFamilyMismatch { declared: u8, expected: u8 },
    /// A jump target is out of bounds or not aligned to an instruction boundary.
    InvalidJumpTarget { target: u32 },
    /// A constant-pool index is out of range.
    InvalidConstId { const_id: u32 },
    /// A field constant exceeds the backend's canonical size.
    ConstTooLarge { len: usize, max: usize },
    /// A register index exceeds the program's declared frame size.
    RegisterOutOfRange { reg: u32, frame_size: u32 },
    /// A register was used with inconsistent type categories (Field vs Int width).
    RegisterTypeConflict { reg: u32 },
    /// The bytecode length declared in the header does not match the body.
    BadBodyLen { declared: u32, actual: usize },
    /// The declared const pool length does not match the body.
    BadConstPoolLen { declared: u32, actual: usize },

    // ── Runtime (executor) ──────────────────────────────────────────
    /// A `PushConst` referenced bytes that could not be decoded as a
    /// canonical field element for the active backend (e.g. the value
    /// is >= modulus, or a Goldilocks entry has non-zero bytes above
    /// the low 8).
    BadConstBytes { const_id: u32 },
    /// A `Trap` opcode fired during execution.
    ExecTrap { code: u16 },
    /// A read reached a register that was never written.
    UndefinedRegister { reg: u32 },
    /// A read expected a different cell category than what is stored —
    /// e.g. a field op reading from an int register. Indicates a
    /// validator gap; execution aborts before corrupting state.
    WrongCellKind { reg: u32 },
    /// `FDiv` or `FInv` on zero.
    FieldDivByZero,
    /// `ReadSignal` referenced a signal index the caller did not provide.
    SignalOutOfBounds { signal_id: u32, len: u32 },
    /// `WriteWitness` referenced a slot index the caller did not provide.
    WitnessSlotOutOfBounds { slot_id: u32, len: u32 },
    /// `LoadArr` / `StoreArr` saw an index >= the array length.
    ArrayIndexOutOfBounds { idx: u64, len: u32 },
    /// The interpreter executed more instructions than the caller's
    /// budget allowed. Guards against non-terminating loops.
    BudgetExhausted,
}

impl fmt::Display for ArtikError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHeader(why) => write!(f, "Artik bad header: {why}"),
            Self::UnexpectedEof { needed, remaining } => write!(
                f,
                "Artik truncated bytecode: needed {needed} bytes, had {remaining}"
            ),
            Self::UnknownOpcode(t) => write!(f, "Artik unknown opcode tag: {t}"),
            Self::UnknownIntBinOp(t) => write!(f, "Artik unknown int binop: {t}"),
            Self::UnknownIntWidth(t) => write!(f, "Artik unknown int width: {t}"),
            Self::UnknownElemTag(t) => write!(f, "Artik unknown element tag: {t}"),
            Self::UnknownFieldFamily(t) => write!(f, "Artik unknown field family: {t}"),
            Self::FieldFamilyMismatch { declared, expected } => write!(
                f,
                "Artik field family mismatch: bytecode={declared}, backend={expected}"
            ),
            Self::InvalidJumpTarget { target } => {
                write!(f, "Artik invalid jump target: {target}")
            }
            Self::InvalidConstId { const_id } => {
                write!(f, "Artik invalid const id: {const_id}")
            }
            Self::ConstTooLarge { len, max } => {
                write!(f, "Artik const too large: {len} bytes, max {max}")
            }
            Self::RegisterOutOfRange { reg, frame_size } => write!(
                f,
                "Artik register out of range: r{reg} >= frame_size {frame_size}"
            ),
            Self::RegisterTypeConflict { reg } => {
                write!(f, "Artik register type conflict on r{reg}")
            }
            Self::BadBodyLen { declared, actual } => write!(
                f,
                "Artik body length mismatch: header says {declared}, body has {actual}"
            ),
            Self::BadConstPoolLen { declared, actual } => write!(
                f,
                "Artik const pool length mismatch: header says {declared}, pool has {actual}"
            ),
            Self::BadConstBytes { const_id } => {
                write!(
                    f,
                    "Artik const #{const_id} is not a canonical field element"
                )
            }
            Self::ExecTrap { code } => {
                write!(f, "Artik trap fired with code {code:#06x}")
            }
            Self::UndefinedRegister { reg } => {
                write!(f, "Artik read of undefined register r{reg}")
            }
            Self::WrongCellKind { reg } => {
                write!(f, "Artik register r{reg} holds a value of the wrong kind")
            }
            Self::FieldDivByZero => write!(f, "Artik field division by zero"),
            Self::SignalOutOfBounds { signal_id, len } => write!(
                f,
                "Artik signal {signal_id} out of bounds: caller provided {len} signal(s)"
            ),
            Self::WitnessSlotOutOfBounds { slot_id, len } => write!(
                f,
                "Artik witness slot {slot_id} out of bounds: caller provided {len} slot(s)"
            ),
            Self::ArrayIndexOutOfBounds { idx, len } => {
                write!(f, "Artik array index {idx} out of bounds: length {len}")
            }
            Self::BudgetExhausted => {
                write!(f, "Artik execution budget exhausted")
            }
        }
    }
}

impl std::error::Error for ArtikError {}
