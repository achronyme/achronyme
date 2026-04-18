//! Error types for Artik bytecode decoding, validation, and execution.

use std::fmt;

/// Errors raised by the Artik subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtikError {
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
        }
    }
}

impl std::error::Error for ArtikError {}
