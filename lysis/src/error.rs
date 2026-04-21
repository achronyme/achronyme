//! Lysis error type.
//!
//! Phase 0 covers only header-level errors; bytecode, validator, and
//! executor variants land in subsequent phases.

use artik::FieldFamily;

/// All error paths produced by Lysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LysisError {
    /// The input is shorter than the header requires.
    UnexpectedEof { needed: usize, remaining: usize },
    /// The magic bytes are not `LYSI`.
    BadMagic { found: [u8; 4] },
    /// The header version tag is not [`crate::header::VERSION`].
    UnsupportedVersion { found: u16, expected: u16 },
    /// The field family tag is not a known `FieldFamily` discriminant.
    UnknownFieldFamily { tag: u8 },
    /// The declared family mismatches the runtime `FieldBackend`.
    FieldFamilyMismatch {
        declared: FieldFamily,
        expected: FieldFamily,
    },
    /// A reserved flag bit was set.
    ReservedFlagSet { flags: u8 },
}

impl std::fmt::Display for LysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof { needed, remaining } => {
                write!(f, "lysis: unexpected eof (needed {needed}, got {remaining})")
            }
            Self::BadMagic { found } => write!(
                f,
                "lysis: bad magic (expected \"LYSI\", got {found:02x?})"
            ),
            Self::UnsupportedVersion { found, expected } => {
                write!(f, "lysis: unsupported version {found} (expected {expected})")
            }
            Self::UnknownFieldFamily { tag } => {
                write!(f, "lysis: unknown field family tag {tag:#04x}")
            }
            Self::FieldFamilyMismatch { declared, expected } => write!(
                f,
                "lysis: field family mismatch (bytecode declares {declared:?}, runtime expects {expected:?})"
            ),
            Self::ReservedFlagSet { flags } => {
                write!(f, "lysis: reserved flag bits set in {flags:#010b}")
            }
        }
    }
}

impl std::error::Error for LysisError {}
