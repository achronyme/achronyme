//! Lysis error type.
//!
//! Single enum covering the whole pipeline (decode → validate →
//! execute) rather than a per-phase split, matching the pattern
//! established by `artik::ArtikError`. Variants are grouped below by
//! phase for readability, but the public surface is one flat enum so
//! the caller matches the error wherever it surfaces.

use memory::FieldFamily;

/// All error paths produced by Lysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LysisError {
    // -----------------------------------------------------------------
    // Decode / header errors
    // -----------------------------------------------------------------
    /// The input is shorter than some decoding step required.
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
    /// An opcode byte does not match any known [`crate::bytecode::Opcode`].
    UnknownOpcode { code: u8, at_offset: u32 },
    /// A const pool entry has an unrecognized tag byte.
    UnknownConstPoolTag { tag: u8, at_entry: u32 },
    /// A const pool field constant has more bytes than the declared
    /// family allows.
    ConstTooLarge {
        at_entry: u32,
        got: usize,
        max: usize,
    },
    /// A `LoadInput` visibility byte is not `0` (public) or `1` (witness).
    BadVisibility { at_offset: u32, got: u8 },
    /// The declared `body_len` in the header does not match the number
    /// of bytes remaining after the const pool.
    BodyLenMismatch { declared: u32, actual: u32 },

    // -----------------------------------------------------------------
    // Validator errors — see RFC §4.5
    // -----------------------------------------------------------------
    /// A generic structural-invariant violation. `rule` is the RFC §4.5
    /// rule number (1-indexed, 1–11); `location` is the byte offset in
    /// the body where the check failed, or 0 if global.
    ValidationFailed {
        rule: u8,
        location: u32,
        detail: &'static str,
    },
    /// Rule 4: `LoadConst idx` is out of range.
    ConstIdxOutOfRange { at_offset: u32, idx: u32, len: u32 },
    /// Rule 5: `LoadCapture idx` is out of range.
    CaptureIdxOutOfRange { at_offset: u32, idx: u32, len: u32 },
    /// Rule 6: a `Jump`/`JumpIf` target does not land on an opcode
    /// boundary inside the current template body.
    BadJumpTarget { at_offset: u32, target_offset: i64 },
    /// Rule 7: `InstantiateTemplate` references an unknown template id.
    UndefinedTemplate { at_offset: u32, template_id: u16 },
    /// Rule 8: a register index exceeds the frame size.
    RegisterOutOfRange {
        at_offset: u32,
        reg: u8,
        frame_size: u32,
    },
    /// Rule 9: a register was read before being written.
    UninitializedRegister { at_offset: u32, reg: u8 },
    /// Rule 10: a code path does not reach a `Return`/`Halt`.
    UnreachableReturn { at_offset: u32 },
    /// Rule 11: the call graph has a cycle (self-loop or SCC > 1).
    CircularTemplateCall { template_id: u16 },
    /// Rule 11: the longest `InstantiateTemplate` chain exceeds
    /// `LysisConfig.max_call_depth`.
    MaxCallDepthExceeded { longest: u32, max: u32 },

    // -----------------------------------------------------------------
    // Execute errors
    // -----------------------------------------------------------------
    /// The executor hit an explicit `Trap` opcode.
    Trap { code: u8, at_offset: u32 },
    /// Instruction budget exhausted.
    BudgetExhausted { ran: u64, budget: u64 },
    /// The call stack exceeded `max_call_depth` at runtime.
    CallStackOverflow { depth: u32, max: u32 },
    /// A captures slice shorter than the program declared was passed
    /// to [`crate::execute`].
    MissingCaptures { needed: usize, provided: usize },
    /// A register read returned `None` (ran before write). Validator
    /// rule 9 should catch this statically; this is the runtime
    /// safety net.
    ReadUndefinedRegister { reg: u8, at_offset: u32 },
}

impl std::fmt::Display for LysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof { needed, remaining } => {
                write!(f, "lysis: unexpected eof (needed {needed}, got {remaining})")
            }
            Self::BadMagic { found } => {
                write!(f, "lysis: bad magic (expected \"LYSI\", got {found:02x?})")
            }
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "lysis: unsupported version {found} (expected {expected})"
                )
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
            Self::UnknownOpcode { code, at_offset } => {
                write!(f, "lysis: unknown opcode {code:#04x} at body offset {at_offset}")
            }
            Self::UnknownConstPoolTag { tag, at_entry } => {
                write!(f, "lysis: unknown const pool tag {tag:#04x} at entry {at_entry}")
            }
            Self::ConstTooLarge { at_entry, got, max } => write!(
                f,
                "lysis: const pool entry {at_entry} is {got} bytes (max {max} for declared field family)"
            ),
            Self::BadVisibility { at_offset, got } => {
                write!(f, "lysis: bad visibility byte {got:#04x} at body offset {at_offset}")
            }
            Self::BodyLenMismatch { declared, actual } => write!(
                f,
                "lysis: body_len mismatch (header declares {declared}, got {actual} bytes after const pool)"
            ),
            Self::ValidationFailed { rule, location, detail } => {
                write!(f, "lysis: validation rule {rule} failed at offset {location}: {detail}")
            }
            Self::ConstIdxOutOfRange { at_offset, idx, len } => write!(
                f,
                "lysis: const pool index {idx} out of range (pool has {len} entries) at offset {at_offset}"
            ),
            Self::CaptureIdxOutOfRange { at_offset, idx, len } => write!(
                f,
                "lysis: capture index {idx} out of range (got {len} captures) at offset {at_offset}"
            ),
            Self::BadJumpTarget { at_offset, target_offset } => write!(
                f,
                "lysis: jump from offset {at_offset} to target {target_offset} does not land on an opcode boundary in the same template"
            ),
            Self::UndefinedTemplate { at_offset, template_id } => write!(
                f,
                "lysis: InstantiateTemplate at offset {at_offset} references undefined template_id {template_id}"
            ),
            Self::RegisterOutOfRange { at_offset, reg, frame_size } => write!(
                f,
                "lysis: register r{reg} at offset {at_offset} >= frame_size {frame_size}"
            ),
            Self::UninitializedRegister { at_offset, reg } => {
                write!(f, "lysis: register r{reg} read before written at offset {at_offset}")
            }
            Self::UnreachableReturn { at_offset } => {
                write!(f, "lysis: unreachable code past offset {at_offset}: no Return/Halt on some path")
            }
            Self::CircularTemplateCall { template_id } => write!(
                f,
                "lysis: template {template_id} is part of a cycle in the call graph"
            ),
            Self::MaxCallDepthExceeded { longest, max } => write!(
                f,
                "lysis: longest template-call chain {longest} exceeds max_call_depth {max}"
            ),
            Self::Trap { code, at_offset } => {
                write!(f, "lysis: trap {code:#04x} at offset {at_offset}")
            }
            Self::BudgetExhausted { ran, budget } => {
                write!(f, "lysis: budget exhausted after {ran} instructions (budget {budget})")
            }
            Self::CallStackOverflow { depth, max } => {
                write!(f, "lysis: call stack depth {depth} exceeded max {max}")
            }
            Self::MissingCaptures { needed, provided } => write!(
                f,
                "lysis: need {needed} captures, only {provided} provided"
            ),
            Self::ReadUndefinedRegister { reg, at_offset } => {
                write!(f, "lysis: read undefined register r{reg} at offset {at_offset}")
            }
        }
    }
}

impl std::error::Error for LysisError {}
