//! `Program` — the decoded Artik bytecode unit: header + shared const
//! pool + one or more subprograms.
//!
//! A program is a list of [`Subprogram`]s sharing a single constant
//! pool. Subprogram 0 is the entry: it is the only one that may touch
//! signals / witness slots and it takes no parameters and returns no
//! values (it communicates exclusively through `WriteWitness`). Every
//! other subprogram is a callable lifted from a circom function: it has
//! a parameter list, a return list, its own register frame, and its own
//! instruction stream with subprogram-local jump offsets.

use memory::FieldFamily;

use crate::header::ArtikHeader;
use crate::ir::{Instr, RegType};

/// A constant in the pool. Stored as length-prefixed little-endian
/// bytes in the serialized form; at runtime each `FieldBackend`
/// decodes its entry via `F::from_le_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldConstEntry {
    pub bytes: Vec<u8>,
}

/// One callable unit. Its `body` is a standalone instruction stream:
/// `Jump` / `JumpIf` targets are byte offsets relative to this
/// subprogram's own start (offset 0), independent of where the
/// subprogram lands in the encoded program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subprogram {
    /// Register frame this subprogram needs. Each call activation gets
    /// a fresh frame of this size.
    pub frame_size: u32,
    /// Parameter register types, bound to registers `0..params.len()`
    /// of a fresh frame in call order.
    pub params: Vec<RegType>,
    /// Return value types. A `Return { srcs }` in this subprogram must
    /// carry exactly `returns.len()` sources with matching categories.
    pub returns: Vec<RegType>,
    pub body: Vec<Instr>,
}

/// A fully-decoded Artik program. After `decode` + validation it is
/// safe to hand to an executor.
#[derive(Debug, Clone)]
pub struct Program {
    pub header: ArtikHeader,
    pub const_pool: Vec<FieldConstEntry>,
    /// Frame size of the entry subprogram. Mirrors
    /// `subprograms[entry].frame_size`; kept as a top-level field so
    /// callers that only build and run a single-subprogram program do
    /// not need to know about the subprogram list.
    pub frame_size: u32,
    pub subprograms: Vec<Subprogram>,
    /// Index of the entry subprogram. Always 0 in practice; kept
    /// explicit so the executor never hard-codes the assumption.
    pub entry: usize,
}

impl Program {
    /// Construct an unvalidated single-subprogram program. This is the
    /// shape every current producer (the builder's `finish`, the circom
    /// witness lift, the ir / zkc evaluators) emits: one entry
    /// subprogram, no parameters, no returns, signals + witness slots
    /// addressed directly.
    ///
    /// Callers should typically round-trip through
    /// [`encode`](crate::bytecode::encode) +
    /// [`decode`](crate::bytecode::decode) rather than constructing
    /// `Program` directly, because `decode` runs the bytecode validator.
    pub fn new(
        family: FieldFamily,
        frame_size: u32,
        const_pool: Vec<FieldConstEntry>,
        body: Vec<Instr>,
    ) -> Self {
        Self::from_subprograms(
            family,
            const_pool,
            vec![Subprogram {
                frame_size,
                params: Vec::new(),
                returns: Vec::new(),
                body,
            }],
        )
    }

    /// Construct an unvalidated multi-subprogram program. Subprogram 0
    /// is the entry. `frame_size` mirrors the entry's frame.
    pub fn from_subprograms(
        family: FieldFamily,
        const_pool: Vec<FieldConstEntry>,
        subprograms: Vec<Subprogram>,
    ) -> Self {
        let entry = 0;
        let frame_size = subprograms.first().map(|s| s.frame_size).unwrap_or(0);
        Self {
            header: ArtikHeader {
                version: crate::header::VERSION,
                family,
                flags: 0,
                // Lengths are filled in by the encoder.
                const_pool_len: 0,
                body_len: 0,
                frame_size,
            },
            const_pool,
            frame_size,
            subprograms,
            entry,
        }
    }

    /// The entry subprogram (subprogram 0).
    pub fn entry_subprogram(&self) -> &Subprogram {
        &self.subprograms[self.entry]
    }
}
