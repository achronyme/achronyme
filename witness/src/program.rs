//! `Program` — the decoded Artik bytecode unit: header + const pool + body.

use crate::header::{ArtikHeader, FieldFamily};
use crate::ir::Instr;

/// A constant in the pool. Stored as length-prefixed little-endian
/// bytes in the serialized form; at runtime each `FieldBackend`
/// decodes its entry via `F::from_le_bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldConstEntry {
    pub bytes: Vec<u8>,
}

/// A fully-decoded Artik program. After `Program::decode` + validation,
/// it is safe to hand to an executor.
#[derive(Debug, Clone)]
pub struct Program {
    pub header: ArtikHeader,
    pub const_pool: Vec<FieldConstEntry>,
    pub frame_size: u32,
    pub body: Vec<Instr>,
}

impl Program {
    /// Construct an unvalidated program. Callers should typically use
    /// [`encode`](crate::bytecode::encode) + [`decode`](crate::bytecode::decode)
    /// rather than constructing `Program` directly, because `decode`
    /// runs the bytecode validator.
    pub fn new(
        family: FieldFamily,
        frame_size: u32,
        const_pool: Vec<FieldConstEntry>,
        body: Vec<Instr>,
    ) -> Self {
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
            body,
        }
    }
}
