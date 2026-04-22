//! `Program<F>` — the decoded, validated, ready-to-execute shape of
//! a Lysis bytecode.
//!
//! `Program` is produced by [`crate::bytecode::decode`] (which itself
//! calls [`crate::bytecode::validate`] before returning) and consumed
//! by [`crate::execute`]. Once you hold a `Program` you can trust
//! every structural invariant from RFC §4.5 — that's the contract the
//! decoder-validator pair enforces.

use memory::field::{Bn254Fr, FieldBackend};

use crate::bytecode::ConstPool;
use crate::bytecode::Opcode;
use crate::header::LysisHeader;

/// Metadata for a template body registered via `DefineTemplate`.
///
/// `body_offset` + `body_len` slice into the program's body stream
/// (byte offsets). The validator checks that the slice is within
/// bounds and aligned to opcode boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template {
    pub id: u16,
    pub frame_size: u8,
    pub n_params: u8,
    pub body_offset: u32,
    pub body_len: u32,
}

/// One decoded instruction, with the byte offset it occupied in the
/// original encoded body kept alongside the opcode. The offset is
/// needed for jump-target validation (rule 6), error messages, and
/// the executor's `offset -> index` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instr {
    pub opcode: Opcode,
    pub offset: u32,
}

/// Decoded Lysis program: header, interned const pool, template
/// table, and a linear body. Every well-formedness invariant from
/// RFC §4.5 holds when a `Program` is produced by the public
/// [`crate::bytecode::decode`] path.
#[derive(Debug, Clone)]
pub struct Program<F: FieldBackend = Bn254Fr> {
    pub header: LysisHeader,
    pub const_pool: ConstPool<F>,
    pub templates: Vec<Template>,
    pub body: Vec<Instr>,
}

impl<F: FieldBackend> Program<F> {
    /// Lookup a template by id. Returns `None` if the id was never
    /// declared via `DefineTemplate`; the validator guarantees no
    /// `InstantiateTemplate` references an unknown id, so this is
    /// primarily a helper for disassembly / debug.
    pub fn template(&self, id: u16) -> Option<&Template> {
        self.templates.iter().find(|t| t.id == id)
    }

    /// Number of instructions in the body stream.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// `true` if the program has no instructions.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Map a byte offset in the encoded body back to the instruction
    /// index in `self.body`. Returns `None` for offsets that do not
    /// land on an opcode boundary.
    ///
    /// Linear scan — fine for validator usage where it's called a
    /// small number of times per program. The executor builds a
    /// one-shot `HashMap<offset, idx>` from the same data.
    pub fn instr_at_offset(&self, offset: u32) -> Option<usize> {
        self.body.iter().position(|i| i.offset == offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::LysisHeader;
    use artik::FieldFamily;

    fn empty_program() -> Program<Bn254Fr> {
        Program {
            header: LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0),
            const_pool: ConstPool::new(FieldFamily::BnLike256),
            templates: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn empty_program_is_empty() {
        let p = empty_program();
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn template_lookup_by_id() {
        let mut p = empty_program();
        p.templates.push(Template {
            id: 7,
            frame_size: 16,
            n_params: 2,
            body_offset: 0,
            body_len: 10,
        });
        assert_eq!(p.template(7).map(|t| t.id), Some(7));
        assert!(p.template(9).is_none());
    }

    #[test]
    fn instr_at_offset_is_linear_lookup() {
        let mut p = empty_program();
        p.body.push(Instr {
            opcode: Opcode::Halt,
            offset: 0,
        });
        p.body.push(Instr {
            opcode: Opcode::Return,
            offset: 1,
        });
        assert_eq!(p.instr_at_offset(0), Some(0));
        assert_eq!(p.instr_at_offset(1), Some(1));
        assert_eq!(p.instr_at_offset(2), None);
    }
}
