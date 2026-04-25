//! `ProgramBuilder<F>` — fluent builder for hand-writing Lysis
//! programs in tests, fuzz harnesses, and during early iteration.
//!
//! The builder mirrors Artik's `ProgramBuilder` in spirit: one method
//! per opcode, chained via `&mut self`, plus const-pool interners
//! that return indices usable in later opcode arguments.
//!
//! This is the *only* way the Phase 1 test surface constructs
//! programs. Fixture files (`tests/bytecode/*`) land in Phase 1 as a
//! migration from the raw-byte fixtures of Phase 0 to builder-based
//! fixtures; the raw bytes are still emitted (encoder produces them),
//! but the test source describes programs semantically.
//!
//! A `ProgramBuilder` finishes into a [`Program`] whose header
//! accurately reports the const pool length, body length, flags, and
//! family. Callers can then feed it to [`crate::bytecode::encode`]
//! (to serialize) or directly to [`crate::bytecode::validate`] /
//! [`crate::execute`] without another byte-level round trip.

use memory::field::{Bn254Fr, FieldBackend, FieldElement};
use memory::FieldFamily;

use crate::bytecode::const_pool::{ConstPool, ConstPoolEntry};
use crate::bytecode::encoding::encode_opcode;
use crate::bytecode::Opcode;
use crate::header::LysisHeader;
use crate::intern::Visibility;
use crate::program::{Instr, Program, Template};

/// Fluent builder for a Lysis [`Program`].
pub struct ProgramBuilder<F: FieldBackend = Bn254Fr> {
    family: FieldFamily,
    flags: u8,
    const_pool: ConstPool<F>,
    body: Vec<Instr>,
    templates: Vec<Template>,
    body_len_bytes: u32,
}

impl<F: FieldBackend> ProgramBuilder<F> {
    /// Start a new builder for the given field family. Flags default
    /// to 0; use [`Self::with_flags`] to set `FLAG_HAS_WITNESS_CALLS`
    /// or future flag bits.
    pub fn new(family: FieldFamily) -> Self {
        Self {
            family,
            flags: 0,
            const_pool: ConstPool::new(family),
            body: Vec::new(),
            templates: Vec::new(),
            body_len_bytes: 0,
        }
    }

    /// Set flag bits on the program header.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Number of instructions pushed so far.
    pub fn instr_count(&self) -> usize {
        self.body.len()
    }

    /// Declared field family.
    pub fn family(&self) -> FieldFamily {
        self.family
    }

    /// Current byte length of the encoded body. Useful for fixtures
    /// that want to compute a jump target against "what's already
    /// been emitted."
    pub fn current_offset(&self) -> u32 {
        self.body_len_bytes
    }

    // -----------------------------------------------------------------
    // Const pool interners
    // -----------------------------------------------------------------

    /// Append a field constant to the const pool and return its index.
    pub fn intern_field(&mut self, fe: FieldElement<F>) -> u32 {
        self.const_pool.push(ConstPoolEntry::Field(fe))
    }

    /// Append a string constant and return its index.
    pub fn intern_string(&mut self, s: impl Into<String>) -> u32 {
        self.const_pool.push(ConstPoolEntry::String(s.into()))
    }

    /// Append an Artik bytecode blob and return its index.
    pub fn intern_artik_bytecode(&mut self, blob: Vec<u8>) -> u32 {
        self.const_pool.push(ConstPoolEntry::ArtikBytecode(blob))
    }

    /// Append a span entry and return its index.
    pub fn intern_span(&mut self, file_id: u32, start: u32, end: u32) -> u32 {
        self.const_pool.push(ConstPoolEntry::Span {
            file_id,
            start,
            end,
        })
    }

    // -----------------------------------------------------------------
    // Opcode helpers (§4.3.1 capture / environment)
    // -----------------------------------------------------------------

    pub fn load_capture(&mut self, dst: u8, idx: u16) -> &mut Self {
        self.push(Opcode::LoadCapture { dst, idx })
    }

    pub fn load_const(&mut self, dst: u8, idx: u16) -> &mut Self {
        self.push(Opcode::LoadConst { dst, idx })
    }

    pub fn load_input(&mut self, dst: u8, name_idx: u16, vis: Visibility) -> &mut Self {
        self.push(Opcode::LoadInput { dst, name_idx, vis })
    }

    pub fn enter_scope(&mut self) -> &mut Self {
        self.push(Opcode::EnterScope)
    }

    pub fn exit_scope(&mut self) -> &mut Self {
        self.push(Opcode::ExitScope)
    }

    // -----------------------------------------------------------------
    // Opcode helpers (§4.3.2 control flow)
    // -----------------------------------------------------------------

    pub fn jump(&mut self, offset: i16) -> &mut Self {
        self.push(Opcode::Jump { offset })
    }

    pub fn jump_if(&mut self, cond: u8, offset: i16) -> &mut Self {
        self.push(Opcode::JumpIf { cond, offset })
    }

    pub fn ret(&mut self) -> &mut Self {
        self.push(Opcode::Return)
    }

    pub fn halt(&mut self) -> &mut Self {
        self.push(Opcode::Halt)
    }

    pub fn trap(&mut self, code: u8) -> &mut Self {
        self.push(Opcode::Trap { code })
    }

    // -----------------------------------------------------------------
    // Opcode helpers (§4.3.3 loop semantics)
    // -----------------------------------------------------------------

    pub fn loop_unroll(&mut self, iter_var: u8, start: u32, end: u32, body_len: u16) -> &mut Self {
        self.push(Opcode::LoopUnroll {
            iter_var,
            start,
            end,
            body_len,
        })
    }

    pub fn loop_rolled(
        &mut self,
        iter_var: u8,
        start: u32,
        end: u32,
        body_template_id: u16,
    ) -> &mut Self {
        self.push(Opcode::LoopRolled {
            iter_var,
            start,
            end,
            body_template_id,
        })
    }

    pub fn loop_range(&mut self, iter_var: u8, end_reg: u8, body_template_id: u16) -> &mut Self {
        self.push(Opcode::LoopRange {
            iter_var,
            end_reg,
            body_template_id,
        })
    }

    // -----------------------------------------------------------------
    // Opcode helpers (§4.3.4 template instantiation)
    // -----------------------------------------------------------------

    pub fn define_template(
        &mut self,
        template_id: u16,
        frame_size: u8,
        n_params: u8,
        body_offset: u32,
        body_len: u32,
    ) -> &mut Self {
        self.push(Opcode::DefineTemplate {
            template_id,
            frame_size,
            n_params,
            body_offset,
            body_len,
        })
    }

    pub fn instantiate_template(
        &mut self,
        template_id: u16,
        capture_regs: Vec<u8>,
        output_regs: Vec<u8>,
    ) -> &mut Self {
        self.push(Opcode::InstantiateTemplate {
            template_id,
            capture_regs,
            output_regs,
        })
    }

    pub fn template_output(&mut self, output_idx: u8, src_reg: u8) -> &mut Self {
        self.push(Opcode::TemplateOutput {
            output_idx,
            src_reg,
        })
    }

    // -----------------------------------------------------------------
    // Opcode helpers (§4.3.5 IR emission)
    // -----------------------------------------------------------------

    pub fn emit_const(&mut self, dst: u8, src_reg: u8) -> &mut Self {
        self.push(Opcode::EmitConst { dst, src_reg })
    }

    pub fn emit_add(&mut self, dst: u8, lhs: u8, rhs: u8) -> &mut Self {
        self.push(Opcode::EmitAdd { dst, lhs, rhs })
    }

    pub fn emit_sub(&mut self, dst: u8, lhs: u8, rhs: u8) -> &mut Self {
        self.push(Opcode::EmitSub { dst, lhs, rhs })
    }

    pub fn emit_mul(&mut self, dst: u8, lhs: u8, rhs: u8) -> &mut Self {
        self.push(Opcode::EmitMul { dst, lhs, rhs })
    }

    pub fn emit_neg(&mut self, dst: u8, operand: u8) -> &mut Self {
        self.push(Opcode::EmitNeg { dst, operand })
    }

    pub fn emit_mux(&mut self, dst: u8, cond: u8, then_v: u8, else_v: u8) -> &mut Self {
        self.push(Opcode::EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        })
    }

    pub fn emit_decompose(&mut self, dst_arr: u8, src: u8, n_bits: u8) -> &mut Self {
        self.push(Opcode::EmitDecompose {
            dst_arr,
            src,
            n_bits,
        })
    }

    pub fn emit_assert_eq(&mut self, lhs: u8, rhs: u8) -> &mut Self {
        self.push(Opcode::EmitAssertEq { lhs, rhs })
    }

    pub fn emit_range_check(&mut self, var: u8, max_bits: u8) -> &mut Self {
        self.push(Opcode::EmitRangeCheck { var, max_bits })
    }

    pub fn emit_witness_call(
        &mut self,
        bytecode_const_idx: u16,
        in_regs: Vec<u8>,
        out_regs: Vec<u8>,
    ) -> &mut Self {
        self.push(Opcode::EmitWitnessCall {
            bytecode_const_idx,
            in_regs,
            out_regs,
        })
    }

    pub fn emit_poseidon_hash(&mut self, dst: u8, in_regs: Vec<u8>) -> &mut Self {
        self.push(Opcode::EmitPoseidonHash { dst, in_regs })
    }

    pub fn emit_is_eq(&mut self, dst: u8, lhs: u8, rhs: u8) -> &mut Self {
        self.push(Opcode::EmitIsEq { dst, lhs, rhs })
    }

    pub fn emit_is_lt(&mut self, dst: u8, lhs: u8, rhs: u8) -> &mut Self {
        self.push(Opcode::EmitIsLt { dst, lhs, rhs })
    }

    pub fn emit_int_div(&mut self, dst: u8, lhs: u8, rhs: u8, max_bits: u8) -> &mut Self {
        self.push(Opcode::EmitIntDiv {
            dst,
            lhs,
            rhs,
            max_bits,
        })
    }

    pub fn emit_int_mod(&mut self, dst: u8, lhs: u8, rhs: u8, max_bits: u8) -> &mut Self {
        self.push(Opcode::EmitIntMod {
            dst,
            lhs,
            rhs,
            max_bits,
        })
    }

    // -----------------------------------------------------------------
    // Low-level push + finish
    // -----------------------------------------------------------------

    /// Push a pre-constructed opcode. Exposed for tests that want to
    /// construct a malformed program (e.g., validator error paths)
    /// without a dedicated helper.
    pub fn push_opcode(&mut self, op: Opcode) -> &mut Self {
        self.push(op)
    }

    fn push(&mut self, op: Opcode) -> &mut Self {
        let offset = self.body_len_bytes;
        let mut buf = Vec::new();
        encode_opcode(&op, &mut buf);
        self.body_len_bytes += buf.len() as u32;
        if let Opcode::DefineTemplate {
            template_id,
            frame_size,
            n_params,
            body_offset,
            body_len,
        } = &op
        {
            self.templates.push(Template {
                id: *template_id,
                frame_size: *frame_size,
                n_params: *n_params,
                body_offset: *body_offset,
                body_len: *body_len,
            });
        }
        self.body.push(Instr { opcode: op, offset });
        self
    }

    /// Finalize the program.
    pub fn finish(self) -> Program<F> {
        let header = LysisHeader::new(
            self.family,
            self.flags,
            self.const_pool.len() as u32,
            self.body_len_bytes,
        );
        Program {
            header,
            const_pool: self.const_pool,
            templates: self.templates,
            body: self.body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{decode, encode};

    #[test]
    fn empty_builder_finishes_to_empty_program() {
        let p = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256).finish();
        assert!(p.is_empty());
        assert_eq!(p.header.const_pool_len, 0);
        assert_eq!(p.header.body_len, 0);
    }

    #[test]
    fn offsets_advance_per_opcode() {
        let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
        b.halt();
        assert_eq!(b.current_offset(), 1); // Halt = 1 byte
        b.emit_add(0, 0, 0);
        assert_eq!(b.current_offset(), 5); // + 1 opcode + 3 operands
    }

    #[test]
    fn builder_matches_encoded_body_length() {
        let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
        b.load_input(0, 0, Visibility::Witness);
        b.emit_range_check(0, 8);
        b.halt();
        let program = b.finish();

        let bytes = encode(&program);
        let decoded = decode::<Bn254Fr>(&bytes).unwrap();
        assert_eq!(decoded.body.len(), 3);
        assert_eq!(decoded.header.body_len, program.header.body_len);
    }

    #[test]
    fn define_template_populates_template_table() {
        let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
        b.define_template(1, 4, 1, 32, 16);
        b.define_template(2, 8, 2, 64, 32);
        let program = b.finish();
        assert_eq!(program.templates.len(), 2);
        assert_eq!(program.templates[0].id, 1);
        assert_eq!(program.templates[1].id, 2);
    }

    #[test]
    fn const_pool_interners_return_indices() {
        let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
        let idx0 = b.intern_string("in");
        let idx1 = b.intern_field(FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0]));
        let idx2 = b.intern_artik_bytecode(vec![0xAA, 0xBB]);
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        let program = b.finish();
        assert_eq!(program.const_pool.len(), 3);
        assert_eq!(program.header.const_pool_len, 3);
    }

    #[test]
    fn chained_builder_produces_valid_roundtrip() {
        let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
        let in_idx = b.intern_string("x");
        b.load_input(0, in_idx as u16, Visibility::Witness)
            .emit_range_check(0, 8)
            .emit_add(1, 0, 0)
            .halt();
        let program = b.finish();

        let bytes = encode(&program);
        let decoded = decode::<Bn254Fr>(&bytes).unwrap();
        assert_eq!(decoded.body.len(), 4);
        assert_eq!(decoded.const_pool.len(), 1);
    }

    #[test]
    fn flags_are_preserved() {
        let p = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256)
            .with_flags(crate::header::FLAG_HAS_WITNESS_CALLS)
            .finish();
        assert_eq!(p.header.flags, crate::header::FLAG_HAS_WITNESS_CALLS);
    }
}
