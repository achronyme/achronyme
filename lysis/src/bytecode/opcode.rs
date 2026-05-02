//! `Opcode` — the 35 instructions Lysis understands, exactly matching
//! the table in RFC §4.3.
//!
//! Each variant carries its operands inline so that after a successful
//! [`decode`](super::encoding::decode) the executor never has to
//! re-parse operand bytes. The raw opcode byte is recovered via
//! [`Opcode::code`] and the canonical name via [`Opcode::mnemonic`].
//!
//! # Layout
//!
//! Fixed-layout opcodes are straight-through: read opcode byte, read
//! the declared operand fields, done. Three opcodes are
//! **variable-length** because their operand count is encoded inline:
//!
//! - `InstantiateTemplate` — `capture_regs` + `output_regs`, each a
//!   length-prefixed byte vector.
//! - `EmitWitnessCall` — `in_regs` + `out_regs`, each a length-prefixed
//!   byte vector.
//! - `EmitPoseidonHash` — `in_regs` as a length-prefixed byte vector.
//!
//! The encoder and decoder in [`super::encoding`] handle the two
//! layouts uniformly; the key invariant is that every opcode's
//! on-disk length is derivable from `opcode_byte + operand_prefix`
//! alone, so a validator can walk the body stream linearly without
//! ever having to execute.

use crate::intern::Visibility;

/// All 35 Lysis opcodes, grouped per RFC §4.3 section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opcode {
    // -----------------------------------------------------------------
    // §4.3.1 Capture / environment (5)
    // -----------------------------------------------------------------
    LoadCapture {
        dst: u8,
        idx: u16,
    },
    LoadConst {
        dst: u8,
        idx: u16,
    },
    LoadInput {
        dst: u8,
        name_idx: u16,
        vis: Visibility,
    },
    EnterScope,
    ExitScope,

    // -----------------------------------------------------------------
    // §4.3.2 Control flow (5)
    // -----------------------------------------------------------------
    Jump {
        offset: i16,
    },
    JumpIf {
        cond: u8,
        offset: i16,
    },
    Return,
    Halt,
    Trap {
        code: u8,
    },

    // -----------------------------------------------------------------
    // §4.3.3 Loop semantics (3)
    // -----------------------------------------------------------------
    LoopUnroll {
        iter_var: u8,
        start: u32,
        end: u32,
        body_len: u16,
    },
    LoopRolled {
        iter_var: u8,
        start: u32,
        end: u32,
        body_template_id: u16,
    },
    LoopRange {
        iter_var: u8,
        end_reg: u8,
        body_template_id: u16,
    },

    // -----------------------------------------------------------------
    // §4.3.4 Template instantiation (3)
    // -----------------------------------------------------------------
    DefineTemplate {
        template_id: u16,
        frame_size: u8,
        n_params: u8,
        body_offset: u32,
        body_len: u32,
    },
    InstantiateTemplate {
        template_id: u16,
        capture_regs: Vec<u8>,
        output_regs: Vec<u8>,
    },
    TemplateOutput {
        output_idx: u8,
        src_reg: u8,
    },

    // -----------------------------------------------------------------
    // §4.3.5 IR emission (14)
    // -----------------------------------------------------------------
    EmitConst {
        dst: u8,
        src_reg: u8,
    },
    EmitAdd {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },
    EmitSub {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },
    EmitMul {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },
    EmitNeg {
        dst: u8,
        operand: u8,
    },
    EmitMux {
        dst: u8,
        cond: u8,
        then_v: u8,
        else_v: u8,
    },
    EmitDecompose {
        dst_arr: u8,
        src: u8,
        n_bits: u8,
    },
    EmitAssertEq {
        lhs: u8,
        rhs: u8,
    },
    /// `EmitAssertEq` variant carrying a user-authored failure message.
    ///
    /// The message lives in [`crate::bytecode::ConstPoolEntry::String`]
    /// at index `msg_idx`. The executor reconstructs an
    /// `InstructionKind::AssertEq { message: Some(_), .. }` so the IR
    /// evaluator can surface the custom string through
    /// `EvalError::AssertEqFailed.message` (see `ir/src/eval/mod.rs`).
    ///
    /// Two opcode tags (`EmitAssertEq` + `EmitAssertEqMsg`) instead of a
    /// single optional-payload opcode keeps the wire format invariant
    /// per opcode tag — old `EmitAssertEq` decoders never see this
    /// variant, so the 2-byte payload of plain `EmitAssertEq` is
    /// preserved across releases.
    EmitAssertEqMsg {
        lhs: u8,
        rhs: u8,
        msg_idx: u16,
    },
    EmitRangeCheck {
        var: u8,
        max_bits: u8,
    },
    EmitWitnessCall {
        bytecode_const_idx: u16,
        in_regs: Vec<u8>,
        out_regs: Vec<u8>,
    },
    EmitPoseidonHash {
        dst: u8,
        in_regs: Vec<u8>,
    },
    EmitIsEq {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },
    EmitIsLt {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },
    EmitIntDiv {
        dst: u8,
        lhs: u8,
        rhs: u8,
        max_bits: u8,
    },
    EmitIntMod {
        dst: u8,
        lhs: u8,
        rhs: u8,
        max_bits: u8,
    },
    /// Field division `dst = lhs / rhs` — emits `Instruction::Div`
    /// to the sink. The downstream R1CS backend lowers it via
    /// `divide_lcs`, which generates the witness-side inverse hint
    /// and the `rhs * inv = 1` constraint.
    EmitDiv {
        dst: u8,
        lhs: u8,
        rhs: u8,
    },

    // -----------------------------------------------------------------
    // §4.3.6 Heap spill — captures-overflow escape valve.
    //
    // Both opcodes operate on a program-global heap (RFC §4.3.6).
    // `slot` is u16 → up to 65 535 distinct entries; the
    // `heap_size_hint` field on the v2 bytecode header sizes the
    // executor's heap vector at load time. The walker emits these
    // only when a split's live set exceeds `MAX_CAPTURES_HOT`;
    // programs that fit in 64 captures emit zero heap opcodes and
    // decode identically against v1 readers minus the version byte.
    // -----------------------------------------------------------------
    StoreHeap {
        src_reg: u8,
        slot: u16,
    },
    LoadHeap {
        dst_reg: u8,
        slot: u16,
    },

    // -----------------------------------------------------------------
    // §4.3.7 Heap-output WitnessCall
    //
    // `EmitWitnessCallHeap` is the heap-destination twin of
    // `EmitWitnessCall`. The walker emits this variant when the
    // Artik program produces too many outputs to fit alongside hot
    // captures in a u8 frame (canonical case: SHA-256 with 256
    // output bits, where `EmitWitnessCall` would need 256 fresh
    // registers and exceed the `FRAME_CAP = 255` cap structurally).
    //
    // Both **inputs** and **outputs** can live in heap slots, not
    // just outputs. Each input is `InputSrc::Reg(u8)` (read from a
    // frame register, classic path) or `InputSrc::Slot(u16)` (read
    // directly from a heap slot, bypassing the LoadHeap + alloc
    // dance entirely). Outputs always land in heap slots. This
    // matters for SHA-256-class circuits where a single
    // `WitnessCall` may have hundreds of cold inputs — emitting one
    // `LoadHeap` per cold input would overflow the frame just as
    // structurally as emitting outputs to regs would.
    // -----------------------------------------------------------------
    EmitWitnessCallHeap {
        bytecode_const_idx: u16,
        inputs: Vec<InputSrc>,
        out_slots: Vec<u16>,
    },
}

/// Per-input source descriptor for [`Opcode::EmitWitnessCallHeap`].
///
/// Each input position in an Artik program comes from either a
/// frame register (hot path, classic) or a heap slot (cold path,
/// no `LoadHeap` needed because the executor reads `heap[slot]`
/// directly). Order is preserved across the wire so the Artik
/// runtime sees its inputs in the original IR order.
///
/// Wire format per element: `1 byte tag + 1-or-2 byte payload`.
/// - `Reg(u8)`: tag `0x00`, payload 1 byte → 2 bytes total.
/// - `Slot(u16)`: tag `0x01`, payload 2 bytes LE → 3 bytes total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSrc {
    Reg(u8),
    Slot(u16),
}

/// Wire-format tag for [`InputSrc::Reg`].
pub const INPUT_SRC_REG: u8 = 0x00;
/// Wire-format tag for [`InputSrc::Slot`].
pub const INPUT_SRC_SLOT: u8 = 0x01;

/// Raw byte identifiers from RFC §4.3.
pub mod code {
    // §4.3.1
    pub const LOAD_CAPTURE: u8 = 0x01;
    pub const LOAD_CONST: u8 = 0x02;
    pub const LOAD_INPUT: u8 = 0x03;
    pub const ENTER_SCOPE: u8 = 0x04;
    pub const EXIT_SCOPE: u8 = 0x05;

    // §4.3.2
    pub const JUMP: u8 = 0x10;
    pub const JUMP_IF: u8 = 0x11;
    pub const RETURN: u8 = 0x12;
    pub const HALT: u8 = 0x13;
    pub const TRAP: u8 = 0x14;

    // §4.3.3
    pub const LOOP_UNROLL: u8 = 0x20;
    pub const LOOP_ROLLED: u8 = 0x21;
    pub const LOOP_RANGE: u8 = 0x22;

    // §4.3.4
    pub const DEFINE_TEMPLATE: u8 = 0x30;
    pub const INSTANTIATE_TEMPLATE: u8 = 0x31;
    pub const TEMPLATE_OUTPUT: u8 = 0x32;

    // §4.3.5
    pub const EMIT_CONST: u8 = 0x40;
    pub const EMIT_ADD: u8 = 0x41;
    pub const EMIT_SUB: u8 = 0x42;
    pub const EMIT_MUL: u8 = 0x43;
    pub const EMIT_NEG: u8 = 0x44;
    pub const EMIT_MUX: u8 = 0x45;
    pub const EMIT_DECOMPOSE: u8 = 0x46;
    pub const EMIT_ASSERT_EQ: u8 = 0x47;
    pub const EMIT_RANGE_CHECK: u8 = 0x48;
    pub const EMIT_WITNESS_CALL: u8 = 0x49;
    pub const EMIT_POSEIDON_HASH: u8 = 0x4A;
    pub const EMIT_IS_EQ: u8 = 0x4B;
    pub const EMIT_IS_LT: u8 = 0x4C;
    pub const EMIT_INT_DIV: u8 = 0x4D;
    pub const EMIT_INT_MOD: u8 = 0x4E;
    pub const EMIT_DIV: u8 = 0x4F;

    // §4.3.6 — heap spill
    pub const STORE_HEAP: u8 = 0x50;
    pub const LOAD_HEAP: u8 = 0x51;

    // §4.3.7 — heap-output WitnessCall
    pub const EMIT_WITNESS_CALL_HEAP: u8 = 0x52;

    // §4.3.5 follow-up — message-bearing AssertEq.
    pub const EMIT_ASSERT_EQ_MSG: u8 = 0x53;
}

impl Opcode {
    /// Raw byte identifier from RFC §4.3.
    pub fn code(&self) -> u8 {
        use code::*;
        match self {
            Self::LoadCapture { .. } => LOAD_CAPTURE,
            Self::LoadConst { .. } => LOAD_CONST,
            Self::LoadInput { .. } => LOAD_INPUT,
            Self::EnterScope => ENTER_SCOPE,
            Self::ExitScope => EXIT_SCOPE,
            Self::Jump { .. } => JUMP,
            Self::JumpIf { .. } => JUMP_IF,
            Self::Return => RETURN,
            Self::Halt => HALT,
            Self::Trap { .. } => TRAP,
            Self::LoopUnroll { .. } => LOOP_UNROLL,
            Self::LoopRolled { .. } => LOOP_ROLLED,
            Self::LoopRange { .. } => LOOP_RANGE,
            Self::DefineTemplate { .. } => DEFINE_TEMPLATE,
            Self::InstantiateTemplate { .. } => INSTANTIATE_TEMPLATE,
            Self::TemplateOutput { .. } => TEMPLATE_OUTPUT,
            Self::EmitConst { .. } => EMIT_CONST,
            Self::EmitAdd { .. } => EMIT_ADD,
            Self::EmitSub { .. } => EMIT_SUB,
            Self::EmitMul { .. } => EMIT_MUL,
            Self::EmitNeg { .. } => EMIT_NEG,
            Self::EmitMux { .. } => EMIT_MUX,
            Self::EmitDecompose { .. } => EMIT_DECOMPOSE,
            Self::EmitAssertEq { .. } => EMIT_ASSERT_EQ,
            Self::EmitAssertEqMsg { .. } => EMIT_ASSERT_EQ_MSG,
            Self::EmitRangeCheck { .. } => EMIT_RANGE_CHECK,
            Self::EmitWitnessCall { .. } => EMIT_WITNESS_CALL,
            Self::EmitPoseidonHash { .. } => EMIT_POSEIDON_HASH,
            Self::EmitIsEq { .. } => EMIT_IS_EQ,
            Self::EmitIsLt { .. } => EMIT_IS_LT,
            Self::EmitIntDiv { .. } => EMIT_INT_DIV,
            Self::EmitIntMod { .. } => EMIT_INT_MOD,
            Self::EmitDiv { .. } => EMIT_DIV,
            Self::StoreHeap { .. } => STORE_HEAP,
            Self::LoadHeap { .. } => LOAD_HEAP,
            Self::EmitWitnessCallHeap { .. } => EMIT_WITNESS_CALL_HEAP,
        }
    }

    /// Human-readable mnemonic (stable; used by error messages,
    /// disassembler, debug output).
    pub fn mnemonic(&self) -> &'static str {
        match self {
            Self::LoadCapture { .. } => "LoadCapture",
            Self::LoadConst { .. } => "LoadConst",
            Self::LoadInput { .. } => "LoadInput",
            Self::EnterScope => "EnterScope",
            Self::ExitScope => "ExitScope",
            Self::Jump { .. } => "Jump",
            Self::JumpIf { .. } => "JumpIf",
            Self::Return => "Return",
            Self::Halt => "Halt",
            Self::Trap { .. } => "Trap",
            Self::LoopUnroll { .. } => "LoopUnroll",
            Self::LoopRolled { .. } => "LoopRolled",
            Self::LoopRange { .. } => "LoopRange",
            Self::DefineTemplate { .. } => "DefineTemplate",
            Self::InstantiateTemplate { .. } => "InstantiateTemplate",
            Self::TemplateOutput { .. } => "TemplateOutput",
            Self::EmitConst { .. } => "EmitConst",
            Self::EmitAdd { .. } => "EmitAdd",
            Self::EmitSub { .. } => "EmitSub",
            Self::EmitMul { .. } => "EmitMul",
            Self::EmitNeg { .. } => "EmitNeg",
            Self::EmitMux { .. } => "EmitMux",
            Self::EmitDecompose { .. } => "EmitDecompose",
            Self::EmitAssertEq { .. } => "EmitAssertEq",
            Self::EmitAssertEqMsg { .. } => "EmitAssertEqMsg",
            Self::EmitRangeCheck { .. } => "EmitRangeCheck",
            Self::EmitWitnessCall { .. } => "EmitWitnessCall",
            Self::EmitPoseidonHash { .. } => "EmitPoseidonHash",
            Self::EmitIsEq { .. } => "EmitIsEq",
            Self::EmitIsLt { .. } => "EmitIsLt",
            Self::EmitIntDiv { .. } => "EmitIntDiv",
            Self::EmitIntMod { .. } => "EmitIntMod",
            Self::EmitDiv { .. } => "EmitDiv",
            Self::StoreHeap { .. } => "StoreHeap",
            Self::LoadHeap { .. } => "LoadHeap",
            Self::EmitWitnessCallHeap { .. } => "EmitWitnessCallHeap",
        }
    }

    /// `true` iff this opcode writes a destination register the
    /// executor must consider initialized afterwards. Used by the
    /// validator's uninitialized-register check (rule 9).
    pub fn writes_register(&self) -> bool {
        matches!(
            self,
            Self::LoadCapture { .. }
                | Self::LoadConst { .. }
                | Self::LoadInput { .. }
                | Self::EmitConst { .. }
                | Self::EmitAdd { .. }
                | Self::EmitSub { .. }
                | Self::EmitMul { .. }
                | Self::EmitNeg { .. }
                | Self::EmitMux { .. }
                | Self::EmitPoseidonHash { .. }
                | Self::EmitIsEq { .. }
                | Self::EmitIsLt { .. }
                | Self::EmitIntDiv { .. }
                | Self::EmitIntMod { .. }
                | Self::EmitDiv { .. }
                | Self::LoadHeap { .. }
        )
    }

    /// `true` iff control flow can continue past this opcode to the
    /// textually-next instruction. Used by the validator's
    /// reachable-return analysis (rule 10).
    pub fn falls_through(&self) -> bool {
        !matches!(
            self,
            Self::Jump { .. } | Self::Return | Self::Halt | Self::Trap { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_stable_code() {
        // Sentinels match the RFC §4.3 table.
        assert_eq!(Opcode::Return.code(), code::RETURN);
        assert_eq!(Opcode::Halt.code(), code::HALT);
        assert_eq!(
            Opcode::LoadCapture { dst: 0, idx: 0 }.code(),
            code::LOAD_CAPTURE
        );
        assert_eq!(
            Opcode::EmitPoseidonHash {
                dst: 0,
                in_regs: vec![]
            }
            .code(),
            code::EMIT_POSEIDON_HASH
        );
    }

    #[test]
    fn control_flow_terminators_do_not_fall_through() {
        assert!(!Opcode::Return.falls_through());
        assert!(!Opcode::Halt.falls_through());
        assert!(!Opcode::Jump { offset: 0 }.falls_through());
        assert!(!Opcode::Trap { code: 0 }.falls_through());
    }

    #[test]
    fn conditional_jump_falls_through() {
        assert!(Opcode::JumpIf { cond: 0, offset: 0 }.falls_through());
    }

    #[test]
    fn emit_ops_write_register() {
        assert!(Opcode::EmitAdd {
            dst: 0,
            lhs: 0,
            rhs: 0
        }
        .writes_register());
        assert!(!Opcode::EmitAssertEq { lhs: 0, rhs: 0 }.writes_register());
        assert!(!Opcode::EmitAssertEqMsg {
            lhs: 0,
            rhs: 0,
            msg_idx: 0
        }
        .writes_register());
        assert!(!Opcode::EmitRangeCheck {
            var: 0,
            max_bits: 8
        }
        .writes_register());
    }

    #[test]
    fn all_34_codes_are_unique() {
        let all = [
            code::LOAD_CAPTURE,
            code::LOAD_CONST,
            code::LOAD_INPUT,
            code::ENTER_SCOPE,
            code::EXIT_SCOPE,
            code::JUMP,
            code::JUMP_IF,
            code::RETURN,
            code::HALT,
            code::TRAP,
            code::LOOP_UNROLL,
            code::LOOP_ROLLED,
            code::LOOP_RANGE,
            code::DEFINE_TEMPLATE,
            code::INSTANTIATE_TEMPLATE,
            code::TEMPLATE_OUTPUT,
            code::EMIT_CONST,
            code::EMIT_ADD,
            code::EMIT_SUB,
            code::EMIT_MUL,
            code::EMIT_NEG,
            code::EMIT_MUX,
            code::EMIT_DECOMPOSE,
            code::EMIT_ASSERT_EQ,
            code::EMIT_RANGE_CHECK,
            code::EMIT_WITNESS_CALL,
            code::EMIT_POSEIDON_HASH,
            code::EMIT_IS_EQ,
            code::EMIT_IS_LT,
            code::EMIT_INT_DIV,
            code::EMIT_INT_MOD,
            code::STORE_HEAP,
            code::LOAD_HEAP,
            code::EMIT_WITNESS_CALL_HEAP,
        ];
        assert_eq!(all.len(), 34, "RFC §4.3 lists 34 opcodes");
        let mut sorted = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 34, "opcode bytes must be unique");
    }

    #[test]
    fn emit_witness_call_heap_does_not_write_register() {
        // Outputs go to heap slots, not registers — so this op is NOT
        // a register-writing op from the validator's perspective.
        // The validator's rule 9 (uninitialized register check) must
        // not consider any register written by this instruction.
        assert!(!Opcode::EmitWitnessCallHeap {
            bytecode_const_idx: 0,
            inputs: vec![],
            out_slots: vec![],
        }
        .writes_register());
    }

    #[test]
    fn emit_witness_call_heap_falls_through() {
        assert!(Opcode::EmitWitnessCallHeap {
            bytecode_const_idx: 0,
            inputs: vec![],
            out_slots: vec![],
        }
        .falls_through());
    }

    #[test]
    fn store_heap_does_not_write_register() {
        // StoreHeap is a *side effect* on the program-global heap; it
        // does not produce a register-resident value. The validator's
        // uninitialized-register check (rule 9) must not consider its
        // src_reg to be a destination.
        assert!(!Opcode::StoreHeap {
            src_reg: 0,
            slot: 0
        }
        .writes_register());
    }

    #[test]
    fn load_heap_writes_register() {
        // LoadHeap materialises a heap entry into a fresh register;
        // post-execute, dst_reg is initialized.
        assert!(Opcode::LoadHeap {
            dst_reg: 0,
            slot: 0
        }
        .writes_register());
    }

    #[test]
    fn heap_opcodes_fall_through() {
        // Neither heap op terminates control flow.
        assert!(Opcode::StoreHeap {
            src_reg: 0,
            slot: 0
        }
        .falls_through());
        assert!(Opcode::LoadHeap {
            dst_reg: 0,
            slot: 0
        }
        .falls_through());
    }

    #[test]
    fn mnemonics_are_stable() {
        assert_eq!(Opcode::Return.mnemonic(), "Return");
        assert_eq!(
            Opcode::InstantiateTemplate {
                template_id: 0,
                capture_regs: vec![],
                output_regs: vec![]
            }
            .mnemonic(),
            "InstantiateTemplate"
        );
    }
}
