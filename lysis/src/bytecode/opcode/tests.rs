use super::*;

#[test]
fn every_variant_has_a_stable_code() {
    // Sentinels match the  table.
    assert_eq!(Opcode::Return.code(), code::RETURN);
    assert_eq!(Opcode::Halt.code(), code::HALT);
    assert_eq!(
        Opcode::LoadCapture { dst: 0, idx: 0 }.code(),
        code::LOAD_CAPTURE
    );
    assert_eq!(
        Opcode::EmitPoseidonHash {
            dst: 0,
            in_regs: Box::new(vec![])
        }
        .code(),
        code::EMIT_POSEIDON_HASH
    );
}

#[test]
fn opcode_and_instr_layout_stays_compact() {
    assert_eq!(std::mem::size_of::<Opcode>(), 24);
    assert_eq!(std::mem::size_of::<crate::program::Instr>(), 32);
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
    assert_eq!(all.len(), 34, " lists 34 opcodes");
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
        inputs: Box::new(vec![]),
        out_slots: Box::new(vec![]),
    }
    .writes_register());
}

#[test]
fn emit_witness_call_heap_falls_through() {
    assert!(Opcode::EmitWitnessCallHeap {
        bytecode_const_idx: 0,
        inputs: Box::new(vec![]),
        out_slots: Box::new(vec![]),
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
            capture_regs: Box::new(vec![]),
            output_regs: Box::new(vec![])
        }
        .mnemonic(),
        "InstantiateTemplate"
    );
}
