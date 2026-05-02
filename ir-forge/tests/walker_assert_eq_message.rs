//! Walker → bytecode → executor round-trip for `Instruction::AssertEq`
//! and `Instruction::Assert` carrying a user-authored message.
//!
//! Background: without a message-aware opcode, the Walker would emit
//! `Opcode::EmitAssertEq { lhs, rhs }` for both messageless and
//! message-bearing IR asserts, the opcode would have no message slot,
//! and every IR re-materialised by the executor would come back with
//! `message: None`. The R1CS evaluator would then surface the generic
//! `assert_eq failed: values are not equal` shape instead of the
//! user's string, breaking
//! `cli/tests/circuit_test.rs::circuit_assert_eq_message_shown_on_failure`
//! whenever the prove handler routes through `instantiate_lysis`.
//!
//! Solution: a sibling opcode `EmitAssertEqMsg { lhs, rhs, msg_idx }`
//! references the const pool's `String` entry; the executor reads
//! the string and rebuilds `InstructionKind::AssertEq { message:
//! Some(_), .. }`. These tests pin the round-trip end-to-end.

use ir_core::{Instruction, SsaVar};
use ir_forge::extended::ExtendedInstruction;
use ir_forge::lysis_lift::Walker;
use lysis::bytecode::Opcode;
use memory::{Bn254Fr, FieldElement, FieldFamily};

fn ssa(i: u32) -> SsaVar {
    SsaVar(i)
}

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

fn plain(inst: Instruction<Bn254Fr>) -> ExtendedInstruction<Bn254Fr> {
    ExtendedInstruction::Plain(inst)
}

/// Build a body that lifts to two field consts and a `Decompose`-free
/// `AssertEq` carrying a custom message. Walker should emit
/// `EmitAssertEqMsg` (not the messageless `EmitAssertEq`) and intern
/// the message string in the const pool.
#[test]
fn walker_emits_assert_eq_msg_when_message_present() {
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(2),
        }),
        plain(Instruction::AssertEq {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            message: Some("values must be equal".to_owned()),
        }),
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(&body).expect("walker lower");

    let mut saw_msg_opcode = false;
    let mut saw_plain_opcode = false;
    for instr in &program.body {
        match &instr.opcode {
            Opcode::EmitAssertEqMsg { msg_idx, .. } => {
                saw_msg_opcode = true;
                let entry = program
                    .const_pool
                    .get(*msg_idx as usize)
                    .expect("msg_idx in pool");
                match entry {
                    lysis::bytecode::ConstPoolEntry::String(s) => {
                        assert_eq!(s, "values must be equal");
                    }
                    other => panic!("expected String entry, got {other:?}"),
                }
            }
            Opcode::EmitAssertEq { .. } => saw_plain_opcode = true,
            _ => {}
        }
    }
    assert!(
        saw_msg_opcode,
        "expected EmitAssertEqMsg in walker output for message-bearing AssertEq"
    );
    assert!(
        !saw_plain_opcode,
        "expected NO plain EmitAssertEq for a message-bearing AssertEq"
    );
}

/// Messageless `AssertEq` keeps the legacy 2-byte `EmitAssertEq`
/// opcode — no const-pool string allocated.
#[test]
fn walker_emits_plain_assert_eq_when_no_message() {
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(1),
        }),
        plain(Instruction::AssertEq {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
            message: None,
        }),
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(&body).expect("walker lower");

    let saw_msg_opcode = program
        .body
        .iter()
        .any(|instr| matches!(instr.opcode, Opcode::EmitAssertEqMsg { .. }));
    let saw_plain_opcode = program
        .body
        .iter()
        .any(|instr| matches!(instr.opcode, Opcode::EmitAssertEq { .. }));
    assert!(
        !saw_msg_opcode,
        "expected NO EmitAssertEqMsg for a messageless AssertEq"
    );
    assert!(
        saw_plain_opcode,
        "expected plain EmitAssertEq for a messageless AssertEq"
    );
}

/// `Instruction::Assert` (operand == 1 desugar) routes through the
/// same channel: message present → `EmitAssertEqMsg`, message absent
/// → `EmitAssertEq`.
#[test]
fn walker_assert_with_message_routes_through_msg_opcode() {
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(1),
        }),
        plain(Instruction::Assert {
            result: ssa(1),
            operand: ssa(0),
            message: Some("must be one".to_owned()),
        }),
    ];

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(&body).expect("walker lower");

    let mut found = false;
    for instr in &program.body {
        if let Opcode::EmitAssertEqMsg { msg_idx, .. } = &instr.opcode {
            let entry = program
                .const_pool
                .get(*msg_idx as usize)
                .expect("msg_idx in pool");
            if let lysis::bytecode::ConstPoolEntry::String(s) = entry {
                assert_eq!(s, "must be one");
                found = true;
            }
        }
    }
    assert!(
        found,
        "expected EmitAssertEqMsg referencing 'must be one' string for message-bearing Assert"
    );
}
