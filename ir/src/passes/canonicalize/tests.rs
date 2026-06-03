use super::*;
use crate::types::{IrType, Visibility, WitnessCallBody};
use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldElement};

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_u64(n)
}

fn span(lo: u32, hi: u32) -> SpanRange {
    SpanRange::new(lo as usize, hi as usize, 1, lo as usize, 1, hi as usize)
}

fn assert_canonical_shape<F: FieldBackend>(p: &IrProgram<F>) {
    let mut expected = 0u64;
    for inst in &p.instructions {
        assert_eq!(
            inst.result_var(),
            SsaVar(expected),
            "primary def out of canonical order"
        );
        expected += 1;
        for &extra in inst.extra_result_vars() {
            assert_eq!(extra, SsaVar(expected), "extra def out of canonical order");
            expected += 1;
        }
    }
    assert_eq!(p.next_var, expected, "next_var trails canonical id count");
}

#[test]
fn canonicalize_empty_program() {
    let p: IrProgram<Bn254Fr> = IrProgram::new();
    let q = canonicalize_ssa(&p);
    assert!(q.instructions.is_empty());
    assert_eq!(q.next_var, 0);
    assert!(q.var_names.is_empty());
    assert!(q.var_types.is_empty());
    assert!(q.var_spans.is_empty());
}

#[test]
fn canonicalize_single_const_renames_to_zero() {
    // Use a non-trivial starting var id so we can see the rename happen.
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 7;
    p.instructions.push(Instruction::Const {
        result: SsaVar(7),
        value: fe(42),
    });
    p.next_var = 8;

    let q = canonicalize_ssa(&p);
    assert_eq!(q.next_var, 1);
    assert_eq!(q.instructions.len(), 1);
    match &q.instructions[0] {
        Instruction::Const { result, value } => {
            assert_eq!(*result, SsaVar(0));
            assert_eq!(*value, fe(42));
        }
        _ => panic!("expected Const"),
    }
    assert_canonical_shape(&q);
}

#[test]
fn canonicalize_renames_in_visitation_order() {
    // Three instructions allocated with non-monotonic SsaVar ids.
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 100;
    p.instructions.push(Instruction::Const {
        result: SsaVar(10),
        value: fe(1),
    });
    p.instructions.push(Instruction::Const {
        result: SsaVar(20),
        value: fe(2),
    });
    p.instructions.push(Instruction::Add {
        result: SsaVar(5),
        lhs: SsaVar(10),
        rhs: SsaVar(20),
    });

    let q = canonicalize_ssa(&p);

    assert_eq!(q.next_var, 3);
    assert_canonical_shape(&q);

    match &q.instructions[2] {
        Instruction::Add { result, lhs, rhs } => {
            assert_eq!(*result, SsaVar(2));
            assert_eq!(*lhs, SsaVar(0)); // was SsaVar(10), first def
            assert_eq!(*rhs, SsaVar(1)); // was SsaVar(20), second def
        }
        _ => panic!("expected Add"),
    }
}

#[test]
fn canonicalize_is_idempotent() {
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 50;
    p.instructions.push(Instruction::Input {
        result: SsaVar(40),
        name: "x".into(),
        visibility: Visibility::Public,
    });
    p.instructions.push(Instruction::Const {
        result: SsaVar(15),
        value: fe(7),
    });
    p.instructions.push(Instruction::Mul {
        result: SsaVar(30),
        lhs: SsaVar(40),
        rhs: SsaVar(15),
    });
    p.instructions.push(Instruction::AssertEq {
        result: SsaVar(45),
        lhs: SsaVar(30),
        rhs: SsaVar(15),
        message: None,
    });

    let q1 = canonicalize_ssa(&p);
    let q2 = canonicalize_ssa(&q1);

    assert_eq!(q1.next_var, q2.next_var);
    assert_eq!(q1.instructions.len(), q2.instructions.len());
    for (a, b) in q1.instructions.iter().zip(q2.instructions.iter()) {
        assert_eq!(format!("{a}"), format!("{b}"));
    }
}

#[test]
fn canonicalize_decompose_extras_renamed() {
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 100;
    p.instructions.push(Instruction::Input {
        result: SsaVar(50),
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    p.instructions.push(Instruction::Decompose {
        result: SsaVar(60),
        operand: SsaVar(50),
        bit_results: vec![SsaVar(70), SsaVar(71), SsaVar(72), SsaVar(73)],
        num_bits: 4,
    });

    let q = canonicalize_ssa(&p);

    assert_eq!(q.next_var, 6); // Input(0) + Decompose primary(1) + 4 bits(2..=5)
    assert_canonical_shape(&q);

    match &q.instructions[1] {
        Instruction::Decompose {
            result,
            operand,
            bit_results,
            ..
        } => {
            assert_eq!(*result, SsaVar(1));
            assert_eq!(*operand, SsaVar(0));
            assert_eq!(
                *bit_results,
                vec![SsaVar(2), SsaVar(3), SsaVar(4), SsaVar(5)]
            );
        }
        _ => panic!("expected Decompose"),
    }
}

#[test]
fn canonicalize_witness_call_outputs_renamed() {
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 100;
    p.instructions.push(Instruction::Input {
        result: SsaVar(80),
        name: "in".into(),
        visibility: Visibility::Witness,
    });
    p.instructions
        .push(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs: vec![SsaVar(90), SsaVar(91), SsaVar(92)],
            inputs: vec![SsaVar(80)],
            program_bytes: vec![0xAB, 0xCD],
        })));

    let q = canonicalize_ssa(&p);

    assert_eq!(q.next_var, 4); // Input(0) + WitnessCall outputs(1,2,3)
    assert_canonical_shape(&q);

    match &q.instructions[1] {
        Instruction::WitnessCall(call) => {
            assert_eq!(call.outputs, vec![SsaVar(1), SsaVar(2), SsaVar(3)]);
            assert_eq!(call.inputs, vec![SsaVar(0)]);
            assert_eq!(call.program_bytes, vec![0xAB, 0xCD]);
        }
        _ => panic!("expected WitnessCall"),
    }
}

#[test]
fn canonicalize_remaps_var_metadata_keys() {
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 10;
    p.instructions.push(Instruction::Const {
        result: SsaVar(5),
        value: fe(99),
    });
    p.set_name(SsaVar(5), "magic".into());
    p.set_type(SsaVar(5), IrType::Field);
    p.set_span(SsaVar(5), span(0, 5));
    p.input_spans.insert("xinput".into(), span(10, 16));

    let q = canonicalize_ssa(&p);

    assert_eq!(q.get_name(SsaVar(0)), Some("magic"));
    assert_eq!(q.get_type(SsaVar(0)), Some(IrType::Field));
    assert_eq!(q.get_span(SsaVar(0)), Some(&span(0, 5)));
    // Input spans are keyed by name — copied verbatim.
    assert_eq!(q.input_spans.get("xinput"), Some(&span(10, 16)));
    // Old keys must not survive.
    assert!(q.get_name(SsaVar(5)).is_none());
    assert!(q.get_type(SsaVar(5)).is_none());
    assert!(q.get_span(SsaVar(5)).is_none());
}

#[test]
fn canonicalize_collapses_different_numbering_into_same_form() {
    // Two structurally identical programs allocated with different
    // SsaVar id sequences. Canonical form must be identical, modulo
    // the FieldElement value ordering that the IR carries.
    let mut a: IrProgram<Bn254Fr> = IrProgram::new();
    a.next_var = 100;
    a.instructions.push(Instruction::Input {
        result: SsaVar(10),
        name: "x".into(),
        visibility: Visibility::Public,
    });
    a.instructions.push(Instruction::Const {
        result: SsaVar(20),
        value: fe(3),
    });
    a.instructions.push(Instruction::Mul {
        result: SsaVar(30),
        lhs: SsaVar(10),
        rhs: SsaVar(20),
    });

    let mut b: IrProgram<Bn254Fr> = IrProgram::new();
    b.next_var = 7;
    b.instructions.push(Instruction::Input {
        result: SsaVar(0),
        name: "x".into(),
        visibility: Visibility::Public,
    });
    b.instructions.push(Instruction::Const {
        result: SsaVar(1),
        value: fe(3),
    });
    b.instructions.push(Instruction::Mul {
        result: SsaVar(6),
        lhs: SsaVar(0),
        rhs: SsaVar(1),
    });

    let qa = canonicalize_ssa(&a);
    let qb = canonicalize_ssa(&b);

    assert_eq!(qa.next_var, qb.next_var);
    assert_eq!(qa.instructions.len(), qb.instructions.len());
    for (x, y) in qa.instructions.iter().zip(qb.instructions.iter()) {
        assert_eq!(format!("{x}"), format!("{y}"));
    }
}

#[test]
fn canonicalize_does_not_mutate_input() {
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 33;
    p.instructions.push(Instruction::Const {
        result: SsaVar(33),
        value: fe(1),
    });
    let snapshot = format!("{p}");
    let snapshot_next = p.next_var;

    let _q = canonicalize_ssa(&p);

    assert_eq!(format!("{p}"), snapshot);
    assert_eq!(p.next_var, snapshot_next);
}

#[test]
fn canonicalize_leaves_undefined_operands_unchanged() {
    // Malformed program: Add references SsaVar(99) which is not defined.
    // canonicalize should not panic; the undefined operand stays as-is.
    let mut p: IrProgram<Bn254Fr> = IrProgram::new();
    p.next_var = 100;
    p.instructions.push(Instruction::Const {
        result: SsaVar(10),
        value: fe(1),
    });
    p.instructions.push(Instruction::Add {
        result: SsaVar(20),
        lhs: SsaVar(10),
        rhs: SsaVar(99),
    });

    let q = canonicalize_ssa(&p);

    match &q.instructions[1] {
        Instruction::Add { result, lhs, rhs } => {
            assert_eq!(*result, SsaVar(1));
            assert_eq!(*lhs, SsaVar(0));
            assert_eq!(*rhs, SsaVar(99)); // unchanged
        }
        _ => panic!("expected Add"),
    }
}
