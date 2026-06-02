use std::collections::HashSet;

use super::super::{CircuitStats, ConstraintCategory};
use crate::types::{Instruction, IrProgram, Visibility};
use memory::Bn254Fr;

use super::empty_proven;

#[test]
fn assert_with_proven_boolean() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Assert {
        result: v1,
        operand: v0,
        message: None,
    });

    // Without proven boolean: 1 enforce + 1 boolean = 2
    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 2);

    // With proven boolean: 1 enforce, no boolean enforcement
    let mut proven = HashSet::new();
    proven.insert(v0);
    let stats = CircuitStats::from_program(&prog, &proven, None);
    assert_eq!(stats.total_constraints, 1);
}

#[test]
fn not_with_proven_boolean_is_free() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Not {
        result: v1,
        operand: v0,
    });

    // Proven boolean: Not is free (just 1 - x)
    let mut proven = HashSet::new();
    proven.insert(v0);
    let stats = CircuitStats::from_program(&prog, &proven, None);
    assert_eq!(stats.total_constraints, 0);
    assert_eq!(stats.n_instructions, 0); // skipped entirely
}

#[test]
fn mux_with_proven_cond() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "c".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v2,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::Mux {
        result: v3,
        cond: v0,
        if_true: v1,
        if_false: v2,
    });

    // Without proven: 1 materialize(diff) + 1 mul + 1 bool = 3
    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 3);

    // With proven cond: 1 materialize(diff) + 1 mul = 2
    let mut proven = HashSet::new();
    proven.insert(v0);
    let stats = CircuitStats::from_program(&prog, &proven, None);
    assert_eq!(stats.total_constraints, 2);
}

#[test]
fn mixed_circuit_total() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let x = prog.fresh_var();
    prog.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    let y = prog.fresh_var();
    prog.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    // x * y
    let mul = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: mul,
        lhs: x,
        rhs: y,
    });
    // poseidon(x, y)
    let hash = prog.fresh_var();
    prog.push(Instruction::PoseidonHash {
        result: hash,
        left: x,
        right: y,
    });
    // assert_eq(mul, hash)
    let eq = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: eq,
        lhs: mul,
        rhs: hash,
        message: None,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    // Mul=1, PoseidonHash=361, AssertEq=1 → total=363
    assert_eq!(stats.total_constraints, 363);
    assert_eq!(stats.n_public, 1);
    assert_eq!(stats.n_witness, 1);
    assert_eq!(stats.n_instructions, 3);
}

#[test]
fn add_sub_neg_are_free() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Add {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::Sub {
        result: v3,
        lhs: v0,
        rhs: v1,
    });
    let v4 = prog.fresh_var();
    prog.push(Instruction::Neg {
        result: v4,
        operand: v0,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 0);
    assert_eq!(stats.n_instructions, 0);
}

#[test]
fn bottleneck_is_highest_cost() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    // Mul = 1 constraint
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    // Poseidon = 362 constraints
    let v3 = prog.fresh_var();
    prog.push(Instruction::PoseidonHash {
        result: v3,
        left: v0,
        right: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    let bottleneck = stats.bottleneck().unwrap();
    assert_eq!(bottleneck.category, ConstraintCategory::Hash);
    assert_eq!(bottleneck.constraints, 361);
}

#[test]
fn display_format() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: Visibility::Public,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), Some("test_circuit"));
    let output = format!("{stats}");
    assert!(output.contains("test_circuit"));
    assert!(output.contains("1 public"));
    assert!(output.contains("1 witness"));
    assert!(output.contains("Arithmetic"));
    assert!(output.contains("TOTAL"));
}

#[test]
fn and_or_boolean_enforcement_cost() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::And {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    // No proven boolean: 1 mul + 2 bool enforcement = 3
    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 3);

    // Both proven: 1 mul only
    let mut proven = HashSet::new();
    proven.insert(v0);
    proven.insert(v1);
    let stats = CircuitStats::from_program(&prog, &proven, None);
    assert_eq!(stats.total_constraints, 1);
}

#[test]
fn is_lt_one_bound_one_unbound() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    // Only range check v0
    let v2 = prog.fresh_var();
    prog.push(Instruction::RangeCheck {
        result: v2,
        operand: v0,
        bits: 8,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::IsLt {
        result: v3,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    // RangeCheck(8) = 9
    // IsLt: bound_a=Some(8), bound_b=None → 253 + 255 = 508
    // Total = 9 + 508 = 517
    assert_eq!(stats.total_constraints, 517);
}
