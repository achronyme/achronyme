use super::super::{CircuitStats, ConstraintCategory};
use crate::types::{Instruction, IrProgram, Visibility};
use memory::Bn254Fr;

use super::empty_proven;

#[test]
fn empty_program() {
    let prog: IrProgram<Bn254Fr> = IrProgram::new();
    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.name, "<anonymous>");
    assert_eq!(stats.total_constraints, 0);
    assert_eq!(stats.n_public, 0);
    assert_eq!(stats.n_witness, 0);
    assert_eq!(stats.n_instructions, 0);
}

#[test]
fn named_circuit() {
    let prog: IrProgram<Bn254Fr> = IrProgram::new();
    let stats = CircuitStats::from_program(&prog, &empty_proven(), Some("my_circuit"));
    assert_eq!(stats.name, "my_circuit");
}

#[test]
fn input_counts() {
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
    prog.push(Instruction::Input {
        result: v2,
        name: "z".into(),
        visibility: Visibility::Public,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.n_public, 2);
    assert_eq!(stats.n_witness, 1);
    assert_eq!(stats.total_constraints, 0);
}

#[test]
fn mul_costs_one() {
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
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 1);
    assert_eq!(stats.n_instructions, 1);
    let arith = stats
        .categories
        .iter()
        .find(|c| c.category == ConstraintCategory::Arithmetic)
        .unwrap();
    assert_eq!(arith.constraints, 1);
    assert_eq!(arith.count, 1);
}

#[test]
fn div_costs_two() {
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
    prog.push(Instruction::Div {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 2);
}

#[test]
fn assert_eq_costs_one() {
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
        visibility: Visibility::Public,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::AssertEq {
        result: v2,
        lhs: v0,
        rhs: v1,
        message: None,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 1);
}

#[test]
fn range_check_cost() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::RangeCheck {
        result: v1,
        operand: v0,
        bits: 64,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    // 64 boolean + 1 sum = 65
    assert_eq!(stats.total_constraints, 65);
}

#[test]
fn poseidon_costs_362() {
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
    prog.push(Instruction::PoseidonHash {
        result: v2,
        left: v0,
        right: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 361);
    let hash = stats
        .categories
        .iter()
        .find(|c| c.category == ConstraintCategory::Hash)
        .unwrap();
    assert_eq!(hash.constraints, 361);
}

#[test]
fn is_eq_costs_two() {
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
    prog.push(Instruction::IsEq {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    assert_eq!(stats.total_constraints, 2);
}

#[test]
fn is_lt_bounded_cost() {
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
    prog.push(Instruction::IsLtBounded {
        result: v2,
        lhs: v0,
        rhs: v1,
        bitwidth: 8,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    // 1 materialize + 9 boolean + 1 sum = 11
    assert_eq!(stats.total_constraints, 11);
}

#[test]
fn is_lt_unbounded_no_range_check() {
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
    prog.push(Instruction::IsLt {
        result: v2,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    // Both unbounded: 253 + 253 + 255 = 761
    assert_eq!(stats.total_constraints, 761);
}

#[test]
fn is_lt_with_range_bounds() {
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
    // Range check both to 8 bits
    let v2 = prog.fresh_var();
    prog.push(Instruction::RangeCheck {
        result: v2,
        operand: v0,
        bits: 8,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::RangeCheck {
        result: v3,
        operand: v1,
        bits: 8,
    });
    let v4 = prog.fresh_var();
    prog.push(Instruction::IsLt {
        result: v4,
        lhs: v0,
        rhs: v1,
    });

    let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
    // 2x RangeCheck(8) = 2*(8+1) = 18
    // IsLt with bounds max(8,8) = 8+3 = 11
    // Total = 29
    assert_eq!(stats.total_constraints, 29);
}
