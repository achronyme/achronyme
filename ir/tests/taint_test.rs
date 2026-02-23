use ir::passes::taint::{taint_analysis, Taint, TaintWarning};
use ir::types::{Instruction, IrProgram, SsaVar, Visibility};
use memory::FieldElement;

/// Helper: build a program manually.
fn prog(instructions: Vec<Instruction>, next_var: u32) -> IrProgram {
    IrProgram {
        instructions,
        next_var,
        var_names: std::collections::HashMap::new(),
        var_types: std::collections::HashMap::new(),
    }
}

#[test]
fn taint_constant_expr() {
    // let a = 3; let b = 4; let c = a + b  — all constant, no warnings
    let p = prog(
        vec![
            Instruction::Const {
                result: SsaVar(0),
                value: FieldElement::from_u64(3),
            },
            Instruction::Const {
                result: SsaVar(1),
                value: FieldElement::from_u64(4),
            },
            Instruction::Add {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            },
        ],
        3,
    );
    let (taints, warnings) = taint_analysis(&p);
    assert_eq!(taints[&SsaVar(0)], Taint::Constant);
    assert_eq!(taints[&SsaVar(1)], Taint::Constant);
    assert_eq!(taints[&SsaVar(2)], Taint::Constant);
    assert!(warnings.is_empty());
}

#[test]
fn taint_public_propagation() {
    // public x; let r = x + 1 → r is Public
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "x".into(),
                visibility: Visibility::Public,
            },
            Instruction::Const {
                result: SsaVar(1),
                value: FieldElement::ONE,
            },
            Instruction::Add {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            },
            Instruction::Const {
                result: SsaVar(3),
                value: FieldElement::from_u64(42),
            },
            Instruction::AssertEq {
                result: SsaVar(4),
                lhs: SsaVar(2),
                rhs: SsaVar(3),
            },
        ],
        5,
    );
    let (taints, warnings) = taint_analysis(&p);
    assert_eq!(taints[&SsaVar(0)], Taint::Public);
    assert_eq!(taints[&SsaVar(2)], Taint::Public);
    assert!(warnings.is_empty(), "x flows to assert_eq transitively");
}

#[test]
fn taint_witness_wins() {
    // public x; witness a; let r = x + a → r is Witness
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "x".into(),
                visibility: Visibility::Public,
            },
            Instruction::Input {
                result: SsaVar(1),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Add {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            },
            Instruction::Const {
                result: SsaVar(3),
                value: FieldElement::from_u64(10),
            },
            Instruction::AssertEq {
                result: SsaVar(4),
                lhs: SsaVar(2),
                rhs: SsaVar(3),
            },
        ],
        5,
    );
    let (taints, warnings) = taint_analysis(&p);
    assert_eq!(taints[&SsaVar(2)], Taint::Witness);
    assert!(warnings.is_empty());
}

#[test]
fn taint_unconstrained_warning() {
    // witness a; let b = a + 1 — used but not constrained
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Const {
                result: SsaVar(1),
                value: FieldElement::ONE,
            },
            Instruction::Add {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            },
        ],
        3,
    );
    let (_, warnings) = taint_analysis(&p);
    assert_eq!(warnings.len(), 1);
    assert!(matches!(&warnings[0], TaintWarning::UnderConstrained { name, .. } if name == "a"));
}

#[test]
fn taint_unused_input_warning() {
    // witness a; assert_eq(1, 1) — a never used
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Const {
                result: SsaVar(1),
                value: FieldElement::ONE,
            },
            Instruction::Const {
                result: SsaVar(2),
                value: FieldElement::ONE,
            },
            Instruction::AssertEq {
                result: SsaVar(3),
                lhs: SsaVar(1),
                rhs: SsaVar(2),
            },
        ],
        4,
    );
    let (_, warnings) = taint_analysis(&p);
    assert_eq!(warnings.len(), 1);
    assert!(matches!(&warnings[0], TaintWarning::UnusedInput { name, .. } if name == "a"));
}

#[test]
fn taint_transitive_constraint() {
    // witness a; let b = a + 1; assert_eq(b, 42) → a is constrained transitively
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Const {
                result: SsaVar(1),
                value: FieldElement::ONE,
            },
            Instruction::Add {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            },
            Instruction::Const {
                result: SsaVar(3),
                value: FieldElement::from_u64(42),
            },
            Instruction::AssertEq {
                result: SsaVar(4),
                lhs: SsaVar(2),
                rhs: SsaVar(3),
            },
        ],
        5,
    );
    let (_, warnings) = taint_analysis(&p);
    assert!(
        warnings.is_empty(),
        "a should be constrained via b → assert_eq"
    );
}

#[test]
fn taint_merkle_no_warnings() {
    // Full Merkle proof circuit — all inputs should be constrained
    use ir::IrLowering;

    let source = r#"
let l0 = mux(d0, s0, leaf)
let r0 = mux(d0, leaf, s0)
let h0 = poseidon(l0, r0)

let l1 = mux(d1, s1, h0)
let r1 = mux(d1, h0, s1)
let h1 = poseidon(l1, r1)

let l2 = mux(d2, s2, h1)
let r2 = mux(d2, h1, s2)
let h2 = poseidon(l2, r2)

assert_eq(h2, root)
"#;

    let program = IrLowering::lower_circuit(
        source,
        &["root"],
        &["leaf", "s0", "s1", "s2", "d0", "d1", "d2"],
    )
    .unwrap();

    let (_, warnings) = taint_analysis(&program);
    assert!(
        warnings.is_empty(),
        "Merkle circuit should have no warnings, got: {warnings:?}"
    );
}

#[test]
fn taint_self_contained_no_warnings() {
    use ir::IrLowering;

    let source = r#"
public root
witness leaf
witness s0, s1, s2
witness d0, d1, d2

let l0 = mux(d0, s0, leaf)
let r0 = mux(d0, leaf, s0)
let h0 = poseidon(l0, r0)

let l1 = mux(d1, s1, h0)
let r1 = mux(d1, h0, s1)
let h1 = poseidon(l1, r1)

let l2 = mux(d2, s2, h1)
let r2 = mux(d2, h1, s2)
let h2 = poseidon(l2, r2)

assert_eq(h2, root)
"#;

    let (_, _, program) = IrLowering::lower_self_contained(source).unwrap();
    let (_, warnings) = taint_analysis(&program);
    assert!(
        warnings.is_empty(),
        "Self-contained Merkle circuit should have no warnings, got: {warnings:?}"
    );
}

#[test]
fn taint_assert_constrains() {
    // witness a; assert(a) — a should be constrained via Assert
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Assert {
                result: SsaVar(1),
                operand: SsaVar(0),
            },
        ],
        2,
    );
    let (_, warnings) = taint_analysis(&p);
    assert!(
        warnings.is_empty(),
        "assert(a) should constrain a, got: {warnings:?}"
    );
}

#[test]
fn taint_is_eq_in_assert() {
    // witness a, b; let eq = a == b; assert(eq)
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Input {
                result: SsaVar(1),
                name: "b".into(),
                visibility: Visibility::Witness,
            },
            Instruction::IsEq {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            },
            Instruction::Assert {
                result: SsaVar(3),
                operand: SsaVar(2),
            },
        ],
        4,
    );
    let (_, warnings) = taint_analysis(&p);
    assert!(
        warnings.is_empty(),
        "assert(a == b) should constrain both a and b, got: {warnings:?}"
    );
}

#[test]
fn taint_not_unconstrained() {
    // witness a; let b = !a — b is not constrained (no assert)
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "a".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Not {
                result: SsaVar(1),
                operand: SsaVar(0),
            },
        ],
        2,
    );
    let (_, warnings) = taint_analysis(&p);
    assert_eq!(warnings.len(), 1, "!a without constraint should warn");
    assert!(matches!(&warnings[0], TaintWarning::UnderConstrained { name, .. } if name == "a"));
}

// ============================================================================
// M8: Sub-self and Div-self taint
// ============================================================================

#[test]
fn taint_sub_self_is_constant() {
    // witness w; let r = w - w → taint of r should be Constant
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "w".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Sub {
                result: SsaVar(1),
                lhs: SsaVar(0),
                rhs: SsaVar(0),
            },
        ],
        2,
    );
    let (taints, _) = taint_analysis(&p);
    assert_eq!(taints[&SsaVar(1)], Taint::Constant);
}

#[test]
fn taint_div_self_is_constant() {
    // witness w; let r = w / w → taint of r should be Constant
    let p = prog(
        vec![
            Instruction::Input {
                result: SsaVar(0),
                name: "w".into(),
                visibility: Visibility::Witness,
            },
            Instruction::Div {
                result: SsaVar(1),
                lhs: SsaVar(0),
                rhs: SsaVar(0),
            },
        ],
        2,
    );
    let (taints, _) = taint_analysis(&p);
    assert_eq!(taints[&SsaVar(1)], Taint::Constant);
}
