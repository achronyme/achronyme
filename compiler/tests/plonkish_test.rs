use std::collections::HashMap;

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use ir::types::{Instruction, IrProgram, Visibility};
use memory::FieldElement;

/// Helper: compile IR, generate witness, verify.
fn compile_and_verify(
    program: &IrProgram,
    inputs: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler
        .system
        .verify()
        .expect("verification failed");
    compiler
}

/// Helper: build program from source string via IR lowering.
fn compile_source(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let program = ir::IrLowering::lower_circuit(source, public, witness).unwrap();
    compile_and_verify(&program, inputs)
}

// ============================================================================
// Basic instruction tests
// ============================================================================

#[test]
fn test_const_no_rows() {
    let mut program = IrProgram::new();
    let v = program.fresh_var();
    program.push(Instruction::Const {
        result: v,
        value: FieldElement::from_u64(42),
    });

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(compiler.num_circuit_rows(), 0);
}

#[test]
fn test_input_public() {
    let mut program = IrProgram::new();
    let v = program.fresh_var();
    program.push(Instruction::Input {
        result: v,
        name: "x".into(),
        visibility: Visibility::Public,
    });

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(7));

    let compiler = compile_and_verify(&program, &inputs);
    assert!(compiler.public_inputs.contains(&"x".to_string()));
}

#[test]
fn test_input_witness() {
    let mut program = IrProgram::new();
    let v = program.fresh_var();
    program.push(Instruction::Input {
        result: v,
        name: "w".into(),
        visibility: Visibility::Witness,
    });

    let mut inputs = HashMap::new();
    inputs.insert("w".to_string(), FieldElement::from_u64(99));

    let compiler = compile_and_verify(&program, &inputs);
    assert!(compiler.witnesses.contains(&"w".to_string()));
}

#[test]
fn test_add_deferred() {
    // x + y should produce a deferred add (materialized on demand)
    let mut program = IrProgram::new();
    let x = program.fresh_var();
    program.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: Visibility::Witness,
    });
    let y = program.fresh_var();
    program.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    let sum = program.fresh_var();
    program.push(Instruction::Add {
        result: sum,
        lhs: x,
        rhs: y,
    });
    // Force materialization via assert_eq
    let const42 = program.fresh_var();
    program.push(Instruction::Const {
        result: const42,
        value: FieldElement::from_u64(42),
    });
    let eq = program.fresh_var();
    program.push(Instruction::AssertEq {
        result: eq,
        lhs: sum,
        rhs: const42,
    });

    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(20));
    inputs.insert("y".to_string(), FieldElement::from_u64(22));
    compile_and_verify(&program, &inputs);
}

#[test]
fn test_mul_one_row() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = a * b
        assert_eq(c, out)
    "#;
    let compiler = compile_source(source, &["out"], &["a", "b"], &inputs);
    // Mul produces 1 arith row (at minimum)
    assert!(compiler.num_circuit_rows() >= 1);
}

#[test]
fn test_mul_const_no_row() {
    // Multiplying two constants should be folded, producing 0 arith rows
    let mut program = IrProgram::new();
    let a = program.fresh_var();
    program.push(Instruction::Const {
        result: a,
        value: FieldElement::from_u64(6),
    });
    let b = program.fresh_var();
    program.push(Instruction::Const {
        result: b,
        value: FieldElement::from_u64(7),
    });
    let c = program.fresh_var();
    program.push(Instruction::Mul {
        result: c,
        lhs: a,
        rhs: b,
    });

    let mut compiler = PlonkishCompiler::new();
    compiler.compile_ir(&program).unwrap();
    assert_eq!(compiler.num_circuit_rows(), 0);
}

#[test]
fn test_div_two_rows() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("y".to_string(), FieldElement::from_u64(6));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = x / y
        assert_eq(c, out)
    "#;
    let compiler = compile_source(source, &["out"], &["x", "y"], &inputs);
    // Division produces at least 2 arith rows
    assert!(compiler.num_circuit_rows() >= 2);
}

#[test]
fn test_mux_rows() {
    let mut inputs = HashMap::new();
    inputs.insert("cond".to_string(), FieldElement::ONE);
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("b".to_string(), FieldElement::from_u64(20));
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let r = mux(cond, a, b)
        assert_eq(r, out)
    "#;
    let compiler = compile_source(source, &["out"], &["cond", "a", "b"], &inputs);
    assert!(compiler.num_circuit_rows() >= 2);
}

#[test]
fn test_assert_eq_copy() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(42));
    inputs.insert("y".to_string(), FieldElement::from_u64(42));

    let source = r#"
        assert_eq(x, y)
    "#;
    let compiler = compile_source(source, &[], &["x", "y"], &inputs);
    // assert_eq should produce at least 1 copy constraint
    assert!(!compiler.system.copies.is_empty());
}

// ============================================================================
// IR-level circuit tests
// ============================================================================

#[test]
fn test_ir_simple_mul() {
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(42));
    inputs.insert("a".to_string(), FieldElement::from_u64(6));
    inputs.insert("b".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let c = a * b
        assert_eq(c, out)
    "#;
    compile_source(source, &["out"], &["a", "b"], &inputs);
}

#[test]
fn test_ir_quadratic() {
    // x^2 + x + 5 = 35 → x = 5
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(35));
    inputs.insert("x".to_string(), FieldElement::from_u64(5));

    let source = r#"
        let y = x^2 + x + 5
        assert_eq(y, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_ir_for_unroll() {
    // Accumulate: sum = 1 + 2 + 3 + 4 = 10
    let mut inputs = HashMap::new();
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let acc = 0
        for i in 1..5 {
            let acc = acc + i
        }
        assert_eq(acc, out)
    "#;
    compile_source(source, &["out"], &[], &inputs);
}

#[test]
fn test_ir_negation() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::from_u64(10));

    let source = r#"
        let y = -(-x)
        assert_eq(y, out)
    "#;
    compile_source(source, &["out"], &["x"], &inputs);
}

#[test]
fn test_ir_subtraction() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(3));
    inputs.insert("out".to_string(), FieldElement::from_u64(7));

    let source = r#"
        let r = x - y
        assert_eq(r, out)
    "#;
    compile_source(source, &["out"], &["x", "y"], &inputs);
}
