//! Phase II — Boolean Logic Truth Table Vectors (R1CS, BN254 Fr)
//!
//! Exhaustive truth table validation for And, Or, Not instructions with
//! algebraic property verification following industry methodologies.
//!
//! Industry sources:
//!   - arkworks r1cs-std Boolean<F>:  https://github.com/arkworks-rs/r1cs-std
//!     Canonical boolean enforcement gadget: b*(1-b)=0. (MIT/Apache-2.0)
//!   - Noir stdlib field/mod.nr:      https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!     Boolean operations and truth table patterns. (MIT/Apache-2.0)
//!   - 0xPARC zk-bug-tracker:        https://github.com/0xPARC/zk-bug-tracker
//!     Under-constrained boolean vulnerability catalog.
//!
//! Note: only numerical test vectors (not code) are used here.
//! These are facts, not copyrightable expression — compatible with our Apache-2.0.

use std::collections::HashMap;

use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

#[allow(dead_code)]
fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

fn compile_and_verify(source: &str, inputs: &[(&str, FieldElement)]) -> usize {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let witness = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("R1CS compilation failed");
    compiler
        .cs
        .verify(&witness)
        .expect("R1CS witness verification failed");
    compiler.cs.num_constraints()
}

fn compile_expect_fail(source: &str, inputs: &[(&str, FieldElement)]) {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let result = compiler.compile_ir_with_witness(&program, &input_map);
    if let Ok(witness) = result {
        let verify = compiler.cs.verify(&witness);
        assert!(
            verify.is_err(),
            "expected verification failure but it passed"
        );
    }
}

/// Macro for parameterized binary boolean tests.
macro_rules! bool_binary_tests {
    ($(($name:ident, $source:expr, $a:expr, $b:expr, $expected:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    $source,
                    &[("a", fe($a)), ("b", fe($b)), ("out", fe($expected))],
                );
            }
        )*
    };
}

/// Macro for parameterized binary boolean property tests (no output, uses assert_eq internally).
macro_rules! bool_property_tests {
    ($(($name:ident, $source:expr, $a:expr, $b:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    $source,
                    &[("a", fe($a)), ("b", fe($b))],
                );
            }
        )*
    };
}

/// Macro for parameterized ternary boolean property tests (three witnesses).
macro_rules! bool_ternary_property_tests {
    ($(($name:ident, $source:expr, $a:expr, $b:expr, $c:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    $source,
                    &[("a", fe($a)), ("b", fe($b)), ("c", fe($c))],
                );
            }
        )*
    };
}

#[path = "boolean_vectors/const_fold.rs"]
mod const_fold;
#[path = "boolean_vectors/constraints.rs"]
mod constraints;
#[path = "boolean_vectors/mixed.rs"]
mod mixed;
#[path = "boolean_vectors/properties.rs"]
mod properties;
#[path = "boolean_vectors/soundness.rs"]
mod soundness;
#[path = "boolean_vectors/truth_tables.rs"]
mod truth_tables;
