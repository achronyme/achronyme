//! Phase III — Division / Modular Inverse Circuit Vectors (R1CS, BN254 Fr)
//!
//! Exhaustive validation of the Div instruction which computes modular
//! multiplicative inverse: a / b = a * b^{-1} mod r.
//!
//! Achronyme does NOT have integer division. All division is field inversion.
//! Div(x, 0) must induce catastrophic failure at witness generation time.
//!
//! Industry sources:
//!   - gnark std (Apache-2.0): Div gadget + modular inverse
//!     https://github.com/Consensys/gnark
//!   - arkworks r1cs-std (MIT/Apache-2.0): AllocatedFp::inverse()
//!     https://github.com/arkworks-rs/r1cs-std
//!   - Noir stdlib (MIT/Apache-2.0): field div + inverse
//!     https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/field/mod.nr
//!   - circomspect (trailofbits): under-constrained division analysis
//!     https://github.com/trailofbits/circomspect
//!

use std::collections::HashMap;

use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

/// BN254 scalar field order minus 1.
fn p_minus_1() -> FieldElement {
    fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616")
}

/// BN254 scalar field order minus 2.
fn p_minus_2() -> FieldElement {
    fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495615")
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

const DIV_SOURCE: &str = "public out\nwitness a\nwitness b\nassert_eq(a / b, out)";

/// Macro for parameterized division tests.
macro_rules! div_tests {
    ($(($name:ident, $a:expr, $b:expr, $expected:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify(
                    DIV_SOURCE,
                    &[("a", $a), ("b", $b), ("out", $expected)],
                );
            }
        )*
    };
}

/// Macro for division property tests (circuit with assert_eq, no public out).
macro_rules! div_property_tests {
    ($(($name:ident, $source:expr, $inputs:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify($source, &$inputs);
            }
        )*
    };
}

#[path = "division_vectors/boundary.rs"]
mod boundary;
#[path = "division_vectors/combinations.rs"]
mod combinations;
#[path = "division_vectors/identity.rs"]
mod identity;
#[path = "division_vectors/inverse.rs"]
mod inverse;
#[path = "division_vectors/soundness.rs"]
mod soundness;
