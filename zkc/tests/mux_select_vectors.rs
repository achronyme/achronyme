//! Phase III — Mux/Select Circuit Vectors (R1CS, BN254 Fr)
//!
//! Exhaustive truth table and algebraic property validation for the Mux instruction.
//! Formula: result = cond * (if_true - if_false) + if_false
//!   cond=1 → if_true, cond=0 → if_false
//!
//! Industry sources:
//!   - ZoKrates stdlib (LGPL-3.0): N-way multiplexer patterns
//!     https://zokrates.github.io/toolbox/stdlib.html
//!   - gnark std (Apache-2.0): frontend.Variable selector gadget
//!     https://github.com/Consensys/gnark
//!   - arkworks r1cs-std (MIT/Apache-2.0): CondSelectGadget
//!     https://github.com/arkworks-rs/r1cs-std
//!   - 0xPARC zk-bug-tracker: under-constrained mux vulnerabilities
//!     https://github.com/0xPARC/zk-bug-tracker
//!
//! Note: only numerical test vectors (not code) are used here.
//! These are facts, not copyrightable expression — compatible with our Apache-2.0.

pub use std::collections::HashMap;

pub use ir::passes::bool_prop::compute_proven_boolean;
pub use ir::IrLowering;
pub use memory::FieldElement;
pub use zkc::r1cs_backend::R1CSCompiler;

// ============================================================================
// Helpers
// ============================================================================

pub(crate) fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

pub(crate) fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

/// BN254 scalar field order minus 1 (the maximum field element).
pub(crate) fn p_minus_1() -> FieldElement {
    fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495616")
}

/// BN254 scalar field order minus 2.
pub(crate) fn p_minus_2() -> FieldElement {
    fe_str("21888242871839275222246405745257275088548364400416034343698204186575808495615")
}

pub(crate) fn compile_and_verify(source: &str, inputs: &[(&str, FieldElement)]) -> usize {
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

pub(crate) fn compile_expect_fail(source: &str, inputs: &[(&str, FieldElement)]) {
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

pub(crate) const MUX_SOURCE: &str =
    "witness cond\nwitness a\nwitness b\npublic out\nassert_eq(mux(cond, a, b), out)";

pub(crate) const MUX4_SOURCE: &str = "\
witness s0\nwitness s1\n\
witness v0\nwitness v1\nwitness v2\nwitness v3\n\
public out\n\
let lo = mux(s0, v1, v0)\n\
let hi = mux(s0, v3, v2)\n\
assert_eq(mux(s1, hi, lo), out)";

/// Macro for parameterized mux tests with explicit expected value.
macro_rules! mux_tests {
    ($(($name:ident, $cond:expr, $a:expr, $b:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                let a_val: FieldElement = $a;
                let b_val: FieldElement = $b;
                let cond_val: u64 = $cond;
                let expected = if cond_val == 1 { a_val } else { b_val };
                compile_and_verify(
                    MUX_SOURCE,
                    &[("cond", fe(cond_val)), ("a", a_val), ("b", b_val), ("out", expected)],
                );
            }
        )*
    };
}

/// Macro for mux property tests (no output — uses assert_eq internally).
macro_rules! mux_property_tests {
    ($(($name:ident, $source:expr, $inputs:expr)),* $(,)?) => {
        $(
            #[test]
            fn $name() {
                compile_and_verify($source, &$inputs);
            }
        )*
    };
}

#[path = "mux_select_vectors/arithmetic_conditions.rs"]
mod arithmetic_conditions;
#[path = "mux_select_vectors/constants_counts.rs"]
mod constants_counts;
#[path = "mux_select_vectors/idempotence_complement.rs"]
mod idempotence_complement;
#[path = "mux_select_vectors/if_linearity_stress.rs"]
mod if_linearity_stress;
#[path = "mux_select_vectors/nested_multiway.rs"]
mod nested_multiway;
#[path = "mux_select_vectors/soundness.rs"]
mod soundness;
#[path = "mux_select_vectors/truth_boundaries.rs"]
mod truth_boundaries;
