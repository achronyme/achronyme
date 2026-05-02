//! Frozen-baseline smoke pins.
//!
//! Validates the `zkc::test_support::compute_frozen_baseline` machinery
//! by pinning canonical-multiset hashes for three small `.ach` circuits.
//! These are smoke tests for the helper plumbing — the main pinning
//! work for the circomlib benchmark templates + prove-block fixtures
//! lives in `circom/tests/cross_path_baseline.rs` and
//! `cli/tests/cross_path_prove_baseline.rs`.
//!
//! ## Why pin smoke fixtures here too
//!
//! The `test_support` helpers themselves need a regression gate —
//! if `compute_frozen_baseline` ever changes its hash derivation
//! (e.g., a refactor of `canonical_multiset_hash`'s byte layout),
//! these smoke pins surface it before the larger fixture set has
//! to re-pin.
//!
//! ## Re-generating pinned values
//!
//! When the optimizer or canonicalization changes intentionally:
//! ```ignore
//! REGEN_FROZEN_BASELINES=1 cargo test --release -p zkc \
//!     --test frozen_baseline -- --nocapture
//! ```
//! Then copy the printed `FrozenBaseline { ... }` literal into the
//! `expected` constant. **Verify the new pin is intentional** — every
//! re-pin is a regression suppressed.

use ir::IrLowering;
use memory::FieldElement;
use zkc::test_support::{assert_frozen_baseline_matches, compute_frozen_baseline, FrozenBaseline};

/// Helper: run baseline pin or print regen value depending on env.
/// Mirrors the "golden file" pattern documented in the module
/// docstring — `REGEN_FROZEN_BASELINES=1` skips assertion and
/// prints the literal to copy.
fn check_pin(label: &str, actual: &FrozenBaseline, expected: &FrozenBaseline) {
    if std::env::var("REGEN_FROZEN_BASELINES").is_ok() {
        println!("\n=== regen baseline for `{label}` ===");
        println!("FrozenBaseline {{");
        println!("    pre_o1_hash: {:?},", actual.pre_o1_hash);
        println!("    pre_o1_count: {},", actual.pre_o1_count);
        println!("    post_o1_hash: {:?},", actual.post_o1_hash);
        println!("    post_o1_count: {},", actual.post_o1_count);
        println!("    num_variables: {},", actual.num_variables);
        println!("    public_inputs: {:?},", actual.public_inputs);
        println!("}}\n");
        return;
    }
    assert_frozen_baseline_matches(actual, expected);
}

// ============================================================================
// Smoke 1: simple multiplication assertion
// ============================================================================

#[test]
fn pin_simple_mul() {
    let mut program = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
    )
    .expect("lower simple mul");
    ir::passes::optimize(&mut program);

    let actual = compute_frozen_baseline(&program);
    let expected = FrozenBaseline {
        pre_o1_hash: PIN_SIMPLE_MUL_PRE,
        pre_o1_count: 2,
        post_o1_hash: PIN_SIMPLE_MUL_POST,
        post_o1_count: 1,
        num_variables: 5,
        public_inputs: vec!["out".to_string()],
    };
    check_pin("pin_simple_mul", &actual, &expected);
}

// ============================================================================
// Smoke 2: chained add-then-assert (exercises optimizer fold)
// ============================================================================

#[test]
fn pin_add_chain() {
    let mut program = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "assert_eq(a + b + c, out)",
        &["out"],
        &["a", "b", "c"],
    )
    .expect("lower add chain");
    ir::passes::optimize(&mut program);

    let actual = compute_frozen_baseline(&program);
    let expected = FrozenBaseline {
        pre_o1_hash: PIN_ADD_CHAIN_PRE,
        pre_o1_count: 1,
        post_o1_hash: PIN_ADD_CHAIN_POST,
        post_o1_count: 0,
        num_variables: 5,
        public_inputs: vec!["out".to_string()],
    };
    check_pin("pin_add_chain", &actual, &expected);
}

// ============================================================================
// Smoke 3: range check (exercises a non-trivial constraint pattern)
// ============================================================================

#[test]
fn pin_mul_then_assert_with_range() {
    let mut program = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "let p = a * b\nrange_check(p, 16)\nassert_eq(p, out)",
        &["out"],
        &["a", "b"],
    )
    .expect("lower mul + range_check");
    ir::passes::optimize(&mut program);

    let actual = compute_frozen_baseline(&program);
    let expected = FrozenBaseline {
        pre_o1_hash: PIN_MUL_RANGE_PRE,
        pre_o1_count: 19,
        post_o1_hash: PIN_MUL_RANGE_POST,
        post_o1_count: 17,
        num_variables: 21,
        public_inputs: vec!["out".to_string()],
    };
    check_pin("pin_mul_then_assert_with_range", &actual, &expected);
}

// ============================================================================
// Sanity: machinery itself
// ============================================================================

/// Two compiles of the same source must produce byte-identical
/// `FrozenBaseline` (the canonical-multiset hash is deterministic).
/// This is the regression gate for the `canonical_multiset_hash`
/// byte-layout — if it ever becomes order-sensitive again, this fails.
#[test]
fn baseline_is_deterministic() {
    let make = || {
        let mut p = IrLowering::<memory::Bn254Fr>::lower_circuit(
            "assert_eq(a * b, out)",
            &["out"],
            &["a", "b"],
        )
        .unwrap();
        ir::passes::optimize(&mut p);
        compute_frozen_baseline(&p)
    };
    let a = make();
    let b = make();
    assert_eq!(a, b, "baseline must be deterministic across runs");
}

/// Different programs must produce different baselines (sanity for
/// hash discrimination — a buggy hash that returns a constant would
/// make every other test pass vacuously).
#[test]
fn baseline_discriminates_different_programs() {
    let mul = {
        let mut p = IrLowering::<memory::Bn254Fr>::lower_circuit(
            "assert_eq(a * b, out)",
            &["out"],
            &["a", "b"],
        )
        .unwrap();
        ir::passes::optimize(&mut p);
        compute_frozen_baseline(&p)
    };
    let add = {
        let mut p = IrLowering::<memory::Bn254Fr>::lower_circuit(
            "assert_eq(a + b + c, out)",
            &["out"],
            &["a", "b", "c"],
        )
        .unwrap();
        ir::passes::optimize(&mut p);
        compute_frozen_baseline(&p)
    };
    assert_ne!(
        mul.pre_o1_hash, add.pre_o1_hash,
        "different programs share hash"
    );
}

/// Witness satisfaction sanity — once the baseline is pinned, the
/// underlying R1CS must still be solvable. Catches the case where a
/// pin freezes a corrupted optimizer state.
#[test]
fn pinned_program_still_solvable() {
    use std::collections::HashMap;

    use zkc::r1cs_backend::R1CSCompiler;
    use zkc::witness::WitnessGenerator;

    let mut program = IrLowering::<memory::Bn254Fr>::lower_circuit(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
    )
    .unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::<memory::Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(7));
    inputs.insert("b".to_string(), FieldElement::from_u64(11));
    inputs.insert("out".to_string(), FieldElement::from_u64(77));

    let w = WitnessGenerator::from_compiler(&compiler)
        .generate(&inputs)
        .unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("R1CS must verify on solved witness");
}

// ============================================================================
// Pinned canonical-multiset hashes
// ============================================================================
//
// These literals are filled in via `REGEN_FROZEN_BASELINES=1`. Each
// regen is a documented intentional change — a passing test that
// later starts failing means a regression that needs root-cause, not
// a re-pin.

const PIN_SIMPLE_MUL_PRE: [u8; 32] = [
    103, 62, 152, 139, 48, 217, 149, 137, 115, 187, 194, 183, 248, 72, 219, 141, 87, 137, 70, 171,
    47, 208, 201, 102, 207, 129, 89, 127, 117, 150, 91, 3,
];
const PIN_SIMPLE_MUL_POST: [u8; 32] = [
    217, 207, 0, 42, 164, 232, 81, 250, 143, 157, 168, 11, 57, 228, 116, 121, 130, 145, 135, 226,
    135, 69, 167, 2, 249, 146, 0, 235, 213, 88, 217, 30,
];
const PIN_ADD_CHAIN_PRE: [u8; 32] = [
    181, 240, 120, 148, 86, 237, 169, 18, 165, 117, 22, 121, 162, 28, 105, 233, 231, 1, 6, 202,
    205, 55, 93, 189, 91, 116, 96, 198, 249, 252, 223, 157,
];
const PIN_ADD_CHAIN_POST: [u8; 32] = [
    227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228,
    100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
];
const PIN_MUL_RANGE_PRE: [u8; 32] = [
    199, 117, 115, 26, 75, 171, 157, 58, 126, 253, 218, 8, 126, 229, 20, 149, 118, 153, 135, 197,
    246, 232, 78, 128, 70, 58, 78, 180, 200, 230, 32, 188,
];
const PIN_MUL_RANGE_POST: [u8; 32] = [
    242, 155, 44, 203, 14, 163, 225, 105, 187, 224, 139, 51, 147, 36, 191, 102, 239, 143, 96, 58,
    252, 60, 57, 231, 245, 72, 126, 180, 99, 130, 184, 204,
];
