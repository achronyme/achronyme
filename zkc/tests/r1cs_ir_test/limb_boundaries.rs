use super::*;

// ============================================================================
// I-04: IsLt/IsLe limb boundary tests at 2^64, 2^128, 2^192
//
// to_canonical() returns little-endian [u64; 4] limbs.
// Comparisons use big-endian tuple: (limbs[3], limbs[2], limbs[1], limbs[0]).
// These tests verify correctness at exact limb transitions where an off-by-one
// in limb ordering would produce reversed results.
// ============================================================================

// --- Circuit path (witness inputs → bit decomposition) ---

#[test]
fn ir_is_lt_limb_boundary_2_64() {
    // 2^64 - 1 < 2^64: crosses limb[0] → limb[1]
    let boundary = pow2(64);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", below), ("b", boundary)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_64_reversed() {
    // 2^64 ≮ 2^64 - 1
    let boundary = pow2(64);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", boundary), ("b", below)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_128() {
    // 2^128 - 1 < 2^128: crosses limb[1] → limb[2]
    let boundary = pow2(128);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", below), ("b", boundary)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_128_reversed() {
    let boundary = pow2(128);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", boundary), ("b", below)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_192() {
    // 2^192 - 1 < 2^192: crosses limb[2] → limb[3]
    let boundary = pow2(192);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", below), ("b", boundary)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_lt_limb_boundary_2_192_reversed() {
    let boundary = pow2(192);
    let below = boundary.sub(&FieldElement::ONE);
    ir_only_verify_fe(
        &[("out", FieldElement::ZERO)],
        &[("a", boundary), ("b", below)],
        "let r = a < b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_limb_boundary_equal_2_64() {
    let v = pow2(64);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", v), ("b", v)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_limb_boundary_equal_2_128() {
    let v = pow2(128);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", v), ("b", v)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

#[test]
fn ir_is_le_limb_boundary_equal_2_192() {
    let v = pow2(192);
    ir_only_verify_fe(
        &[("out", FieldElement::ONE)],
        &[("a", v), ("b", v)],
        "let r = a <= b\nassert_eq(r, out)",
    );
}

// --- Const-fold path (big number literals, optimization folds the comparison) ---

/// Helper: compile with optimization, verify the folded result.
fn const_fold_verify(source: &str) {
    let mut program = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &[]).unwrap();
    ir::passes::optimize(&mut program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    let gen = WitnessGenerator::from_compiler(&compiler);
    let w = gen.generate(&HashMap::new()).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("const-folded assertion should verify");
}

#[test]
fn ir_is_lt_const_fold_limb_2_64() {
    // 2^64 - 1 = 18446744073709551615
    // 2^64     = 18446744073709551616
    const_fold_verify("assert(18446744073709551615 < 18446744073709551616)");
}

#[test]
fn ir_is_lt_const_fold_limb_2_128() {
    // 2^128 - 1 = 340282366920938463463374607431768211455
    // 2^128     = 340282366920938463463374607431768211456
    const_fold_verify(
        "assert(340282366920938463463374607431768211455 < 340282366920938463463374607431768211456)",
    );
}

#[test]
fn ir_is_lt_const_fold_limb_2_192() {
    // 2^192 - 1 = 6277101735386680763835789423207666416102355444464034512895
    // 2^192     = 6277101735386680763835789423207666416102355444464034512896
    const_fold_verify("assert(6277101735386680763835789423207666416102355444464034512895 < 6277101735386680763835789423207666416102355444464034512896)");
}

#[test]
fn ir_is_lt_const_fold_near_modulus() {
    // p - 2 < p - 1 (near the BN254 scalar field modulus)
    // p - 1 = 21888242871839275222246405745257275088548364400416034343698204186575808495616
    // p - 2 = 21888242871839275222246405745257275088548364400416034343698204186575808495615
    const_fold_verify("assert(21888242871839275222246405745257275088548364400416034343698204186575808495615 < 21888242871839275222246405745257275088548364400416034343698204186575808495616)");
}

#[test]
fn ir_is_le_const_fold_near_modulus() {
    // p - 1 <= p - 1
    const_fold_verify("assert(21888242871839275222246405745257275088548364400416034343698204186575808495616 <= 21888242871839275222246405745257275088548364400416034343698204186575808495616)");
}

#[test]
fn ir_is_lt_const_fold_limb_2_64_false() {
    // 2^64 ≮ 2^64 - 1 → const_fold produces false → assert(false) → verification fails
    let source = "assert(18446744073709551616 < 18446744073709551615)";
    let mut program = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &[]).unwrap();
    ir::passes::optimize(&mut program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    let gen = WitnessGenerator::from_compiler(&compiler);
    let w = gen.generate(&HashMap::new()).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "2^64 < 2^64-1 should be false, assert must fail"
    );
}
