//! Systematic Malicious Prover Tests
//!
//! These tests simulate an adversarial prover who KNOWS the circuit structure
//! and attempts to forge witnesses that satisfy the constraints while producing
//! incorrect outputs.
//!
//! Unlike proptest (random valid/invalid inputs) and cargo-fuzz (random bytes),
//! these tests directly manipulate the witness vector post-generation to simulate
//! specific attack vectors documented in the ZK vulnerability literature.
//!
//! Attack taxonomy:
//!   A1. Bit flip — corrupt a single wire value
//!   A2. Zero witness — set all intermediate wires to zero
//!   A3. Field boundary — inject p-1 values
//!   A4. Output forgery — change the public output wire
//!   A5. Poseidon state corruption — tamper with hash intermediate wires
//!   A6. Mux condition bypass — non-boolean condition values
//!   A7. Division inverse forgery — wrong modular inverse
//!   A8. Bit decomposition overflow — Dark Forest class attack
//!
//! Reference: 0xPARC zk-bug-tracker, circomspect analysis

#![allow(clippy::needless_range_loop, clippy::manual_swap, unused_mut)]

use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::{Bn254Fr, FieldElement};

// ============================================================================
// Helpers
// ============================================================================

fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

fn p_minus_1() -> FieldElement {
    FieldElement::from_decimal_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    )
    .unwrap()
}

/// Compile a circuit and generate a VALID witness, returning the compiler
/// and witness vector for subsequent manipulation.
fn compile_valid_witness(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &[(&str, FieldElement)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    let mut program = IrLowering::<Bn254Fr>::lower_circuit(source, public, witness).unwrap();
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);

    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let w = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("valid witness gen failed");

    // Sanity: valid witness must pass
    compiler.cs.verify(&w).expect("valid witness must verify");
    (compiler, w)
}

// ============================================================================
// A1. Bit flip attack — corrupt a single wire value
// ============================================================================

#[test]
fn a1_bit_flip_on_mul_output() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Flip the output wire (wire 1)
    w[1] = fe(43);
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A1: flipped output must be rejected"
    );
}

#[test]
fn a1_bit_flip_on_intermediate_wire() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b + c, out)",
        &["out"],
        &["a", "b", "c"],
        &[("out", fe(47)), ("a", fe(6)), ("b", fe(7)), ("c", fe(5))],
    );
    // Wire 0 = ONE, wire 1 = out, wires 2-4 = a,b,c, wire 5+ = intermediates
    // Corrupt an intermediate (the mul result)
    if w.len() > 5 {
        w[5] = w[5].add(&fe(1)); // off by one
        assert!(
            compiler.cs.verify(&w).is_err(),
            "A1: flipped intermediate must be rejected"
        );
    }
}

#[test]
fn a1_bit_flip_every_wire() {
    let (compiler, w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Flip each wire individually — all must fail (except if the flip is a no-op)
    for i in 0..w.len() {
        let mut corrupted = w.clone();
        corrupted[i] = corrupted[i].add(&fe(1));
        // wire 0 is ONE — corrupting it definitely fails
        // Other wires should also fail
        let result = compiler.cs.verify(&corrupted);
        assert!(
            result.is_err(),
            "A1: flipping wire {i} should be rejected (value was {:?})",
            w[i].to_canonical()
        );
    }
}

// ============================================================================
// A2. Zero witness attack — set all intermediates to zero
// ============================================================================

#[test]
fn a2_zero_all_intermediates_mul() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Zero out all intermediate wires (keep ONE, public, witness)
    let n_fixed = 1 + compiler.cs.num_pub_inputs() + 2; // ONE + pub + witnesses
    for i in n_fixed..w.len() {
        w[i] = FieldElement::ZERO;
    }
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A2: zeroed intermediates must be rejected"
    );
}

#[test]
fn a2_zero_all_intermediates_poseidon() {
    let hash = {
        let params = constraints::poseidon::PoseidonParams::bn254_t3();
        constraints::poseidon::poseidon_hash(&params, fe(1), fe(2))
    };
    let (compiler, mut w) = compile_valid_witness(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", hash), ("a", fe(1)), ("b", fe(2))],
    );
    let n_fixed = 1 + 1 + 2; // ONE + expected + a,b
    for i in n_fixed..w.len() {
        w[i] = FieldElement::ZERO;
    }
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A2: zeroed Poseidon intermediates must be rejected"
    );
}

// ============================================================================
// A3. Field boundary injection — inject p-1 into wires
// ============================================================================

#[test]
fn a3_pminus1_as_output() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a + b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(13)), ("a", fe(6)), ("b", fe(7))],
    );
    w[1] = p_minus_1(); // forge output as p-1
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A3: p-1 as output must be rejected when real output is 13"
    );
}

#[test]
fn a3_pminus1_as_witness_input() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    w[2] = p_minus_1(); // forge witness a as p-1
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A3: p-1 as witness input must be rejected"
    );
}

// ============================================================================
// A4. Output forgery — change the public output to a desired value
// ============================================================================

#[test]
fn a4_forge_output_to_one() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    w[1] = fe(1); // attacker wants output to be 1
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A4: forged output = 1 must be rejected"
    );
}

#[test]
fn a4_forge_poseidon_output() {
    let hash = {
        let params = constraints::poseidon::PoseidonParams::bn254_t3();
        constraints::poseidon::poseidon_hash(&params, fe(1), fe(2))
    };
    let (compiler, mut w) = compile_valid_witness(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", hash), ("a", fe(1)), ("b", fe(2))],
    );
    // Try to forge: claim poseidon(1,2) = 0
    w[1] = FieldElement::ZERO;
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A4: forged Poseidon output must be rejected"
    );
}

// ============================================================================
// A5. Poseidon state corruption — tamper with hash intermediates
// ============================================================================

#[test]
fn a5_corrupt_poseidon_sbox_output() {
    let hash = {
        let params = constraints::poseidon::PoseidonParams::bn254_t3();
        constraints::poseidon::poseidon_hash(&params, fe(1), fe(2))
    };
    let (compiler, mut w) = compile_valid_witness(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", hash), ("a", fe(1)), ("b", fe(2))],
    );
    // Corrupt S-box outputs (wires 5-13 are round 0 S-box intermediates)
    // capacity=wire4, first sbox starts at wire5
    for offset in [5, 8, 11] {
        if offset < w.len() {
            let mut corrupted = w.clone();
            corrupted[offset] = corrupted[offset].add(&fe(1));
            assert!(
                compiler.cs.verify(&corrupted).is_err(),
                "A5: corrupted Poseidon S-box wire {offset} must be rejected"
            );
        }
    }
}

#[test]
fn a5_corrupt_poseidon_capacity_wire() {
    let hash = {
        let params = constraints::poseidon::PoseidonParams::bn254_t3();
        constraints::poseidon::poseidon_hash(&params, fe(1), fe(2))
    };
    let (compiler, mut w) = compile_valid_witness(
        "let h = poseidon(a, b)\nassert_eq(h, expected)",
        &["expected"],
        &["a", "b"],
        &[("expected", hash), ("a", fe(1)), ("b", fe(2))],
    );
    // Wire 4 = capacity (must be 0). Set it to 1 — attempts to forge hash
    w[4] = fe(1);
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A5: non-zero capacity must be rejected (prevents hash forgery)"
    );
}

// ============================================================================
// A6. Mux condition bypass — non-boolean condition values
// ============================================================================

#[test]
fn a6_mux_condition_2() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(mux(c, a, b), out)",
        &["out"],
        &["c", "a", "b"],
        &[("out", fe(10)), ("c", fe(1)), ("a", fe(10)), ("b", fe(20))],
    );
    // Wire 2 = c. Set to 2 (not boolean)
    w[2] = fe(2);
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A6: mux condition = 2 must be rejected"
    );
}

#[test]
fn a6_mux_condition_pminus1() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(mux(c, a, b), out)",
        &["out"],
        &["c", "a", "b"],
        &[("out", fe(10)), ("c", fe(1)), ("a", fe(10)), ("b", fe(20))],
    );
    w[2] = p_minus_1(); // p-1 as condition
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A6: mux condition = p-1 must be rejected"
    );
}

// ============================================================================
// A7. Division inverse forgery — provide wrong modular inverse
// ============================================================================

#[test]
fn a7_wrong_inverse_in_division() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a / b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(6)), ("a", fe(42)), ("b", fe(7))],
    );
    // The division gadget allocates an inverse wire. Find and corrupt it.
    // Wire layout: ONE(0), out(1), a(2), b(3), inv_b(4), product(5)
    if w.len() > 4 {
        w[4] = fe(999); // wrong inverse
        assert!(
            compiler.cs.verify(&w).is_err(),
            "A7: wrong modular inverse must be rejected"
        );
    }
}

#[test]
fn a7_forge_division_result() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a / b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(6)), ("a", fe(42)), ("b", fe(7))],
    );
    // Try to claim 42/7 = 999 by corrupting output AND inverse
    w[1] = fe(999);
    if w.len() > 4 {
        w[4] = fe(1); // set inverse to 1 (hoping b*1=b makes something work)
    }
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A7: forged division result must be rejected even with corrupted inverse"
    );
}

// ============================================================================
// A8. Bit decomposition overflow — Dark Forest class
// ============================================================================

#[test]
fn a8_overflow_range_check_8bit() {
    let (compiler, mut w) =
        compile_valid_witness("range_check(x, 8)", &[], &["x"], &[("x", fe(42))]);
    // Replace x with 256 (overflows 8-bit range check)
    w[1] = fe(256);
    // Also need to fix the bit decomposition wires to match 256
    // But even if we try, the bit extraction should catch it
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A8: 256 must fail 8-bit range check (Dark Forest class)"
    );
}

#[test]
fn a8_overflow_range_check_pminus1() {
    let (compiler, mut w) =
        compile_valid_witness("range_check(x, 64)", &[], &["x"], &[("x", fe(42))]);
    // Replace x with p-1 (way beyond 64-bit range)
    w[1] = p_minus_1();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A8: p-1 must fail 64-bit range check"
    );
}

#[test]
fn a8_islt_with_overflow_input() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a < b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(1)), ("a", fe(3)), ("b", fe(5))],
    );
    // Replace a with p-1 — IsLt should reject because p-1 > 5 but the
    // bit decomposition was computed for a=3
    w[2] = p_minus_1();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A8: IsLt with p-1 input must be rejected"
    );
}

// ============================================================================
// A9. Wire swapping — swap two witness values
// ============================================================================

#[test]
fn a9_swap_witness_inputs() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a - b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(3)), ("a", fe(10)), ("b", fe(7))],
    );
    // Swap a and b — 7-10 = p-3 ≠ 3
    let tmp = w[2];
    w[2] = w[3];
    w[3] = tmp;
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A9: swapped witnesses must be rejected for non-commutative ops"
    );
}

// ============================================================================
// A10. Constant wire attack — corrupt the ONE wire
// ============================================================================

#[test]
fn a10_corrupt_constant_wire() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a + b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(13)), ("a", fe(6)), ("b", fe(7))],
    );
    // Wire 0 MUST be 1 (FieldElement::ONE). Corrupt it.
    w[0] = fe(2);
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A10: corrupted constant-one wire must be rejected"
    );
}

#[test]
fn a10_zero_constant_wire() {
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    w[0] = FieldElement::ZERO;
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A10: zeroed constant wire must be rejected"
    );
}

// ============================================================================
// A11. Combined attack — forge multiple wires coherently
// ============================================================================

#[test]
fn a11_coherent_forgery_mul() {
    // Attacker tries to prove 6*7=100 by adjusting both output AND intermediates
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // Set output to 100 and try to adjust
    w[1] = fe(100);
    // Even with coherent attempt, constraints enforce a*b=out
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A11: coherent forgery (change output only) must be rejected"
    );
}

#[test]
fn a11_coherent_forgery_change_inputs_and_output() {
    // More sophisticated: attacker changes a=10, b=10, out=100 (10*10=100 is valid math)
    // But the constraint was COMPILED for the original circuit structure
    let (compiler, mut w) = compile_valid_witness(
        "assert_eq(a * b, out)",
        &["out"],
        &["a", "b"],
        &[("out", fe(42)), ("a", fe(6)), ("b", fe(7))],
    );
    // This IS actually valid: 10*10=100 satisfies a*b=out
    // Must also update intermediate wire (mul_result = wire 4)
    w[1] = fe(100); // out
    w[2] = fe(10); // a
    w[3] = fe(10); // b
    if w.len() > 4 {
        w[4] = fe(100); // mul_result intermediate
    }
    // This SHOULD pass because ALL constraints are satisfied with the new values
    // This is NOT an attack — it's a different valid witness for the same circuit
    let result = compiler.cs.verify(&w);
    assert!(
        result.is_ok(),
        "A11: coherent valid witness (10*10=100) should be accepted — circuit is parametric"
    );
}

// ============================================================================
// A12. IntDiv remainder forgery — claim wrong quotient with valid r < 2^max_bits
// ============================================================================

/// Compile a circuit file and generate a valid witness via ProveIR path.
fn compile_circuit_witness(
    source: &str,
    inputs: &[(&str, FieldElement)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    use ir::prove_ir::ProveIrCompiler;
    use std::path::Path;

    let prove_ir =
        ProveIrCompiler::<memory::Bn254Fr>::compile_circuit(source, Some(Path::new("test.ach")))
            .unwrap();
    let mut program = prove_ir.instantiate(&HashMap::new()).unwrap();
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);

    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let w = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("valid witness gen failed");

    compiler.cs.verify(&w).expect("valid witness must verify");
    (compiler, w)
}

#[test]
fn a12_intdiv_wrong_quotient_valid_range() {
    // 43 / 6 = 7 remainder 1.
    // Attack: forge expected output as 6 instead of 7.
    // With the r<b fix, r=7 >= b=6 fails the range check on (b-r-1).
    let source = r#"
circuit test(expected: Public, a: Witness, b: Witness) {
    let q = int_div(a, b, 32)
    assert_eq(q, expected)
}
"#;
    let (compiler, mut w) =
        compile_circuit_witness(source, &[("expected", fe(7)), ("a", fe(43)), ("b", fe(6))]);
    // Forge: claim quotient is 6
    w[1] = fe(6);
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A12: forged IntDiv quotient must be rejected (r<b constraint prevents forgery)"
    );
}

#[test]
fn a12_intmod_wrong_remainder() {
    // 43 % 6 = 1.
    // Attack: forge expected output as 7.
    let source = r#"
circuit test(expected: Public, a: Witness, b: Witness) {
    let r = int_mod(a, b, 32)
    assert_eq(r, expected)
}
"#;
    let (compiler, mut w) =
        compile_circuit_witness(source, &[("expected", fe(1)), ("a", fe(43)), ("b", fe(6))]);
    w[1] = fe(7); // forge: claim remainder is 7
    assert!(
        compiler.cs.verify(&w).is_err(),
        "A12: forged IntMod remainder must be rejected"
    );
}
