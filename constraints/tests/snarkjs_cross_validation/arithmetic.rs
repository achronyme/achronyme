use std::collections::HashMap;

use memory::FieldElement;

use super::helpers::{cross_validate, fe, snarkjs_available};

#[test]
fn golden_mul_6x7() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Multiplication 6 × 7 = 42 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(42));
    inputs.insert("a".into(), fe(6));
    inputs.insert("b".into(), fe(7));

    let result = cross_validate("assert_eq(a * b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);

    // Wire[0] = 1 (constant), Wire[1] = out = 42, Wire[2] = a = 6, Wire[3] = b = 7
    assert_eq!(result.wire_values[0], "1", "wire[0] should be constant 1");
    assert_eq!(result.wire_values[1], "42", "wire[1] (out) should be 42");
    assert_eq!(result.wire_values[2], "6", "wire[2] (a) should be 6");
    assert_eq!(result.wire_values[3], "7", "wire[3] (b) should be 7");

    eprintln!("  Wire values match: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

// ============================================================================
// 4. Mux — conditional selection
//    mux(1, 10, 20) = 10, mux(0, 10, 20) = 20
// ============================================================================
#[test]
fn golden_mux_sel1() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: mux(1, 10, 20) = 10 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(10));
    inputs.insert("cond".into(), fe(1));
    inputs.insert("a".into(), fe(10));
    inputs.insert("b".into(), fe(20));

    let result = cross_validate(
        "assert_eq(mux(cond, a, b), out)",
        &["out"],
        &["cond", "a", "b"],
        &inputs,
    );

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "10", "mux(1, 10, 20) should be 10");
    eprintln!("  Wire[1] = 10: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

#[test]
fn golden_mux_sel0() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: mux(0, 10, 20) = 20 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(20));
    inputs.insert("cond".into(), fe(0));
    inputs.insert("a".into(), fe(10));
    inputs.insert("b".into(), fe(20));

    let result = cross_validate(
        "assert_eq(mux(cond, a, b), out)",
        &["out"],
        &["cond", "a", "b"],
        &inputs,
    );

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "20", "mux(0, 10, 20) should be 20");
    eprintln!("  Wire[1] = 20: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

// ============================================================================
// 5. Division — modular inverse
//    42 / 7 = 6 (integer), 1 / 2 = (p+1)/2 (field inverse)
// ============================================================================

#[test]
fn golden_div_42_7() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: 42 / 7 = 6 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(6));
    inputs.insert("a".into(), fe(42));
    inputs.insert("b".into(), fe(7));

    let result = cross_validate("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "6", "42/7 should be 6");
    eprintln!("  Wire[1] = 6: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

#[test]
fn golden_div_field_inverse_1_over_2() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: 1 / 2 = (p+1)/2 (field inverse) ===");

    // inv(2) = (p+1)/2 = 10944121435919637611123202872628637544274182200208017171849102093287904247809
    let inv2_str = "10944121435919637611123202872628637544274182200208017171849102093287904247809";
    let inv2 = FieldElement::from_decimal_str(inv2_str).unwrap();
    eprintln!("  Expected inv(2) = {inv2_str}");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), inv2);
    inputs.insert("a".into(), fe(1));
    inputs.insert("b".into(), fe(2));

    let result = cross_validate("assert_eq(a / b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(
        result.wire_values[1], inv2_str,
        "1/2 field inverse mismatch"
    );
    eprintln!("  Wire[1] matches: ✓");
    eprintln!("  Verification: 2 × {} mod p = 1", inv2_str);
    eprintln!("  Constraints: {}", result.constraint_count);
}
