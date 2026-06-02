use std::collections::HashMap;

use super::helpers::{cross_validate, fe, snarkjs_available};

#[test]
fn golden_iseq_true() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: IsEq(5, 5) = 1 ===");
    eprintln!("  Circom IsEqual: output = 1 (golden)");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(1));
    inputs.insert("a".into(), fe(5));
    inputs.insert("b".into(), fe(5));

    let result = cross_validate("assert_eq(a == b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "1", "IsEq(5,5) should be 1");
    eprintln!("  Wire[1] = 1 (matches Circom): ✓");
    eprintln!(
        "  Constraints: {} (Circom IsEqual: 3)",
        result.constraint_count
    );
}

#[test]
fn golden_iseq_false() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: IsEq(5, 3) = 0 ===");
    eprintln!("  Circom IsEqual: output = 0 (golden)");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(0));
    inputs.insert("a".into(), fe(5));
    inputs.insert("b".into(), fe(3));

    let result = cross_validate("assert_eq(a == b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "0", "IsEq(5,3) should be 0");
    eprintln!("  Wire[1] = 0 (matches Circom): ✓");
    eprintln!(
        "  Constraints: {} (Circom IsEqual: 3)",
        result.constraint_count
    );
}

// ============================================================================
// 9. IsLt — inequality comparison (bit decomposition, gap D7)
//    Circom: circomlib/comparators.circom LessThan(64) → 68 constraints
//    Achronyme: ~760 constraints (full 252-bit decomposition)
// ============================================================================

#[test]
fn golden_islt_true() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: IsLt(3, 5) = 1 ===");
    eprintln!("  Circom LessThan(64): output = 1, 68 constraints (golden)");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(1));
    inputs.insert("a".into(), fe(3));
    inputs.insert("b".into(), fe(5));

    let result = cross_validate("assert_eq(a < b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "1", "IsLt(3,5) should be 1");
    eprintln!("  Wire[1] = 1 (matches Circom): ✓");
    eprintln!(
        "  Constraints: {} (Circom LessThan(64): 68) ← GAP D7",
        result.constraint_count
    );
}

#[test]
fn golden_islt_bounded_64bit() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: IsLt(3, 5) BOUNDED 64-bit ===");
    eprintln!("  With range_check(a, 64) + range_check(b, 64) → IsLtBounded(64)");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(1));
    inputs.insert("a".into(), fe(3));
    inputs.insert("b".into(), fe(5));

    let result = cross_validate(
        "range_check(a, 64)\nrange_check(b, 64)\nassert_eq(a < b, out)",
        &["out"],
        &["a", "b"],
        &inputs,
    );

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "1", "IsLt(3,5) bounded should be 1");
    eprintln!("  Wire[1] = 1: ✓");
    eprintln!("  snarkjs wtns check: ✓ (bounded optimization verified externally)");
    eprintln!(
        "  Constraints: {} (unbounded: 761, Circom LessThan(64): 68)",
        result.constraint_count
    );
    assert!(
        result.constraint_count < 250,
        "bounded 64-bit IsLt should be <250 total constraints, got: {}",
        result.constraint_count
    );
}

#[test]
fn golden_islt_false() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: IsLt(10, 3) = 0 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(0));
    inputs.insert("a".into(), fe(10));
    inputs.insert("b".into(), fe(3));

    let result = cross_validate("assert_eq(a < b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "0", "IsLt(10,3) should be 0");
    eprintln!("  Wire[1] = 0 (matches Circom): ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

// ============================================================================
// 10. RangeCheck — bit decomposition
//     Circom: circomlib/bitify.circom Num2Bits(8) → 9 constraints
// ============================================================================

#[test]
fn golden_rangecheck_8bit() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: RangeCheck(42, 8 bits) ===");
    eprintln!("  Circom Num2Bits(8): 9 constraints (golden)");

    let mut inputs = HashMap::new();
    inputs.insert("x".into(), fe(42));

    let result = cross_validate("range_check(x, 8)", &[], &["x"], &inputs);

    assert!(result.wtns_check_passed);
    eprintln!("  snarkjs wtns check: ✓");
    eprintln!(
        "  Constraints: {} (Circom Num2Bits(8): 9)",
        result.constraint_count
    );
}

// ============================================================================
