use std::collections::HashMap;

use super::helpers::{cross_validate, fe, snarkjs_available};

#[test]
fn golden_bool_and() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: And(1, 1) = 1 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(1));
    inputs.insert("a".into(), fe(1));
    inputs.insert("b".into(), fe(1));

    let result = cross_validate("assert_eq(a && b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "1", "And(1,1) should be 1");
    eprintln!("  Wire[1] = 1: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

#[test]
fn golden_bool_or() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Or(0, 1) = 1 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(1));
    inputs.insert("a".into(), fe(0));
    inputs.insert("b".into(), fe(1));

    let result = cross_validate("assert_eq(a || b, out)", &["out"], &["a", "b"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "1", "Or(0,1) should be 1");
    eprintln!("  Wire[1] = 1: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

#[test]
fn golden_bool_not() {
    if !snarkjs_available() {
        eprintln!("SKIP: snarkjs not available");
        return;
    }
    eprintln!("\n=== GOLDEN CROSS-VALIDATION: Not(0) = 1 ===");

    let mut inputs = HashMap::new();
    inputs.insert("out".into(), fe(1));
    inputs.insert("a".into(), fe(0));

    let result = cross_validate("assert_eq(!a, out)", &["out"], &["a"], &inputs);

    assert!(result.wtns_check_passed);
    assert_eq!(result.wire_values[1], "1", "Not(0) should be 1");
    eprintln!("  Wire[1] = 1: ✓");
    eprintln!("  Constraints: {}", result.constraint_count);
}

// ============================================================================
// 12. Full benchmark comparison table: Achronyme vs Circom
