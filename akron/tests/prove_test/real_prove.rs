use super::common::{run_source, run_source_with_prove};
use akronc::Compiler;
use memory::FieldElement;

// ======================================================================
// VM unit tests
// ======================================================================

#[test]
fn prove_handler_not_configured() {
    let source = r#"
        let x = 0p42
        prove {
            witness x
            assert_eq(x, 42)
        }
    "#;
    let result = run_source(source);
    match result {
        Ok(_) => panic!("Expected ProveHandlerNotConfigured error"),
        Err(err) => assert!(
            err.contains("ProveHandlerNotConfigured"),
            "Expected ProveHandlerNotConfigured, got: {err}"
        ),
    }
}

// ======================================================================
// Integration tests (E2E with real prove handler)
// ======================================================================

#[test]
fn prove_simple_assert_eq() {
    let source = r#"
        let x = 0p42
        prove {
            witness x
            assert_eq(x, 42)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "prove simple assert_eq failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_addition() {
    let source = r#"
        let a = 0p3
        let b = 0p5
        let c = 0p8
        prove {
            witness a, b
            public c
            assert_eq(a + b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(result.is_ok(), "prove addition failed: {:?}", result.err());
}

#[test]
fn prove_multiplication() {
    let source = r#"
        let a = 0p6
        let b = 0p7
        let c = 0p42
        prove {
            witness a, b
            public c
            assert_eq(a * b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "prove multiplication failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_failing_constraint() {
    let source = r#"
        let a = 0p3
        let b = 0p5
        let c = 0p42
        prove {
            witness a, b
            public c
            assert_eq(a + b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    match result {
        Ok(_) => panic!("prove should fail: 3+5 != 42"),
        Err(err) => assert!(
            err.contains("ProveBlockFailed"),
            "Expected ProveBlockFailed, got: {err}"
        ),
    }
}

#[test]
fn prove_int_promotion() {
    // Integer values should be promoted to FieldElement
    let source = r#"
        let x = 42
        prove {
            witness x
            assert_eq(x, 42)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "prove int promotion failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_missing_variable_compile_error() {
    // Variable referenced in prove block not found in scope → compile-time error
    let source = r#"
        prove {
            witness missing_var
            assert_eq(missing_var, 1)
        }
    "#;
    let mut compiler = Compiler::new();
    let result = compiler.compile(source);
    assert!(result.is_err(), "Should error on missing variable");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("missing_var") && err.contains("not found"),
        "Expected missing variable error, got: {err}"
    );
}

#[test]
fn prove_result_is_nil() {
    // prove {} evaluates to nil — verify no runtime error
    let source = r#"
        let x = 0p1
        let result = prove {
            witness x
            assert_eq(x, 1)
        }
    "#;
    run_source_with_prove(source).expect("prove should succeed");
}

#[test]
fn prove_wrong_witness_fails() {
    // Witness doesn't satisfy constraint
    let source = r#"
        let a = 0p10
        let b = 0p20
        let c = 0p999
        prove {
            witness a, b
            public c
            assert_eq(a * b, c)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(result.is_err(), "prove should fail: 10*20 != 999");
}

#[test]
fn prove_poseidon_inside_prove_block() {
    // Poseidon is a circuit-level builtin, not a VM function.
    // We precompute the hash using Rust and pass its decimal string as a field literal.
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(42);
    let right = FieldElement::ZERO;
    let hash = constraints::poseidon::poseidon_hash(&params, left, right);
    let hash_str = hash.to_decimal_string();

    let source = format!(
        r#"
        let s = 0p42
        let h = 0p{hash_str}
        prove {{
            witness s
            public h
            assert_eq(poseidon(s, 0), h)
        }}
    "#
    );
    let result = run_source_with_prove(&source);
    assert!(result.is_ok(), "prove poseidon failed: {:?}", result.err());
}

#[test]
fn prove_poseidon_wrong_witness() {
    // Same structure but with wrong witness → should fail
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let left = FieldElement::from_u64(42);
    let right = FieldElement::ZERO;
    let hash = constraints::poseidon::poseidon_hash(&params, left, right);
    let hash_str = hash.to_decimal_string();

    let source = format!(
        r#"
        let s = 0p99
        let h = 0p{hash_str}
        prove {{
            witness s
            public h
            assert_eq(poseidon(s, 0), h)
        }}
    "#
    );
    let result = run_source_with_prove(&source);
    assert!(
        result.is_err(),
        "prove should fail: wrong witness for poseidon"
    );
}

#[test]
fn prove_multiple_blocks() {
    // Multiple prove blocks in sequence
    let source = r#"
        let a = 0p10
        let b = 0p20
        prove {
            witness a
            assert_eq(a, 10)
        }
        prove {
            witness b
            assert_eq(b, 20)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(
        result.is_ok(),
        "multiple prove blocks failed: {:?}",
        result.err()
    );
}

#[test]
fn prove_power_circuit() {
    let source = r#"
        let x = 0p3
        let y = 0p27
        prove {
            witness x
            public y
            assert_eq(x ^ 3, y)
        }
    "#;
    let result = run_source_with_prove(source);
    assert!(result.is_ok(), "prove power failed: {:?}", result.err());
}
