use super::common::{run_source_with_mock_proof, run_source_with_mock_verify};

// ======================================================================
// verify_proof tests
// ======================================================================
#[test]
fn verify_proof_returns_true_for_valid() {
    let source = r#"
        let x = 0p42
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        assert(verify_proof(p))
    "#;
    run_source_with_mock_verify(source, true).expect("should succeed");
}

#[test]
fn verify_proof_returns_false_for_invalid() {
    let source = r#"
        let x = 0p42
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        assert(!verify_proof(p))
    "#;
    run_source_with_mock_verify(source, false).expect("should succeed");
}

#[test]
fn verify_proof_type_error_on_non_proof() {
    let source = r#"
        let x = 42
        verify_proof(x)
    "#;
    let result = run_source_with_mock_verify(source, true);
    match result {
        Ok(_) => panic!("verify_proof on int should fail"),
        Err(err) => assert!(
            err.contains("TypeMismatch"),
            "Expected TypeMismatch, got: {err}"
        ),
    }
}

#[test]
fn verify_proof_no_handler_gives_error() {
    let source = r#"
        let x = 0p42
        let p = prove {
            witness x
            assert_eq(x, 42)
        }
        verify_proof(p)
    "#;
    // Use mock proof handler but NO verify handler
    let result = run_source_with_mock_proof(source);
    match result {
        Ok(_) => panic!("should fail without verify handler"),
        Err(err) => assert!(
            err.contains("VerifyHandlerNotConfigured"),
            "Expected handler error, got: {err}"
        ),
    }
}
