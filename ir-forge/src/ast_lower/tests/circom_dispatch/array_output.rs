use super::bindings::{compile_block, ArrayOutputLibrary};
use super::*;

#[test]
fn dot_access_on_array_output_bit_resolves_via_indexed_env_key() {
    // `r.out_2` should resolve to the mangled `circom_call_0_out_2`.
    let lib: Arc<dyn CircomLibraryHandle> = Arc::new(ArrayOutputLibrary {
        name: "Num2Bits".to_string(),
        dims: vec![4],
    });
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    compiler.register_circom_template("Num2Bits".to_string(), lib, "Num2Bits".to_string());
    compiler
        .env
        .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));

    compile_block(
        &mut compiler,
        "let r = Num2Bits(4)(x)\nassert_eq(r.out_2, x)",
    )
    .expect("dot access on array-output bit should resolve");
    // Verify an AssertEq landed that references the mangled
    // 2nd element of the array output.
    let has_expected = compiler.body.iter().any(|n| match n {
        CircuitNode::AssertEq {
            lhs: CircuitExpr::Var(lhs),
            ..
        } => lhs == "circom_call_0_out_2",
        _ => false,
    });
    assert!(
        has_expected,
        "expected assert_eq lhs = circom_call_0_out_2, body: {:?}",
        compiler.body
    );
}
