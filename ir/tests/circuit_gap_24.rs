//! Regression test for transitive private-fn resolution in
//! `compile_circuit`.
//!
//! The standalone [`ProveIrCompiler::compile_circuit`] entry used
//! to call a surface-level `register_module_exports` that only
//! registered exported fns from direct imports. An inlined
//! `b::middle()` body that references its module-private
//! `helper()` failed with `UndeclaredVariable: helper`, because
//! `b::helper` was never added to `fn_table`.
//!
//! The current path auto-builds a [`resolve::ResolverState`] from
//! the parsed program + source directory, walks the full module
//! graph to derive fn_table entries for every transitively
//! reachable [`resolve::CallableKind::UserFn`] (exported *and*
//! private), pre-populates the ProveIR compiler's fn_table, and
//! installs the resolver state so annotation-driven dispatch picks
//! up. This test pins that path.

use std::path::{Path, PathBuf};

use ir_forge::ProveIrCompiler;
use memory::Bn254Fr;

/// Absolute path to the `circuit_gap_24_repro` fixture directory
/// shipped alongside this integration test.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/circuit_gap_24_repro")
}

#[test]
fn transitive_bare_identifier_in_inlined_circuit_body_compiles() {
    let dir = fixture_dir();
    let a_path = dir.join("a.ach");
    let source = std::fs::read_to_string(&a_path).expect("read a.ach");

    let result =
        ProveIrCompiler::<Bn254Fr>::compile_circuit(&source, Some(a_path.as_path() as &Path));
    assert!(
        result.is_ok(),
        "transitive-private-fn fixture should compile cleanly, got: {:?}",
        result.err()
    );

    // Sanity check the resulting ProveIR: one public input
    // (`expected`), a body containing at least the AssertEq from
    // the circuit decl, and the name matches the decl.
    let prove_ir = result.unwrap();
    assert_eq!(prove_ir.name.as_deref(), Some("Foo"));
    assert_eq!(prove_ir.public_inputs.len(), 1);
    assert_eq!(prove_ir.public_inputs[0].name, "expected");
    assert!(
        !prove_ir.body.is_empty(),
        "expected a non-empty ProveIR body"
    );
}
