//! Movimiento 2 Phase 3G — gap 2.4 regression test in circuit mode.
//!
//! The standalone [`ProveIrCompiler::compile_circuit`] entry has
//! historically used a surface-level `register_module_exports`
//! mechanism that only registers exported fns from direct
//! imports. As a result, gap 2.4 in circuit mode is
//! fundamentally worse than in prove-block mode: an inlined
//! `b::middle()` body that references its module-private
//! `helper()` fails to compile with
//! `UndeclaredVariable: helper`, because `b::helper` was never
//! added to `fn_table`.
//!
//! Phase 3G fix: auto-build a [`resolve::ResolverState`] from
//! the parsed program + source directory, walk the full module
//! graph to derive fn_table entries for every transitively
//! reachable [`resolve::CallableKind::UserFn`] (exported *and*
//! private), pre-populate the ProveIR compiler's fn_table, and
//! install the resolver state so the annotation-driven dispatch
//! picks up. This test documents the fix.

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
        "circuit-mode gap 2.4 repro should compile cleanly post Phase 3G, got: {:?}",
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
