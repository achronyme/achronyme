//! Movimiento 2 Phase 3F — Gap 2.4 regression test.
//!
//! Verifies that a prove block calling a user fn from another
//! module, whose body references a module-private bare identifier,
//! compiles cleanly. The scenario is:
//!
//! ```ach
//! // a.ach
//! import "./b.ach" as b
//! prove { public out: Field\n assert_eq(out, b::middle()) }
//! ```
//!
//! ```ach
//! // b.ach
//! fn helper() { 1 }
//! export fn middle() { helper() }   // ← bare identifier
//! ```
//!
//! Before Phase 3F this failed with `UndeclaredVariable: helper`
//! — the ProveIR compiler inlined `middle`'s body and looked up
//! the bare `helper` in its fn_table, which only had the mangled
//! `b::helper` key. The repro documents the failure mode; the
//! Phase 3F fix threads resolver annotations + a precomputed
//! fn_table dispatch map to resolve the bare identifier against
//! the definer's module.

use std::path::PathBuf;

use akronc::Compiler;

/// Absolute path to the `gap_24_repro` fixture directory shipped
/// alongside this integration test.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gap_24_repro")
}

#[test]
fn transitive_bare_identifier_in_inlined_body_compiles() {
    let dir = fixture_dir();
    let a_path = dir.join("a.ach");
    let source = std::fs::read_to_string(&a_path).expect("read a.ach");

    let mut compiler = Compiler::new();
    compiler.base_path = Some(dir);

    let result = compiler.compile(&source);
    assert!(
        result.is_ok(),
        "gap 2.4 repro should compile cleanly post Phase 3F, got: {:?}",
        result.err()
    );
}
