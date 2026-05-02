//! Regression test for transitive private-identifier resolution.
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
//! Naively this would fail with `UndeclaredVariable: helper` because
//! the ProveIR compiler inlines `middle`'s body and looks up the
//! bare `helper` in its fn_table, which only contains the mangled
//! `b::helper` key. Resolver annotations + a precomputed fn_table
//! dispatch map resolve the bare identifier against the definer's
//! module.

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
        "transitive-bare-identifier fixture should compile cleanly, got: {:?}",
        result.err()
    );
}
