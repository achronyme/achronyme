pub use super::*;

/// Parse source and return the AST, panicking on any parse error.
pub(crate) fn parse_ok(source: &str) -> Program {
    let (prog, errors) = parse_program(source);
    assert!(errors.is_empty(), "unexpected parse errors: {errors:?}");
    prog
}

/// Parse source expecting errors, returning true if any errors were produced.
pub(crate) fn has_errors(source: &str) -> bool {
    let (_, errors) = parse_program(source);
    !errors.is_empty()
}

#[path = "tests/depth_limits.rs"]
mod depth_limits;
#[path = "tests/expr_ids.rs"]
mod expr_ids;
#[path = "tests/expressions_control.rs"]
mod expressions_control;
#[path = "tests/import_export.rs"]
mod import_export;
#[path = "tests/recovery.rs"]
mod recovery;
#[path = "tests/statements_literals.rs"]
mod statements_literals;
#[path = "tests/types.rs"]
mod types;
