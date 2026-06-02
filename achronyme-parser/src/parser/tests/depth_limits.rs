/// Regression: deeply nested blocks must not blow the stack.
/// Discovered by fuzz_parser on an 836-byte input of `{`
/// characters; the recursive-descent block parser had no depth
/// cap and ASAN flagged the overflow. The parser now bails with
/// a diagnostic at a fixed depth limit instead.
#[test]
fn deeply_nested_blocks_do_not_overflow() {
    let source: String = "{".repeat(2000);
    let (_program, diagnostics) = crate::parse_program(&source);
    assert!(
        !diagnostics.is_empty(),
        "expected parse diagnostics for deeply nested blocks"
    );
}

/// Regression: deeply nested expressions (`[[[...]]]`, `((((...))))`)
/// must not blow the stack either. The block-depth cap only tracks
/// `{...}` nesting, so fuzz_parser found a follow-up crash using
/// chained `[` brackets. The parser now caps expression recursion
/// depth separately.
#[test]
fn deeply_nested_exprs_do_not_overflow() {
    let source: String = "[".repeat(2000);
    let (_program, diagnostics) = crate::parse_program(&source);
    assert!(
        !diagnostics.is_empty(),
        "expected parse diagnostics for deeply nested expressions"
    );
}
