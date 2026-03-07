use achronyme_parser::parse_program;

fn parse_ok(source: &str) {
    let (_, errors) = parse_program(source);
    assert!(errors.is_empty(), "unexpected parse errors: {errors:?}");
}

fn has_errors(source: &str) -> bool {
    let (_, errors) = parse_program(source);
    !errors.is_empty()
}

#[test]
fn prove_expr_parses() {
    let input = r#"prove { witness s; public h; assert_eq(poseidon(s, 0), h) }"#;
    parse_ok(input);
}

#[test]
fn prove_expr_empty_block() {
    let input = "prove { }";
    parse_ok(input);
}

#[test]
fn prove_is_keyword_not_identifier() {
    // "prove" alone should NOT parse as a valid identifier expression
    let input = "let prove = 1";
    assert!(
        has_errors(input),
        "prove should be a keyword, not an identifier"
    );
}

#[test]
fn prove_expr_with_arithmetic() {
    let input = r#"prove {
        witness a, b
        public c
        assert_eq(a + b, c)
    }"#;
    parse_ok(input);
}

#[test]
fn prove_after_let() {
    let input = r#"
        let x = 42
        prove { witness x; assert_eq(x, 42) }
    "#;
    parse_ok(input);
}
