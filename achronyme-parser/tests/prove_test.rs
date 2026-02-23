use achronyme_parser::parse_program;

#[test]
fn prove_expr_parses() {
    let input = r#"prove { witness s; public h; assert_eq(poseidon(s, 0), h) }"#;
    let result = parse_program(input);
    assert!(
        result.is_ok(),
        "Failed to parse prove expr: {:?}",
        result.err()
    );
}

#[test]
fn prove_expr_empty_block() {
    let input = "prove { }";
    let result = parse_program(input);
    assert!(
        result.is_ok(),
        "Failed to parse empty prove block: {:?}",
        result.err()
    );
}

#[test]
fn prove_is_keyword_not_identifier() {
    // "prove" alone should NOT parse as a valid identifier expression
    let input = "let prove = 1";
    let result = parse_program(input);
    assert!(
        result.is_err(),
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
    let result = parse_program(input);
    assert!(
        result.is_ok(),
        "Failed to parse prove with arithmetic: {:?}",
        result.err()
    );
}

#[test]
fn prove_after_let() {
    let input = r#"
        let x = 42
        prove { witness x; assert_eq(x, 42) }
    "#;
    let result = parse_program(input);
    assert!(
        result.is_ok(),
        "Failed to parse prove after let: {:?}",
        result.err()
    );
}
