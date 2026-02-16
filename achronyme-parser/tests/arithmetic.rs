use achronyme_parser::parse_expression;

#[test]
fn test_integer_arithmetic() {
    let input = "1 + 2 * 3";
    let pairs = parse_expression(input).expect("Failed to parse");
    println!("Parsed: {:?}", pairs);
}

#[test]
fn test_grouping() {
    let input = "(1 + 2) * 3";
    parse_expression(input).expect("Failed to parse grouping");
}
