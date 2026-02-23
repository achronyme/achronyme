use achronyme_parser::ast::{BinOp, Expr, Stmt};
use achronyme_parser::parse_program;

#[test]
fn test_integer_arithmetic() {
    let input = "1 + 2 * 3";
    let prog = parse_program(input).expect("Failed to parse");
    assert!(!prog.stmts.is_empty());
}

#[test]
fn test_grouping() {
    let input = "(1 + 2) * 3";
    parse_program(input).expect("Failed to parse grouping");
}

#[test]
fn test_pow_right_associative() {
    // 2^3^2 should parse as 2^(3^2), not (2^3)^2
    let prog = parse_program("2^3^2").unwrap();
    let expr = match &prog.stmts[0] {
        Stmt::Expr(e) => e,
        _ => panic!("expected expression statement"),
    };

    // Should be BinOp(Pow, 2, BinOp(Pow, 3, 2))
    match expr {
        Expr::BinOp { op, lhs, rhs, .. } => {
            assert!(matches!(op, BinOp::Pow));
            // lhs should be 2
            match lhs.as_ref() {
                Expr::Number { value, .. } => assert_eq!(value, "2"),
                _ => panic!("expected number 2 as lhs, got: {lhs:?}"),
            }
            // rhs should be BinOp(Pow, 3, 2)
            match rhs.as_ref() {
                Expr::BinOp {
                    op: inner_op,
                    lhs: inner_lhs,
                    rhs: inner_rhs,
                    ..
                } => {
                    assert!(matches!(inner_op, BinOp::Pow));
                    match inner_lhs.as_ref() {
                        Expr::Number { value, .. } => assert_eq!(value, "3"),
                        _ => panic!("expected number 3"),
                    }
                    match inner_rhs.as_ref() {
                        Expr::Number { value, .. } => assert_eq!(value, "2"),
                        _ => panic!("expected number 2"),
                    }
                }
                _ => panic!("expected BinOp(Pow, 3, 2) as rhs, got: {rhs:?}"),
            }
        }
        _ => panic!("expected BinOp at top level"),
    }
}

#[test]
fn test_pow_single_operand() {
    // x^3 should just be BinOp(Pow, x, 3)
    let prog = parse_program("x^3").unwrap();
    let expr = match &prog.stmts[0] {
        Stmt::Expr(e) => e,
        _ => panic!("expected expression statement"),
    };
    match expr {
        Expr::BinOp { op, .. } => assert!(matches!(op, BinOp::Pow)),
        _ => panic!("expected BinOp(Pow)"),
    }
}
