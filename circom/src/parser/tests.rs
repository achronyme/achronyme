mod errors;
mod syntax;

use super::parse_circom;
use crate::ast::{BinOp, CircomProgram, Expr, PostfixOp};

fn parse(src: &str) -> CircomProgram {
    let (prog, errors) = parse_circom(src).expect("parse failed");
    if !errors.is_empty() {
        panic!("parse errors: {:?}", errors);
    }
    prog
}

fn error_code(errors: &[diagnostics::Diagnostic]) -> Option<String> {
    errors.first().and_then(|d| d.code.clone())
}
