use super::super::super::test_helpers::parse_program;
use super::*;
use crate::ast::Definition;

fn extract_template_body(src: &str) -> Vec<Stmt> {
    let prog = parse_program(src);
    for def in prog.definitions {
        if let Definition::Template(t) = def {
            return t.body.stmts;
        }
    }
    panic!("expected a template definition");
}

mod classification;
mod memo_accept;
mod memo_reject;
