//! Tests for template lowering.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `template/mod.rs`.

use super::{lower_template, LowerTemplateResult};
use crate::parser::parse_circom;
use ir_forge::types::ProveIR;

fn parse_and_lower_full(src: &str) -> LowerTemplateResult {
    let (prog, errors) = parse_circom(src).expect("parse failed");
    assert!(errors.is_empty(), "parse errors: {:?}", errors);

    let main_name = prog
        .main_component
        .as_ref()
        .map(|m| m.template_name.as_str());
    let template = prog
        .definitions
        .iter()
        .find_map(|d| match d {
            crate::ast::Definition::Template(t)
                if main_name.is_none() || main_name == Some(t.name.as_str()) =>
            {
                Some(t)
            }
            _ => None,
        })
        .expect("no matching template found");

    lower_template(template, prog.main_component.as_ref(), &prog).unwrap()
}

fn parse_and_lower(src: &str) -> ProveIR {
    parse_and_lower_full(src).prove_ir
}

mod basic;
mod captures_arrays;
mod components;
mod flush_tracker;
mod num2bits;
