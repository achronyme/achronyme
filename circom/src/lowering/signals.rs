//! Signal lowering: Circom signal declarations → ProveIR input declarations.
//!
//! Maps Circom's signal system to ProveIR's public/witness input model:
//! - `signal input x`  → public or witness (determined by `component main {public [...]}`)
//! - `signal output x` → public output (represented as let-binding + assert)
//! - `signal x`        → intermediate (local let-binding, not an input)
//!
//! Array signals (`signal input x[N]`) map to `ProveInputDecl` with `ArraySize`.

use std::collections::HashSet;

use ir::prove_ir::types::{ArraySize, ProveInputDecl};
use ir::types::IrType;

use crate::ast::{Expr, MainComponent, SignalType, Stmt, TemplateDef};

use super::error::LoweringError;
use super::utils::const_eval_u64;

/// Collected signal declarations from a template, categorized by role.
#[derive(Debug)]
pub struct SignalLayout {
    /// Signals declared as `signal input` that are in the main component's
    /// `{public [...]}` list → ProveIR public inputs.
    pub public_inputs: Vec<ProveInputDecl>,
    /// Signals declared as `signal input` that are NOT in the public list
    /// → ProveIR witness inputs.
    pub witness_inputs: Vec<ProveInputDecl>,
    /// Signals declared as `signal output` → will become let-bindings with
    /// public output semantics.
    pub outputs: Vec<OutputSignal>,
    /// Signals declared as `signal` (intermediate) → local let-bindings.
    pub intermediates: Vec<IntermediateSignal>,
}

/// An output signal to be lowered as a let-binding.
#[derive(Debug)]
pub struct OutputSignal {
    pub name: String,
    pub dimensions: Vec<u64>,
}

/// An intermediate signal to be lowered as a local let-binding.
#[derive(Debug)]
pub struct IntermediateSignal {
    pub name: String,
    pub dimensions: Vec<u64>,
}

/// Extract signal layout from a template, using the main component's public
/// signal list to distinguish public vs witness inputs.
pub fn extract_signal_layout(
    template: &TemplateDef,
    main: Option<&MainComponent>,
) -> Result<SignalLayout, LoweringError> {
    let public_set: HashSet<&str> = main
        .map(|m| m.public_signals.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let mut layout = SignalLayout {
        public_inputs: Vec::new(),
        witness_inputs: Vec::new(),
        outputs: Vec::new(),
        intermediates: Vec::new(),
    };

    for stmt in &template.body.stmts {
        if let Stmt::SignalDecl {
            signal_type,
            declarations,
            span,
            ..
        } = stmt
        {
            for decl in declarations {
                let dimensions = eval_dimensions(&decl.dimensions, span)?;

                match signal_type {
                    SignalType::Input => {
                        let input_decl = make_input_decl(&decl.name, &dimensions)?;
                        if public_set.contains(decl.name.as_str()) {
                            layout.public_inputs.push(input_decl);
                        } else {
                            layout.witness_inputs.push(input_decl);
                        }
                    }
                    SignalType::Output => {
                        layout.outputs.push(OutputSignal {
                            name: decl.name.clone(),
                            dimensions,
                        });
                    }
                    SignalType::Intermediate => {
                        layout.intermediates.push(IntermediateSignal {
                            name: decl.name.clone(),
                            dimensions,
                        });
                    }
                }
            }
        }
    }

    Ok(layout)
}

/// Evaluate signal dimension expressions to constant u64 values.
///
/// In Circom, signal array dimensions must be compile-time constants
/// (literal numbers or template parameters that are known at lowering time).
fn eval_dimensions(
    dims: &[Expr],
    parent_span: &diagnostics::Span,
) -> Result<Vec<u64>, LoweringError> {
    let mut result = Vec::with_capacity(dims.len());
    for dim in dims {
        match const_eval_u64(dim) {
            Some(n) => result.push(n),
            None => {
                return Err(LoweringError::new(
                    "signal array dimension must be a compile-time constant",
                    parent_span,
                ));
            }
        }
    }
    Ok(result)
}

/// Create a `ProveInputDecl` from a signal name and its evaluated dimensions.
fn make_input_decl(name: &str, dimensions: &[u64]) -> Result<ProveInputDecl, LoweringError> {
    let array_size = match dimensions.len() {
        0 => None,
        1 => Some(ArraySize::Literal(dimensions[0] as usize)),
        _ => {
            // Multi-dimensional arrays: flatten to total size.
            // e.g., signal input x[3][4] → array of 12 elements.
            let total: u64 = dimensions.iter().product();
            Some(ArraySize::Literal(total as usize))
        }
    };

    Ok(ProveInputDecl {
        name: name.to_string(),
        array_size,
        ir_type: IrType::Field, // Circom signals are always field elements
    })
}

/// Collect all signal names declared in a template body (non-recursive, top-level only).
pub fn collect_signal_names(stmts: &[Stmt]) -> Vec<(String, SignalType)> {
    let mut names = Vec::new();
    collect_signals_recursive(stmts, &mut names);
    names
}

fn collect_signals_recursive(stmts: &[Stmt], names: &mut Vec<(String, SignalType)>) {
    for stmt in stmts {
        match stmt {
            Stmt::SignalDecl {
                signal_type,
                declarations,
                ..
            } => {
                for decl in declarations {
                    names.push((decl.name.clone(), *signal_type));
                }
            }
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                collect_signals_recursive(&then_body.stmts, names);
                if let Some(else_branch) = else_body {
                    match else_branch {
                        crate::ast::ElseBranch::Block(block) => {
                            collect_signals_recursive(&block.stmts, names);
                        }
                        crate::ast::ElseBranch::IfElse(if_stmt) => {
                            collect_signals_recursive(&[*if_stmt.clone()], names);
                        }
                    }
                }
            }
            Stmt::For { body, .. } | Stmt::While { body, .. } => {
                collect_signals_recursive(&body.stmts, names);
            }
            Stmt::Block(block) => {
                collect_signals_recursive(&block.stmts, names);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;

    fn parse_template(src: &str) -> TemplateDef {
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => t.clone(),
            _ => panic!("expected template"),
        }
    }

    fn parse_main(src: &str) -> Option<MainComponent> {
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);
        prog.main_component
    }

    #[test]
    fn input_signals_without_public_are_witness() {
        let t = parse_template("template T() { signal input a; signal input b; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert!(layout.public_inputs.is_empty());
        assert_eq!(layout.witness_inputs.len(), 2);
        assert_eq!(layout.witness_inputs[0].name, "a");
        assert_eq!(layout.witness_inputs[1].name, "b");
    }

    #[test]
    fn input_signals_with_public_list() {
        let src = r#"
            template T() { signal input a; signal input b; signal input c; }
            component main {public [a, c]} = T();
        "#;
        let t = parse_template(src);
        let main = parse_main(src);
        let layout = extract_signal_layout(&t, main.as_ref()).unwrap();
        assert_eq!(layout.public_inputs.len(), 2);
        assert_eq!(layout.witness_inputs.len(), 1);
        assert_eq!(layout.public_inputs[0].name, "a");
        assert_eq!(layout.public_inputs[1].name, "c");
        assert_eq!(layout.witness_inputs[0].name, "b");
    }

    #[test]
    fn output_signals() {
        let t = parse_template("template T() { signal output out; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert_eq!(layout.outputs.len(), 1);
        assert_eq!(layout.outputs[0].name, "out");
    }

    #[test]
    fn intermediate_signals() {
        let t = parse_template("template T() { signal inv; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert_eq!(layout.intermediates.len(), 1);
        assert_eq!(layout.intermediates[0].name, "inv");
    }

    #[test]
    fn array_signal_single_dimension() {
        let t = parse_template("template T() { signal input x[4]; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert_eq!(layout.witness_inputs.len(), 1);
        assert_eq!(
            layout.witness_inputs[0].array_size,
            Some(ArraySize::Literal(4))
        );
    }

    #[test]
    fn array_signal_multi_dimension() {
        let t = parse_template("template T() { signal input m[3][4]; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert_eq!(layout.witness_inputs.len(), 1);
        // 3*4 = 12 elements flattened
        assert_eq!(
            layout.witness_inputs[0].array_size,
            Some(ArraySize::Literal(12))
        );
    }

    #[test]
    fn scalar_signal_has_no_array_size() {
        let t = parse_template("template T() { signal input x; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert!(layout.witness_inputs[0].array_size.is_none());
    }

    #[test]
    fn all_signals_are_field_type() {
        let t = parse_template("template T() { signal input a; signal output b; signal c; }");
        let layout = extract_signal_layout(&t, None).unwrap();
        assert_eq!(layout.witness_inputs[0].ir_type, IrType::Field);
    }

    #[test]
    fn mixed_signal_types() {
        let src = r#"
            template T() {
                signal input in;
                signal output out;
                signal intermediate;
            }
            component main {public [in]} = T();
        "#;
        let t = parse_template(src);
        let main = parse_main(src);
        let layout = extract_signal_layout(&t, main.as_ref()).unwrap();
        assert_eq!(layout.public_inputs.len(), 1);
        assert_eq!(layout.public_inputs[0].name, "in");
        assert!(layout.witness_inputs.is_empty());
        assert_eq!(layout.outputs.len(), 1);
        assert_eq!(layout.intermediates.len(), 1);
    }

    #[test]
    fn collect_signal_names_finds_all() {
        let t = parse_template(
            r#"
            template T() {
                signal input a;
                signal output b;
                signal c;
            }
            "#,
        );
        let names = collect_signal_names(&t.body.stmts);
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], ("a".to_string(), SignalType::Input));
        assert_eq!(names[1], ("b".to_string(), SignalType::Output));
        assert_eq!(names[2], ("c".to_string(), SignalType::Intermediate));
    }
}
