//! Signal lowering: Circom signal declarations → ProveIR input declarations.
//!
//! Maps Circom's signal system to ProveIR's public/witness input model:
//! - `signal input x`  → public or witness (determined by `component main {public [...]}`)
//! - `signal output x` → public output (represented as let-binding + assert)
//! - `signal x`        → intermediate (local let-binding, not an input)
//!
//! Array signals (`signal input x[N]`) map to `ProveInputDecl` with `ArraySize`.

use std::collections::{HashMap, HashSet};

use ir::prove_ir::types::{ArraySize, ProveInputDecl};
use ir::types::IrType;

use crate::ast::{Expr, MainComponent, SignalType, Stmt, TemplateDef};

use super::error::LoweringError;
use super::utils::{const_eval_u64, const_eval_with_params};

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
    known_vars: &HashMap<String, u64>,
) -> Result<SignalLayout, LoweringError> {
    let public_set: HashSet<&str> = main
        .map(|m| m.public_signals.iter().map(|s| s.as_str()).collect())
        .unwrap_or_default();

    let template_params: HashSet<String> = template.params.iter().cloned().collect();

    // Build param values from main component template args (if available).
    // This allows evaluating expression dimensions like `n+1` eagerly.
    let mut param_values: HashMap<String, u64> = template
        .params
        .iter()
        .enumerate()
        .filter_map(|(i, param)| {
            main.and_then(|m| m.template_args.get(i))
                .and_then(const_eval_u64)
                .map(|val| (param.clone(), val))
        })
        .collect();

    // Merge pre-computed vars (e.g., `var nout = nbits(...)`) so they
    // are available for signal dimension resolution.
    for (name, &val) in known_vars {
        param_values.insert(name.clone(), val);
    }

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
                let dimensions =
                    eval_dimensions(&decl.dimensions, &template_params, &param_values, span)?;

                match signal_type {
                    SignalType::Input => {
                        let input_decl = make_input_decl(&decl.name, &dimensions);
                        if public_set.contains(decl.name.as_str()) {
                            layout.public_inputs.push(input_decl);
                        } else {
                            layout.witness_inputs.push(input_decl);
                        }
                    }
                    SignalType::Output => {
                        let dim_literals: Vec<u64> = dimensions
                            .iter()
                            .filter_map(|d| match d {
                                ResolvedDim::Literal(n) => Some(*n),
                                ResolvedDim::Capture(_) => None,
                            })
                            .collect();
                        layout.outputs.push(OutputSignal {
                            name: decl.name.clone(),
                            dimensions: dim_literals,
                        });
                    }
                    SignalType::Intermediate => {
                        let dim_literals: Vec<u64> = dimensions
                            .iter()
                            .filter_map(|d| match d {
                                ResolvedDim::Literal(n) => Some(*n),
                                ResolvedDim::Capture(_) => None,
                            })
                            .collect();
                        layout.intermediates.push(IntermediateSignal {
                            name: decl.name.clone(),
                            dimensions: dim_literals,
                        });
                    }
                }
            }
        }
    }

    Ok(layout)
}

/// A resolved dimension: either a literal or a template parameter name.
#[derive(Debug)]
enum ResolvedDim {
    Literal(u64),
    Capture(String),
}

/// Evaluate signal dimension expressions.
///
/// Dimensions can be:
/// - Literal numbers: `signal input x[4]`
/// - Template parameter identifiers: `signal input x[n]`
/// - Expressions over params: `signal output x[n+1]` (evaluated with param_values)
fn eval_dimensions(
    dims: &[Expr],
    template_params: &HashSet<String>,
    param_values: &HashMap<String, u64>,
    parent_span: &diagnostics::Span,
) -> Result<Vec<ResolvedDim>, LoweringError> {
    let mut result = Vec::with_capacity(dims.len());
    for dim in dims {
        // 1. Try pure constant (no params needed)
        if let Some(n) = const_eval_u64(dim) {
            result.push(ResolvedDim::Literal(n));
        }
        // 2. Simple template param identifier or pre-computed var
        else if let Expr::Ident { name, .. } = dim {
            if template_params.contains(name) {
                // If we have the value, resolve eagerly
                if let Some(&val) = param_values.get(name) {
                    result.push(ResolvedDim::Literal(val));
                } else {
                    result.push(ResolvedDim::Capture(name.clone()));
                }
            } else if let Some(&val) = param_values.get(name.as_str()) {
                // Pre-computed var (e.g., `var nb = nbits(...)`)
                result.push(ResolvedDim::Literal(val));
            } else {
                return Err(LoweringError::new(
                    format!(
                        "signal array dimension `{name}` is not a compile-time constant \
                         or template parameter"
                    ),
                    parent_span,
                ));
            }
        }
        // 3. Expression involving params (e.g., n+1, n*2)
        else if let Some(n) = const_eval_with_params(dim, param_values) {
            result.push(ResolvedDim::Literal(n));
        }
        // 4. Expression with unknown params — check if all vars are params
        else if expr_uses_only_params(dim, template_params) {
            // Valid expression but param values not available yet.
            // Store the first param as capture (best effort — works for simple cases).
            if let Some(name) = find_first_param(dim, template_params) {
                result.push(ResolvedDim::Capture(name));
            } else {
                return Err(LoweringError::new(
                    "signal array dimension must be a compile-time constant or template parameter",
                    parent_span,
                ));
            }
        } else {
            return Err(LoweringError::new(
                "signal array dimension must be a compile-time constant or template parameter",
                parent_span,
            ));
        }
    }
    Ok(result)
}

/// Check if an expression only references template parameters (no unknown vars).
fn expr_uses_only_params(expr: &Expr, params: &HashSet<String>) -> bool {
    match expr {
        Expr::Number { .. } | Expr::HexNumber { .. } => true,
        Expr::Ident { name, .. } => params.contains(name),
        Expr::BinOp { lhs, rhs, .. } => {
            expr_uses_only_params(lhs, params) && expr_uses_only_params(rhs, params)
        }
        Expr::UnaryOp { operand, .. } => expr_uses_only_params(operand, params),
        _ => false,
    }
}

/// Find the first template parameter referenced in an expression.
fn find_first_param(expr: &Expr, params: &HashSet<String>) -> Option<String> {
    match expr {
        Expr::Ident { name, .. } if params.contains(name) => Some(name.clone()),
        Expr::BinOp { lhs, rhs, .. } => {
            find_first_param(lhs, params).or_else(|| find_first_param(rhs, params))
        }
        Expr::UnaryOp { operand, .. } => find_first_param(operand, params),
        _ => None,
    }
}

/// Convert resolved dimensions to an `ArraySize`.
fn dims_to_array_size(dims: &[ResolvedDim]) -> Option<ArraySize> {
    match dims.len() {
        0 => None,
        1 => match &dims[0] {
            ResolvedDim::Literal(n) => Some(ArraySize::Literal(*n as usize)),
            ResolvedDim::Capture(name) => Some(ArraySize::Capture(name.clone())),
        },
        _ => {
            // Multi-dimensional: flatten if all literal.
            let mut total: u64 = 1;
            for d in dims {
                match d {
                    ResolvedDim::Literal(n) => total *= n,
                    ResolvedDim::Capture(name) => {
                        return Some(ArraySize::Capture(name.clone()));
                    }
                }
            }
            Some(ArraySize::Literal(total as usize))
        }
    }
}

/// Create a `ProveInputDecl` from a signal name and resolved dimensions.
fn make_input_decl(name: &str, dims: &[ResolvedDim]) -> ProveInputDecl {
    ProveInputDecl {
        name: name.to_string(),
        array_size: dims_to_array_size(dims),
        ir_type: IrType::Field,
    }
}

/// Extract multi-dimensional array stride info from a template's signal declarations.
///
/// For each signal with 2+ dimensions, computes the inner dimension strides.
/// Used during component inlining to enable linearized multi-dim indexing.
///
/// `param_values` maps template param names to their concrete values.
pub fn extract_signal_strides(
    template: &TemplateDef,
    param_values: &HashMap<String, u64>,
) -> HashMap<String, Vec<usize>> {
    let mut strides = HashMap::new();

    for stmt in &template.body.stmts {
        if let Stmt::SignalDecl { declarations, .. } = stmt {
            for decl in declarations {
                if decl.dimensions.len() >= 2 {
                    // Resolve each dimension to a concrete size
                    let resolved: Vec<Option<u64>> = decl
                        .dimensions
                        .iter()
                        .map(|dim| {
                            const_eval_u64(dim)
                                .or_else(|| const_eval_with_params(dim, param_values))
                        })
                        .collect();

                    // Compute strides from right to left:
                    // For dims [d0, d1, d2], strides = [d1*d2, d2]
                    let n = resolved.len();
                    let mut dim_strides = Vec::with_capacity(n - 1);
                    let mut product: usize = 1;
                    for i in (1..n).rev() {
                        if let Some(d) = resolved[i] {
                            product *= d as usize;
                        }
                        dim_strides.push(product);
                    }
                    dim_strides.reverse();
                    // Only the first n-1 dimensions have strides
                    // (the last dimension has implicit stride 1)

                    if dim_strides.iter().all(|&s| s > 0) {
                        strides.insert(decl.name.clone(), dim_strides);
                    }
                }
            }
        }
    }

    strides
}

/// Extract total array sizes for all array signals in a template.
///
/// Returns a map of signal name → total flattened element count.
/// Used during component inlining to register arrays in the env.
pub fn extract_signal_array_sizes(
    template: &TemplateDef,
    param_values: &HashMap<String, u64>,
) -> HashMap<String, usize> {
    let mut sizes = HashMap::new();

    for stmt in &template.body.stmts {
        if let Stmt::SignalDecl { declarations, .. } = stmt {
            for decl in declarations {
                if !decl.dimensions.is_empty() {
                    let mut total: usize = 1;
                    let mut resolved = true;
                    for dim in &decl.dimensions {
                        if let Some(n) = const_eval_u64(dim)
                            .or_else(|| const_eval_with_params(dim, param_values))
                        {
                            total *= n as usize;
                        } else {
                            resolved = false;
                            break;
                        }
                    }
                    if resolved && total > 0 {
                        sizes.insert(decl.name.clone(), total);
                    }
                }
            }
        }
    }

    sizes
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
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
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
        let layout = extract_signal_layout(&t, main.as_ref(), &HashMap::new()).unwrap();
        assert_eq!(layout.public_inputs.len(), 2);
        assert_eq!(layout.witness_inputs.len(), 1);
        assert_eq!(layout.public_inputs[0].name, "a");
        assert_eq!(layout.public_inputs[1].name, "c");
        assert_eq!(layout.witness_inputs[0].name, "b");
    }

    #[test]
    fn output_signals() {
        let t = parse_template("template T() { signal output out; }");
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
        assert_eq!(layout.outputs.len(), 1);
        assert_eq!(layout.outputs[0].name, "out");
    }

    #[test]
    fn intermediate_signals() {
        let t = parse_template("template T() { signal inv; }");
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
        assert_eq!(layout.intermediates.len(), 1);
        assert_eq!(layout.intermediates[0].name, "inv");
    }

    #[test]
    fn array_signal_single_dimension() {
        let t = parse_template("template T() { signal input x[4]; }");
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
        assert_eq!(layout.witness_inputs.len(), 1);
        assert_eq!(
            layout.witness_inputs[0].array_size,
            Some(ArraySize::Literal(4))
        );
    }

    #[test]
    fn array_signal_multi_dimension() {
        let t = parse_template("template T() { signal input m[3][4]; }");
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
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
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
        assert!(layout.witness_inputs[0].array_size.is_none());
    }

    #[test]
    fn all_signals_are_field_type() {
        let t = parse_template("template T() { signal input a; signal output b; signal c; }");
        let layout = extract_signal_layout(&t, None, &HashMap::new()).unwrap();
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
        let layout = extract_signal_layout(&t, main.as_ref(), &HashMap::new()).unwrap();
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
