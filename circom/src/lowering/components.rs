//! Component instantiation: inline Circom template bodies.
//!
//! When a Circom template instantiates a component:
//! ```circom
//! component c = Multiplier();
//! c.a <== x;
//! c.b <== y;
//! out <== c.out;
//! ```
//!
//! We inline the template body at the point where all input signals are wired,
//! mangling signal/variable names with the component prefix (`c_a`, `c_b`, `c_c`).
//!
//! The mangling format matches the existing `DotAccess` lowering in `expressions.rs`:
//! `component_field` (single underscore separator).

use std::collections::HashMap;

use ir::prove_ir::types::{
    CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitNode, CircuitUnaryOp, ForRange,
};

use crate::ast::TemplateDef;

use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::signals::collect_signal_names;
use super::statements::lower_stmts;

/// Inline a component's template body with mangled names.
///
/// Returns a list of `CircuitNode`s from the template body, with all
/// variable names prefixed by `comp_name_` and template parameter
/// captures substituted with argument expressions.
///
/// The caller is responsible for emitting the signal wirings (Let bindings)
/// before these nodes.
pub fn inline_component_body<'a>(
    comp_name: &str,
    template: &'a TemplateDef,
    template_args: &[CircuitExpr],
    ctx: &mut LoweringContext<'a>,
    span: &diagnostics::Span,
) -> Result<Vec<CircuitNode>, LoweringError> {
    // Check recursion depth
    if ctx.inline_depth >= super::context::MAX_INLINE_DEPTH {
        return Err(LoweringError::new(
            format!(
                "component inlining depth limit ({}) exceeded — \
                 possible recursion via `{}`",
                super::context::MAX_INLINE_DEPTH,
                template.name,
            ),
            span,
        ));
    }
    ctx.inline_depth += 1;

    // Build parameter substitution map: param_name → arg_expr
    let mut param_subs: HashMap<String, CircuitExpr> = HashMap::new();
    for (i, param) in template.params.iter().enumerate() {
        if let Some(arg) = template_args.get(i) {
            param_subs.insert(param.clone(), arg.clone());
        }
    }

    // Build env for the sub-template (original signal names)
    let mut env = LoweringEnv::new();

    let signals = collect_signal_names(&template.body.stmts);
    for (name, sig_type) in &signals {
        match sig_type {
            crate::ast::SignalType::Input => {
                // Input signals are wired from outside → they'll be Var references
                // (the Let bindings from wirings use the mangled name)
                env.inputs.insert(name.clone());
            }
            crate::ast::SignalType::Output | crate::ast::SignalType::Intermediate => {
                env.locals.insert(name.clone());
            }
        }
    }
    for param in &template.params {
        env.captures.insert(param.clone());
    }

    // Lower template body with original names
    let nodes = lower_stmts(&template.body.stmts, &mut env, ctx)?;

    // Mangle all names and substitute captures
    let mangled = mangle_nodes(&nodes, comp_name, &param_subs);

    ctx.inline_depth -= 1;
    Ok(mangled)
}

/// Register a component's output and intermediate signals as locals in the
/// parent environment (with mangled names).
pub fn register_component_locals(
    comp_name: &str,
    template: &TemplateDef,
    parent_env: &mut LoweringEnv,
) {
    let signals = collect_signal_names(&template.body.stmts);
    for (name, sig_type) in &signals {
        match sig_type {
            // Input signals are wired explicitly — they become locals too
            crate::ast::SignalType::Input
            | crate::ast::SignalType::Output
            | crate::ast::SignalType::Intermediate => {
                parent_env.locals.insert(format!("{comp_name}.{name}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Name mangling
// ---------------------------------------------------------------------------

/// Mangle a list of CircuitNodes: prefix all names and substitute captures.
fn mangle_nodes(
    nodes: &[CircuitNode],
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> Vec<CircuitNode> {
    nodes
        .iter()
        .map(|n| mangle_node(n, prefix, param_subs))
        .collect()
}

fn mangle_node(
    node: &CircuitNode,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> CircuitNode {
    match node {
        CircuitNode::Let { name, value, span } => CircuitNode::Let {
            name: mangle_name(prefix, name),
            value: mangle_expr(value, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::LetArray {
            name,
            elements,
            span,
        } => CircuitNode::LetArray {
            name: mangle_name(prefix, name),
            elements: elements
                .iter()
                .map(|e| mangle_expr(e, prefix, param_subs))
                .collect(),
            span: span.clone(),
        },
        CircuitNode::AssertEq {
            lhs,
            rhs,
            message,
            span,
        } => CircuitNode::AssertEq {
            lhs: mangle_expr(lhs, prefix, param_subs),
            rhs: mangle_expr(rhs, prefix, param_subs),
            message: message.clone(),
            span: span.clone(),
        },
        CircuitNode::Assert {
            expr,
            message,
            span,
        } => CircuitNode::Assert {
            expr: mangle_expr(expr, prefix, param_subs),
            message: message.clone(),
            span: span.clone(),
        },
        CircuitNode::For {
            var,
            range,
            body,
            span,
        } => CircuitNode::For {
            var: mangle_name(prefix, var),
            range: mangle_range(range, prefix, param_subs),
            body: mangle_nodes(body, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            span,
        } => CircuitNode::If {
            cond: mangle_expr(cond, prefix, param_subs),
            then_body: mangle_nodes(then_body, prefix, param_subs),
            else_body: mangle_nodes(else_body, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::Expr { expr, span } => CircuitNode::Expr {
            expr: mangle_expr(expr, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::Decompose {
            name,
            value,
            num_bits,
            span,
        } => CircuitNode::Decompose {
            name: mangle_name(prefix, name),
            value: mangle_expr(value, prefix, param_subs),
            num_bits: *num_bits,
            span: span.clone(),
        },
        CircuitNode::WitnessHint { name, hint, span } => CircuitNode::WitnessHint {
            name: mangle_name(prefix, name),
            hint: mangle_expr(hint, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::LetIndexed {
            array,
            index,
            value,
            span,
        } => CircuitNode::LetIndexed {
            array: mangle_name(prefix, array),
            index: mangle_expr(index, prefix, param_subs),
            value: mangle_expr(value, prefix, param_subs),
            span: span.clone(),
        },
        CircuitNode::WitnessHintIndexed {
            array,
            index,
            hint,
            span,
        } => CircuitNode::WitnessHintIndexed {
            array: mangle_name(prefix, array),
            index: mangle_expr(index, prefix, param_subs),
            hint: mangle_expr(hint, prefix, param_subs),
            span: span.clone(),
        },
    }
}

fn mangle_expr(
    expr: &CircuitExpr,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> CircuitExpr {
    match expr {
        // Leaf nodes
        CircuitExpr::Const(c) => CircuitExpr::Const(*c),
        CircuitExpr::Input(name) => {
            // Input signals in inlined body → Var with mangled name
            // (they are wired from outside as Let bindings)
            CircuitExpr::Var(mangle_name(prefix, name))
        }
        CircuitExpr::Var(name) => CircuitExpr::Var(mangle_name(prefix, name)),
        CircuitExpr::Capture(name) => {
            // Substitute capture with template argument expression
            if let Some(sub) = param_subs.get(name) {
                sub.clone()
            } else {
                // Unknown capture — keep as-is with mangled name
                CircuitExpr::Capture(mangle_name(prefix, name))
            }
        }

        // Binary ops
        CircuitExpr::BinOp { op, lhs, rhs } => CircuitExpr::BinOp {
            op: *op,
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
        },
        CircuitExpr::Comparison { op, lhs, rhs } => CircuitExpr::Comparison {
            op: *op,
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
        },
        CircuitExpr::BoolOp { op, lhs, rhs } => CircuitExpr::BoolOp {
            op: *op,
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
        },

        // Unary
        CircuitExpr::UnaryOp { op, operand } => CircuitExpr::UnaryOp {
            op: *op,
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
        },

        // Mux
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => CircuitExpr::Mux {
            cond: Box::new(mangle_expr(cond, prefix, param_subs)),
            if_true: Box::new(mangle_expr(if_true, prefix, param_subs)),
            if_false: Box::new(mangle_expr(if_false, prefix, param_subs)),
        },

        // Crypto
        CircuitExpr::PoseidonHash { left, right } => CircuitExpr::PoseidonHash {
            left: Box::new(mangle_expr(left, prefix, param_subs)),
            right: Box::new(mangle_expr(right, prefix, param_subs)),
        },
        CircuitExpr::PoseidonMany(args) => CircuitExpr::PoseidonMany(
            args.iter()
                .map(|a| mangle_expr(a, prefix, param_subs))
                .collect(),
        ),
        CircuitExpr::RangeCheck { value, bits } => CircuitExpr::RangeCheck {
            value: Box::new(mangle_expr(value, prefix, param_subs)),
            bits: *bits,
        },
        CircuitExpr::MerkleVerify {
            root,
            leaf,
            path,
            indices,
        } => CircuitExpr::MerkleVerify {
            root: Box::new(mangle_expr(root, prefix, param_subs)),
            leaf: Box::new(mangle_expr(leaf, prefix, param_subs)),
            path: mangle_name(prefix, path),
            indices: mangle_name(prefix, indices),
        },

        // Array
        CircuitExpr::ArrayIndex { array, index } => CircuitExpr::ArrayIndex {
            array: mangle_name(prefix, array),
            index: Box::new(mangle_expr(index, prefix, param_subs)),
        },
        CircuitExpr::ArrayLen(name) => CircuitExpr::ArrayLen(mangle_name(prefix, name)),

        // Power
        CircuitExpr::Pow { base, exp } => CircuitExpr::Pow {
            base: Box::new(mangle_expr(base, prefix, param_subs)),
            exp: *exp,
        },

        // Integer ops
        CircuitExpr::IntDiv { lhs, rhs, max_bits } => CircuitExpr::IntDiv {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            max_bits: *max_bits,
        },
        CircuitExpr::IntMod { lhs, rhs, max_bits } => CircuitExpr::IntMod {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            max_bits: *max_bits,
        },

        // Bitwise ops
        CircuitExpr::BitAnd { lhs, rhs, num_bits } => CircuitExpr::BitAnd {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::BitOr { lhs, rhs, num_bits } => CircuitExpr::BitOr {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::BitXor { lhs, rhs, num_bits } => CircuitExpr::BitXor {
            lhs: Box::new(mangle_expr(lhs, prefix, param_subs)),
            rhs: Box::new(mangle_expr(rhs, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::BitNot { operand, num_bits } => CircuitExpr::BitNot {
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::ShiftR {
            operand,
            shift,
            num_bits,
        } => CircuitExpr::ShiftR {
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
            shift: Box::new(mangle_expr(shift, prefix, param_subs)),
            num_bits: *num_bits,
        },
        CircuitExpr::ShiftL {
            operand,
            shift,
            num_bits,
        } => CircuitExpr::ShiftL {
            operand: Box::new(mangle_expr(operand, prefix, param_subs)),
            shift: Box::new(mangle_expr(shift, prefix, param_subs)),
            num_bits: *num_bits,
        },
    }
}

fn mangle_range(
    range: &ForRange,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> ForRange {
    match range {
        ForRange::Literal { start, end } => ForRange::Literal {
            start: *start,
            end: *end,
        },
        ForRange::WithCapture { start, end_capture } => {
            match param_subs.get(end_capture) {
                // Substitution is a constant → fold to Literal
                Some(CircuitExpr::Const(fc)) => {
                    if let Some(end) = fc.to_u64() {
                        return ForRange::Literal { start: *start, end };
                    }
                    ForRange::WithCapture {
                        start: *start,
                        end_capture: mangle_name(prefix, end_capture),
                    }
                }
                // Substitution is an expression (e.g., Capture("n") + Const(1)
                // from `Num2Bits(n+1)`) → use WithExpr so the instantiator
                // can evaluate it when capture values are known
                Some(expr) => ForRange::WithExpr {
                    start: *start,
                    end_expr: Box::new(expr.clone()),
                },
                // No substitution → mangle capture name
                None => ForRange::WithCapture {
                    start: *start,
                    end_capture: mangle_name(prefix, end_capture),
                },
            }
        }
        ForRange::WithExpr { start, end_expr } => ForRange::WithExpr {
            start: *start,
            end_expr: Box::new(mangle_expr(end_expr, prefix, param_subs)),
        },
        ForRange::Array(name) => ForRange::Array(mangle_name(prefix, name)),
    }
}

/// Mangle a variable name with the component prefix.
///
/// Uses `.` as separator to match the DotAccess convention in
/// `expressions.rs`: `comp.field` → `comp.field`. The `.` character
/// cannot appear in Circom identifiers, making collisions impossible.
fn mangle_name(prefix: &str, name: &str) -> String {
    format!("{prefix}.{name}")
}

// Suppress unused warnings for operator enums that are used indirectly
// through the CircuitExpr/CircuitNode match arms above.
#[allow(unused_imports)]
use {CircuitBinOp as _, CircuitBoolOp as _, CircuitCmpOp as _, CircuitUnaryOp as _};

#[cfg(test)]
mod tests {
    use super::*;
    use ir::prove_ir::types::FieldConst;

    #[test]
    fn mangle_name_format() {
        assert_eq!(mangle_name("c", "a"), "c.a");
        assert_eq!(mangle_name("comp", "signal"), "comp.signal");
    }

    #[test]
    fn mangle_expr_input_becomes_var() {
        let expr = CircuitExpr::Input("a".to_string());
        let result = mangle_expr(&expr, "c", &HashMap::new());
        assert_eq!(result, CircuitExpr::Var("c.a".to_string()));
    }

    #[test]
    fn mangle_expr_var_prefixed() {
        let expr = CircuitExpr::Var("x".to_string());
        let result = mangle_expr(&expr, "c", &HashMap::new());
        assert_eq!(result, CircuitExpr::Var("c.x".to_string()));
    }

    #[test]
    fn mangle_expr_capture_substituted() {
        let mut subs = HashMap::new();
        subs.insert("n".to_string(), CircuitExpr::Const(FieldConst::from_u64(8)));
        let expr = CircuitExpr::Capture("n".to_string());
        let result = mangle_expr(&expr, "c", &subs);
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(8)));
    }

    #[test]
    fn mangle_expr_const_unchanged() {
        let expr = CircuitExpr::Const(FieldConst::from_u64(42));
        let result = mangle_expr(&expr, "c", &HashMap::new());
        assert_eq!(result, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn mangle_node_let() {
        let node = CircuitNode::Let {
            name: "x".to_string(),
            value: CircuitExpr::Input("a".to_string()),
            span: None,
        };
        let result = mangle_node(&node, "c", &HashMap::new());
        match result {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "c.x");
                assert_eq!(value, CircuitExpr::Var("c.a".to_string()));
            }
            _ => panic!("expected Let"),
        }
    }

    #[test]
    fn mangle_node_assert_eq() {
        let node = CircuitNode::AssertEq {
            lhs: CircuitExpr::Var("out".to_string()),
            rhs: CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                lhs: Box::new(CircuitExpr::Input("a".to_string())),
                rhs: Box::new(CircuitExpr::Input("b".to_string())),
            },
            message: None,
            span: None,
        };
        let result = mangle_node(&node, "m", &HashMap::new());
        match result {
            CircuitNode::AssertEq { lhs, rhs, .. } => {
                assert_eq!(lhs, CircuitExpr::Var("m.out".to_string()));
                match rhs {
                    CircuitExpr::BinOp { lhs, rhs, .. } => {
                        assert_eq!(*lhs, CircuitExpr::Var("m.a".to_string()));
                        assert_eq!(*rhs, CircuitExpr::Var("m.b".to_string()));
                    }
                    _ => panic!("expected BinOp"),
                }
            }
            _ => panic!("expected AssertEq"),
        }
    }

    #[test]
    fn mangle_for_range_literal_unchanged() {
        let range = ForRange::Literal { start: 0, end: 8 };
        let result = mangle_range(&range, "c", &HashMap::new());
        assert_eq!(result, ForRange::Literal { start: 0, end: 8 });
    }

    #[test]
    fn mangle_for_range_capture_with_known_const() {
        let mut subs = HashMap::new();
        subs.insert(
            "n".to_string(),
            CircuitExpr::Const(FieldConst::from_u64(16)),
        );
        let range = ForRange::WithCapture {
            start: 0,
            end_capture: "n".to_string(),
        };
        let result = mangle_range(&range, "c", &subs);
        assert_eq!(result, ForRange::Literal { start: 0, end: 16 });
    }
}
