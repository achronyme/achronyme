//! Component-prefix name mangling for `CircuitNode` bodies.
//!
//! When a template body is reused under a component instance, every
//! signal / variable name it declares or references is rewritten with
//! the instance prefix (`comp.signal`) so distinct instances don't
//! collide, and template parameters are substituted with the caller's
//! argument expressions. `.` is the separator (it cannot appear in a
//! Circom identifier, so collisions are impossible).
//!
//! This is a pure transform over the `ir_forge` `CircuitNode` /
//! `CircuitExpr` tree with no frontend dependency, so it serves as the
//! single canonical mangle for both the lowering-time inline path and
//! the instantiation-time [`CircuitNode::ComponentCall`] expansion.
//! Both paths calling the same function is what makes deferred
//! expansion byte-identical to eager inlining.

use std::collections::HashMap;

use super::{CircuitExpr, CircuitNode, ForRange};

/// Mangle every node in `nodes` with `prefix`, substituting captures
/// via `param_subs` (param name → argument expression).
pub fn mangle_nodes(
    nodes: &[CircuitNode],
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> Vec<CircuitNode> {
    nodes
        .iter()
        .map(|n| mangle_node(n, prefix, param_subs))
        .collect()
}

pub fn mangle_node(
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
        CircuitNode::WitnessArrayDecl { name, size, span } => CircuitNode::WitnessArrayDecl {
            name: mangle_name(prefix, name),
            size: size.clone(),
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
        CircuitNode::WitnessCall {
            output_bindings,
            input_signals,
            program_bytes,
            span,
        } => CircuitNode::WitnessCall {
            output_bindings: output_bindings
                .iter()
                .map(|n| mangle_name(prefix, n))
                .collect(),
            input_signals: input_signals
                .iter()
                .map(|e| mangle_expr(e, prefix, param_subs))
                .collect(),
            // Opaque Artik bytecode is unaffected by template
            // mangling — its internal signal / slot ids are set at
            // lift time and do not collide with outer-template names.
            program_bytes: program_bytes.clone(),
            span: span.clone(),
        },
        // A deferred component instance nested inside a reused body.
        // Composing prefixes here is what keeps deferred expansion
        // equivalent to eager inlining: applying the outer prefix to
        // this node's instance name, then expanding the referenced
        // body under that composed prefix, yields the same final
        // names as if the inner body had been inlined first and the
        // whole thing mangled once. `body_key` indexes shared
        // unmangled content and is therefore prefix-independent.
        CircuitNode::ComponentCall {
            body_key,
            comp_name,
            param_subs: subs,
            span,
        } => CircuitNode::ComponentCall {
            body_key: body_key.clone(),
            comp_name: mangle_name(prefix, comp_name),
            param_subs: subs
                .iter()
                .map(|(k, v)| (k.clone(), mangle_expr(v, prefix, param_subs)))
                .collect(),
            span: span.clone(),
        },
    }
}

pub fn mangle_expr(
    expr: &CircuitExpr,
    prefix: &str,
    param_subs: &HashMap<String, CircuitExpr>,
) -> CircuitExpr {
    match expr {
        // Leaf nodes
        CircuitExpr::Const(c) => CircuitExpr::Const(*c),
        // R1″ placeholder is loop-local, not template-level. Pass
        // through unchanged so the for-loop unroller can substitute
        // it after template-inlining mangling has finished.
        CircuitExpr::LoopVar(token) => CircuitExpr::LoopVar(*token),
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

pub fn mangle_range(
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
/// Uses `.` as separator to match the DotAccess convention:
/// `comp.field`. The `.` character cannot appear in Circom
/// identifiers, making collisions impossible.
pub fn mangle_name(prefix: &str, name: &str) -> String {
    let mut mangled = String::with_capacity(prefix.len() + 1 + name.len());
    mangled.push_str(prefix);
    mangled.push('.');
    mangled.push_str(name);
    mangled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CircuitBinOp, FieldConst};

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

    /// Nested `ComponentCall` composition: applying an outer prefix to
    /// a body that already holds a deferred inner instance must prefix
    /// the inner instance name and mangle its substitution expressions,
    /// while leaving the content-addressed `body_key` untouched. This
    /// is the invariant that makes deferred expansion equivalent to
    /// eager inlining.
    #[test]
    fn mangle_nested_component_call_composes_prefix() {
        let inner = CircuitNode::ComponentCall {
            body_key: "Inner:n=4".to_string(),
            comp_name: "sub_0".to_string(),
            param_subs: vec![("n".to_string(), CircuitExpr::Var("acc".to_string()))],
            span: None,
        };
        let result = mangle_node(&inner, "outer_3", &HashMap::new());
        match result {
            CircuitNode::ComponentCall {
                body_key,
                comp_name,
                param_subs,
                ..
            } => {
                assert_eq!(body_key, "Inner:n=4", "content key is prefix-independent");
                assert_eq!(comp_name, "outer_3.sub_0");
                assert_eq!(param_subs.len(), 1);
                assert_eq!(param_subs[0].0, "n");
                assert_eq!(
                    param_subs[0].1,
                    CircuitExpr::Var("outer_3.acc".to_string()),
                    "substitution expressions are mangled with the outer prefix"
                );
            }
            _ => panic!("expected ComponentCall"),
        }
    }
}
