//! Template lowering: Circom template → complete ProveIR.
//!
//! Orchestrates signal extraction, environment setup, and body lowering
//! to produce a fully-formed `ProveIR` from a Circom `TemplateDef`.

use std::collections::HashSet;

use ir::prove_ir::types::{CaptureDef, CaptureUsage, CircuitExpr, CircuitNode, ForRange, ProveIR};

use crate::ast::{CircomProgram, MainComponent, TemplateDef};

use super::context::LoweringContext;
use super::env::LoweringEnv;
use super::error::LoweringError;
use super::signals::extract_signal_layout;
use super::statements::lower_stmts;

/// Lower a Circom template definition to a ProveIR circuit template.
///
/// The `program` provides access to all template and function definitions
/// for component inlining and function call resolution.
/// The `main_component` determines which input signals are public vs witness.
pub fn lower_template(
    template: &TemplateDef,
    main: Option<&MainComponent>,
    program: &CircomProgram,
) -> Result<ProveIR, LoweringError> {
    let mut ctx = LoweringContext::from_program(program);
    // 1. Extract signal layout
    let layout = extract_signal_layout(template, main)?;

    // 2. Build lowering environment
    let mut env = LoweringEnv::new();

    // Input signals → env.inputs
    for input in &layout.public_inputs {
        env.inputs.insert(input.name.clone());
    }
    for input in &layout.witness_inputs {
        env.inputs.insert(input.name.clone());
    }

    // Output signals → env.locals (they'll be assigned in the body)
    for out in &layout.outputs {
        env.locals.insert(out.name.clone());
    }

    // Intermediate signals → env.locals
    for inter in &layout.intermediates {
        env.locals.insert(inter.name.clone());
    }

    // Template parameters → env.captures
    for param in &template.params {
        env.captures.insert(param.clone());
    }

    // 3. Lower body statements
    let body = lower_stmts(&template.body.stmts, &mut env, &mut ctx)?;

    // 4. Classify captures
    let captures = classify_captures(&template.params, &body);

    // 5. Assemble ProveIR
    Ok(ProveIR {
        name: Some(template.name.clone()),
        public_inputs: layout.public_inputs,
        witness_inputs: layout.witness_inputs,
        captures,
        body,
        capture_arrays: Vec::new(),
    })
}

/// Classify template parameter captures based on how they are used in the body.
///
/// - **StructureOnly**: only in loop bounds (`ForRange::WithCapture`) or
///   `Pow` exponents — affects circuit shape, not constraint values.
/// - **CircuitInput**: only in constraint expressions (`CircuitExpr::Capture`).
/// - **Both**: used in both structural and constraint positions.
fn classify_captures(params: &[String], body: &[CircuitNode]) -> Vec<CaptureDef> {
    let mut structural: HashSet<&str> = HashSet::new();
    let mut circuit: HashSet<&str> = HashSet::new();

    for node in body {
        collect_capture_usage(node, &mut structural, &mut circuit);
    }

    let param_set: HashSet<&str> = params.iter().map(|s| s.as_str()).collect();
    let mut captures = Vec::new();

    for param in params {
        if !param_set.contains(param.as_str()) {
            continue;
        }
        let in_struct = structural.contains(param.as_str());
        let in_circuit = circuit.contains(param.as_str());

        if !in_struct && !in_circuit {
            // Capture is declared but never referenced — still include it
            // as StructureOnly (no-op at instantiation).
            captures.push(CaptureDef {
                name: param.clone(),
                usage: CaptureUsage::StructureOnly,
            });
        } else {
            let usage = match (in_struct, in_circuit) {
                (true, true) => CaptureUsage::Both,
                (true, false) => CaptureUsage::StructureOnly,
                (false, true) => CaptureUsage::CircuitInput,
                (false, false) => unreachable!(),
            };
            captures.push(CaptureDef {
                name: param.clone(),
                usage,
            });
        }
    }

    captures
}

/// Walk a CircuitNode, recording which captures appear in structural vs
/// circuit positions.
fn collect_capture_usage<'a>(
    node: &'a CircuitNode,
    structural: &mut HashSet<&'a str>,
    circuit: &mut HashSet<&'a str>,
) {
    match node {
        CircuitNode::Let { value, .. } => collect_expr_captures(value, circuit),
        CircuitNode::LetArray { elements, .. } => {
            for e in elements {
                collect_expr_captures(e, circuit);
            }
        }
        CircuitNode::AssertEq { lhs, rhs, .. } => {
            collect_expr_captures(lhs, circuit);
            collect_expr_captures(rhs, circuit);
        }
        CircuitNode::Assert { expr, .. } => collect_expr_captures(expr, circuit),
        CircuitNode::For { range, body, .. } => {
            // Loop bound captures are structural
            if let ForRange::WithCapture { end_capture, .. } = range {
                structural.insert(end_capture.as_str());
            }
            for n in body {
                collect_capture_usage(n, structural, circuit);
            }
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            collect_expr_captures(cond, circuit);
            for n in then_body {
                collect_capture_usage(n, structural, circuit);
            }
            for n in else_body {
                collect_capture_usage(n, structural, circuit);
            }
        }
        CircuitNode::Expr { expr, .. } => collect_expr_captures(expr, circuit),
        CircuitNode::Decompose { value, .. } => collect_expr_captures(value, circuit),
        CircuitNode::WitnessHint { hint, .. } => collect_expr_captures(hint, circuit),
        CircuitNode::LetIndexed { index, value, .. } => {
            collect_expr_captures(index, circuit);
            collect_expr_captures(value, circuit);
        }
        CircuitNode::WitnessHintIndexed { index, hint, .. } => {
            collect_expr_captures(index, circuit);
            collect_expr_captures(hint, circuit);
        }
    }
}

/// Collect all `Capture(name)` references in a circuit expression.
fn collect_expr_captures<'a>(expr: &'a CircuitExpr, captures: &mut HashSet<&'a str>) {
    match expr {
        CircuitExpr::Capture(name) => {
            captures.insert(name.as_str());
        }
        CircuitExpr::BinOp { lhs, rhs, .. }
        | CircuitExpr::Comparison { lhs, rhs, .. }
        | CircuitExpr::BoolOp { lhs, rhs, .. }
        | CircuitExpr::IntDiv { lhs, rhs, .. }
        | CircuitExpr::IntMod { lhs, rhs, .. } => {
            collect_expr_captures(lhs, captures);
            collect_expr_captures(rhs, captures);
        }
        CircuitExpr::UnaryOp { operand, .. } => collect_expr_captures(operand, captures),
        CircuitExpr::Mux {
            cond,
            if_true,
            if_false,
        } => {
            collect_expr_captures(cond, captures);
            collect_expr_captures(if_true, captures);
            collect_expr_captures(if_false, captures);
        }
        CircuitExpr::PoseidonHash { left, right } => {
            collect_expr_captures(left, captures);
            collect_expr_captures(right, captures);
        }
        CircuitExpr::PoseidonMany(args) => {
            for a in args {
                collect_expr_captures(a, captures);
            }
        }
        CircuitExpr::RangeCheck { value, .. } => collect_expr_captures(value, captures),
        CircuitExpr::MerkleVerify { root, leaf, .. } => {
            collect_expr_captures(root, captures);
            collect_expr_captures(leaf, captures);
        }
        CircuitExpr::ArrayIndex { index, .. } => collect_expr_captures(index, captures),
        CircuitExpr::Pow { base, .. } => collect_expr_captures(base, captures),
        CircuitExpr::BitAnd { lhs, rhs, .. }
        | CircuitExpr::BitOr { lhs, rhs, .. }
        | CircuitExpr::BitXor { lhs, rhs, .. } => {
            collect_expr_captures(lhs, captures);
            collect_expr_captures(rhs, captures);
        }
        CircuitExpr::BitNot { operand, .. }
        | CircuitExpr::ShiftR { operand, .. }
        | CircuitExpr::ShiftL { operand, .. } => {
            collect_expr_captures(operand, captures);
        }
        // Leaf nodes with no captures
        CircuitExpr::Const(_)
        | CircuitExpr::Input(_)
        | CircuitExpr::Var(_)
        | CircuitExpr::ArrayLen(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;
    use ir::prove_ir::types::{CaptureUsage, CircuitNode, ForRange};

    fn parse_and_lower(src: &str) -> ProveIR {
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);

        // Find the template that matches the main component, or use the first one.
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

    // ── Basic template ──────────────────────────────────────────────

    #[test]
    fn simple_multiplier() {
        let ir = parse_and_lower(
            r#"
            template Multiplier() {
                signal input a;
                signal input b;
                signal output c;
                c <== a * b;
            }
            component main = Multiplier();
            "#,
        );

        assert_eq!(ir.name, Some("Multiplier".to_string()));
        // No public signals declared in main, so all inputs are witness
        assert!(ir.public_inputs.is_empty());
        assert_eq!(ir.witness_inputs.len(), 2);
        assert_eq!(ir.witness_inputs[0].name, "a");
        assert_eq!(ir.witness_inputs[1].name, "b");

        // c <== a * b → Let(c) + AssertEq(c, a*b)
        assert_eq!(ir.body.len(), 2);
        assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "c"));
        assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
    }

    #[test]
    fn multiplier_with_public_inputs() {
        let ir = parse_and_lower(
            r#"
            template Multiplier() {
                signal input a;
                signal input b;
                signal output c;
                c <== a * b;
            }
            component main {public [a]} = Multiplier();
            "#,
        );

        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "a");
        assert_eq!(ir.witness_inputs.len(), 1);
        assert_eq!(ir.witness_inputs[0].name, "b");
    }

    // ── IsZero pattern ──────────────────────────────────────────────

    #[test]
    fn iszero_template() {
        let ir = parse_and_lower(
            r#"
            template IsZero() {
                signal input in;
                signal output out;
                signal inv;
                inv <-- 1;
                out <== 0 - in * inv + 1;
                in * out === 0;
            }
            component main = IsZero();
            "#,
        );

        assert_eq!(ir.name, Some("IsZero".to_string()));
        assert_eq!(ir.witness_inputs.len(), 1);
        assert_eq!(ir.witness_inputs[0].name, "in");

        // inv <-- 1 → Let
        // out <== ... → Let + AssertEq
        // in * out === 0 → AssertEq
        assert_eq!(ir.body.len(), 4);
    }

    // ── For loop template ───────────────────────────────────────────

    #[test]
    fn num2bits_style() {
        let ir = parse_and_lower(
            r#"
            template Num2Bits() {
                signal input in;
                signal output out;
                var lc = 0;
                for (var i = 0; i < 8; i++) {
                    out <-- 1;
                    lc += 1;
                }
                lc === in;
            }
            component main = Num2Bits();
            "#,
        );

        // var lc = 0 → Let(lc)
        // for loop → For
        // lc === in → AssertEq
        assert_eq!(ir.body.len(), 3);
        match &ir.body[1] {
            CircuitNode::For {
                var, range, body, ..
            } => {
                assert_eq!(var, "i");
                assert_eq!(*range, ForRange::Literal { start: 0, end: 8 });
                // out <-- 1 → Let, lc += 1 → Let
                assert_eq!(body.len(), 2);
            }
            other => panic!("expected For, got {:?}", other),
        }
    }

    // ── If/else template ────────────────────────────────────────────

    #[test]
    fn conditional_template() {
        let ir = parse_and_lower(
            r#"
            template Cond() {
                signal input sel;
                signal output out;
                if (sel == 0) {
                    out <-- 1;
                } else {
                    out <-- 2;
                }
                out === sel + 1;
            }
            component main = Cond();
            "#,
        );

        // if/else → If, out === ... → AssertEq
        assert_eq!(ir.body.len(), 2);
        assert!(matches!(&ir.body[0], CircuitNode::If { .. }));
        assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
    }

    // ── Assert template ─────────────────────────────────────────────

    #[test]
    fn assert_in_template() {
        let ir = parse_and_lower(
            r#"
            template CheckNonZero() {
                signal input x;
                assert(x != 0);
            }
            component main = CheckNonZero();
            "#,
        );

        assert_eq!(ir.body.len(), 1);
        assert!(matches!(&ir.body[0], CircuitNode::Assert { .. }));
    }

    // ── Empty template ──────────────────────────────────────────────

    #[test]
    fn empty_template() {
        let ir = parse_and_lower(
            r#"
            template Empty() {}
            component main = Empty();
            "#,
        );

        assert_eq!(ir.name, Some("Empty".to_string()));
        assert!(ir.public_inputs.is_empty());
        assert!(ir.witness_inputs.is_empty());
        assert!(ir.body.is_empty());
    }

    // ── Template name ───────────────────────────────────────────────

    #[test]
    fn template_name_preserved() {
        let ir = parse_and_lower(
            r#"
            template MyCircuit() {
                signal input x;
                signal output y;
                y <== x;
            }
            component main = MyCircuit();
            "#,
        );

        assert_eq!(ir.name, Some("MyCircuit".to_string()));
    }

    // ── BabyAdd-style pattern ───────────────────────────────────────

    #[test]
    fn babyadd_pattern() {
        let ir = parse_and_lower(
            r#"
            template BabyAdd() {
                signal input x1;
                signal input y1;
                signal output xout;
                signal output yout;
                signal beta;
                signal gamma;
                xout <-- 1;
                yout <-- 1;
                xout === beta + gamma;
                yout === beta - gamma;
            }
            component main = BabyAdd();
            "#,
        );

        // 4 inputs (witness), 4 body nodes:
        // xout <-- 1, yout <-- 1, xout === ..., yout === ...
        assert_eq!(ir.witness_inputs.len(), 2); // x1, y1
        assert_eq!(ir.body.len(), 4);
    }

    // ── Component inlining ─────────────────────────────────────────

    #[test]
    fn component_inlining_multiplier() {
        let ir = parse_and_lower(
            r#"
            template Multiplier() {
                signal input a;
                signal input b;
                signal output c;
                c <== a * b;
            }
            template Main() {
                signal input x;
                signal input y;
                signal output out;
                component m = Multiplier();
                m.a <== x;
                m.b <== y;
                out <== m.c;
            }
            component main = Main();
            "#,
        );

        assert_eq!(ir.name, Some("Main".to_string()));
        assert_eq!(ir.witness_inputs.len(), 2); // x, y

        // Body should contain:
        // m.a = x (wiring Let + AssertEq)
        // m.b = y (wiring Let + AssertEq)
        // [inlined Multiplier body: m.c = m.a * m.b (Let + AssertEq)]
        // out = m.c (Let + AssertEq)
        // Check that inlined body references mangled names
        let has_mangled_let = ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "m.c"));
        assert!(has_mangled_let, "should have Let for m.c from inlined body");
    }

    #[test]
    fn component_no_inputs() {
        let ir = parse_and_lower(
            r#"
            template Constant() {
                signal output out;
                out <== 42;
            }
            template Main() {
                signal output result;
                component c = Constant();
                result <== c.out;
            }
            component main = Main();
            "#,
        );

        // Constant has no inputs → inlined immediately at ComponentDecl
        let has_mangled = ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "c.out"));
        assert!(has_mangled, "should have Let for c.out from inlined body");
    }

    #[test]
    fn component_with_template_args() {
        let ir = parse_and_lower(
            r#"
            template Scale(factor) {
                signal input in;
                signal output out;
                out <== in * factor;
            }
            template Main() {
                signal input x;
                signal output y;
                component s = Scale(3);
                s.in <== x;
                y <== s.out;
            }
            component main = Main();
            "#,
        );

        // The inlined body should have substituted `factor` with 3
        let has_scale_out = ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "s.out"));
        assert!(has_scale_out, "should have Let for s.out");
    }

    // ── Function inlining ──────────────────────────────────────────

    #[test]
    fn function_inlining_simple() {
        let ir = parse_and_lower(
            r#"
            function square(x) {
                return x * x;
            }
            template Main() {
                signal input a;
                signal output b;
                b <== square(a);
            }
            component main = Main();
            "#,
        );

        assert_eq!(ir.witness_inputs.len(), 1);
        // b <== square(a) should inline to b <== a * a
        assert_eq!(ir.body.len(), 2); // Let + AssertEq
    }

    #[test]
    fn function_inlining_with_two_args() {
        let ir = parse_and_lower(
            r#"
            function add_mul(a, b) {
                return (a + b) * a;
            }
            template Main() {
                signal input x;
                signal input y;
                signal output z;
                z <== add_mul(x, y);
            }
            component main = Main();
            "#,
        );

        assert_eq!(ir.body.len(), 2); // Let + AssertEq
    }

    #[test]
    fn function_inlining_nested_call() {
        let ir = parse_and_lower(
            r#"
            function double(x) {
                return x + x;
            }
            function quad(x) {
                return double(double(x));
            }
            template Main() {
                signal input a;
                signal output b;
                b <== quad(a);
            }
            component main = Main();
            "#,
        );

        assert_eq!(ir.body.len(), 2); // Let + AssertEq
    }

    #[test]
    fn function_undefined_errors() {
        let src = r#"
            template Main() {
                signal input a;
                signal output b;
                b <== unknown_fn(a);
            }
            component main = Main();
        "#;
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty());
        let template = match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };
        let result = lower_template(template, prog.main_component.as_ref(), &prog);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("undefined function"));
    }

    // ── Capture classification ─────────────────────────────────────

    #[test]
    fn capture_circuit_input() {
        let ir = parse_and_lower(
            r#"
            template Scale(factor) {
                signal input x;
                signal output y;
                y <== x * factor;
            }
            component main = Scale();
            "#,
        );

        assert_eq!(ir.captures.len(), 1);
        assert_eq!(ir.captures[0].name, "factor");
        assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
    }

    #[test]
    fn capture_unused_is_structure_only() {
        let ir = parse_and_lower(
            r#"
            template T(unused_param) {
                signal input x;
                signal output y;
                y <== x;
            }
            component main = T();
            "#,
        );

        assert_eq!(ir.captures.len(), 1);
        assert_eq!(ir.captures[0].name, "unused_param");
        assert_eq!(ir.captures[0].usage, CaptureUsage::StructureOnly);
    }

    #[test]
    fn capture_no_params_no_captures() {
        let ir = parse_and_lower(
            r#"
            template T() {
                signal input x;
                signal output y;
                y <== x;
            }
            component main = T();
            "#,
        );

        assert!(ir.captures.is_empty());
    }

    // ── Array literal expansion ────────────────────────────────────

    #[test]
    fn array_literal_expands_to_individual_lets() {
        let ir = parse_and_lower(
            r#"
            template T() {
                signal input x;
                signal output out;
                var coeffs = [1, 2, 3];
                out <== x * coeffs[1];
            }
            component main = T();
            "#,
        );

        // coeffs = [1, 2, 3] → Let(coeffs_0=1), Let(coeffs_1=2), Let(coeffs_2=3)
        // out <== x * coeffs[1] → Let(out) + AssertEq
        // coeffs[1] should resolve to Var("coeffs_1")
        let let_names: Vec<&str> = ir
            .body
            .iter()
            .filter_map(|n| match n {
                CircuitNode::Let { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert!(let_names.contains(&"coeffs_0"));
        assert!(let_names.contains(&"coeffs_1"));
        assert!(let_names.contains(&"coeffs_2"));
        assert!(let_names.contains(&"out"));
    }

    // ── Real circomlib Num2Bits ────────────────────────────────────

    #[test]
    fn real_num2bits_lowering() {
        let ir = parse_and_lower(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
                var lc1 = 0;
                var e2 = 1;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    out[i] * (out[i] - 1) === 0;
                    lc1 += out[i] * e2;
                    e2 = e2 + e2;
                }
                lc1 === in;
            }
            component main {public [in]} = Num2Bits(8);
            "#,
        );

        assert_eq!(ir.name, Some("Num2Bits".to_string()));
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "in");
        // n is a capture (template parameter)
        assert!(!ir.captures.is_empty());
        assert_eq!(ir.captures[0].name, "n");
        // Body should have: Let(lc1), Let(e2), For { ... }, AssertEq(lc1 === in)
        assert!(ir.body.len() >= 3, "body has {} nodes", ir.body.len());
        // Verify the For node exists
        let has_for = ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. }));
        assert!(has_for, "should have a For node for the loop");
    }
}
