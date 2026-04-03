//! Template lowering: Circom template → complete ProveIR.
//!
//! Orchestrates signal extraction, environment setup, and body lowering
//! to produce a fully-formed `ProveIR` from a Circom `TemplateDef`.

use ir::prove_ir::types::ProveIR;

use crate::ast::{MainComponent, TemplateDef};

use super::error::LoweringError;
use super::expressions::LoweringEnv;
use super::signals::extract_signal_layout;
use super::statements::lower_stmts;

/// Lower a Circom template definition to a ProveIR circuit template.
///
/// The `main_component` is needed to determine which input signals are
/// public vs witness (from `component main {public [...]}`).
/// Template parameters become captures.
pub fn lower_template(
    template: &TemplateDef,
    main: Option<&MainComponent>,
) -> Result<ProveIR, LoweringError> {
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
    let body = lower_stmts(&template.body.stmts, &mut env)?;

    // 4. Assemble ProveIR
    //
    // Captures are classified later (when we have usage analysis).
    // For now, all template params are registered but capture classification
    // (StructureOnly vs CircuitInput vs Both) will be done in a later phase.
    Ok(ProveIR {
        name: Some(template.name.clone()),
        public_inputs: layout.public_inputs,
        witness_inputs: layout.witness_inputs,
        captures: Vec::new(), // TODO: capture classification (Fase 6)
        body,
        capture_arrays: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_circom;
    use ir::prove_ir::types::{CircuitNode, ForRange};

    fn parse_and_lower(src: &str) -> ProveIR {
        let (prog, errors) = parse_circom(src).expect("parse failed");
        assert!(errors.is_empty(), "parse errors: {:?}", errors);

        let template = match &prog.definitions[0] {
            crate::ast::Definition::Template(t) => t,
            _ => panic!("expected template"),
        };

        lower_template(template, prog.main_component.as_ref()).unwrap()
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
            CircuitNode::For { var, range, body, .. } => {
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
}
