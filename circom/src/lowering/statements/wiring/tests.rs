use super::*;
use crate::ast::{Block, TemplateDef, TemplateModifiers};
use diagnostics::Span;
use ir_forge::types::FieldConst;

fn dummy_span() -> Span {
    Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    }
}

fn dummy_template() -> TemplateDef {
    TemplateDef {
        name: "T".into(),
        params: vec![],
        modifiers: TemplateModifiers::default(),
        body: Block {
            stmts: vec![],
            span: dummy_span(),
        },
        span: dummy_span(),
        source_file: None,
    }
}

fn pending_with_inputs<'a>(template: &'a TemplateDef, inputs: &[&str]) -> PendingComponent<'a> {
    let input_signals: HashSet<String> = inputs.iter().map(|s| s.to_string()).collect();
    PendingComponent::new(template, vec![], HashMap::new(), input_signals)
}

#[test]
fn new_initializes_to_all_scalar_empty() {
    let tmpl = dummy_template();
    let comp = pending_with_inputs(&tmpl, &["a", "b"]);
    assert!(matches!(&comp.state, WiringState::AllScalar { wired } if wired.is_empty()));
    assert!(comp.const_wired.is_empty());
    assert!(!comp.is_ready_to_inline());
}

#[test]
fn scalar_only_path_reaches_ready_when_all_inputs_wired() {
    let tmpl = dummy_template();
    let mut comp = pending_with_inputs(&tmpl, &["a", "b"]);
    comp.mark_wired("a".into(), None, false);
    assert!(!comp.is_ready_to_inline());
    comp.mark_wired("b".into(), None, false);
    assert!(comp.is_ready_to_inline());
    assert!(matches!(comp.state, WiringState::AllScalar { .. }));
}

#[test]
fn extra_scalar_wirings_beyond_inputs_still_ready() {
    let tmpl = dummy_template();
    let mut comp = pending_with_inputs(&tmpl, &["a"]);
    comp.mark_wired("a".into(), None, false);
    comp.mark_wired("extra".into(), None, false);
    assert!(comp.is_ready_to_inline());
}

#[test]
fn indexed_wiring_disables_trigger_even_with_full_coverage() {
    let tmpl = dummy_template();
    let mut comp = pending_with_inputs(&tmpl, &["a", "b"]);
    comp.mark_wired("a".into(), None, true);
    comp.mark_wired("b".into(), None, false);
    assert!(!comp.is_ready_to_inline());
    assert!(matches!(comp.state, WiringState::PartialIndexed { .. }));
}

#[test]
fn indexed_then_scalar_stays_partial_indexed() {
    let tmpl = dummy_template();
    let mut comp = pending_with_inputs(&tmpl, &["a", "b", "c"]);
    comp.mark_wired("a".into(), None, true);
    assert!(matches!(comp.state, WiringState::PartialIndexed { .. }));
    // Subsequent scalar wirings cannot revert the state.
    comp.mark_wired("b".into(), None, false);
    comp.mark_wired("c".into(), None, false);
    assert!(matches!(comp.state, WiringState::PartialIndexed { .. }));
    assert!(!comp.is_ready_to_inline());
}

#[test]
fn const_value_is_recorded_in_const_wired() {
    let tmpl = dummy_template();
    let mut comp = pending_with_inputs(&tmpl, &["a"]);
    let fc = FieldConst::from_u64(42);
    comp.mark_wired("a".into(), Some(&CircuitExpr::Const(fc)), false);
    assert_eq!(comp.const_wired.get("a"), Some(&fc));
}

#[test]
fn non_const_value_does_not_populate_const_wired() {
    let tmpl = dummy_template();
    let mut comp = pending_with_inputs(&tmpl, &["a"]);
    comp.mark_wired("a".into(), Some(&CircuitExpr::Var("x".into())), false);
    assert!(comp.const_wired.is_empty());
}

#[test]
fn template_span_returns_template_declaration_span() {
    let tmpl = dummy_template();
    let comp = pending_with_inputs(&tmpl, &["a"]);
    assert_eq!(comp.template_span(), &tmpl.span);
}
