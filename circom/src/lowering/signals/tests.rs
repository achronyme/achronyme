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
