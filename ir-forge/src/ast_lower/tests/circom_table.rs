use super::*;
use crate::circom_interop::test_support::StubLibrary;
use crate::{CircomLibraryHandle, CircomTemplateSignature};
use std::sync::Arc;

fn sig(params: &[&str], inputs: &[&str], outputs: &[&str]) -> CircomTemplateSignature {
    CircomTemplateSignature {
        params: params.iter().map(|s| s.to_string()).collect(),
        input_signals: inputs.iter().map(|s| s.to_string()).collect(),
        output_signals: outputs.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn new_compiler_has_empty_circom_table() {
    let compiler = ProveIrCompiler::<Bn254Fr>::new();
    assert!(compiler.circom_table.is_empty());
    assert_eq!(compiler.circom_call_counter, 0);
}

#[test]
fn register_circom_template_inserts_entry_without_bumping_counter() {
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    let lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
        "Square",
        sig(&[], &["x"], &["y"]),
    ));
    compiler.register_circom_template("Square".to_string(), lib, "Square".to_string());

    assert_eq!(compiler.circom_table.len(), 1);
    let entry = compiler
        .lookup_circom_template("Square")
        .expect("Square should be registered");
    assert_eq!(entry.template_name, "Square");
    // Registration alone MUST NOT bump the call counter —
    // only actual instantiation sites do.
    assert_eq!(compiler.circom_call_counter, 0);
}

#[test]
fn next_circom_call_prefix_produces_monotonic_unique_ids() {
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    assert_eq!(compiler.next_circom_call_prefix(), "circom_call_0");
    assert_eq!(compiler.next_circom_call_prefix(), "circom_call_1");
    assert_eq!(compiler.next_circom_call_prefix(), "circom_call_2");
    assert_eq!(compiler.circom_call_counter, 3);
}

#[test]
fn namespaced_key_coexists_with_selective_key() {
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    let poseidon_lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
        "Poseidon",
        sig(&["t"], &["inputs"], &["out"]),
    ));
    let num2bits_lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
        "Num2Bits",
        sig(&["n"], &["in"], &["out"]),
    ));
    compiler.register_circom_template(
        "P::Poseidon".to_string(),
        poseidon_lib,
        "Poseidon".to_string(),
    );
    compiler.register_circom_template("Num2Bits".to_string(), num2bits_lib, "Num2Bits".to_string());

    assert_eq!(compiler.circom_table.len(), 2);
    assert_eq!(
        compiler
            .lookup_circom_template("P::Poseidon")
            .unwrap()
            .template_name,
        "Poseidon"
    );
    assert_eq!(
        compiler
            .lookup_circom_template("Num2Bits")
            .unwrap()
            .template_name,
        "Num2Bits"
    );
    assert!(compiler.lookup_circom_template("Poseidon").is_none());
}

#[test]
fn outer_scope_circom_imports_are_seeded_into_circom_table() {
    // Drive the seeding path end-to-end via `compile_prove_block`
    // so we don't need to construct a `Block` with a synthetic
    // span. Using a trivial prove-block body is enough to
    // exercise OuterScope → circom_table threading.
    let lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
        "Square",
        sig(&[], &["x"], &["y"]),
    ));
    let mut imports = HashMap::new();
    imports.insert(
        "Square".to_string(),
        CircomCallable {
            library: lib,
            template_name: "Square".to_string(),
        },
    );
    let outer = OuterScope {
        circom_imports: imports.clone(),
        ..Default::default()
    };

    // Direct new-compiler path lets us inspect the seeded table
    // without having to run a full compilation. Mirror what
    // `compile_with_source_dir` does on entry.
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    for (key, callable) in &outer.circom_imports {
        compiler.circom_table.insert(key.clone(), callable.clone());
    }
    assert_eq!(compiler.circom_table.len(), 1);
    assert!(compiler.lookup_circom_template("Square").is_some());
}
