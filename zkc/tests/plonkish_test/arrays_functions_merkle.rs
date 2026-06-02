use super::*;

// ============================================================================
// Arrays, functions, merkle_verify — parity tests
// ============================================================================

/// Plonkish helper: compile from source with array-style declarations.
fn compile_source_arrays(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &HashMap<String, FieldElement>,
) -> PlonkishCompiler {
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, public, witness).unwrap();
    compile_and_verify(&program, inputs)
}

#[test]
fn plonkish_array_literal_and_index() {
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(10));
    inputs.insert("y".to_string(), FieldElement::from_u64(20));
    inputs.insert("z".to_string(), FieldElement::from_u64(30));
    compile_source(
        "let a = [x, y, z]\nassert_eq(a[1], y)",
        &[],
        &["x", "y", "z"],
        &inputs,
    );
}

#[test]
fn plonkish_array_declaration() {
    let mut inputs = HashMap::new();
    inputs.insert("arr_0".to_string(), FieldElement::from_u64(1));
    inputs.insert("arr_1".to_string(), FieldElement::from_u64(2));
    inputs.insert("arr_2".to_string(), FieldElement::from_u64(3));
    inputs.insert("sum".to_string(), FieldElement::from_u64(6));
    compile_source_arrays(
        "assert_eq(arr[0] + arr[1] + arr[2], sum)",
        &["sum"],
        &["arr[3]"],
        &inputs,
    );
}

#[test]
fn plonkish_fn_basic_inline() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(10));
    inputs.insert("out".to_string(), FieldElement::from_u64(20));
    compile_source(
        "fn double(x) { x + x }\nassert_eq(double(a), out)",
        &["out"],
        &["a"],
        &inputs,
    );
}

#[test]
fn plonkish_poseidon_many_three() {
    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::from_u64(1));
    inputs.insert("b".to_string(), FieldElement::from_u64(2));
    inputs.insert("c".to_string(), FieldElement::from_u64(3));
    compile_source("poseidon_many(a, b, c)", &[], &["a", "b", "c"], &inputs);
}

#[test]
fn plonkish_merkle_verify_depth_1() {
    let leaf = FieldElement::from_u64(42);
    let sibling = FieldElement::from_u64(99);
    let params = constraints::poseidon::PoseidonParams::bn254_t3();
    let hash = constraints::poseidon::poseidon_hash(&params, leaf, sibling);

    let mut inputs = HashMap::new();
    inputs.insert("root".to_string(), hash);
    inputs.insert("leaf".to_string(), leaf);
    inputs.insert("sibling".to_string(), sibling);
    inputs.insert("dir".to_string(), FieldElement::ZERO);

    let source = r#"
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    compile_source(source, &["root"], &["leaf", "sibling", "dir"], &inputs);
}
