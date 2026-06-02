use super::*;

// ============================================================================
// Arrays
// ============================================================================

/// IR-only pipeline that uses `lower_circuit` with array syntax in decl specs.
fn ir_array_verify(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    pub_decls: &[&str],
    wit_decls: &[&str],
    source: &str,
) {
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, pub_decls, wit_decls).unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), *val);
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), *val);
    }

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("array pipeline witness failed verification");
}

#[test]
fn ir_array_literal_and_index() {
    // let a = [x, y, z]; assert_eq(a[1], y)
    ir_only_verify_fe(
        &[],
        &[
            ("x", FieldElement::from_u64(10)),
            ("y", FieldElement::from_u64(20)),
            ("z", FieldElement::from_u64(30)),
        ],
        "let a = [x, y, z]\nassert_eq(a[1], y)",
    );
}

#[test]
fn ir_array_public_declaration() {
    // public path[3] creates path_0, path_1, path_2
    ir_array_verify(
        &[
            ("path_0", FieldElement::from_u64(1)),
            ("path_1", FieldElement::from_u64(2)),
            ("path_2", FieldElement::from_u64(3)),
        ],
        &[],
        &["path[3]"],
        &[],
        "assert_eq(path[0] + path[1], path[2])",
    );
}

#[test]
fn ir_array_witness_declaration() {
    // witness bits[4] creates bits_0..bits_3
    ir_array_verify(
        &[("sum", FieldElement::from_u64(10))],
        &[
            ("bits_0", FieldElement::from_u64(1)),
            ("bits_1", FieldElement::from_u64(2)),
            ("bits_2", FieldElement::from_u64(3)),
            ("bits_3", FieldElement::from_u64(4)),
        ],
        &["sum"],
        &["bits[4]"],
        "assert_eq(bits[0] + bits[1] + bits[2] + bits[3], sum)",
    );
}

#[test]
fn ir_array_for_iteration() {
    // for elem in arr { ... } unrolls over array elements
    ir_only_verify_fe(
        &[("sum", FieldElement::from_u64(60))],
        &[
            ("x", FieldElement::from_u64(10)),
            ("y", FieldElement::from_u64(20)),
            ("z", FieldElement::from_u64(30)),
        ],
        r#"let a = [x, y, z]
let acc = 0
for elem in a {
    assert_eq(elem, elem)
}
assert_eq(x + y + z, sum)"#,
    );
}

#[test]
fn ir_array_index_out_of_bounds() {
    let result = IrLowering::<Bn254Fr>::lower_circuit(
        "let a = [x, y, z]\nassert_eq(a[5], x)",
        &[],
        &["x", "y", "z"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("out of bounds"),
        "expected IndexOutOfBounds, got: {err}"
    );
}

#[test]
fn ir_array_dynamic_index_rejected() {
    // a[x] where x is a witness (not compile-time constant) → error
    let result = IrLowering::<Bn254Fr>::lower_circuit(
        "let a = [y, y, y]\nassert_eq(a[x], y)",
        &[],
        &["x", "y"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("compile-time constant"),
        "expected compile-time constant error, got: {err}"
    );
}

#[test]
fn ir_array_len_builtin() {
    // a.len() returns compile-time constant
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(3))],
        &[
            ("x", FieldElement::from_u64(1)),
            ("y", FieldElement::from_u64(2)),
            ("z", FieldElement::from_u64(3)),
        ],
        "let a = [x, y, z]\nassert_eq(a.len(), out)",
    );
}

#[test]
fn ir_array_in_let_binding() {
    // let arr = [a, b]; assert_eq(arr[0], a)
    ir_only_verify_fe(
        &[],
        &[
            ("a", FieldElement::from_u64(42)),
            ("b", FieldElement::from_u64(99)),
        ],
        "let arr = [a, b]\nassert_eq(arr[0], a)\nassert_eq(arr[1], b)",
    );
}

#[test]
fn ir_array_empty_rejected() {
    let result = IrLowering::<Bn254Fr>::lower_circuit("let a = []", &[], &[]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("empty"),
        "expected empty array error, got: {err}"
    );
}

#[test]
fn ir_array_index_with_for_counter() {
    // arr[i] where i is the for loop counter — compile-time constant
    ir_array_verify(
        &[("sum", FieldElement::from_u64(6))],
        &[
            ("arr_0", FieldElement::from_u64(1)),
            ("arr_1", FieldElement::from_u64(2)),
            ("arr_2", FieldElement::from_u64(3)),
        ],
        &["sum"],
        &["arr[3]"],
        r#"let total = arr[0] + arr[1] + arr[2]
assert_eq(total, sum)"#,
    );
}
