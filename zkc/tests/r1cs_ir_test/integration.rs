use super::*;

// ============================================================================
// Constraint count validation
// ============================================================================

#[test]
fn ir_fn_inline_same_constraints() {
    // double(a) should produce same constraints as a + a
    let prog_fn = IrLowering::<Bn254Fr>::lower_circuit(
        "fn double(x) { x + x }\nassert_eq(double(a), out)",
        &["out"],
        &["a"],
    )
    .unwrap();
    let prog_direct =
        IrLowering::<Bn254Fr>::lower_circuit("assert_eq(a + a, out)", &["out"], &["a"]).unwrap();

    let mut comp_fn = R1CSCompiler::<Bn254Fr>::new();
    comp_fn.compile_ir(&prog_fn).unwrap();
    let mut comp_direct = R1CSCompiler::<Bn254Fr>::new();
    comp_direct.compile_ir(&prog_direct).unwrap();

    assert_eq!(
        comp_fn.cs.num_constraints(),
        comp_direct.cs.num_constraints(),
        "fn inline should have same constraint count as direct expression"
    );
}

// ============================================================================
// Integration: self-contained with arrays and functions
// ============================================================================

#[test]
fn ir_self_contained_with_arrays() {
    // public path[3] in source
    let source = r#"
public sum
witness arr[3]
assert_eq(arr[0] + arr[1] + arr[2], sum)
"#;
    ir_self_contained_verify(
        &[
            ("sum", FieldElement::from_u64(6)),
            ("arr_0", FieldElement::from_u64(1)),
            ("arr_1", FieldElement::from_u64(2)),
            ("arr_2", FieldElement::from_u64(3)),
        ],
        source,
    );
}

#[test]
fn ir_self_contained_with_functions() {
    let source = r#"
public out
witness a
fn double(x) { x + x }
assert_eq(double(a), out)
"#;
    ir_self_contained_verify(
        &[
            ("out", FieldElement::from_u64(20)),
            ("a", FieldElement::from_u64(10)),
        ],
        source,
    );
}

#[test]
fn ir_merkle_proof_self_contained() {
    // Full self-contained Merkle circuit using merkle_verify builtin
    let source = r#"
public root
witness leaf, sibling, dir
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let leaf = FieldElement::from_u64(42);
    let sibling = FieldElement::from_u64(99);
    let hash = constraints::poseidon::poseidon_hash(&params, leaf, sibling);

    ir_self_contained_verify(
        &[
            ("root", hash),
            ("leaf", leaf),
            ("sibling", sibling),
            ("dir", FieldElement::ZERO),
        ],
        source,
    );
}

#[test]
fn ir_fn_returning_expression() {
    // Function returns its last expression (x * x)
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(100))],
        &[("a", FieldElement::from_u64(10))],
        "fn square(x) { x * x }\nassert_eq(square(a), out)",
    );
}

#[test]
fn ir_array_scalar_type_mismatch() {
    // Using a scalar as array → TypeMismatch
    let result = IrLowering::<Bn254Fr>::lower_circuit("assert_eq(x[0], x)", &[], &["x"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("type mismatch") || format!("{err}").contains("scalar"),
        "expected TypeMismatch for indexing scalar, got: {err}"
    );
}

#[test]
fn ir_array_as_bare_expression_rejected() {
    // Array not in let binding → TypeMismatch
    let result = IrLowering::<Bn254Fr>::lower_circuit("assert_eq([x, y], x)", &[], &["x", "y"]);
    assert!(result.is_err());
}

#[test]
fn ir_merkle_verify_depth_3_builtin() {
    // Depth-3 Merkle membership proof using merkle_verify builtin
    let source = r#"
let path = [s0, s1, s2]
let dirs = [d0, d1, d2]
merkle_verify(root, leaf, path, dirs)
"#;
    let prog = IrLowering::<Bn254Fr>::lower_circuit(
        source,
        &["root"],
        &["leaf", "s0", "s1", "s2", "d0", "d1", "d2"],
    )
    .unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&prog).unwrap();

    // Conditional swap: 3 * (2 mux + 1 poseidon + 2 materialize) + 1 assert_eq ≈ 1099
    let nc = compiler.cs.num_constraints();
    assert!(
        (1000..=1200).contains(&nc),
        "expected ~1099 constraints for depth-3 Merkle, got {nc}"
    );
}
