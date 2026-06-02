use super::*;

// ============================================================================
// Functions
// ============================================================================

#[test]
fn ir_fn_basic_inline() {
    // fn double(x) { x + x }  assert_eq(double(a), a + a)
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(20))],
        &[("a", FieldElement::from_u64(10))],
        "fn double(x) { x + x }\nassert_eq(double(a), out)",
    );
}

#[test]
fn ir_fn_multi_param() {
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(30))],
        &[
            ("a", FieldElement::from_u64(10)),
            ("b", FieldElement::from_u64(20)),
        ],
        "fn add(x, y) { x + y }\nassert_eq(add(a, b), out)",
    );
}

#[test]
fn ir_fn_multiple_calls() {
    // Same fn called twice, independent inlines
    ir_only_verify_fe(
        &[
            ("out1", FieldElement::from_u64(20)),
            ("out2", FieldElement::from_u64(40)),
        ],
        &[
            ("a", FieldElement::from_u64(10)),
            ("b", FieldElement::from_u64(20)),
        ],
        "fn double(x) { x + x }\nassert_eq(double(a), out1)\nassert_eq(double(b), out2)",
    );
}

#[test]
fn ir_fn_wrong_arg_count() {
    let result = IrLowering::<Bn254Fr>::lower_circuit(
        "fn double(x) { x + x }\ndouble(a, b)",
        &[],
        &["a", "b"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("expects 1 arguments, got 2"),
        "expected WrongArgumentCount, got: {err}"
    );
}

#[test]
fn ir_fn_recursive_rejected() {
    let result = IrLowering::<Bn254Fr>::lower_circuit("fn f(x) { f(x) }\nf(a)", &[], &["a"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("recursive"),
        "expected RecursiveFunction, got: {err}"
    );
}

#[test]
fn ir_fn_mutual_recursive_rejected() {
    let result = IrLowering::<Bn254Fr>::lower_circuit(
        "fn f(x) { g(x) }\nfn g(x) { f(x) }\nf(a)",
        &[],
        &["a"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("recursive"),
        "expected RecursiveFunction, got: {err}"
    );
}

#[test]
fn ir_fn_with_for_loop() {
    // Function body contains a for loop
    ir_only_verify_fe(
        &[("out", FieldElement::from_u64(10))],
        &[("a", FieldElement::from_u64(1))],
        r#"fn sum10(x) {
    let acc = 0
    for i in 0..10 {
        x
    }
}
assert_eq(sum10(a) + 9 * a, out)"#,
    );
}

#[test]
fn ir_fn_with_builtins() {
    // Function body uses poseidon
    let program = IrLowering::<Bn254Fr>::lower_circuit(
        "fn hash_pair(a, b) { poseidon(a, b) }\nhash_pair(x, y)",
        &[],
        &["x", "y"],
    )
    .unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();
    // Should produce same constraints as a direct poseidon call
    assert!(
        compiler.cs.num_constraints() >= 361,
        "expected ~361 constraints for poseidon, got {}",
        compiler.cs.num_constraints()
    );
}

#[test]
fn ir_fn_scope_isolation() {
    // Inner let doesn't leak to caller
    let result = IrLowering::<Bn254Fr>::lower_circuit(
        "fn f(x) { let inner = x + 1\n inner }\nf(a)\nassert_eq(inner, a)",
        &[],
        &["a"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("undeclared") || format!("{err}").contains("inner"),
        "expected undeclared variable error for 'inner', got: {err}"
    );
}

#[test]
fn ir_fn_forward_reference_rejected() {
    // Call before definition → error
    let result = IrLowering::<Bn254Fr>::lower_circuit("f(a)\nfn f(x) { x + x }", &[], &["a"]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("not defined") || format!("{err}").contains("not supported"),
        "expected function-not-defined error, got: {err}"
    );
}

// ============================================================================
// Crypto builtins
// ============================================================================

#[test]
fn ir_poseidon_many_single() {
    // poseidon_many(a) = poseidon(a, 0)
    let source_many = "poseidon_many(a)";
    let source_direct = "poseidon(a, 0)";

    let prog_many = IrLowering::<Bn254Fr>::lower_circuit(source_many, &[], &["a"]).unwrap();
    let prog_direct = IrLowering::<Bn254Fr>::lower_circuit(source_direct, &[], &["a"]).unwrap();

    let mut comp_many = R1CSCompiler::<Bn254Fr>::new();
    comp_many.compile_ir(&prog_many).unwrap();
    let mut comp_direct = R1CSCompiler::<Bn254Fr>::new();
    comp_direct.compile_ir(&prog_direct).unwrap();

    assert_eq!(
        comp_many.cs.num_constraints(),
        comp_direct.cs.num_constraints(),
        "poseidon_many(a) should have same constraints as poseidon(a, 0)"
    );

    // Verify with actual inputs
    let gen = WitnessGenerator::from_compiler(&comp_many);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(42));
    let w = gen.generate(&inputs).unwrap();
    comp_many.cs.verify(&w).unwrap();
}

#[test]
fn ir_poseidon_many_two() {
    // poseidon_many(a, b) = poseidon(a, b)
    let prog_many =
        IrLowering::<Bn254Fr>::lower_circuit("poseidon_many(a, b)", &[], &["a", "b"]).unwrap();
    let prog_direct =
        IrLowering::<Bn254Fr>::lower_circuit("poseidon(a, b)", &[], &["a", "b"]).unwrap();

    let mut comp_many = R1CSCompiler::<Bn254Fr>::new();
    comp_many.compile_ir(&prog_many).unwrap();
    let mut comp_direct = R1CSCompiler::<Bn254Fr>::new();
    comp_direct.compile_ir(&prog_direct).unwrap();

    assert_eq!(
        comp_many.cs.num_constraints(),
        comp_direct.cs.num_constraints()
    );
}

#[test]
fn ir_poseidon_many_three() {
    // poseidon_many(a, b, c) = poseidon(poseidon(a, b), c)
    let source = "poseidon_many(a, b, c)";
    let prog = IrLowering::<Bn254Fr>::lower_circuit(source, &[], &["a", "b", "c"]).unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&prog).unwrap();

    // Should be ~722 constraints (2 poseidon hashes)
    assert!(
        compiler.cs.num_constraints() >= 722,
        "expected ~722 constraints for 2 poseidon hashes, got {}",
        compiler.cs.num_constraints()
    );

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("a".into(), FieldElement::from_u64(1));
    inputs.insert("b".into(), FieldElement::from_u64(2));
    inputs.insert("c".into(), FieldElement::from_u64(3));
    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).unwrap();
}

#[test]
fn ir_poseidon_many_empty_rejected() {
    let result = IrLowering::<Bn254Fr>::lower_circuit("poseidon_many()", &[], &[]);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("expects 1 arguments, got 0"),
        "expected WrongArgumentCount, got: {err}"
    );
}

#[test]
fn ir_merkle_verify_depth_1() {
    // Single sibling: merkle_verify(root, leaf, [sibling], [dir])
    let source = r#"
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    let prog = IrLowering::<Bn254Fr>::lower_circuit(source, &["root"], &["leaf", "sibling", "dir"])
        .unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&prog).unwrap();

    // At depth 1: 2 poseidon hashes + 1 mux + 1 assert_eq ≈ 725 constraints
    let gen = WitnessGenerator::from_compiler(&compiler);

    // Compute expected root: poseidon(leaf, sibling) when dir=0
    use constraints::poseidon::PoseidonParams;
    let params = PoseidonParams::bn254_t3();
    let leaf = FieldElement::from_u64(42);
    let sibling = FieldElement::from_u64(99);
    let hash = constraints::poseidon::poseidon_hash(&params, leaf, sibling);

    let mut inputs = HashMap::new();
    inputs.insert("root".into(), hash);
    inputs.insert("leaf".into(), leaf);
    inputs.insert("sibling".into(), sibling);
    inputs.insert("dir".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    compiler.cs.verify(&w).unwrap();
}

#[test]
fn ir_merkle_verify_mismatched_lengths() {
    let source = r#"
let path = [s0, s1, s2]
let dirs = [d0, d1]
merkle_verify(root, leaf, path, dirs)
"#;
    let result = IrLowering::<Bn254Fr>::lower_circuit(
        source,
        &["root"],
        &["leaf", "s0", "s1", "s2", "d0", "d1"],
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        format!("{err}").contains("length mismatch"),
        "expected ArrayLengthMismatch, got: {err}"
    );
}

#[test]
fn ir_merkle_verify_wrong_root_fails() {
    let source = r#"
let path = [sibling]
let dirs = [dir]
merkle_verify(root, leaf, path, dirs)
"#;
    let prog = IrLowering::<Bn254Fr>::lower_circuit(source, &["root"], &["leaf", "sibling", "dir"])
        .unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&prog).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    inputs.insert("root".into(), FieldElement::from_u64(999)); // WRONG root
    inputs.insert("leaf".into(), FieldElement::from_u64(42));
    inputs.insert("sibling".into(), FieldElement::from_u64(99));
    inputs.insert("dir".into(), FieldElement::ZERO);

    let w = gen.generate(&inputs).unwrap();
    assert!(
        compiler.cs.verify(&w).is_err(),
        "wrong root should fail verification"
    );
}
