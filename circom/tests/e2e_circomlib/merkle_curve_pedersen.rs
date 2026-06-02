use super::*;

/// EscalarMul(8, base): generic scalar multiplication on BabyJubJub
/// using the windowed-add algorithm. Exercises array-literal template
/// arguments (`base = [Gx, Gy]`) propagating through nested template
/// instantiations and into compile-time function calls
/// (`EscalarMulW4Table(base, k)`) inside `EscalarMulWindow`.
///
/// Identity-point input (escalar = 0, inp = (0, 1)) — exercises the
/// pipeline without forcing a specific math result; the constraint
/// system is the test surface here, not curve correctness.
#[test]
fn escalarmul_circomlib() {
    let mut inputs = HashMap::new();
    for i in 0..8 {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    inputs.insert("inp_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("inp_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_verify_fe(
        "EscalarMul(8, base)",
        "test/circomlib/escalarmul_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for EscalarMul(8, base)");
}

/// SMTVerifier(10): sparse Merkle tree inclusion/exclusion verifier
/// at depth 10 (1024 leaves). Largest standalone circomlib template
/// not yet covered. Exercises descending for-loops (`i != -1`),
/// component arrays sized from template params, and compile-time
/// `var n1 = n\2` propagation through `MultiAND`.
///
/// Run with `enabled=0` so the R1CS verification is a no-op — the
/// frontend pipeline + constraint generation are the test surface;
/// witness validity for inclusion/exclusion semantics is out of
/// scope for this compile-coverage gate.
#[test]
fn smtverifier_circomlib() {
    let mut inputs = HashMap::new();
    inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("fnc".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("root".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldKey".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldValue".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("isOld0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("key".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("value".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    for i in 0..10 {
        inputs.insert(
            format!("siblings_{i}"),
            FieldElement::<Bn254Fr>::from_u64(0),
        );
    }

    let n = circomlib_e2e_verify_fe(
        "SMTVerifier(10) (enabled=0)",
        "test/circomlib/smtverifier_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for SMTVerifier(10)");
}

/// SMTProcessor(10): sparse Merkle tree state-transition processor at
/// depth 10. Larger sibling of SMTVerifier — adds insert/update/delete
/// state machines around the same core hash chain.
///
/// Run with `fnc=[0,0]` (no-op processor), so `enabled = 0` and the
/// R1CS check passes with the trivial state transition (newRoot ==
/// oldRoot). Same scope as the verifier test: compile-coverage gate.
#[test]
fn smtprocessor_circomlib() {
    let mut inputs = HashMap::new();
    inputs.insert("oldRoot".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("newRoot".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldKey".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("oldValue".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("isOld0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("newKey".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("newValue".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("fnc_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("fnc_1".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    for i in 0..10 {
        inputs.insert(
            format!("siblings_{i}"),
            FieldElement::<Bn254Fr>::from_u64(0),
        );
    }

    let n = circomlib_e2e_verify_fe(
        "SMTProcessor(10) (fnc=[0,0])",
        "test/circomlib/smtprocessor_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for SMTProcessor(10)");
}

/// Edwards2Montgomery: convert a Twisted-Edwards point to its
/// Montgomery-form representation. Single-template test on the
/// generator point — exercises the modular-inverse division
/// (`(1+y)/(1-y)`) the frontend lowers as a witness hint.
#[test]
fn montgomery_circomlib() {
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut inputs = HashMap::new();
    // BabyJubJub generator point (Edwards form).
    inputs.insert(
        "in_0".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    inputs.insert(
        "in_1".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );

    let n = circomlib_e2e_verify_fe(
        "Edwards2Montgomery",
        "test/circomlib/montgomery_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for Edwards2Montgomery");
}

/// Pedersen_old(8): hash 8 bits using the legacy Pedersen
/// template that delegates to `EscalarMul` + `EscalarMulWindow` +
/// `EscalarMulW4Table`. The table-builder function does compile-
/// time Edwards-curve point doubling and addition via `pointAdd`
/// (whose `/` is modular inverse in the scalar field, not integer
/// division). Exercises:
///
///   - Array-valued reassignment at template level (`table =
///     EscalarMulW4Table(base, k);`)
///   - Deferred scalar component instantiation (`component mux;`
///     then `mux = MultiMux4(2);`)
///   - Partial array slice as component arg (`EscalarMul(n,
///     PBASE[i])` where PBASE is a 2-D var)
///   - Field-aware compile-time `+ - * /` in function bodies
///
/// Covers Fase 5.2. The test asserts the circuit compiles through
/// to a non-empty R1CS — full Groth16 verification is a separate
/// concern since computing a golden digest requires an independent
/// Edwards-curve implementation.
#[test]
fn pedersen_old_circomlib_r1cs() {
    let n = circomlib_e2e_verify(
        "Pedersen_old(8)",
        "test/circomlib/pedersen_old_test.circom",
        &[
            ("in_0", 0),
            ("in_1", 1),
            ("in_2", 0),
            ("in_3", 0),
            ("in_4", 1),
            ("in_5", 1),
            ("in_6", 0),
            ("in_7", 1),
        ],
    );
    eprintln!("  Pedersen_old(8): {n} constraints");
    assert!(n > 0, "expected constraints for Pedersen_old");
}

/// Pedersen(8): hash 8 bits using BabyJubjub curve.
///
/// Tests: Window4, MontgomeryAdd/Double, Edwards2Montgomery,
/// Montgomery2Edwards, BabyAdd, Mux3 — completely different hash
/// construction from Poseidon/MiMC. Uses hardcoded base points
/// via 2D array literal (`var BASE[10][2] = [[...], ...]`).
#[test]
fn pedersen_circomlib() {
    // Hash input: 0b10110010 (bits LSB-first)
    let n = circomlib_e2e_verify(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &[
            ("in_0", 0),
            ("in_1", 1),
            ("in_2", 0),
            ("in_3", 0),
            ("in_4", 1),
            ("in_5", 1),
            ("in_6", 0),
            ("in_7", 1),
        ],
    );
    eprintln!("  Constraints: {n}");
    assert!(n > 0, "expected constraints for Pedersen hash");
}

#[test]
fn pedersen_o2() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/pedersen_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs).unwrap();
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap();
    ir::passes::optimize(&mut program);

    let mut inputs = HashMap::new();
    for (i, bit) in [0u64, 1, 0, 0, 1, 1, 0, 1].iter().enumerate() {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(*bit));
    }

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
            .unwrap();
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    r1cs_compiler.set_proven_boolean(proven);
    let mut witness = r1cs_compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap();

    let pre_opt = r1cs_compiler.cs.num_constraints();
    let stats = r1cs_compiler.optimize_r1cs_o2();
    if let Some(subs) = &r1cs_compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }
    let post_opt = r1cs_compiler.cs.num_constraints();

    eprintln!("  Pedersen(8) O2: {pre_opt} → {post_opt}");
    eprintln!(
        "  vars_elim={} dedup={} trivial={}",
        stats.variables_eliminated, stats.duplicates_removed, stats.trivial_removed
    );

    r1cs_compiler.cs.verify(&witness).unwrap();
    // Constant propagation through template inlining collapses Montgomery/
    // Edwards operations with known base points to scalars. The remaining
    // constraints are: 2×Window4 MUX (3+1 each = 8) + 1 MontgomeryAdd (3) +
    // 1 Montgomery2Edwards (2) = 13. Matches circom --O1.
    assert!(
        post_opt <= 13,
        "O2 should match circom (13): got {post_opt}"
    );
}
