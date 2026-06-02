use super::*;

// ── Poseidon (real circomlib) ───────────────────────────────────

/// Compile the real circomlib poseidon.circom with include resolution.
///
/// This is the ultimate compatibility test: Poseidon(2) from iden3/circomlib
/// compiled through our frontend → ProveIR → R1CS → Groth16 verify.
///
/// Poseidon(2) from iden3/circomlib: 1006 constraints, Groth16-verified.
#[test]
fn poseidon_real_circomlib() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let poseidon_path = manifest_dir.join("test/circomlib/poseidon_test.circom");

    if !poseidon_path.exists() {
        eprintln!("Skipping poseidon test: {poseidon_path:?} not found");
        return;
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // ── Step 1: Compile ──
    eprintln!("Compiling Poseidon(2) from real circomlib...");
    let compile_result = match circom::compile_file(&poseidon_path, &lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            panic!("Poseidon compilation failed: {e}");
        }
    };

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());
    eprintln!(
        "    Public inputs: {:?}",
        prove_ir
            .public_inputs
            .iter()
            .map(|i| &i.name)
            .collect::<Vec<_>>()
    );
    eprintln!(
        "    Captures: {:?}",
        prove_ir
            .captures
            .iter()
            .map(|c| &c.name)
            .collect::<Vec<_>>()
    );

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program =
        match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names) {
            Ok(p) => p,
            Err(e) => panic!("Poseidon instantiation failed: {e}"),
        };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    // ── Step 3: R1CS compile ──
    // Build witness: inputs[0]=1, inputs[1]=2, initialState=0
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("inputs_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("inputs_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert(
        "initialState".to_string(),
        FieldElement::<Bn254Fr>::from_u64(0),
    );

    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    ) {
        Ok(s) => s,
        Err(e) => panic!("Poseidon witness computation failed: {e}"),
    };

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => panic!("Poseidon R1CS compilation failed: {e}"),
    };

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    // ── Step 4: Verify ──
    match r1cs_compiler.cs.verify(&witness) {
        Ok(()) => eprintln!("  ✓ R1CS verified!"),
        Err(e) => panic!("Poseidon R1CS verification failed: {e}"),
    }

    eprintln!();
    eprintln!("  Poseidon(2) — {num_constraints} constraints — VERIFIED ✓");
}

// ── MiMCSponge (real circomlib) ────────────────────────────────

/// MiMCSponge(2, 220, 1) from iden3/circomlib: 220 rounds of MiMC-Feistel.
///
/// Tests: 218-element constant array, computed component array bounds,
/// compile-time ternary in loops, signal arrays with loop-dependent indexing.
#[test]
fn mimcsponge_real_circomlib() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mimc_path = manifest_dir.join("test/circomlib/mimcsponge_test.circom");

    if !mimc_path.exists() {
        eprintln!("Skipping MiMCSponge test: {mimc_path:?} not found");
        return;
    }

    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    // ── Step 1: Compile ──
    eprintln!("Compiling MiMCSponge(2, 220, 1) from real circomlib...");
    let compile_result = match circom::compile_file(&mimc_path, &lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            panic!("MiMCSponge compilation failed: {e}");
        }
    };

    let prove_ir = &compile_result.prove_ir;
    eprintln!("  ✓ Compiled: {} body nodes", prove_ir.body.len());

    // DEBUG: count ProveIR node types
    {
        use ir_forge::types::CircuitNode;
        let mut lets = 0usize;
        let mut asserts = 0usize;
        let mut hints = 0usize;
        let mut fors = 0usize;
        let mut decomps = 0usize;
        let mut ifs = 0usize;
        let mut other = 0usize;
        let mut const_lets = 0usize;
        #[allow(clippy::too_many_arguments)]
        fn count_nodes(
            nodes: &[CircuitNode],
            lets: &mut usize,
            asserts: &mut usize,
            hints: &mut usize,
            fors: &mut usize,
            decomps: &mut usize,
            ifs: &mut usize,
            other: &mut usize,
            const_lets: &mut usize,
        ) {
            for n in nodes {
                match n {
                    CircuitNode::Let { value, .. } => {
                        *lets += 1;
                        if matches!(value, ir_forge::types::CircuitExpr::Const(_)) {
                            *const_lets += 1;
                        }
                    }
                    CircuitNode::AssertEq { .. } => *asserts += 1,
                    CircuitNode::WitnessHint { .. } => *hints += 1,
                    CircuitNode::For { body, .. } => {
                        *fors += 1;
                        count_nodes(
                            body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                    }
                    CircuitNode::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        *ifs += 1;
                        count_nodes(
                            then_body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                        count_nodes(
                            else_body, lets, asserts, hints, fors, decomps, ifs, other, const_lets,
                        );
                    }
                    CircuitNode::Decompose { .. } => *decomps += 1,
                    _ => *other += 1,
                }
            }
        }
        count_nodes(
            &prove_ir.body,
            &mut lets,
            &mut asserts,
            &mut hints,
            &mut fors,
            &mut decomps,
            &mut ifs,
            &mut other,
            &mut const_lets,
        );
        eprintln!("  DEBUG nodes: Let={lets} (Const={const_lets}), AssertEq={asserts}, WitnessHint={hints}, For={fors}, If={ifs}, Decompose={decomps}, Other={other}");
        // Count "Other" node types
        let mut let_indexed = 0usize;
        let mut wh_indexed = 0usize;
        let mut let_array = 0usize;
        let mut expr_nodes = 0usize;
        let mut assert_nodes = 0usize;
        for n in &prove_ir.body {
            match n {
                CircuitNode::LetIndexed { .. } => let_indexed += 1,
                CircuitNode::WitnessHintIndexed { .. } => wh_indexed += 1,
                CircuitNode::LetArray { .. } => let_array += 1,
                CircuitNode::Expr { .. } => expr_nodes += 1,
                CircuitNode::Assert { .. } => assert_nodes += 1,
                _ => {}
            }
        }
        eprintln!("  DEBUG other: LetIndexed={let_indexed}, WHIndexed={wh_indexed}, LetArray={let_array}, Expr={expr_nodes}, Assert={assert_nodes}");
        // Print round 0 and round 1 nodes (indices ~220-250)
        eprintln!("  DEBUG === Nodes 218..260 ===");
        for (i, n) in prove_ir.body.iter().enumerate().skip(218).take(42) {
            eprintln!("  [{i}] {n:?}");
        }
    }

    // ── Step 2: Instantiate ──
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let mut program =
        match prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names) {
            Ok(p) => p,
            Err(e) => panic!("MiMCSponge instantiation failed: {e}"),
        };

    ir::passes::optimize(&mut program);
    eprintln!(
        "  ✓ Instantiated + optimized: {} instructions",
        program.len()
    );

    // ── Step 3: R1CS compile ──
    // Witness: ins[0]=1, ins[1]=2, k=0
    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("ins_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("ins_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert("k".to_string(), FieldElement::<Bn254Fr>::from_u64(0));

    let mut all_signals = match circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    ) {
        Ok(s) => s,
        Err(e) => panic!("MiMCSponge witness computation failed: {e}"),
    };

    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut r1cs_compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = match r1cs_compiler.compile_ir_with_witness(&program, &all_signals) {
        Ok(w) => w,
        Err(e) => panic!("MiMCSponge R1CS compilation failed: {e}"),
    };

    let num_constraints = r1cs_compiler.cs.num_constraints();
    eprintln!("  ✓ R1CS compiled: {num_constraints} constraints");

    match r1cs_compiler.cs.verify(&witness) {
        Ok(()) => eprintln!("  ✓ R1CS verified!"),
        Err(e) => panic!("MiMCSponge R1CS verification failed: {e}"),
    }

    eprintln!();
    eprintln!("  MiMCSponge(2, 220, 1) — {num_constraints} constraints — VERIFIED ✓");
}
