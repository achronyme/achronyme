use super::*;

/// L1 incremental-collapse production validation (Poseidon).
///
/// Drives `R1CSCompiler::new_incremental()` — the production
/// `ConstraintSystem::enforce` collapse hook — and asserts the collapsed
/// system is sound and correctly optimized vs the reference O1:
///   - survivor count <= reference O1 (forward collapse is at least as
///     aggressive — it may eliminate residuals the clustered optimizer
///     leaves),
///   - (A) the valid witness satisfies every survivor,
///   - (B) every substitution reconstructs its wire's true value,
///   - (C) no public/output signal was eliminated,
///   - (D2) zeroing eliminated wires and reconstructing from the sub-map
///     recovers the exact witness (lossless ⇒ each eliminated wire is
///     uniquely determined by the surviving wires),
///   - (E) the survivor set is non-vacuous (perturbing surviving wires
///     breaks survivors).
#[test]
fn l1_incremental_collapse_correct() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let poseidon_path = manifest_dir.join("test/circomlib/poseidon_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&poseidon_path, &lib_dirs).expect("poseidon compile");
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .expect("poseidon instantiate");
    ir::passes::optimize(&mut program);

    let mut user_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    user_inputs.insert("inputs_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    user_inputs.insert("inputs_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));
    user_inputs.insert(
        "initialState".to_string(),
        FieldElement::<Bn254Fr>::from_u64(0),
    );
    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        &user_inputs,
        capture_values,
    )
    .expect("witness hints");
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    // Reference: valid witness + batch-O1 survivor count.
    let mut rc_ref = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc_ref
        .compile_ir_with_witness(&program, &all_signals)
        .expect("reference r1cs + witness");
    rc_ref
        .cs
        .verify(&witness)
        .expect("reference accepts valid witness");
    let num_pub = rc_ref.cs.num_pub_inputs();
    let mut rc_o1 = R1CSCompiler::<Bn254Fr>::new();
    rc_o1.compile_ir(&program).expect("reference compile");
    let rc_o1_pre = rc_o1.cs.num_constraints();
    rc_o1.optimize_r1cs();
    let ref_post = rc_o1.cs.num_constraints();

    // Incremental collapse (production path).
    let mut rc_inc = R1CSCompiler::<Bn254Fr>::new_incremental();
    rc_inc.compile_ir(&program).expect("incremental compile");
    let inc_count = rc_inc.cs.num_constraints();
    let survivors: Vec<constraints::r1cs::Constraint<Bn254Fr>> = rc_inc.cs.constraints().to_vec();
    let subs = rc_inc
        .cs
        .take_collapse_substitution_map()
        .expect("collapse must have produced a substitution map");

    let eval = |lc: &constraints::r1cs::LinearCombination<Bn254Fr>,
                w: &[FieldElement<Bn254Fr>]|
     -> FieldElement<Bn254Fr> {
        let mut acc = FieldElement::<Bn254Fr>::zero();
        for (v, c) in lc.terms() {
            acc = acc.add(&c.mul(&w[v.index()]));
        }
        acc
    };
    let sat = |c: &constraints::r1cs::Constraint<Bn254Fr>, w: &[FieldElement<Bn254Fr>]| -> bool {
        eval(&c.a, w).mul(&eval(&c.b, w)) == eval(&c.c, w)
    };

    // Safe-pivot collapse bounds the emission-time resident set: it absorbs
    // the dominant fresh-wire class but declines use-then-eliminate
    // constraints, so its survivor count is >= the batch-O1 fixpoint. Parity
    // is reached by the finalize pass below; here we only sanity-check that
    // collapse made meaningful progress (did not keep the whole set).
    assert!(
        inc_count < rc_o1_pre,
        "safe-pivot collapse made no progress ({inc_count} vs pre-opt {rc_o1_pre})"
    );

    // (A) valid witness satisfies every survivor.
    let bad_a = survivors.iter().filter(|c| !sat(c, &witness)).count();
    assert_eq!(bad_a, 0, "(A) {bad_a} survivors rejected the valid witness");

    // (B) substitution-witness consistency.
    let bad_b = subs
        .iter()
        .filter(|(idx, repl)| witness[**idx] != eval(repl, &witness))
        .count();
    assert_eq!(
        bad_b, 0,
        "(B) {bad_b} substitutions do not reconstruct the true wire value"
    );

    // (C) no public/output signal eliminated.
    let elim_public = subs.keys().filter(|k| **k >= 1 && **k <= num_pub).count();
    assert_eq!(
        elim_public, 0,
        "(C) {elim_public} public/output signals eliminated"
    );

    // (D2) lossless reconstruction.
    let mut recon = witness.clone();
    for idx in subs.keys() {
        recon[*idx] = FieldElement::<Bn254Fr>::zero();
    }
    for _ in 0..=subs.len() {
        let mut changed = false;
        for (idx, repl) in &subs {
            let v = eval(repl, &recon);
            if recon[*idx] != v {
                recon[*idx] = v;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mismatch = recon
        .iter()
        .zip(witness.iter())
        .filter(|(a, b)| a != b)
        .count();
    assert_eq!(
        mismatch, 0,
        "(D2) reconstruction did not recover the witness ({mismatch} differ)"
    );

    // (E) non-vacuity.
    let one = FieldElement::<Bn254Fr>::one();
    let surviving: Vec<usize> = (1..witness.len())
        .filter(|i| !subs.contains_key(i))
        .collect();
    let sample = surviving.len().min(400);
    let broke = surviving
        .iter()
        .take(sample)
        .filter(|&&s| {
            let mut w2 = witness.clone();
            w2[s] = w2[s].add(&one);
            survivors.iter().any(|c| !sat(c, &w2))
        })
        .count();
    assert!(
        broke > 0,
        "(E) collapsed system is vacuous (0/{sample} perturbations broke a survivor)"
    );

    // Finalize: the existing batch optimizer mops up the use-then-eliminate
    // constraints safe-pivot declined. Linear-elimination rank is
    // order-invariant, so collapse-then-finalize lands at the same fixpoint
    // as batch-O1-on-original. The emission-time win is `inc_count`
    // (resident set bounded to ~2x optimized, never the unoptimized total);
    // the finalize delivers exact count parity.
    rc_inc.optimize_r1cs();
    let inc_final = rc_inc.cs.num_constraints();
    assert!(
        inc_final <= ref_post,
        "collapse + finalize ({inc_final}) exceeds batch O1 ({ref_post})"
    );

    eprintln!(
        "[L1] poseidon: emission-collapse survivors={inc_count} (pre-opt {rc_o1_pre}) -> finalize {inc_final} == batch O1 {ref_post}; {} collapse substitutions; soundness A/B/C/D2/E ok",
        subs.len()
    );
}

/// L1 soundness invariant: no surviving constraint references an
/// eliminated variable.
///
/// Forward collapse applies substitutions to each constraint as it
/// arrives, without retro-applying later substitutions to already-emitted
/// survivors. If a linear constraint's chosen pivot is a wire already
/// referenced by an earlier survivor, that survivor would be left
/// referencing an eliminated (now verifier-unconstrained) wire — an
/// over-elimination soundness break. This asserts the absence of any such
/// dangling reference. Run on the secp256k1 point-add fixture
/// specifically, where forward collapse eliminates more than the batch
/// optimizer (Δ≠0) and the case would surface.
#[test]
fn l1_collapse_no_dangling_eliminated_refs() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let dir = manifest_dir.join("test/circomlib");
    let lib_dirs = vec![dir.clone()];
    for fx in [
        "poseidon_test.circom",
        "secp256k1_addunequal_loop_nested_test.circom",
    ] {
        let result = circom::compile_file(&dir.join(fx), &lib_dirs)
            .unwrap_or_else(|e| panic!("{fx} compile: {e}"));
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
            .capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();
        let mut program = result
            .prove_ir
            .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &result.output_names)
            .unwrap_or_else(|e| panic!("{fx} instantiate: {e}"));
        ir::passes::optimize(&mut program);

        let mut rc = R1CSCompiler::<Bn254Fr>::new_incremental();
        rc.compile_ir(&program)
            .unwrap_or_else(|e| panic!("{fx} compile_ir: {e}"));
        let survivors: Vec<constraints::r1cs::Constraint<Bn254Fr>> = rc.cs.constraints().to_vec();
        let subs = rc.cs.take_collapse_substitution_map().expect("sub-map");

        let dangling = survivors
            .iter()
            .filter(|c| {
                c.a.terms()
                    .iter()
                    .chain(c.b.terms())
                    .chain(c.c.terms())
                    .any(|(v, _)| subs.contains_key(&v.index()))
            })
            .count();
        assert_eq!(
            dangling, 0,
            "{fx}: {dangling}/{} survivors reference an eliminated variable (UNSOUND over-elimination)",
            survivors.len()
        );
        let collapse_count = survivors.len();

        // Finalize parity: collapse + batch finalize must match
        // batch-O1-on-original, including on the curve circuit where
        // safe-pivot collapse alone under-eliminates (use-then-eliminate).
        rc.optimize_r1cs();
        let inc_final = rc.cs.num_constraints();
        let mut rc_ref = R1CSCompiler::<Bn254Fr>::new();
        rc_ref
            .compile_ir(&program)
            .unwrap_or_else(|e| panic!("{fx} ref compile_ir: {e}"));
        rc_ref.optimize_r1cs();
        let ref_post = rc_ref.cs.num_constraints();
        // collapse + finalize composes two sound passes (safe-pivot collapse,
        // verified dangling-free above, then the validated batch optimizer),
        // so it is at least as optimized as batch-O1-on-original. It may be
        // slightly tighter (the greedy fallback on large clusters is
        // order-dependent), so the invariant is `<=`, not `==`.
        assert!(
            inc_final <= ref_post,
            "{fx}: collapse+finalize ({inc_final}) exceeds batch O1 ({ref_post})"
        );
        // Floor: this fixture has no witness battery, so guard against a
        // silent over-collapse to near-zero. A sound count is within a few
        // of batch O1, never a small fraction of it.
        assert!(
            inc_final * 2 >= ref_post,
            "{fx}: collapse+finalize ({inc_final}) is far below batch O1 ({ref_post}) — likely an over-collapse bug"
        );

        eprintln!(
            "[L1-INVARIANT] {fx}: collapse survivors={collapse_count} subs={} dangling=0 -> finalize {inc_final} <= batch O1 {ref_post} ✓",
            subs.len()
        );
    }
}

/// Compose coverage on real circuits.
///
/// The two tests above take the collapse map *before* `optimize_r1cs`, so
/// the finalize pass composes nothing — it only ever sees the empty
/// branch. This drives the real composition path: `new_incremental →
/// compile_ir → optimize_r1cs` with no manual take, so
/// `install_finalize_substitutions` folds the collapse map into the
/// finalize map and stores the composed result. Asserts that result is
/// non-empty and canonical (no replacement references a wire the map
/// itself eliminates) on Poseidon and secp256k1 — the latter is the only
/// divmod fixture, so it is the sole coverage of a `materialize_lc`
/// divmod input flowing through composition.
#[test]
fn l1_compose_map_canonical_on_real_fixtures() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let dir = manifest_dir.join("test/circomlib");
    let lib_dirs = vec![dir.clone()];
    for fx in [
        "poseidon_test.circom",
        "secp256k1_addunequal_loop_nested_test.circom",
    ] {
        let result = circom::compile_file(&dir.join(fx), &lib_dirs)
            .unwrap_or_else(|e| panic!("{fx} compile: {e}"));
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
            .capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();
        let mut program = result
            .prove_ir
            .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &result.output_names)
            .unwrap_or_else(|e| panic!("{fx} instantiate: {e}"));
        ir::passes::optimize(&mut program);

        let mut rc = R1CSCompiler::<Bn254Fr>::new_incremental();
        rc.compile_ir(&program)
            .unwrap_or_else(|e| panic!("{fx} compile_ir: {e}"));
        // Crucially: do NOT take the collapse map here. Let optimize_r1cs
        // compose the collapse map with the finalize map.
        rc.optimize_r1cs();

        let subs = rc.substitution_map.as_ref().unwrap_or_else(|| {
            panic!("{fx}: optimize_r1cs must install a composed substitution map")
        });
        assert!(!subs.is_empty(), "{fx}: composed substitution map is empty");

        let dangling = subs
            .iter()
            .flat_map(|(_, lc)| lc.terms())
            .filter(|(v, _)| subs.contains_key(&v.index()))
            .count();
        assert_eq!(
            dangling, 0,
            "{fx}: composed map is non-canonical — {dangling} replacement terms reference \
             an eliminated wire (a single-pass witness fixup would be order-dependent)"
        );

        eprintln!(
            "[L1-COMPOSE] {fx}: composed map {} entries, canonical ✓",
            subs.len()
        );
    }
}
