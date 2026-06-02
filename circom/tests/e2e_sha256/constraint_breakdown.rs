use super::*;

/// Diagnostic instrumentation for the SHA-256(64) constraint-parity gap.
///
/// The hard-gate (`sha256_64_lysis_hard_gate`) reports 70,623 constraints
/// post-IR-optimize, *pre*-R1CS-optimize. circom 2.2.3 with `--O2` on the
/// same circuit reports 29,014 (0 linear, 29,014 non-linear). This test
/// runs the full pipeline through `optimize_r1cs()` (O1 -- linear
/// elimination only, no DEDUCE) and prints:
///
///   - constraint count + shape histogram pre-optimize
///   - constraint count + shape histogram post-O1
///   - the gap vs circom O0/O1/O2
///
/// O2 (DEDUCE Gaussian elimination) is intentionally skipped -- the
/// monomial x constraint matrix is `~k x q` `FieldElement`s where both
/// dimensions reach ~60k for SHA-256(64), exceeding 16 GB of RAM.
/// circom's own progression (O0->O1 kills 171k linears, O1->O2 only ~2k
/// more) suggests O1 closes most of the gap by itself.
///
/// Shape categories follow the `is_linear` predicate from
/// `r1cs_optimize::predicates`: a constraint with one of A/B simplifying
/// to a constant counts as "linear", everything else gets bucketed by
/// term-count of A,B,C. The `(|A|,|B|,|C|)` histogram surfaces dominant
/// patterns (e.g. `(1,1,0)` for `x*x=0`-shaped, `(1,2,0)` for bool
/// checks, `(1,N,0)` for bit-decomposition equality).
///
/// `#[ignore]`d -- compile alone is ~47s on this host.
#[test]
#[ignore = "SHA-256(64) constraint shape diagnostic -- compile is ~47s. Run with `--ignored sha256_64_constraint_breakdown` to capture pre/post-O1 distributions."]
fn sha256_64_constraint_breakdown() {
    use std::collections::HashSet;
    use std::time::Instant;

    // circom 2.2.3 baseline from
    // `circom test/circomlib/sha256_test.circom --r1cs --O{0,1,2}`.
    const CIRCOM_O0: usize = 204_576;
    const CIRCOM_O1: usize = 31_264;
    const CIRCOM_O2: usize = 29_014;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    eprintln!("[compile]      {:?}", t0.elapsed());

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t1 = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    eprintln!(
        "[instantiate]  {:?}  ir_inst={}",
        t1.elapsed(),
        program.len()
    );

    let t2 = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "[ir-opt]       {:?}  ir_inst={}",
        t2.elapsed(),
        program.len()
    );

    let t3 = Instant::now();
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_o2 = rc.cs.num_constraints();
    eprintln!("[r1cs build]   {:?}  constraints={pre_o2}", t3.elapsed());

    eprintln!("\n-- PRE-R1CS-O2 shape histogram ----------------------");
    print_constraint_histogram(rc.cs.constraints());

    // Note: we run only O1 (`optimize_r1cs`) here, not O2.
    // For SHA-256(64) the DEDUCE Gaussian elimination in O2 builds a
    // monomial x constraint matrix of order ~60k x 60k field elements,
    // which is ~100 GB and OOMs on a 16 GB host. circom's progression
    // (O0->O1 kills 171k linears, O1->O2 only saves ~2k more) suggests
    // O1 is sufficient for the parity gap on this circuit.
    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "\n[r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}  trivial_removed={}  duplicates_removed={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
        stats.trivial_removed,
        stats.duplicates_removed,
    );
    eprintln!("\n-- O1 round_details (linear_eliminated, newly_linear) ----");
    let total_newly_linear: usize = stats.round_details.iter().map(|(_, n)| n).sum();
    for (i, (lin_elim, newly_lin)) in stats.round_details.iter().enumerate() {
        eprintln!(
            "  round {}: linear_eliminated={lin_elim}  newly_linear={newly_lin}",
            i + 1
        );
    }
    eprintln!("  total newly_linear across rounds = {total_newly_linear}");

    eprintln!("\n-- POST-R1CS-O1 shape histogram ---------------------");
    print_constraint_histogram(rc.cs.constraints());

    eprintln!("\n-- circom 2.2.3 baseline ----------------------------");
    eprintln!("  --O0 = {CIRCOM_O0}");
    eprintln!("  --O1 = {CIRCOM_O1}");
    eprintln!("  --O2 = {CIRCOM_O2}");

    eprintln!("\n-- achronyme vs circom delta ------------------------");
    let delta_vs_o1 = post_o1 as i64 - CIRCOM_O1 as i64;
    let pct_vs_o1 = (delta_vs_o1 as f64 / CIRCOM_O1 as f64) * 100.0;
    let delta_vs_o2 = post_o1 as i64 - CIRCOM_O2 as i64;
    let pct_vs_o2 = (delta_vs_o2 as f64 / CIRCOM_O2 as f64) * 100.0;
    eprintln!("  achronyme pre-opt   = {pre_o2}");
    eprintln!("  achronyme post-O1   = {post_o1}");
    eprintln!("  vs circom O1 ({CIRCOM_O1})  -> delta = {delta_vs_o1:+}  ({pct_vs_o1:+.1}%)");
    eprintln!("  vs circom O2 ({CIRCOM_O2})  -> delta = {delta_vs_o2:+}  ({pct_vs_o2:+.1}%)");

    eprintln!("\n[total] {:?}", total.elapsed());
}
