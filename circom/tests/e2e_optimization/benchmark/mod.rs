mod cases;
mod helpers;

/// Benchmark: compare constraint counts before/after R1CS linear
/// constraint elimination for key circomlib circuits.
///
/// The `cirO0` / `cirO1` / `cirO2` columns are measured directly against
/// `circom` 2.2.3 (`circom --r1cs --Ox -l test/circomlib`) and reported
/// as **total constraints (non-linear + linear)**, matching the semantics
/// of `R1CSCompiler::cs::num_constraints()`. Re-measure these literals
/// whenever the upstream `circom` baseline shifts; stale values silently
/// distort the achronyme-vs-circom narrative.
///
/// The sparse DEDUCE comparison (second table) is informational and
/// re-runs the linear optimizer on pre-O1 snapshots, which takes tens
/// of minutes on the large circuits. It only runs with
/// `ACH_BENCH_SPARSE=1`; the default run keeps the per-circuit
/// compile + O1 + witness-verify coverage.
#[test]
fn r1cs_optimization_benchmark() {
    eprintln!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    eprintln!("║            R1CS Constraint Benchmark: achronyme vs circom               ║");
    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ {:26} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>7} ║",
        "Circuit", "achO0", "achO1", "cirO0", "cirO1", "cirO2", "Elim", "Time"
    );
    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");

    let t0 = std::time::Instant::now();

    // Collected (name, achO1, achO2-sparse, circom-O2-baseline-str) per
    // circuit. Printed in the second comparison table after the main
    // achronyme-vs-circom view -- focuses the reader on the hypothesis
    // under test ("does sparse DEDUCE recover constraints we miss with
    // O1 alone?") without breaking the existing column layout.
    let mut sparse_summary: Vec<(&'static str, usize, usize, &'static str)> = Vec::new();

    cases::run_core_circuits(&mut sparse_summary);
    cases::run_point_sha_eddsa(&mut sparse_summary);
    cases::run_large_witnessless(&mut sparse_summary);
    cases::run_poseidon_sweep(&mut sparse_summary);

    eprintln!("╠════════════════════════════════════════════════════════════════════════════╣");
    eprintln!(
        "║ Total achronyme time: {:>5.0}ms {:>42} ║",
        t0.elapsed().as_secs_f64() * 1000.0,
        ""
    );
    eprintln!("╚════════════════════════════════════════════════════════════════════════════╝");
    eprintln!();

    if helpers::sparse_enabled() {
        cases::print_sparse_summary(&sparse_summary);
    }
}
