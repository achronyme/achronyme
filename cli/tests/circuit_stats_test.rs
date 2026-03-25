use std::io::Write;

use cli::commands::ErrorFormat;
use tempfile::NamedTempFile;

const EF: ErrorFormat = ErrorFormat::Human;

fn fixture(name: &str) -> String {
    format!(
        "{}/test/circuit/{name}",
        env!("CARGO_MANIFEST_DIR").trim_end_matches("/cli")
    )
}

fn write_temp_source(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".ach").unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ======================================================================
// ach circuit --circuit-stats
// ======================================================================

#[test]
fn circuit_stats_basic_mul() {
    let src =
        write_temp_source("circuit mul(z: Public, x: Witness, y: Witness) { assert_eq(x * y, z) }");
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        src.path().to_str().unwrap(),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        true, // circuit_stats
        EF,
    );
    assert!(result.is_ok(), "circuit_command failed: {:?}", result.err());
}

#[test]
fn circuit_stats_poseidon() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("poseidon.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        true, // circuit_stats
        EF,
    );
    assert!(result.is_ok(), "circuit_command failed: {:?}", result.err());
}

#[test]
fn circuit_stats_merkle() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("merkle.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        true, // circuit_stats
        EF,
    );
    assert!(result.is_ok(), "circuit_command failed: {:?}", result.err());
}

#[test]
fn circuit_stats_comparison() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("comparison_ops.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        true, // circuit_stats
        EF,
    );
    assert!(result.is_ok(), "circuit_command failed: {:?}", result.err());
}

#[test]
fn circuit_stats_disabled_no_crash() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false, // circuit_stats disabled
        EF,
    );
    assert!(result.is_ok());
}

// ======================================================================
// CircuitStats::from_program accuracy (regression)
// ======================================================================

#[test]
fn stats_matches_actual_r1cs_count_for_merkle() {
    use compiler::r1cs_backend::R1CSCompiler;
    use ir::passes::bool_prop::compute_proven_boolean;
    use ir::prove_ir::ProveIrCompiler;
    use ir::stats::CircuitStats;

    let source = std::fs::read_to_string(fixture("merkle.ach")).unwrap();
    let prove_ir = ProveIrCompiler::compile_circuit(&source).unwrap();
    let mut program = prove_ir
        .instantiate(&std::collections::HashMap::new())
        .unwrap();
    ir::passes::optimize(&mut program);

    let proven = compute_proven_boolean(&program);
    let stats = CircuitStats::from_program(&program, &proven, Some("merkle"));

    let mut r1cs = R1CSCompiler::new();
    r1cs.set_proven_boolean(proven);
    r1cs.compile_ir(&program).unwrap();

    assert_eq!(
        stats.total_constraints,
        r1cs.cs.num_constraints(),
        "Stats estimate must match actual R1CS count for merkle circuit"
    );
}
