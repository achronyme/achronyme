//! Wall-clock baseline of `circom::compile_file` with NO profiling
//! instrumentation (no dhat, no pprof). The number this prints is the
//! one to quote when comparing against `circom 2.2.3 --r1cs`.
//!
//! Build & run:
//!     cargo run --release --example profile_compile_baseline -p circom \
//!         -- <circuit>
//!
//! `<circuit>` is one of: poseidon | sha256 | eddsa | mimc | smt.

use std::path::{Path, PathBuf};
use std::time::Instant;

fn fixture(circuit: &str, manifest_dir: &Path) -> (PathBuf, Vec<PathBuf>) {
    match circuit {
        "poseidon" => (
            manifest_dir.join("test/circomlib/poseidon_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        "sha256" | "sha256_64" => (
            manifest_dir.join("test/circomlib/sha256_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        "eddsa" | "eddsa_verifier" => (
            manifest_dir.join("test/circomlib/eddsa_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        "mimc" | "mimcsponge" => (
            manifest_dir.join("test/circomlib/mimcsponge_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        "smt" | "smtverifier" => (
            manifest_dir.join("test/circomlib/smtverifier_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        other => panic!("unknown circuit '{other}'"),
    }
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let circuit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "sha256".to_string());
    let (path, lib_dirs) = fixture(&circuit, manifest_dir);

    let t0 = Instant::now();
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compile_file({circuit}) failed: {e}"));
    let dt = t0.elapsed();
    eprintln!(
        "compile_file({circuit}) = {:.3} s, {} ProveIR nodes",
        dt.as_secs_f64(),
        result.prove_ir.body.len()
    );
}
