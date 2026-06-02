//! End-to-end pipeline benchmark: Achronyme vs circom+snarkjs.
//!
//! For each circuit, measures wall time of every step a developer actually
//! runs in a ZK dev loop:
//!
//!   Achronyme:        ach circom <file> (--r1cs | --prove)
//!   circom+snarkjs:   circom <file> --r1cs --wasm
//!                     node generate_witness.js <wasm> input.json <wtns>
//!                     snarkjs groth16 prove <zkey> <wtns> proof.json public.json
//!                     snarkjs groth16 verify <vkey> public.json proof.json
//!
//! The Powers-of-Tau file and per-circuit zkey/vkey are generated once and
//! cached under `target/bench_cache/` so subsequent runs only time the
//! developer-facing steps. Groth16 setup is timed separately.
//!
//! Run with:
//!   cargo test --release -p circom --test perf_external -- --ignored --nocapture
//!
//! Skips cleanly if `ach`, `circom`, `snarkjs`, or `node` are missing.

use std::process::Command;

#[path = "perf_external/bench.rs"]
mod bench;
#[path = "perf_external/cache.rs"]
mod cache;
#[path = "perf_external/circuits.rs"]
mod circuits;
#[path = "perf_external/inputs.rs"]
mod inputs;
#[path = "perf_external/printing.rs"]
mod printing;
#[path = "perf_external/timing.rs"]
mod timing;
#[path = "perf_external/tools.rs"]
mod tools;
#[path = "perf_external/types.rs"]
mod types;

#[test]
#[ignore]
fn perf_external_vs_circom_snarkjs() {
    if !tools::have("circom", &["--version"]) {
        eprintln!("skip: `circom` binary not available");
        return;
    }
    if !tools::have("node", &["--version"]) {
        eprintln!("skip: `node` not available");
        return;
    }
    if !tools::snarkjs_available() {
        eprintln!("skip: `npx snarkjs` not available");
        return;
    }

    let ach = tools::build_ach_binary();
    // ptau 2^15 = 32 768 covers Sha256(64)'s ~29k post-O2 constraints.
    let ptau = cache::ensure_ptau(15);

    eprintln!("\n== External pipeline benchmark ==");
    eprintln!("  ach    : {}", ach.display());
    eprintln!(
        "  circom : {}",
        String::from_utf8_lossy(
            &Command::new("circom")
                .arg("--version")
                .output()
                .unwrap()
                .stdout
        )
        .trim()
    );
    eprintln!("  ptau   : {}", ptau.display());

    for circuit in circuits::CIRCUITS {
        let workdir = tempfile::tempdir().unwrap();
        let (cir_timings, setup, _r1cs) = bench::bench_circom(circuit, workdir.path(), &ptau);
        let ach_timings = bench::bench_ach(&ach, circuit, workdir.path());
        printing::print_row(circuit, &ach_timings, &cir_timings, setup);
    }
}
