use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::cache::ensure_zkey;
use super::timing::{median, run_timed};
use super::types::{AchTimings, CircomTimings, Circuit};

pub(crate) fn bench_ach(ach: &Path, circuit: &Circuit, workdir: &Path) -> AchTimings {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let src = workspace.join(circuit.circom_src);
    let r1cs = workdir.join("ach_circuit.r1cs");
    let wtns = workdir.join("ach_circuit.wtns");
    let (_json, toml) = (circuit.inputs)();
    let inputs = workdir.join("inputs.toml");
    fs::write(&inputs, toml).unwrap();

    let lib_args: Vec<String> = circuit
        .libs
        .iter()
        .map(|l| workspace.join(l).display().to_string())
        .collect();

    let mut cw_samples = Vec::with_capacity(3);
    let mut full_samples = Vec::with_capacity(3);
    for _ in 0..3 {
        // compile + witness: --r1cs --wtns --input-file (no proof)
        let mut cmd = Command::new(ach);
        cmd.arg("circom")
            .arg(&src)
            .arg("--r1cs")
            .arg(&r1cs)
            .arg("--wtns")
            .arg(&wtns)
            .arg("--input-file")
            .arg(&inputs);
        for l in &lib_args {
            cmd.args(["--lib", l]);
        }
        cw_samples.push(run_timed(&mut cmd));

        // full: add --prove (produces proof + verify)
        let mut cmd = Command::new(ach);
        cmd.arg("circom")
            .arg(&src)
            .arg("--r1cs")
            .arg(&r1cs)
            .arg("--wtns")
            .arg(&wtns)
            .arg("--input-file")
            .arg(&inputs)
            .arg("--prove");
        for l in &lib_args {
            cmd.args(["--lib", l]);
        }
        full_samples.push(run_timed(&mut cmd));
    }

    AchTimings {
        compile_plus_witness: median(cw_samples),
        full: median(full_samples),
    }
}

pub(crate) fn bench_circom(
    circuit: &Circuit,
    workdir: &Path,
    ptau: &Path,
) -> (CircomTimings, Duration, PathBuf) {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let src = workspace.join(circuit.circom_src);
    let (json, _toml) = (circuit.inputs)();
    let input_json = workdir.join("input.json");
    fs::write(&input_json, json).unwrap();

    // Out paths produced by `circom --r1cs --wasm`:
    //   {workdir}/{basename}.r1cs
    //   {workdir}/{basename}_js/{basename}.wasm + generate_witness.js
    let basename = src.file_stem().unwrap().to_string_lossy().to_string();

    let lib_args: Vec<String> = circuit
        .libs
        .iter()
        .map(|l| workspace.join(l).display().to_string())
        .collect();

    // Compile once (outside timing loop) to know the r1cs path for zkey setup
    // `--O2` matches Achronyme's default: full constraint simplification
    // (linear elimination + signal dedup). circom's default is `--O1`
    // which only does signal→signal / signal→constant substitution and
    // would leave us comparing apples (circom lightly-optimized) to
    // oranges (Achronyme fully-optimized).
    let mut cmd = Command::new("circom");
    cmd.arg(&src)
        .arg("--r1cs")
        .arg("--wasm")
        .arg("--O2")
        .arg("-o")
        .arg(workdir);
    for l in &lib_args {
        cmd.args(["-l", l]);
    }
    run_timed(&mut cmd);
    let r1cs = workdir.join(format!("{basename}.r1cs"));
    let wasm_dir = workdir.join(format!("{basename}_js"));
    let wasm = wasm_dir.join(format!("{basename}.wasm"));
    let gen_witness = wasm_dir.join("generate_witness.js");

    let (setup_time, zkey, vkey) = ensure_zkey(circuit.name, &r1cs, ptau);

    let wtns = workdir.join("witness.wtns");
    let proof = workdir.join("proof.json");
    let public = workdir.join("public.json");

    let mut compile_samples = Vec::with_capacity(3);
    let mut witness_samples = Vec::with_capacity(3);
    let mut prove_samples = Vec::with_capacity(3);
    let mut verify_samples = Vec::with_capacity(3);
    for _ in 0..3 {
        // compile (r1cs + wasm) — same --O2 flag as the outside-loop
        // compile to keep r1cs / witness / zkey wire-count consistent.
        let mut cmd = Command::new("circom");
        cmd.arg(&src)
            .arg("--r1cs")
            .arg("--wasm")
            .arg("--O2")
            .arg("-o")
            .arg(workdir);
        for l in &lib_args {
            cmd.args(["-l", l]);
        }
        compile_samples.push(run_timed(&mut cmd));

        // witness
        witness_samples.push(run_timed(
            Command::new("node")
                .arg(&gen_witness)
                .arg(&wasm)
                .arg(&input_json)
                .arg(&wtns),
        ));

        // prove
        prove_samples.push(run_timed(
            Command::new("npx")
                .args(["snarkjs", "groth16", "prove"])
                .arg(&zkey)
                .arg(&wtns)
                .arg(&proof)
                .arg(&public),
        ));

        // verify
        verify_samples.push(run_timed(
            Command::new("npx")
                .args(["snarkjs", "groth16", "verify"])
                .arg(&vkey)
                .arg(&public)
                .arg(&proof),
        ));
    }

    (
        CircomTimings {
            compile: median(compile_samples),
            witness: median(witness_samples),
            prove: median(prove_samples),
            verify: median(verify_samples),
        },
        setup_time,
        r1cs,
    )
}
