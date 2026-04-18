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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Tool discovery
// ---------------------------------------------------------------------------

fn have(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn snarkjs_available() -> bool {
    // `snarkjs --version` exits non-zero on 0.7.x but still prints version.
    let out = Command::new("npx").args(["snarkjs", "--version"]).output();
    matches!(out, Ok(o) if !o.stdout.is_empty() || !o.stderr.is_empty())
}

fn build_ach_binary() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().unwrap();
    let bin = workspace.join("target/release/ach");
    if !bin.exists() {
        eprintln!("  building ach release binary (first run only)...");
        let status = Command::new("cargo")
            .args(["build", "--release", "-p", "cli", "--bin", "ach"])
            .current_dir(workspace)
            .status()
            .expect("cargo build failed");
        assert!(status.success(), "cargo build -p cli failed");
    }
    bin
}

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

/// Run a command and return wall-clock duration. Panics on non-zero exit,
/// printing captured stdout/stderr for diagnostics.
fn run_timed(cmd: &mut Command) -> Duration {
    let label = format!("{cmd:?}");
    let t = Instant::now();
    let output = cmd.output().expect("failed to spawn");
    let elapsed = t.elapsed();
    if !output.status.success() {
        panic!(
            "command failed: {label}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    elapsed
}

fn median(mut xs: Vec<Duration>) -> Duration {
    xs.sort();
    xs[xs.len() / 2]
}

// ---------------------------------------------------------------------------
// Powers-of-tau + zkey caching
// ---------------------------------------------------------------------------

fn bench_cache_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.parent().unwrap().join("target/bench_cache");
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Generate (or reuse) a Powers-of-Tau file of the requested size.
///
/// 2^14 handles all three benchmark circuits (EscalarMulAny peaks at 2310
/// constraints). Generation takes ~60s the first time; subsequent runs are
/// instant because of the filesystem cache.
fn ensure_ptau(size: u32) -> PathBuf {
    let cache = bench_cache_dir();
    let final_ptau = cache.join(format!("pot{size}_final.ptau"));
    if final_ptau.exists() {
        return final_ptau;
    }

    eprintln!("  generating PowersOfTau 2^{size} (one-time, ~60s)...");

    let pot0 = cache.join(format!("pot{size}_0000.ptau"));
    let pot1 = cache.join(format!("pot{size}_0001.ptau"));

    // Phase 1: new
    run_timed(
        Command::new("npx")
            .args(["snarkjs", "powersoftau", "new", "bn128", &size.to_string()])
            .arg(&pot0)
            .arg("-v"),
    );
    // Contribute (fake entropy — this is a benchmark, not a real ceremony)
    run_timed(
        Command::new("npx")
            .args(["snarkjs", "powersoftau", "contribute"])
            .arg(&pot0)
            .arg(&pot1)
            .args(["--name=bench", "-e=bench_entropy_not_secure"]),
    );
    // Phase 2 prep
    run_timed(
        Command::new("npx")
            .args(["snarkjs", "powersoftau", "prepare", "phase2"])
            .arg(&pot1)
            .arg(&final_ptau)
            .arg("-v"),
    );

    let _ = fs::remove_file(&pot0);
    let _ = fs::remove_file(&pot1);
    final_ptau
}

/// Generate (or reuse) a Groth16 zkey + verification key for a given R1CS.
/// Returns `(setup_time, zkey_path, vkey_path)`.
fn ensure_zkey(circuit_name: &str, r1cs: &Path, ptau: &Path) -> (Duration, PathBuf, PathBuf) {
    let cache = bench_cache_dir().join(circuit_name);
    fs::create_dir_all(&cache).unwrap();
    let zkey0 = cache.join("circuit_0000.zkey");
    let zkey = cache.join("circuit_final.zkey");
    let vkey = cache.join("verification_key.json");

    if zkey.exists() && vkey.exists() {
        return (Duration::ZERO, zkey, vkey);
    }

    let t = Instant::now();
    run_timed(
        Command::new("npx")
            .args(["snarkjs", "groth16", "setup"])
            .arg(r1cs)
            .arg(ptau)
            .arg(&zkey0),
    );
    run_timed(
        Command::new("npx")
            .args(["snarkjs", "zkey", "contribute"])
            .arg(&zkey0)
            .arg(&zkey)
            .args(["--name=bench", "-e=bench_entropy"]),
    );
    run_timed(
        Command::new("npx")
            .args(["snarkjs", "zkey", "export", "verificationkey"])
            .arg(&zkey)
            .arg(&vkey),
    );
    let _ = fs::remove_file(&zkey0);
    (t.elapsed(), zkey, vkey)
}

// ---------------------------------------------------------------------------
// Per-circuit benchmark driver
// ---------------------------------------------------------------------------

/// Describes one circuit under test — all paths are relative to the workspace
/// root so the harness can be invoked from anywhere.
struct Circuit {
    name: &'static str,
    /// `.circom` source file.
    circom_src: &'static str,
    /// Library dirs to pass to both `circom -l` and `ach circom --lib`.
    libs: &'static [&'static str],
    /// Produces matching input representations — `(circom_json, ach_toml)` —
    /// for this circuit. Programmatic generation avoids hand-counting array
    /// lengths in long scalar vectors.
    inputs: fn() -> (String, String),
}

struct AchTimings {
    /// `ach circom --r1cs --wtns --input-file` — compile + witness.
    /// `ach circom` always computes witness hints (for `<--`) even without
    /// `--prove`, so measuring a pure compile-only phase isn't possible from
    /// the CLI. This column is the closest apples-to-apples equivalent to
    /// `circom --r1cs --wasm` + `generate_witness.js` combined.
    compile_plus_witness: Duration,
    /// Same plus Groth16 prove + verify.
    full: Duration,
}

struct CircomTimings {
    compile: Duration,
    witness: Duration,
    prove: Duration,
    verify: Duration,
}

fn bench_ach(ach: &Path, circuit: &Circuit, workdir: &Path) -> AchTimings {
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

fn bench_circom(
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
    // Using circom's default optimization (between --O0 and --O2). Enabling
    // --O2 produces R1CS files that occasionally mismatch snarkjs' wire
    // expectations on MiMCSponge-style circuits; the default is what most
    // tutorials and circom users actually run.
    let mut cmd = Command::new("circom");
    cmd.arg(&src)
        .arg("--r1cs")
        .arg("--wasm")
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
        // compile (r1cs + wasm)
        let mut cmd = Command::new("circom");
        cmd.arg(&src)
            .arg("--r1cs")
            .arg("--wasm")
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

// ---------------------------------------------------------------------------
// Pretty printing
// ---------------------------------------------------------------------------

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn print_row(circuit: &Circuit, ach: &AchTimings, cir: &CircomTimings, setup: Duration) {
    let cir_cw = cir.compile + cir.witness;
    let cir_full = cir_cw + cir.prove + cir.verify;
    let ach_cw = ms(ach.compile_plus_witness);
    let ach_full = ms(ach.full);
    eprintln!("\n--- {} ---", circuit.name);
    eprintln!(
        "  {:<22} {:>12} {:>14} {:>10}",
        "phase", "achronyme", "circom+snarkjs", "ratio"
    );
    eprintln!(
        "  {:<22} {:>10.2}ms {:>12.2}ms {:>9.2}×",
        "compile + witness",
        ach_cw,
        ms(cir_cw),
        ms(cir_cw) / ach_cw
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "  └─ circom compile",
        "—",
        ms(cir.compile)
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "  └─ node witness",
        "—",
        ms(cir.witness)
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "groth16 prove",
        "(bundled)",
        ms(cir.prove)
    );
    eprintln!(
        "  {:<22} {:>12} {:>12.2}ms",
        "groth16 verify",
        "(bundled)",
        ms(cir.verify)
    );
    eprintln!(
        "  {:<22} {:>10.2}ms {:>12.2}ms {:>9.2}×",
        "end-to-end",
        ach_full,
        ms(cir_full),
        ms(cir_full) / ach_full
    );
    if !setup.is_zero() {
        eprintln!(
            "  (one-time snarkjs groth16 setup for this circuit: {:.1}s)",
            setup.as_secs_f64()
        );
    }
}

// ---------------------------------------------------------------------------
// Circuit definitions
// ---------------------------------------------------------------------------

fn num2bits8_inputs() -> (String, String) {
    (r#"{"in":"13"}"#.to_string(), "in = 13\n".to_string())
}

fn mimcsponge_inputs() -> (String, String) {
    (
        r#"{"ins":["1","2"],"k":"0"}"#.to_string(),
        "ins = [1, 2]\nk = 0\n".to_string(),
    )
}

fn escalarmulany_inputs() -> (String, String) {
    // 254 zero scalar bits, identity point (0, 1).
    let zeros: Vec<&str> = (0..254).map(|_| "\"0\"").collect();
    let json = format!(r#"{{"e":[{}],"p":["0","1"]}}"#, zeros.join(","));
    let mut toml = String::from("p = [0, 1]\ne = [");
    for i in 0..254 {
        if i > 0 {
            toml.push_str(", ");
        }
        toml.push('0');
    }
    toml.push_str("]\n");
    (json, toml)
}

const CIRCUITS: &[Circuit] = &[
    Circuit {
        name: "Num2Bits(8)",
        circom_src: "test/circom/num2bits_8.circom",
        libs: &[],
        inputs: num2bits8_inputs,
    },
    Circuit {
        name: "MiMCSponge(2,220,1)",
        circom_src: "test/circomlib/mimcsponge_test.circom",
        libs: &["test/circomlib"],
        inputs: mimcsponge_inputs,
    },
    Circuit {
        name: "EscalarMulAny(254)",
        circom_src: "test/circomlib/escalarmulany254_test.circom",
        libs: &["test/circomlib"],
        inputs: escalarmulany_inputs,
    },
];

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn perf_external_vs_circom_snarkjs() {
    if !have("circom", &["--version"]) {
        eprintln!("skip: `circom` binary not available");
        return;
    }
    if !have("node", &["--version"]) {
        eprintln!("skip: `node` not available");
        return;
    }
    if !snarkjs_available() {
        eprintln!("skip: `npx snarkjs` not available");
        return;
    }

    let ach = build_ach_binary();
    let ptau = ensure_ptau(14);

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

    for circuit in CIRCUITS {
        let workdir = tempfile::tempdir().unwrap();
        let (cir_timings, setup, _r1cs) = bench_circom(circuit, workdir.path(), &ptau);
        let ach_timings = bench_ach(&ach, circuit, workdir.path());
        print_row(circuit, &ach_timings, &cir_timings, setup);
    }
}
