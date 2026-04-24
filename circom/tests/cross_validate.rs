//! Cross-validation: Achronyme ↔ snarkjs Groth16 proof interoperability.
//!
//! Closes Circom Frontend Phase 6.3. Two directions are tested on
//! every circuit:
//!
//!   (A) Achronyme compiles + proves → snarkjs verifies.
//!       Confirms Achronyme's proof / public / vkey JSON is bit-for-bit
//!       the format snarkjs expects.
//!
//!   (B) circom compiles, snarkjs sets up + proves → Achronyme verifies.
//!       Confirms Achronyme's `verify_proof_from_json` parser accepts
//!       the exact byte layout snarkjs emits.
//!
//! Together these prove the interoperability claim made in the docs
//! ("Groth16 proofs produced here are wire-compatible with the
//! circomlib ecosystem"). Without both directions an interop claim is
//! wishful — two pipelines producing independently valid proofs do
//! not prove either one can verify the other.
//!
//! Run with:
//!   cargo test --release -p circom --test cross_validate -- \
//!       --ignored --nocapture
//!
//! Skips gracefully if `circom`, `node`, or `npx snarkjs` are missing.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

type Fe = FieldElement<Bn254Fr>;

// ---------------------------------------------------------------------------
// Tool discovery (mirror of perf_external.rs)
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
    let out = Command::new("npx").args(["snarkjs", "--version"]).output();
    matches!(out, Ok(o) if !o.stdout.is_empty() || !o.stderr.is_empty())
}

fn tools_available() -> bool {
    have("circom", &["--version"]) && have("node", &["--version"]) && snarkjs_available()
}

fn run(cmd: &mut Command) {
    let label = format!("{cmd:?}");
    let out = cmd.output().expect("spawn failed");
    if !out.status.success() {
        panic!(
            "command failed: {label}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

fn bench_cache_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest.parent().unwrap().join("target/bench_cache");
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// Direction A — Achronyme proves, snarkjs verifies
// ---------------------------------------------------------------------------

/// Compile `<circom_file>`, generate a Groth16 proof with Achronyme's
/// native pipeline, and hand the resulting `proof.json`,
/// `public.json`, and `vkey.json` to `snarkjs groth16 verify`. A
/// successful verification proves Achronyme writes the snarkjs JSON
/// format byte-faithfully — drift between the two formats would
/// break the interop claim.
fn achronyme_prove_snarkjs_verify(
    circom_file: &str,
    libs: &[&str],
    inputs: &[(&str, u64)],
) -> Result<usize, String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = workspace.join(circom_file);
    let lib_dirs: Vec<PathBuf> = libs.iter().map(|l| workspace.join(l)).collect();

    // 1. Achronyme frontend → ProveIR → SSA IR → R1CS + witness.
    let compile_result = circom::compile_file(&path, &lib_dirs)
        .map_err(|e| format!("circom compile failed: {e}"))?;
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, Fe> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_with_outputs(&fe_captures, &compile_result.output_names)
        .map_err(|e| format!("instantiate failed: {e}"))?;
    ir::passes::optimize(&mut program);

    let fe_inputs: HashMap<String, Fe> = inputs
        .iter()
        .map(|(k, v)| (k.to_string(), Fe::from_u64(*v)))
        .collect();
    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &fe_inputs, capture_values)
            .map_err(|e| format!("witness hints failed: {e}"))?;
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    let witness = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .map_err(|e| format!("r1cs compile failed: {e}"))?;
    let num_constraints = compiler.cs.num_constraints();

    // 2. Achronyme Groth16 proof generation.
    let cache_dir = bench_cache_dir().join("achronyme_keys");
    let result = proving::groth16_bn254::generate_proof(&compiler.cs, &witness, &cache_dir)
        .map_err(|e| format!("Groth16 proof gen failed: {e}"))?;

    let (proof_json, public_json, vkey_json) = match result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => (proof_json, public_json, vkey_json),
        _ => return Err("expected Proof variant from generate_proof".into()),
    };

    // 3. Write JSONs to a tempdir and let snarkjs verify them.
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let proof_p = dir.path().join("proof.json");
    let public_p = dir.path().join("public.json");
    let vkey_p = dir.path().join("vkey.json");
    fs::write(&proof_p, &proof_json).map_err(|e| format!("write proof: {e}"))?;
    fs::write(&public_p, &public_json).map_err(|e| format!("write public: {e}"))?;
    fs::write(&vkey_p, &vkey_json).map_err(|e| format!("write vkey: {e}"))?;

    let output = Command::new("npx")
        .args(["snarkjs", "groth16", "verify"])
        .arg(&vkey_p)
        .arg(&public_p)
        .arg(&proof_p)
        .output()
        .map_err(|e| format!("snarkjs spawn: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // snarkjs 0.7.x prints "OK!" to stdout on success; some paths
    // emit it via the info logger on stderr.
    let ok = output.status.success()
        && (stdout.contains("OK!")
            || stderr.contains("OK!")
            || stdout.to_lowercase().contains("snarkjs: ok"));
    if !ok {
        return Err(format!(
            "snarkjs rejected Achronyme's proof.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        ));
    }
    Ok(num_constraints)
}

// ---------------------------------------------------------------------------
// Direction B — snarkjs proves, Achronyme verifies
// ---------------------------------------------------------------------------

/// Generate (or reuse) a Powers-of-Tau 2^14 ceremony file under the
/// shared bench-cache directory. Sharing with `perf_external.rs`
/// avoids re-running the ~60-second phase-1 ceremony.
fn ensure_ptau14() -> PathBuf {
    let cache = bench_cache_dir();
    let final_ptau = cache.join("pot14_final.ptau");
    if final_ptau.exists() {
        return final_ptau;
    }
    eprintln!("  generating PowersOfTau 2^14 (one-time, ~60s)…");
    let pot0 = cache.join("pot14_0000.ptau");
    let pot1 = cache.join("pot14_0001.ptau");
    run(Command::new("npx")
        .args(["snarkjs", "powersoftau", "new", "bn128", "14"])
        .arg(&pot0)
        .arg("-v"));
    run(Command::new("npx")
        .args(["snarkjs", "powersoftau", "contribute"])
        .arg(&pot0)
        .arg(&pot1)
        .args(["--name=bench", "-e=bench_entropy_not_secure"]));
    run(Command::new("npx")
        .args(["snarkjs", "powersoftau", "prepare", "phase2"])
        .arg(&pot1)
        .arg(&final_ptau)
        .arg("-v"));
    let _ = fs::remove_file(&pot0);
    let _ = fs::remove_file(&pot1);
    final_ptau
}

/// Compile `<circom_file>` with circom (using `--O2` to match
/// Achronyme's default optimization level), build a witness via the
/// circom-generated WASM, run Groth16 setup + prove with snarkjs,
/// then verify the resulting proof with Achronyme's native
/// `verify_proof_from_json` parser. Asserts `Ok(true)`.
fn snarkjs_prove_achronyme_verify(
    circom_file: &str,
    libs: &[&str],
    input_json: &str,
) -> Result<(), String> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = workspace.join(circom_file);
    let lib_paths: Vec<PathBuf> = libs.iter().map(|l| workspace.join(l)).collect();
    let basename = path.file_stem().unwrap().to_string_lossy().to_string();

    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;

    // 1. circom compile (`--O2` so the constraint layout matches the
    // comparison already published in the external benchmark).
    let mut cmd = Command::new("circom");
    cmd.arg(&path)
        .arg("--r1cs")
        .arg("--wasm")
        .arg("--O2")
        .arg("-o")
        .arg(dir.path());
    for l in &lib_paths {
        cmd.args(["-l", l.to_str().unwrap()]);
    }
    run(&mut cmd);
    let r1cs = dir.path().join(format!("{basename}.r1cs"));
    let wasm_dir = dir.path().join(format!("{basename}_js"));
    let wasm = wasm_dir.join(format!("{basename}.wasm"));
    let gen_witness = wasm_dir.join("generate_witness.js");

    // 2. Witness via node + generated wasm.
    let input_path = dir.path().join("input.json");
    fs::write(&input_path, input_json).map_err(|e| format!("write input: {e}"))?;
    let wtns = dir.path().join("witness.wtns");
    run(Command::new("node")
        .arg(&gen_witness)
        .arg(&wasm)
        .arg(&input_path)
        .arg(&wtns));

    // 3. Groth16 setup + prove.
    let ptau = ensure_ptau14();
    let zkey0 = dir.path().join("circuit_0000.zkey");
    let zkey = dir.path().join("circuit_final.zkey");
    let vkey = dir.path().join("verification_key.json");
    let proof = dir.path().join("proof.json");
    let public = dir.path().join("public.json");

    run(Command::new("npx")
        .args(["snarkjs", "groth16", "setup"])
        .arg(&r1cs)
        .arg(&ptau)
        .arg(&zkey0));
    run(Command::new("npx")
        .args(["snarkjs", "zkey", "contribute"])
        .arg(&zkey0)
        .arg(&zkey)
        .args(["--name=bench", "-e=bench_entropy"]));
    run(Command::new("npx")
        .args(["snarkjs", "zkey", "export", "verificationkey"])
        .arg(&zkey)
        .arg(&vkey));
    run(Command::new("npx")
        .args(["snarkjs", "groth16", "prove"])
        .arg(&zkey)
        .arg(&wtns)
        .arg(&proof)
        .arg(&public));

    // 4. Achronyme verify against snarkjs' JSON artifacts.
    let proof_json = fs::read_to_string(&proof).map_err(|e| format!("read proof: {e}"))?;
    let public_json = fs::read_to_string(&public).map_err(|e| format!("read public: {e}"))?;
    let vkey_json = fs::read_to_string(&vkey).map_err(|e| format!("read vkey: {e}"))?;

    let ok = proving::groth16_bn254::verify_proof_from_json(&proof_json, &public_json, &vkey_json)
        .map_err(|e| format!("Achronyme verify_proof_from_json: {e}"))?;
    if !ok {
        return Err("Achronyme rejected snarkjs's proof".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — one pair per circuit
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn cross_num2bits_achronyme_prove_snarkjs_verify() {
    if !tools_available() {
        eprintln!("skip: circom/node/snarkjs not all available");
        return;
    }
    let n = achronyme_prove_snarkjs_verify("test/circom/num2bits_8.circom", &[], &[("in", 13)])
        .expect("Num2Bits(8): Achronyme-prove → snarkjs-verify must succeed");
    eprintln!("  Num2Bits(8): {n} constraints, snarkjs accepted Achronyme's proof ✓");
}

#[test]
#[ignore]
fn cross_num2bits_snarkjs_prove_achronyme_verify() {
    if !tools_available() {
        eprintln!("skip: circom/node/snarkjs not all available");
        return;
    }
    snarkjs_prove_achronyme_verify("test/circom/num2bits_8.circom", &[], r#"{"in":"13"}"#)
        .expect("Num2Bits(8): snarkjs-prove → Achronyme-verify must succeed");
    eprintln!("  Num2Bits(8): Achronyme accepted snarkjs's proof ✓");
}

#[test]
#[ignore]
fn cross_mimcsponge_achronyme_prove_snarkjs_verify() {
    if !tools_available() {
        eprintln!("skip: circom/node/snarkjs not all available");
        return;
    }
    let n = achronyme_prove_snarkjs_verify(
        "test/circomlib/mimcsponge_test.circom",
        &["test/circomlib"],
        &[("ins_0", 1), ("ins_1", 2), ("k", 0)],
    )
    .expect("MiMCSponge: Achronyme-prove → snarkjs-verify must succeed");
    eprintln!("  MiMCSponge(2,220,1): {n} constraints, snarkjs accepted Achronyme's proof ✓");
}

#[test]
#[ignore]
fn cross_mimcsponge_snarkjs_prove_achronyme_verify() {
    if !tools_available() {
        eprintln!("skip: circom/node/snarkjs not all available");
        return;
    }
    snarkjs_prove_achronyme_verify(
        "test/circomlib/mimcsponge_test.circom",
        &["test/circomlib"],
        r#"{"ins":["1","2"],"k":"0"}"#,
    )
    .expect("MiMCSponge: snarkjs-prove → Achronyme-verify must succeed");
    eprintln!("  MiMCSponge(2,220,1): Achronyme accepted snarkjs's proof ✓");
}
