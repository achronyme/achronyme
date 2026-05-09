//! Regression: heavy circomlib templates dispatched from a `.ach
//! prove` block compile through the For-preserving path without
//! exhausting Lysis's 255-slot frame ceiling.

use std::io::Write;

use cli::commands::ErrorFormat;
use memory::field::PrimeId;

const EF: ErrorFormat = ErrorFormat::Human;

fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run_ach(source: &str) -> anyhow::Result<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let ach_path = dir.path().join("main.ach");
    let mut f = std::fs::File::create(&ach_path).expect("create ach file");
    f.write_all(source.as_bytes()).expect("write ach source");
    f.flush().expect("flush ach source");

    cli::commands::run::run_file(
        ach_path.to_str().unwrap(),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
        &[],
    )
}

fn sha256_source(circomlib: &std::path::Path, n_bits: usize, mix: bool) -> String {
    let mut bits = String::from("[");
    for i in 0..n_bits {
        if i > 0 {
            bits.push_str(", ");
        }
        bits.push_str(if mix && i % 2 == 0 { "0p1" } else { "0p0" });
    }
    bits.push(']');
    format!(
        r#"
import {{ Sha256 }} from "{lib}/circuits/sha256/sha256.circom"

prove() {{
    let _r = Sha256({n_bits})({bits})
}}
"#,
        lib = circomlib.to_str().unwrap(),
    )
}

#[test]
fn iszero_via_ach_prove_compiles() {
    let circomlib = workspace_root().join("test/circomlib");
    if !circomlib.join("circuits/comparators.circom").exists() {
        eprintln!("skipping: circomlib not present at {circomlib:?}");
        return;
    }

    let source = format!(
        r#"
import {{ IsZero }} from "{lib}/circuits/comparators.circom"

prove() {{
    let _r = IsZero()(0p0)
}}
"#,
        lib = circomlib.to_str().unwrap()
    );

    run_ach(&source).expect("IsZero via .ach prove must compile + run");
}

#[test]
fn sha256_64_all_zero_inputs_compiles() {
    let circomlib = workspace_root().join("test/circomlib");
    if !circomlib.join("circuits/sha256/sha256.circom").exists() {
        eprintln!("skipping: circomlib/sha256 not present at {circomlib:?}");
        return;
    }
    let source = sha256_source(&circomlib, 64, false);
    run_ach(&source).expect("Sha256(64) all-zero via .ach prove must compile + run");
}

#[test]
fn sha256_64_mixed_inputs_compiles() {
    let circomlib = workspace_root().join("test/circomlib");
    if !circomlib.join("circuits/sha256/sha256.circom").exists() {
        eprintln!("skipping: circomlib/sha256 not present at {circomlib:?}");
        return;
    }
    let source = sha256_source(&circomlib, 64, true);
    run_ach(&source).expect("Sha256(64) mixed via .ach prove must compile + run");
}

#[test]
fn sha256_8_compiles() {
    let circomlib = workspace_root().join("test/circomlib");
    if !circomlib.join("circuits/sha256/sha256.circom").exists() {
        return;
    }
    let source = sha256_source(&circomlib, 8, false);
    run_ach(&source).expect("Sha256(8) all-zero via .ach prove must compile + run");
}

#[test]
fn sha256_8_mixed_inputs_compiles() {
    let circomlib = workspace_root().join("test/circomlib");
    if !circomlib.join("circuits/sha256/sha256.circom").exists() {
        return;
    }
    let source = sha256_source(&circomlib, 8, true);
    run_ach(&source).expect("Sha256(8) mixed via .ach prove must compile + run");
}

/// Sha256_2 dispatched from a `.ach` prove block.
///
/// Distinct shape from `Sha256(N)`: hardcoded length encoding via raw
/// `inp[i] <== const` assignments + 2× Num2Bits(216) + Bits2Num(216),
/// not a parametric padding loop. Two 216-bit field-element inputs
/// instead of a bit array. Pure-circom path matches circom O2 ±0.05%
/// (see `sha256_2_real_circomlib` in `circom/tests/e2e.rs`); this test
/// pins the same template through the `CallCircomTemplate` dispatch
/// path that historically tripped Lysis's 255-slot frame ceiling.
#[test]
fn sha256_2_compiles() {
    let circomlib = workspace_root().join("test/circomlib");
    if !circomlib.join("circuits/sha256/sha256_2.circom").exists() {
        eprintln!("skipping: circomlib/sha256 not present at {circomlib:?}");
        return;
    }
    let source = format!(
        r#"
import {{ Sha256_2 }} from "{lib}/circuits/sha256/sha256_2.circom"

prove() {{
    let _r = Sha256_2()(0p1, 0p2)
}}
"#,
        lib = circomlib.to_str().unwrap(),
    );
    run_ach(&source).expect("Sha256_2 via .ach prove must compile + run");
}
