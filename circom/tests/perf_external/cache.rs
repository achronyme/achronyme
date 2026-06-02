use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::timing::run_timed;

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
pub(crate) fn ensure_ptau(size: u32) -> PathBuf {
    let cache = bench_cache_dir();
    let final_ptau = cache.join(format!("pot{size}_final.ptau"));
    if final_ptau.exists() {
        return final_ptau;
    }

    eprintln!("  generating PowersOfTau 2^{size} (one-time, ~60s)...");

    let pot0 = cache.join(format!("pot{size}_0000.ptau"));
    let pot1 = cache.join(format!("pot{size}_0001.ptau"));

    // Powers-of-tau: new
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
    // Circuit-specific prep (snarkjs' `prepare phase2` step)
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
pub(crate) fn ensure_zkey(
    circuit_name: &str,
    r1cs: &Path,
    ptau: &Path,
) -> (Duration, PathBuf, PathBuf) {
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
