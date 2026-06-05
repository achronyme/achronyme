//! Release-mode witness field-operation profile.
//!
//! Build & run:
//!     cargo run --release -p circom --example profile_witness_ops \
//!         --features memory/field-op-profile -- ecdsa

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use memory::{Bn254Fr, FieldElement};

fn fixture(circuit: &str, manifest_dir: &Path) -> (PathBuf, Vec<PathBuf>) {
    match circuit {
        "sha256" | "sha256_64" => (
            manifest_dir.join("test/circomlib/sha256_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        "smt" | "smtverifier" => (
            manifest_dir.join("test/circomlib/smtverifier_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        "eddsa" | "eddsaposeidon" => (
            manifest_dir.join("test/circomlib/eddsaposeidon_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        "ecdsa" | "ecdsa_verify" => (
            manifest_dir.join("test/circomlib/ecdsa_verify_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        other => panic!("unknown circuit '{other}'. supported: sha256 | smt | eddsa | ecdsa"),
    }
}

fn fe(s: &str) -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_decimal_str(s).unwrap_or_else(|| panic!("bad field element: {s}"))
}

fn build_inputs(circuit: &str) -> HashMap<String, FieldElement<Bn254Fr>> {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    match circuit {
        "sha256" | "sha256_64" => {
            for i in 0..64 {
                inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
            }
        }
        "smt" | "smtverifier" => {
            for k in [
                "enabled", "fnc", "root", "oldKey", "oldValue", "isOld0", "key", "value",
            ] {
                inputs.insert(k.to_string(), FieldElement::<Bn254Fr>::from_u64(0));
            }
            for i in 0..10 {
                inputs.insert(
                    format!("siblings_{i}"),
                    FieldElement::<Bn254Fr>::from_u64(0),
                );
            }
        }
        "eddsa" | "eddsaposeidon" => {
            inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
            inputs.insert(
                "Ax".to_string(),
                fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
            );
            inputs.insert(
                "Ay".to_string(),
                fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
            );
            inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
            inputs.insert(
                "R8x".to_string(),
                fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
            );
            inputs.insert(
                "R8y".to_string(),
                fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
            );
            inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));
        }
        "ecdsa" | "ecdsa_verify" => {
            for i in 0..4 {
                inputs.insert(format!("r_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
                inputs.insert(format!("s_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
                inputs.insert(format!("msghash_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
                inputs.insert(
                    format!("pubkey_0_{i}"),
                    FieldElement::<Bn254Fr>::from_u64(0),
                );
                inputs.insert(
                    format!("pubkey_1_{i}"),
                    FieldElement::<Bn254Fr>::from_u64(0),
                );
            }
            inputs.insert("s_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
        }
        _ => unreachable!(),
    }
    inputs
}

fn print_isa() {
    #[cfg(target_arch = "x86_64")]
    {
        eprintln!(
            "isa avx2={} avx512f={} avx512dq={} avx512vl={} avx512ifma={} adx={} bmi2={}",
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("avx512f"),
            std::arch::is_x86_feature_detected!("avx512dq"),
            std::arch::is_x86_feature_detected!("avx512vl"),
            std::arch::is_x86_feature_detected!("avx512ifma"),
            std::arch::is_x86_feature_detected!("adx"),
            std::arch::is_x86_feature_detected!("bmi2"),
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    eprintln!("isa target_arch={}", std::env::consts::ARCH);
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let circuit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ecdsa".to_string());
    let (path, lib_dirs) = fixture(&circuit, manifest_dir);
    let inputs = build_inputs(&circuit);

    eprintln!("witness field-op profile ({circuit})");
    eprintln!("  fixture: {}", path.display());
    eprintln!("  field-op-profile: {}", memory::field::profile::enabled());
    eprintln!("  witness-profile: {}", circom::witness::profile::enabled());
    print_isa();

    let t = Instant::now();
    let compile_result =
        circom::compile_file(&path, &lib_dirs).unwrap_or_else(|e| panic!("compile_file: {e}"));
    eprintln!("compile_file_ms={:.3}", t.elapsed().as_secs_f64() * 1000.0);

    memory::field::profile::reset();
    circom::witness::profile::reset();
    let t = Instant::now();
    let env = circom::witness::compute_witness_hints_with_captures(
        &compile_result.prove_ir,
        &inputs,
        &compile_result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness hints: {e}"));
    let elapsed_ms = t.elapsed().as_secs_f64() * 1000.0;
    let ops = memory::field::profile::snapshot();
    let witness_ops = circom::witness::profile::snapshot();

    eprintln!(
        "witness_hints_ms={elapsed_ms:.3} env_len={} total_ops={} mul={} add={} sub={} neg={} inv={} reduce={} ct_select={}",
        env.len(),
        ops.total(),
        ops.mul,
        ops.add,
        ops.sub,
        ops.neg,
        ops.inv,
        ops.reduce,
        ops.ct_select,
    );
    if circom::witness::profile::enabled() {
        eprintln!(
            "witness_profile hint_div={} hint_div_zero={} hint_div_invertible={}",
            witness_ops.hint_div, witness_ops.hint_div_zero, witness_ops.hint_div_invertible,
        );
    }
}
