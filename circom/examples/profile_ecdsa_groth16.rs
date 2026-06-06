//! Release-mode ECDSA R1CS witness verification and optional Groth16 timing.
//!
//! Safe default: compile, build the witness-bearing R1CS, O1-optimize, and
//! verify the optimized witness without entering the memory-heavy proof path:
//!     cargo run --release -p circom --example profile_ecdsa_groth16
//!
//! Full native Groth16 wrapper timing:
//!     ACH_ECDSA_GROTH16_FULL=1 cargo run --release -p circom \
//!         --example profile_ecdsa_groth16

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

type Fe = FieldElement<Bn254Fr>;

fn main() {
    let total = Instant::now();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/ecdsa_verify_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let verify_only =
        env_flag("ACH_ECDSA_GROTH16_VERIFY_ONLY") || !env_flag("ACH_ECDSA_GROTH16_FULL");

    eprintln!("ecdsa groth16 profile");
    eprintln!("  fixture: {}", path.display());
    eprintln!("  verify_only={verify_only}");

    let start = Instant::now();
    let compile_result =
        circom::compile_file(&path, &lib_dirs).unwrap_or_else(|e| panic!("compile_file: {e}"));
    eprintln!("compile_file_ms={:.3}", elapsed_ms(start));

    let fe_captures: HashMap<String, Fe> = compile_result
        .capture_values
        .iter()
        .map(|(name, value)| (name.clone(), Fe::from_u64(*value)))
        .collect();

    let start = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("instantiate: {e}"));
    eprintln!(
        "instantiate_ms={:.3} ir_len={}",
        elapsed_ms(start),
        program.instructions().len()
    );

    let start = Instant::now();
    ir::passes::optimize(&mut program);
    eprintln!(
        "ir_optimize_ms={:.3} ir_len={}",
        elapsed_ms(start),
        program.instructions().len()
    );

    let inputs = build_ecdsa_inputs();

    // Share an Artik execution cache between the hint walk and the witness
    // fill: the lifted big-integer programs run in both passes, so the fill
    // reuses the hint walk's results instead of re-executing them.
    let mut artik_memo = artik::ArtikMemo::<Bn254Fr>::new();

    let start = Instant::now();
    let mut all_signals = circom::witness::compute_witness_hints_with_captures_memo(
        &compile_result.prove_ir,
        &inputs,
        &compile_result.capture_values,
        &mut artik_memo,
    )
    .unwrap_or_else(|e| panic!("witness hints: {e}"));
    for (name, value) in &fe_captures {
        all_signals.entry(name.clone()).or_insert(*value);
    }
    eprintln!(
        "witness_hints_ms={:.3} env_len={}",
        elapsed_ms(start),
        all_signals.len(),
    );

    let start = Instant::now();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new_prover();
    compiler.set_artik_memo(artik_memo);
    let mut witness = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("r1cs compile with witness: {e}"));
    eprintln!(
        "r1cs_compile_with_witness_ms={:.3} constraints={} variables={}",
        elapsed_ms(start),
        compiler.cs.num_constraints(),
        compiler.cs.num_variables()
    );

    let start = Instant::now();
    compiler.optimize_r1cs();
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap_or_else(|e| {
                panic!("substitution witness fill failed for var {var_idx}: {e}")
            });
        }
    }
    eprintln!(
        "r1cs_o1_ms={:.3} constraints={} variables={}",
        elapsed_ms(start),
        compiler.cs.num_constraints(),
        compiler.cs.num_variables()
    );

    let start = Instant::now();
    compiler
        .cs
        .verify(&witness)
        .expect("optimized ECDSA witness must verify");
    eprintln!("r1cs_verify_ms={:.3}", elapsed_ms(start));

    if !verify_only {
        let cache_dir = cache_dir(manifest_dir);
        let start = Instant::now();
        let result = proving::groth16_bn254::generate_proof(&compiler.cs, &witness, &cache_dir)
            .unwrap_or_else(|e| panic!("groth16 proof: {e}"));
        eprintln!("groth16_generate_proof_ms={:.3}", elapsed_ms(start));
        if let akron::machine::prove::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } = result
        {
            eprintln!(
                "groth16_json_bytes proof={} public={} vkey={}",
                proof_json.len(),
                public_json.len(),
                vkey_json.len()
            );
        }
    }

    eprintln!("total_ms={:.3}", elapsed_ms(total));
}

fn build_ecdsa_inputs() -> HashMap<String, Fe> {
    let mut inputs = HashMap::new();

    // Fixed valid secp256k1 ECDSA assignment: private key 1, SHA-256 prehash of
    // "achronyme ecdsa groth16 diagnostic vector", little-endian 64-bit limbs.
    let r = [
        8640493642804984513,
        1852904973164856822,
        5243193105603364912,
        5650329140883233571,
    ];
    let s = [
        10600419463435818137,
        3653588198612269470,
        8464183763061628065,
        6201689187478580395,
    ];
    let msghash = [
        1494920748616258398,
        7901943616638701318,
        16907130083731622963,
        14369586280073249507,
    ];
    let pubkey = [
        [
            6481385041966929816,
            188021827762530521,
            6170039885052185351,
            8772561819708210092,
        ],
        [
            11261198710074299576,
            18237243440184513561,
            6747795201694173352,
            5204712524664259685,
        ],
    ];

    for i in 0..4 {
        inputs.insert(format!("r_{i}"), Fe::from_u64(r[i]));
        inputs.insert(format!("s_{i}"), Fe::from_u64(s[i]));
        inputs.insert(format!("msghash_{i}"), Fe::from_u64(msghash[i]));
        inputs.insert(format!("pubkey_0_{i}"), Fe::from_u64(pubkey[0][i]));
        inputs.insert(format!("pubkey_1_{i}"), Fe::from_u64(pubkey[1][i]));
    }
    for row in 0..2 {
        for col in 0..4 {
            let name = format!("pubkey_{row}_{col}");
            inputs.insert(format!("pubkey_{}", row * 4 + col), inputs[&name]);
        }
    }
    inputs
}

fn cache_dir(manifest_dir: &Path) -> PathBuf {
    std::env::var_os("ACH_ECDSA_GROTH16_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join(".codex-results/ecdsa-groth16-cache"))
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}
