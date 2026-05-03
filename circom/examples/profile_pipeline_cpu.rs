//! CPU sampling profile of the full Circom→R1CS pipeline:
//! `compile_file` + `instantiate_lysis_with_outputs` + `ir::passes::optimize`
//! + `R1CSCompiler::compile_ir` + `optimize_r1cs`.
//!
//! Sister of `profile_compile_cpu` for circuits where lowering is *not* the
//! dominant cost (SMTVerifier(10) spends ~66 % of pipeline wall in
//! `optimize_o1`, so a `compile_file`-only profile misses the real target).
//!
//! Build & run:
//!     cargo run --profile profile-cpu --example profile_pipeline_cpu \
//!         --features cpu-profile -p circom -- <circuit>

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use memory::{Bn254Fr, FieldElement};
use pprof::ProfilerGuardBuilder;
use zkc::r1cs_backend::R1CSCompiler;

fn fixture(circuit: &str, manifest_dir: &Path) -> (PathBuf, Vec<PathBuf>, u64) {
    match circuit {
        "sha256" | "sha256_64" => (
            manifest_dir.join("test/circomlib/sha256_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
            64,
        ),
        "smt" | "smtverifier" => (
            manifest_dir.join("test/circomlib/smtverifier_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
            0,
        ),
        "eddsa" | "eddsaposeidon" => (
            manifest_dir.join("test/circomlib/eddsaposeidon_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
            0,
        ),
        other => panic!("unknown circuit '{other}'. supported: sha256 | smt | eddsa"),
    }
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
            let fe = |s: &str| {
                FieldElement::<Bn254Fr>::from_decimal_str(s)
                    .unwrap_or_else(|| panic!("bad field element: {s}"))
            };
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
        _ => unreachable!(),
    }
    inputs
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let circuit = std::env::args().nth(1).unwrap_or_else(|| "smt".to_string());
    let rate: i32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);

    let (path, lib_dirs, nbits_capture) = fixture(&circuit, manifest_dir);
    let inputs = build_inputs(&circuit);

    eprintln!("CPU profile of full pipeline ({circuit})");
    eprintln!("  fixture:  {}", path.display());
    eprintln!("  rate:     {rate} Hz");

    let guard = ProfilerGuardBuilder::default()
        .frequency(rate)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .expect("start pprof");

    let t_total = Instant::now();

    let t = Instant::now();
    let compile_result =
        circom::compile_file(&path, &lib_dirs).unwrap_or_else(|e| panic!("compile_file: {e}"));
    let lower_ms = t.elapsed().as_secs_f64() * 1000.0;

    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = compile_result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    if matches!(circuit.as_str(), "sha256" | "sha256_64") {
        captures.insert(
            "nBits".to_string(),
            FieldElement::<Bn254Fr>::from_u64(nbits_capture),
        );
    }
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let t = Instant::now();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    let inst_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    ir::passes::optimize(&mut program);
    let iropt_ms = t.elapsed().as_secs_f64() * 1000.0;

    // Witness hints (so the R1CS compile path matches what real users hit).
    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(&compile_result.prove_ir, &inputs, &compile_result.capture_values)
            .unwrap_or_else(|e| panic!("witness hints: {e}"));
    for (cname, fe) in &captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let t = Instant::now();
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_proven_boolean(proven);
    let mut witness = rc
        .compile_ir_with_witness(&program, &all_signals)
        .expect("r1cs emit");
    let r1cs_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pre_opt = rc.cs.num_constraints();

    let t = Instant::now();
    let stats = rc.optimize_r1cs();
    if let Some(subs) = &rc.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).unwrap();
        }
    }
    let o1_ms = t.elapsed().as_secs_f64() * 1000.0;
    let post_opt = rc.cs.num_constraints();

    let total_ms = t_total.elapsed().as_secs_f64() * 1000.0;

    let report = guard.report().build().expect("build pprof report");

    eprintln!(
        "\nfull pipeline ({circuit}) — {total_ms:.2} ms wall \
         (lower={lower_ms:.1} inst={inst_ms:.1} iropt={iropt_ms:.1} \
         r1cs={r1cs_ms:.1} o1={o1_ms:.1})  constraints={pre_opt} → {post_opt} \
         (rounds={}, eliminated={}, dedup={})",
        stats.rounds, stats.variables_eliminated, stats.duplicates_removed,
    );

    let svg_path = format!("cpu_pipeline_{circuit}.svg");
    let svg = std::fs::File::create(&svg_path).expect("create svg");
    report.flamegraph(svg).expect("write flamegraph");
    eprintln!("{svg_path} written.");

    let folded_path = format!("cpu_pipeline_{circuit}.txt");
    let mut entries: Vec<(String, isize)> = report
        .data
        .iter()
        .map(|(frames, count)| {
            let mut parts: Vec<String> = Vec::new();
            for frame_inlines in frames.frames.iter().rev() {
                for sym in frame_inlines {
                    let n = sym.name();
                    if !n.is_empty() {
                        parts.push(n);
                    }
                }
            }
            (parts.join(";"), *count)
        })
        .collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    let total: isize = entries.iter().map(|(_, c)| *c).sum();
    let mut folded = String::with_capacity(entries.len() * 64);
    for (stack, count) in &entries {
        folded.push_str(stack);
        folded.push(' ');
        folded.push_str(&count.to_string());
        folded.push('\n');
    }
    std::fs::write(&folded_path, folded).expect("write folded");
    eprintln!(
        "{folded_path} written ({} unique stacks, {} total samples).",
        entries.len(),
        total
    );

    eprintln!("\nTop 30 stacks by sample count:");
    for (stack, count) in entries.iter().take(30) {
        let pct = (*count as f64) * 100.0 / (total as f64);
        let display = if stack.len() > 220 {
            format!("…{}", &stack[stack.len().saturating_sub(220)..])
        } else {
            stack.clone()
        };
        eprintln!("  {count:>6} ({pct:5.2}%)  {display}");
    }

    drop(witness);
}
