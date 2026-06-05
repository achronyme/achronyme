use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use akron::ProveResult;
use memory::{Bn254Fr, FieldElement};
use zkc::plonkish_backend::PlonkishCompiler;

fn main() {
    let chain_len = env_usize("ACH_PLONKISH_BENCH_CHAIN", 256);
    let repeats = env_usize("ACH_PLONKISH_BENCH_REPEATS", 3);
    let cache_dir = cache_dir();

    eprintln!("plonkish synthetic timing");
    eprintln!(
        "chain_len={chain_len} repeats={repeats} cache_dir={}",
        cache_dir.display()
    );

    let mut totals = Totals::default();
    for repeat in 0..repeats {
        let started = Instant::now();
        let compiler = build_compiler(chain_len);
        let compile = started.elapsed();

        let timed = proving::halo2_proof::generate_plonkish_proof_timed(compiler, &cache_dir)
            .expect("plonkish proof must generate and verify");
        let total = started.elapsed();
        assert!(matches!(timed.result, ProveResult::Proof { .. }));

        totals.add(compile, timed.timing, total);
        eprintln!(
            "repeat={repeat} rows={} k={} compile_ms={:.3} params_ms={:.3} \
             keygen_vk_ms={:.3} keygen_pk_ms={:.3} prove_ms={:.3} verify_ms={:.3} \
             serialize_ms={:.3} total_ms={:.3}",
            timed.rows,
            timed.k,
            ms(compile),
            ms(timed.timing.params),
            ms(timed.timing.keygen_vk),
            ms(timed.timing.keygen_pk),
            ms(timed.timing.prove),
            ms(timed.timing.verify),
            ms(timed.timing.serialize),
            ms(total),
        );
    }

    let n = repeats as f64;
    eprintln!("averages:");
    eprintln!("compile_ms_avg={:.3}", ms(totals.compile) / n);
    eprintln!("params_ms_avg={:.3}", ms(totals.params) / n);
    eprintln!("keygen_vk_ms_avg={:.3}", ms(totals.keygen_vk) / n);
    eprintln!("keygen_pk_ms_avg={:.3}", ms(totals.keygen_pk) / n);
    eprintln!("prove_ms_avg={:.3}", ms(totals.prove) / n);
    eprintln!("verify_ms_avg={:.3}", ms(totals.verify) / n);
    eprintln!("serialize_ms_avg={:.3}", ms(totals.serialize) / n);
    eprintln!("total_ms_avg={:.3}", ms(totals.total) / n);
    eprintln!("all_verified=true");
}

fn build_compiler(chain_len: usize) -> PlonkishCompiler {
    let source = synthetic_source(chain_len);
    let mut program = ir::IrLowering::<Bn254Fr>::lower_self_contained(&source)
        .expect("synthetic source must lower")
        .2;
    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let mut inputs = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(3));
    inputs.insert("out".to_string(), expected_output(chain_len));

    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler
        .compile_ir_with_witness(&program, &inputs)
        .expect("synthetic Plonkish compile must succeed");
    compiler
        .system
        .verify()
        .expect("synthetic Plonkish constraints must verify");
    compiler
}

fn synthetic_source(chain_len: usize) -> String {
    let mut source = String::from("witness a\npublic out\nlet x0 = a\n");
    for i in 0..chain_len {
        source.push_str(&format!("let x{} = x{} * x{} + x{}\n", i + 1, i, i, i));
    }
    source.push_str(&format!("assert_eq(x{chain_len}, out)\n"));
    source
}

fn expected_output(chain_len: usize) -> FieldElement<Bn254Fr> {
    let mut x = FieldElement::<Bn254Fr>::from_u64(3);
    for _ in 0..chain_len {
        x = x.mul(&x).add(&x);
    }
    x
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn cache_dir() -> PathBuf {
    std::env::var_os("ACH_PLONKISH_BENCH_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".codex-results/plonkish-synthetic-cache"))
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[derive(Default)]
struct Totals {
    compile: Duration,
    params: Duration,
    keygen_vk: Duration,
    keygen_pk: Duration,
    prove: Duration,
    verify: Duration,
    serialize: Duration,
    total: Duration,
}

impl Totals {
    fn add(
        &mut self,
        compile: Duration,
        timing: proving::halo2_proof::PlonkishProofTiming,
        total: Duration,
    ) {
        self.compile += compile;
        self.params += timing.params;
        self.keygen_vk += timing.keygen_vk;
        self.keygen_pk += timing.keygen_pk;
        self.prove += timing.prove;
        self.verify += timing.verify;
        self.serialize += timing.serialize;
        self.total += total;
    }
}
