//! Heap-allocation profile of the EdDSAVerifier compile pipeline.
//!
//! Mirrors the body of `circom/tests/e2e.rs::eddsa_verifier_compile`,
//! adding a phase-by-phase live-heap snapshot via `dhat-rs` so we can
//! attribute peak memory to {compile_file, capture_values map,
//! instantiate_lysis, ir::passes::optimize}. On `Profiler` drop the
//! tool also writes `dhat-heap.json` next to the working directory,
//! viewable at <https://nnethercote.github.io/dh_view/dh_view.html>.
//!
//! Build & run:
//!     cargo run --release --example profile_eddsa_verifier \
//!         --features dhat-heap --manifest-path circom/Cargo.toml
//!
//! `dhat` itself recommends release builds — debug allocator overhead
//! distorts the picture.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use memory::{Bn254Fr, FieldElement};

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(feature = "dhat-heap")]
fn snapshot(label: &str, t0: Instant) {
    let stats = dhat::HeapStats::get();
    eprintln!(
        "  [{:>5} ms]  curr_live = {:>9.2} MB ({} blocks)   peak_so_far = {:>7.3} GB",
        t0.elapsed().as_millis(),
        stats.curr_bytes as f64 / (1024.0 * 1024.0),
        stats.curr_blocks,
        stats.max_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
    );
    eprintln!("        ({})", label);
}

#[cfg(not(feature = "dhat-heap"))]
fn snapshot(_label: &str, _t0: Instant) {}

fn main() {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/eddsa_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib/circuits")];

    let t0 = Instant::now();
    eprintln!("EdDSAVerifier heap profile starting...");
    snapshot("baseline (before compile_file)", t0);

    eprintln!("\n[1/4] compile_file (lex + parse + lower → ProveIR) ...");
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compile_file failed: {e}"));
    snapshot("after compile_file", t0);

    eprintln!("\n[2/4] capture_values → FieldElement<Bn254Fr> map ...");
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    snapshot("after fe_captures map", t0);

    eprintln!("\n[3/4] instantiate_lysis_with_outputs (Lysis VM run → IR program) ...");
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    snapshot(
        "after instantiate (ProveIR + Lysis bytecode + IR all alive)",
        t0,
    );

    eprintln!("\n[4/4] ir::passes::optimize (IR-level passes) ...");
    ir::passes::optimize(&mut program);
    snapshot("after ir::passes::optimize", t0);

    eprintln!(
        "\nEdDSAVerifier(1) — {} ProveIR nodes → {} IR instructions",
        result.prove_ir.body.len(),
        program.len()
    );

    drop(program);
    drop(fe_captures);
    drop(result);
    snapshot("after dropping all stage values", t0);

    #[cfg(feature = "dhat-heap")]
    {
        let stats = dhat::HeapStats::get();
        eprintln!(
            "\n=== final ===\n  peak live = {:.3} GB\n  total alloc = {:.3} GB ({} allocs)",
            stats.max_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            stats.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            stats.total_blocks,
        );
    }

    eprintln!("\ndhat-heap.json written to current dir.");
    eprintln!("Inspect at https://nnethercote.github.io/dh_view/dh_view.html");
}
