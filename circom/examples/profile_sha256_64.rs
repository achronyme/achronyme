//! Heap-allocation profile of the SHA-256(64) compile pipeline.
//!
//! Mirrors the body of `circom/tests/e2e.rs::sha256_64_constraint_breakdown`
//! up through `ir::passes::optimize`. SHA-256 is the heaviest non-EdDSA
//! template the circom frontend currently handles end-to-end, so it is a
//! second discriminator for "is the next runtime/memory peak in
//! `compile_file` or in `instantiate`?".
//!
//! Build & run:
//!     cargo run --release --example profile_sha256_64 \
//!         --features dhat-heap --manifest-path circom/Cargo.toml

use std::collections::{HashMap, HashSet};
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
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let t0 = Instant::now();
    eprintln!("SHA-256(64) heap profile starting...");
    snapshot("baseline (before compile_file)", t0);

    eprintln!("\n[1/4] compile_file (lex + parse + lower → ProveIR) ...");
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compile_file failed: {e}"));
    snapshot("after compile_file", t0);

    eprintln!("\n[2/4] captures + output set ...");
    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = result.output_names.iter().cloned().collect();
    snapshot("after captures + outputs", t0);

    eprintln!("\n[3/4] instantiate_lysis_with_outputs (Lysis VM run → IR program) ...");
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    snapshot("after instantiate", t0);

    eprintln!("\n[4/4] ir::passes::optimize (IR-level passes) ...");
    ir::passes::optimize(&mut program);
    snapshot("after ir::passes::optimize", t0);

    eprintln!(
        "\nSHA-256(64) — {} ProveIR nodes → {} IR instructions",
        result.prove_ir.body.len(),
        program.len()
    );

    drop(program);
    drop(captures);
    drop(outs);
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
}
