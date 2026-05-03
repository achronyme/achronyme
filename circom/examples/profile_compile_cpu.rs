//! CPU sampling profile of `circom::compile_file` (parser + AST →
//! ProveIR lowering).
//!
//! Builds an in-process pprof-rs profile while compiling a single
//! circomlib fixture, then dumps a flamegraph SVG and a folded
//! stack-collapse text file (one stack per line, sample count
//! suffix). The text file is grep-friendly for top-N hot frames.
//!
//! Build & run:
//!     cargo run --profile profile-cpu --example profile_compile_cpu \
//!         --features cpu-profile -p circom -- <circuit>
//!
//! `<circuit>` selects a fixture; default is `poseidon` because it
//! compiles in seconds and is a safe smoke test before committing
//! to the SHA-256(64) or EdDSAVerifier runs that take minutes.
//!
//! Use `--profile profile-cpu` (defined in the workspace
//! `Cargo.toml`) so the binary keeps line-table debuginfo —
//! optimization stays at release level.

use std::path::{Path, PathBuf};
use std::time::Instant;

use pprof::ProfilerGuardBuilder;

fn fixture(circuit: &str, manifest_dir: &Path) -> (PathBuf, Vec<PathBuf>) {
    match circuit {
        "poseidon" => (
            manifest_dir.join("test/circomlib/poseidon_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        "sha256" | "sha256_64" => (
            manifest_dir.join("test/circomlib/sha256_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        "eddsa" | "eddsa_verifier" => (
            manifest_dir.join("test/circomlib/eddsa_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        "mimc" | "mimcsponge" => (
            manifest_dir.join("test/circomlib/mimcsponge_test.circom"),
            vec![manifest_dir.join("test/circomlib/circuits")],
        ),
        "smt" | "smtverifier" => (
            manifest_dir.join("test/circomlib/smtverifier_test.circom"),
            vec![manifest_dir.join("test/circomlib")],
        ),
        other => {
            panic!("unknown circuit '{other}'. supported: poseidon | sha256 | eddsa | mimc | smt")
        }
    }
}

fn main() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let circuit = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "poseidon".to_string());
    let rate: i32 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let (path, lib_dirs) = fixture(&circuit, manifest_dir);

    eprintln!("CPU profile of compile_file({circuit})");
    eprintln!("  fixture:  {}", path.display());
    eprintln!("  lib_dirs: {lib_dirs:?}");
    eprintln!("  rate:     {rate} Hz");

    let guard = ProfilerGuardBuilder::default()
        .frequency(rate)
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .expect("start pprof");

    let t0 = Instant::now();
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compile_file({circuit}) failed: {e}"));
    let elapsed = t0.elapsed();

    let report = guard.report().build().expect("build pprof report");

    eprintln!(
        "\ncompile_file({circuit}) — {:.2} s wall — {} ProveIR nodes",
        elapsed.as_secs_f64(),
        result.prove_ir.body.len()
    );

    // 1. Flamegraph SVG (visual).
    let svg_path = format!("cpu_flamegraph_{circuit}.svg");
    let svg = std::fs::File::create(&svg_path).expect("create svg");
    report.flamegraph(svg).expect("write flamegraph");
    eprintln!("{svg_path} written.");

    // 2. Folded stack-collapse text (grep-friendly, sorted by samples).
    //    Format: `root;...;leaf <count>` per line — same shape Brendan
    //    Gregg's `stackcollapse-perf.pl` emits, ready for inferno or
    //    flamegraph.pl re-rendering.
    let folded_path = format!("cpu_folded_{circuit}.txt");
    let mut entries: Vec<(String, isize)> = report
        .data
        .iter()
        .map(|(frames, count)| {
            // `frames.frames`: Vec<Vec<Symbol>> — outer index is the
            // call-stack frame (0 = leaf), inner Vec is inlined symbols
            // resolved into that frame.
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

    // 3. Top-30 stacks to stderr for at-a-glance inspection.
    eprintln!("\nTop 30 stacks by sample count:");
    for (stack, count) in entries.iter().take(30) {
        let pct = (*count as f64) * 100.0 / (total as f64);
        // Trim very long stacks for readable stderr — full stack lives
        // in the folded file.
        let display = if stack.len() > 200 {
            format!("…{}", &stack[stack.len().saturating_sub(200)..])
        } else {
            stack.clone()
        };
        eprintln!("  {count:>6} ({pct:5.2}%)  {display}");
    }

    drop(result);
}
