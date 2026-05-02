//! Microbenchmark: SHA-256 round body through the Lysis pipeline
//! vs. equivalent emit-into-vec straight-line Rust.
//!
//! Per RFC §10's exit criterion ("SHA-256 round microbenchmark
//! within 2× of inline Rust"), this bench validates VM dispatch
//! overhead is acceptable. It measures three costs:
//!
//! 1. Pure decode — bytes → `Program` (no execution).
//! 2. Decode + execute — bytes → `Program` → `StubSink` stream.
//! 3. Inline Rust — the "ideal" baseline: build the equivalent
//!    `InstructionKind` sequence directly in a `Vec` with no
//!    dispatch overhead at all.
//!
//! Run with `cargo bench -p lysis`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use lysis::{
    bytecode::validate, decode, encode, execute, InstructionKind, InterningSink, LysisConfig,
    NodeId, ProgramBuilder, StubSink, Visibility,
};
use memory::field::{Bn254Fr, FieldElement};
use memory::FieldFamily;

fn fe(x: u64) -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([x, 0, 0, 0])
}

fn build_sha256_round() -> lysis::Program<Bn254Fr> {
    let mut b = ProgramBuilder::<Bn254Fr>::new(FieldFamily::BnLike256);
    let k_t = b.intern_field(fe(0x428a_2f98));
    for name in ["a", "b", "c", "d", "e", "f", "g", "h", "w"] {
        b.intern_string(name);
    }
    b.load_input(0, 1, Visibility::Public)
        .load_input(1, 2, Visibility::Public)
        .load_input(2, 3, Visibility::Public)
        .load_input(3, 4, Visibility::Public)
        .load_input(4, 5, Visibility::Public)
        .load_input(5, 6, Visibility::Public)
        .load_input(6, 7, Visibility::Public)
        .load_input(7, 8, Visibility::Public)
        .load_input(8, 9, Visibility::Witness)
        .load_const(9, k_t as u16)
        .emit_add(10, 7, 9)
        .emit_add(11, 10, 8)
        .emit_add(12, 11, 4)
        .emit_add(13, 12, 0)
        .halt();
    b.finish()
}

/// Baseline: emit the same InstructionKind stream directly, with no
/// bytecode, no decode, no dispatch.
fn inline_rust_emit() -> Vec<InstructionKind<Bn254Fr>> {
    let mut out = Vec::with_capacity(14);
    let mk = |i: usize| NodeId::from_zero_based(i);
    // 9 Inputs.
    for (i, name) in ["a", "b", "c", "d", "e", "f", "g", "h", "w"]
        .iter()
        .enumerate()
    {
        let vis = if *name == "w" {
            Visibility::Witness
        } else {
            Visibility::Public
        };
        out.push(InstructionKind::Input {
            result: mk(i),
            name: (*name).into(),
            visibility: vis,
        });
    }
    // 1 Const (K_t).
    out.push(InstructionKind::Const {
        result: mk(9),
        value: fe(0x428a_2f98),
    });
    // 4 Adds.
    out.push(InstructionKind::Add {
        result: mk(10),
        lhs: mk(7),
        rhs: mk(9),
    });
    out.push(InstructionKind::Add {
        result: mk(11),
        lhs: mk(10),
        rhs: mk(8),
    });
    out.push(InstructionKind::Add {
        result: mk(12),
        lhs: mk(11),
        rhs: mk(4),
    });
    out.push(InstructionKind::Add {
        result: mk(13),
        lhs: mk(12),
        rhs: mk(0),
    });
    out
}

fn bench(c: &mut Criterion) {
    let program = build_sha256_round();
    let bytes = encode(&program);
    let cfg = LysisConfig::default();

    c.bench_function("lysis_decode", |b| {
        b.iter(|| {
            let _ = decode::<Bn254Fr>(black_box(&bytes));
        });
    });

    c.bench_function("lysis_decode_validate", |b| {
        b.iter(|| {
            let p = decode::<Bn254Fr>(black_box(&bytes)).unwrap();
            let _ = validate(&p, &cfg);
        });
    });

    c.bench_function("lysis_decode_validate_execute", |b| {
        b.iter(|| {
            let p = decode::<Bn254Fr>(black_box(&bytes)).unwrap();
            validate(&p, &cfg).unwrap();
            let mut sink = StubSink::<Bn254Fr>::new();
            execute(&p, &[], &cfg, &mut sink).unwrap();
            black_box(sink.into_instructions());
        });
    });

    c.bench_function("lysis_execute_only_cached_program", |b| {
        // Decode + validate once; bench the execute pass in isolation.
        let p = decode::<Bn254Fr>(&bytes).unwrap();
        validate(&p, &cfg).unwrap();
        b.iter(|| {
            let mut sink = StubSink::<Bn254Fr>::new();
            execute(&p, &[], &cfg, &mut sink).unwrap();
            black_box(sink.into_instructions());
        });
    });

    // Same hot path, but with the hash-consing sink. On a single
    // SHA-256 round there's no structural duplication to collapse,
    // so the curve measures pure interning overhead — useful to
    // track how much the IndexMap lookup costs on a worst-case
    // (all-unique) workload.
    c.bench_function("lysis_execute_only_interning_sink", |b| {
        let p = decode::<Bn254Fr>(&bytes).unwrap();
        validate(&p, &cfg).unwrap();
        b.iter(|| {
            let mut sink = InterningSink::<Bn254Fr>::new();
            execute(&p, &[], &cfg, &mut sink).unwrap();
            black_box(sink.materialize());
        });
    });

    c.bench_function("inline_rust_baseline", |b| {
        b.iter(|| {
            black_box(inline_rust_emit());
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
