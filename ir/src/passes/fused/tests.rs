//! Differential parity: the fused pipeline must equal materialize →
//! `optimize()` byte-for-byte (instruction stream, `next_var`, every
//! stats field) on the same interner contents.

use std::collections::HashMap;

use lysis::execute::IrSink;
use lysis::intern::{InstructionKind, NodeId, Visibility, WitnessCallBody};
use lysis::InterningSink;
use memory::field::Bn254Fr;
use memory::FieldElement;

use ir_forge::instantiate::LysisSinkBundle;
use ir_forge::lysis_materialize::materialize_interning_sink;

use crate::passes::optimize;
use crate::types::IrProgram;

use super::optimize_lean_sink;

type F = Bn254Fr;
type Fe = FieldElement<F>;

fn fe(n: u64) -> Fe {
    Fe::from_u64(n)
}

fn bundle(sink: InterningSink<F>) -> LysisSinkBundle<F> {
    LysisSinkBundle {
        sink,
        next_var: 0,
        var_names: HashMap::new(),
        var_types: HashMap::new(),
        var_spans: HashMap::new(),
        input_spans: HashMap::new(),
    }
}

/// Reference pipeline on the same sink contents: materialize, apply
/// the reassembly watermark formula, run `optimize()`.
fn reference(sink: InterningSink<F>) -> (IrProgram<F>, crate::passes::OptimizeStats) {
    let instructions = materialize_interning_sink(sink);
    let mut watermark: u64 = 0;
    for inst in &instructions {
        watermark = watermark.max(inst.result_var().0 + 1);
        for extra in inst.extra_result_vars() {
            watermark = watermark.max(extra.0 + 1);
        }
    }
    let mut program = IrProgram::<F>::new();
    program.set_instructions(instructions);
    program.set_next_var(watermark);
    let stats = optimize(&mut program);
    (program, stats)
}

/// Feed both pipelines the same stream and require equality on every
/// observable: per-instruction Debug, `next_var`, stats fields.
fn assert_parity(
    feed: impl Fn(&mut InterningSink<F>),
    expect_fallback: bool,
) -> crate::passes::OptimizeStats {
    let mut sink = InterningSink::<F>::without_span_tracking();
    feed(&mut sink);
    let (ref_program, ref_stats) = reference(sink.clone());

    let outcome = optimize_lean_sink(bundle(sink));
    assert_eq!(
        outcome.used_fallback, expect_fallback,
        "fallback discriminator"
    );
    assert_eq!(
        outcome.program.instructions.len(),
        ref_program.instructions.len(),
        "instruction count"
    );
    for (i, (fused, reference)) in outcome
        .program
        .instructions
        .iter()
        .zip(ref_program.instructions.iter())
        .enumerate()
    {
        assert_eq!(
            format!("{fused:?}"),
            format!("{reference:?}"),
            "instruction {i} diverged"
        );
    }
    assert_eq!(outcome.program.next_var, ref_program.next_var, "next_var");

    let s = &outcome.stats;
    assert_eq!(s.total_before, ref_stats.total_before, "total_before");
    assert_eq!(s.total_after, ref_stats.total_after, "total_after");
    assert_eq!(
        s.const_fold_converted, ref_stats.const_fold_converted,
        "const_fold_converted"
    );
    assert_eq!(s.cse_eliminated, ref_stats.cse_eliminated, "cse_eliminated");
    assert_eq!(s.dce_eliminated, ref_stats.dce_eliminated, "dce_eliminated");
    assert_eq!(
        s.tautological_asserts_eliminated, ref_stats.tautological_asserts_eliminated,
        "taut"
    );
    assert_eq!(
        s.bound_inference.rewritten, ref_stats.bound_inference.rewritten,
        "bi rewritten"
    );
    assert_eq!(
        s.bound_inference.unbounded, ref_stats.bound_inference.unbounded,
        "bi unbounded"
    );
    assert_eq!(
        s.bit_pattern_bounds, ref_stats.bit_pattern_bounds,
        "bp bounds"
    );
    assert_eq!(
        s.bit_pattern_booleans, ref_stats.bit_pattern_booleans,
        "bp booleans"
    );
    outcome.stats
}

fn input(sink: &mut InterningSink<F>, name: &str) -> NodeId {
    let id = sink.fresh_id();
    sink.emit_effect(InstructionKind::Input {
        result: id,
        name: name.into(),
        visibility: Visibility::Witness,
    });
    id
}

fn konst(sink: &mut InterningSink<F>, n: u64) -> NodeId {
    sink.intern_pure(InstructionKind::Const {
        result: NodeId::PLACEHOLDER,
        value: fe(n),
    })
}

fn assert_eq_effect(sink: &mut InterningSink<F>, lhs: NodeId, rhs: NodeId) {
    let r = sink.fresh_id();
    sink.emit_effect(InstructionKind::AssertEq {
        result: r,
        lhs,
        rhs,
        message: None,
    });
}

#[test]
fn fold_chain_with_dce_parity() {
    // Const ops fold; the orphaned chain dies; the assert anchors the
    // live slice. Also exercises x*0, x+0 and Sub(x, x) arms.
    let stats = assert_parity(
        |sink| {
            let x = input(sink, "x");
            let c2 = konst(sink, 2);
            let c3 = konst(sink, 3);
            let sum = sink.intern_pure(InstructionKind::Add {
                result: NodeId::PLACEHOLDER,
                lhs: c2,
                rhs: c3,
            }); // folds to 5
            let zero = sink.intern_pure(InstructionKind::Sub {
                result: NodeId::PLACEHOLDER,
                lhs: x,
                rhs: x,
            }); // folds to 0 regardless of x
            let dead = sink.intern_pure(InstructionKind::Mul {
                result: NodeId::PLACEHOLDER,
                lhs: sum,
                rhs: zero,
            }); // folds to 0, then dies unused
            let _ = dead;
            let live = sink.intern_pure(InstructionKind::Mul {
                result: NodeId::PLACEHOLDER,
                lhs: x,
                rhs: sum,
            });
            assert_eq_effect(sink, live, x);
        },
        false,
    );
    assert!(stats.const_fold_converted >= 3);
    assert!(stats.dce_eliminated >= 1);
}

#[test]
fn tautological_assert_chain_dies_parity() {
    // Mirror of dce's chain_feeding_only_tautological_assert_is_removed.
    assert_parity(
        |sink| {
            let x = input(sink, "x");
            let a = sink.intern_pure(InstructionKind::Neg {
                result: NodeId::PLACEHOLDER,
                operand: x,
            });
            let b = sink.intern_pure(InstructionKind::Mul {
                result: NodeId::PLACEHOLDER,
                lhs: a,
                rhs: a,
            });
            assert_eq_effect(sink, b, b);
        },
        false,
    );
}

#[test]
fn rangecheck_bound_rewrite_parity() {
    // RangeCheck(64) on both operands proves the comparison bounded:
    // IsLt -> IsLtBounded { bitwidth: 64 }; one unbounded IsLe stays.
    let stats = assert_parity(
        |sink| {
            let a = input(sink, "a");
            let b = input(sink, "b");
            let c = input(sink, "c");
            let r1 = sink.fresh_id();
            sink.emit_effect(InstructionKind::RangeCheck {
                result: r1,
                operand: a,
                bits: 64,
            });
            let r2 = sink.fresh_id();
            sink.emit_effect(InstructionKind::RangeCheck {
                result: r2,
                operand: b,
                bits: 64,
            });
            let lt = sink.intern_pure(InstructionKind::IsLt {
                result: NodeId::PLACEHOLDER,
                lhs: a,
                rhs: b,
            });
            let le = sink.intern_pure(InstructionKind::IsLe {
                result: NodeId::PLACEHOLDER,
                lhs: a,
                rhs: c,
            });
            let both = sink.intern_pure(InstructionKind::And {
                result: NodeId::PLACEHOLDER,
                lhs: lt,
                rhs: le,
            });
            let one = konst(sink, 1);
            assert_eq_effect(sink, both, one);
        },
        false,
    );
    assert_eq!(stats.bound_inference.rewritten, 1);
    assert_eq!(stats.bound_inference.unbounded.len(), 1);
}

#[test]
fn num2bits_pattern_bound_parity() {
    // Circom Num2Bits(2) shape: boolean enforcement per bit plus the
    // weighted sum — bit_pattern infers a 2-bit bound on `x`, which
    // then bounds IsLt(x, y) together with y's RangeCheck.
    let stats = assert_parity(
        |sink| {
            let x = input(sink, "x");
            let y = input(sink, "y");
            let b0 = input(sink, "b0");
            let b1 = input(sink, "b1");
            let one = konst(sink, 1);
            let zero = konst(sink, 0);
            for bit in [b0, b1] {
                let m1 = sink.intern_pure(InstructionKind::Sub {
                    result: NodeId::PLACEHOLDER,
                    lhs: bit,
                    rhs: one,
                });
                let prod = sink.intern_pure(InstructionKind::Mul {
                    result: NodeId::PLACEHOLDER,
                    lhs: bit,
                    rhs: m1,
                });
                assert_eq_effect(sink, prod, zero);
            }
            let two = konst(sink, 2);
            let term1 = sink.intern_pure(InstructionKind::Mul {
                result: NodeId::PLACEHOLDER,
                lhs: b1,
                rhs: two,
            });
            let sum = sink.intern_pure(InstructionKind::Add {
                result: NodeId::PLACEHOLDER,
                lhs: b0,
                rhs: term1,
            });
            assert_eq_effect(sink, sum, x);
            let ry = sink.fresh_id();
            sink.emit_effect(InstructionKind::RangeCheck {
                result: ry,
                operand: y,
                bits: 8,
            });
            let lt = sink.intern_pure(InstructionKind::IsLt {
                result: NodeId::PLACEHOLDER,
                lhs: x,
                rhs: y,
            });
            assert_eq_effect(sink, lt, one);
        },
        false,
    );
    assert!(stats.bit_pattern_bounds >= 1);
    assert_eq!(stats.bound_inference.rewritten, 1);
}

#[test]
fn decompose_stream_takes_reference_fallback() {
    // Decompose aliases its operand as result (duplicate definition):
    // the fused path must hand the whole stream to the reference.
    assert_parity(
        |sink| {
            let x = input(sink, "x");
            let b0 = sink.fresh_id();
            let b1 = sink.fresh_id();
            sink.emit_effect(InstructionKind::Decompose {
                result: x,
                operand: x,
                num_bits: 2,
                bit_results: vec![b0, b1],
            });
            let s = sink.intern_pure(InstructionKind::Add {
                result: NodeId::PLACEHOLDER,
                lhs: b0,
                rhs: b1,
            });
            assert_eq_effect(sink, s, x);
        },
        true,
    );
}

#[test]
fn bound_rewrite_colliding_with_existing_bounded_takes_fallback() {
    // A pre-existing IsLtBounded{a,b,64} plus an unbounded IsLt(a,b)
    // whose inferred bitwidth is also 64: the reference pipeline
    // rewrites the IsLt and then CSEs the duplicate key — the only
    // post-fold key collision a hash-consed stream can produce. The
    // fused path must hand the whole stream to the reference.
    let stats = assert_parity(
        |sink| {
            let a = input(sink, "a");
            let b = input(sink, "b");
            let r1 = sink.fresh_id();
            sink.emit_effect(InstructionKind::RangeCheck {
                result: r1,
                operand: a,
                bits: 64,
            });
            let r2 = sink.fresh_id();
            sink.emit_effect(InstructionKind::RangeCheck {
                result: r2,
                operand: b,
                bits: 64,
            });
            let pre = sink.intern_pure(InstructionKind::IsLtBounded {
                result: NodeId::PLACEHOLDER,
                lhs: a,
                rhs: b,
                bitwidth: 64,
            });
            let lt = sink.intern_pure(InstructionKind::IsLt {
                result: NodeId::PLACEHOLDER,
                lhs: a,
                rhs: b,
            });
            assert_eq_effect(sink, pre, lt);
        },
        true,
    );
    assert_eq!(stats.cse_eliminated, 1);
}

#[test]
fn witness_call_outputs_kept_parity() {
    // WitnessCall defines multiple outputs; its inputs count as uses.
    assert_parity(
        |sink| {
            let x = input(sink, "x");
            let o0 = sink.fresh_id();
            let o1 = sink.fresh_id();
            sink.emit_effect(InstructionKind::WitnessCall(Box::new(WitnessCallBody {
                outputs: vec![o0, o1],
                inputs: vec![x],
                program_bytes: vec![1, 2, 3],
            })));
            let s = sink.intern_pure(InstructionKind::Add {
                result: NodeId::PLACEHOLDER,
                lhs: o0,
                rhs: o1,
            });
            assert_eq_effect(sink, s, x);
        },
        false,
    );
}

#[test]
fn windowed_sink_takes_reference_fallback() {
    let mut sink = InterningSink::<F>::with_streaming_window(8);
    let x = input(&mut sink, "x");
    let c = konst(&mut sink, 7);
    let s = sink.intern_pure(InstructionKind::Add {
        result: NodeId::PLACEHOLDER,
        lhs: x,
        rhs: c,
    });
    assert_eq_effect(&mut sink, s, x);
    let outcome = optimize_lean_sink(bundle(sink));
    assert!(outcome.used_fallback);
    assert_eq!(outcome.program.instructions.len(), 4);
}
