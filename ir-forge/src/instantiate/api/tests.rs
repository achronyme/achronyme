use std::collections::HashMap;

use ir_core::{Instruction, SsaVar, Visibility};
use memory::Bn254Fr;

use crate::extended::ExtendedInstruction;
use crate::extended_program::ExtendedIrProgram;
use crate::test_utils::compile_circuit;

use super::direct_plain::drain_plain_extended_chunks_interned;
use super::drain::lower_extended_with_chunk_drain;
use super::trace::positive_usize_or_default;

type F = Bn254Fr;

#[test]
fn positive_usize_or_default_rejects_missing_zero_and_invalid_values() {
    assert_eq!(positive_usize_or_default(None, 17), 17);
    assert_eq!(positive_usize_or_default(Some("0"), 17), 17);
    assert_eq!(positive_usize_or_default(Some("nope"), 17), 17);
    assert_eq!(positive_usize_or_default(Some("42"), 17), 42);
}

#[test]
fn direct_plain_drain_chunks_plain_body_without_walker() {
    let body = vec![
        ExtendedInstruction::Plain(Instruction::Const {
            result: SsaVar(0),
            value: memory::FieldElement::<F>::from_u64(1),
        }),
        ExtendedInstruction::Plain(Instruction::Add {
            result: SsaVar(1),
            lhs: SsaVar(0),
            rhs: SsaVar(0),
        }),
        ExtendedInstruction::Plain(Instruction::Mul {
            result: SsaVar(2),
            lhs: SsaVar(1),
            rhs: SsaVar(0),
        }),
    ];
    let mut chunks = Vec::new();
    let total = drain_plain_extended_chunks_interned(body, 8, 2, &mut |chunk| chunks.push(chunk))
        .expect("all-plain body drains without error");

    assert_eq!(total, 3);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len(), 2);
    assert_eq!(chunks[1].len(), 1);
    assert!(matches!(chunks[0][0], lysis::InstructionKind::Const { .. }));
    assert!(matches!(chunks[0][1], lysis::InstructionKind::Add { .. }));
    assert!(matches!(chunks[1][0], lysis::InstructionKind::Mul { .. }));
}

#[test]
fn direct_plain_drain_matches_walker_on_desugared_forms() {
    // Contract pin for the shared interning core: the direct chunk-
    // drain path (driving `DirectInternState::feed_plain`) and the
    // Walker → bytecode → executor cable must materialize the
    // byte-identical instruction stream. This exercises the desugar
    // arms (`Not`/`And`/`Or`/`IsNeq`/`IsLe`/`IsLeBounded`/`Assert`),
    // the u8 bit-width guards, and the non-binding effect arms
    // (`AssertEq`/`RangeCheck`/`Decompose`) — none of which the
    // lean/streaming pins cover.
    fn sugar_body() -> Vec<ExtendedInstruction<F>> {
        vec![
            ExtendedInstruction::Plain(Instruction::Input {
                result: SsaVar(0),
                name: "a".to_string(),
                visibility: Visibility::Witness,
            }),
            ExtendedInstruction::Plain(Instruction::Input {
                result: SsaVar(1),
                name: "b".to_string(),
                visibility: Visibility::Witness,
            }),
            ExtendedInstruction::Plain(Instruction::And {
                result: SsaVar(2),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            }),
            ExtendedInstruction::Plain(Instruction::Or {
                result: SsaVar(3),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            }),
            ExtendedInstruction::Plain(Instruction::Not {
                result: SsaVar(4),
                operand: SsaVar(0),
            }),
            ExtendedInstruction::Plain(Instruction::IsNeq {
                result: SsaVar(5),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            }),
            ExtendedInstruction::Plain(Instruction::IsLe {
                result: SsaVar(6),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
            }),
            ExtendedInstruction::Plain(Instruction::IsLeBounded {
                result: SsaVar(7),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
                bitwidth: 16,
            }),
            ExtendedInstruction::Plain(Instruction::RangeCheck {
                result: SsaVar(8),
                operand: SsaVar(0),
                bits: 16,
            }),
            ExtendedInstruction::Plain(Instruction::Decompose {
                result: SsaVar(9),
                bit_results: vec![SsaVar(10), SsaVar(11), SsaVar(12), SsaVar(13)],
                operand: SsaVar(0),
                num_bits: 4,
            }),
            ExtendedInstruction::Plain(Instruction::Assert {
                result: SsaVar(14),
                operand: SsaVar(2),
                message: None,
            }),
            ExtendedInstruction::Plain(Instruction::AssertEq {
                result: SsaVar(15),
                lhs: SsaVar(0),
                rhs: SsaVar(1),
                message: None,
            }),
        ]
    }

    // Same window/capacity the drain entry defaults to, so chunk
    // boundaries line up; we compare the flattened streams anyway.
    let window = 131_072;
    let chunk_capacity = 1_000_000;

    // Subject: the direct interning drain path (always direct,
    // independent of the `ACH_LYSIS_DIRECT_PLAIN_DRAIN` toggle).
    let mut direct_stream: Vec<lysis::InstructionKind<F>> = Vec::new();
    drain_plain_extended_chunks_interned(sugar_body(), window, chunk_capacity, &mut |chunk| {
        direct_stream.extend(chunk)
    })
    .expect("direct drain succeeds");

    // Reference: the same body routed through the Walker cable. With
    // the toggle unset (the default; no test sets it) the chunk-drain
    // entry falls through to `Walker → execute`.
    let mut prog = ExtendedIrProgram::<F>::new();
    prog.body = sugar_body();
    prog.next_var = 16;
    let mut walker_stream: Vec<lysis::InstructionKind<F>> = Vec::new();
    lower_extended_with_chunk_drain(prog, &mut |chunk| walker_stream.extend(chunk))
        .expect("walker drain succeeds");

    assert_eq!(
        direct_stream.len(),
        walker_stream.len(),
        "direct drain and walker emit the same number of instructions"
    );
    for (i, (d, w)) in direct_stream.iter().zip(walker_stream.iter()).enumerate() {
        assert_eq!(
            format!("{d:?}"),
            format!("{w:?}"),
            "instruction {i} diverges between direct drain and walker"
        );
    }
}

#[test]
fn extended_emits_loop_unroll_for_for_loops() {
    // Loops emit a single LoopUnroll node containing the body,
    // instead of N inlined copies — the extended program is not
    // fully Plain.
    //
    // The body must NOT carry a mut accumulator, because
    // carry-set loops eager-unroll at lower time and never
    // produce a `CircuitNode::For` for the extended sink to lift.
    // A body that just emits one assertion per iteration over a
    // witness array is the canonical no-carry shape that still
    // exercises the symbolic LoopUnroll path.
    let source = "public out\nwitness arr[4]\nfor i in 0..4 { assert_eq(arr[i], arr[i]) }\nassert(out == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let extended = prove_ir
        .instantiate_extended::<F>(&HashMap::new())
        .expect("instantiate_extended");
    assert!(
        !extended.is_fully_plain(),
        "post-2.5 the body must contain at least one LoopUnroll"
    );
    let loop_unroll_count = extended
        .body
        .iter()
        .filter(|i| matches!(i, ExtendedInstruction::LoopUnroll { .. }))
        .count();
    assert_eq!(
        loop_unroll_count, 1,
        "exactly one LoopUnroll for one for-loop"
    );
}

#[test]
fn metadata_propagates_through_extended_sink() {
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let extended = prove_ir
        .instantiate_extended::<F>(&HashMap::new())
        .expect("instantiate_extended");
    // Inputs should appear in var_names and var_types.
    assert!(
        !extended.var_names.is_empty(),
        "var_names should track inputs"
    );
    assert!(
        !extended.var_types.is_empty(),
        "var_types should track Inputs/RangeChecks"
    );
}

#[test]
fn lean_instantiate_extended_skips_name_and_span_maps() {
    // Contract pin: the lean variant emits the same body as the
    // non-lean entry point but skips populating the three write-
    // only metadata channels at the sink boundary. `var_types`
    // also stays empty in the returned program; the lean sink uses
    // a transient dense table for type propagation during the walk.
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let lean = prove_ir
        .instantiate_extended_lean::<F>(&HashMap::new())
        .expect("instantiate_extended_lean");
    assert!(lean.var_names.is_empty(), "lean must skip var_names");
    assert!(lean.var_spans.is_empty(), "lean must skip var_spans");
    assert!(lean.input_spans.is_empty(), "lean must skip input_spans");
    assert!(lean.var_types.is_empty(), "lean must skip var_types");

    // Same body shape as the non-lean entry point.
    let full = prove_ir
        .instantiate_extended::<F>(&HashMap::new())
        .expect("instantiate_extended");
    assert_eq!(
        lean.body.len(),
        full.body.len(),
        "lean and full variants emit the same body"
    );
    assert_eq!(lean.next_var, full.next_var, "next_var watermark matches");
}

#[test]
fn lean_instantiate_with_outputs_extended_skips_name_and_span_maps() {
    // Sibling pin for the public-output variant — the two share
    // dispatch through the lean sink constructor but pinning both
    // heads keeps the contract enforced if they ever diverge.
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let outputs: std::collections::HashSet<String> = std::iter::once("out".to_string()).collect();
    let lean = prove_ir
        .instantiate_with_outputs_extended_lean::<F>(&HashMap::new(), &outputs)
        .expect("instantiate_with_outputs_extended_lean");
    assert!(lean.var_names.is_empty(), "lean must skip var_names");
    assert!(lean.var_spans.is_empty(), "lean must skip var_spans");
    assert!(lean.input_spans.is_empty(), "lean must skip input_spans");
    assert!(lean.var_types.is_empty(), "lean must skip var_types");
}

#[test]
fn streaming_sink_with_outputs_path_leaves_metadata_empty() {
    // Sibling of `streaming_sink_path_leaves_metadata_empty` for the
    // `_with_outputs` variant. The two share dispatch through
    // `lower_extended_to_sink(_, false)`, but pinning both heads
    // separately keeps the contract enforced if they ever diverge.
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let outputs: std::collections::HashSet<String> = std::iter::once("out".to_string()).collect();
    let bundle = prove_ir
        .instantiate_lysis_sink_with_outputs::<F>(&HashMap::new(), &outputs)
        .expect("instantiate_lysis_sink_with_outputs");
    assert!(bundle.var_names.is_empty(), "var_names must be empty");
    assert!(bundle.var_types.is_empty(), "var_types must be empty");
    assert!(bundle.var_spans.is_empty(), "var_spans must be empty");
    assert!(bundle.input_spans.is_empty(), "input_spans must be empty");
}

#[test]
fn chunk_drain_path_delivers_full_emission_stream() {
    // Contract pin: the chunk-draining entry point
    // (`instantiate_lysis_drain_with_outputs`) delivers exactly
    // the same emission stream that the streaming sink path
    // would produce, just routed through the consumer closure
    // instead of accumulating in `streaming_chunks`. On a tiny
    // circuit the stream is a single partial chunk, drained at
    // `sink.finalize()` time.
    use std::cell::RefCell;
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let outputs: std::collections::HashSet<String> = std::iter::once("out".to_string()).collect();

    // Reference: collect the emission stream via the streaming
    // sink path.
    let reference_bundle = prove_ir
        .instantiate_lysis_sink_with_outputs::<F>(&HashMap::new(), &outputs)
        .expect("reference instantiate_lysis_sink_with_outputs");
    let reference_stream: Vec<_> = reference_bundle.sink.into_chunked_iter().collect();

    // Subject: collect the emission stream via the chunk-drain
    // entry point's consumer closure.
    let received: RefCell<Vec<lysis::InstructionKind<F>>> = RefCell::new(Vec::new());
    let mut consumer = |chunk: Vec<lysis::InstructionKind<F>>| {
        received.borrow_mut().extend(chunk);
    };
    let mut drain_bundle = prove_ir
        .instantiate_lysis_drain_with_outputs::<F>(&HashMap::new(), &outputs, &mut consumer)
        .expect("instantiate_lysis_drain_with_outputs");

    // The drain bundle's residual sink carries the dedup state
    // but the emission buffer is empty.
    assert!(
        drain_bundle.residual_sink.take_sealed_chunks().is_empty(),
        "drain residual sink should have no sealed chunks left"
    );
    assert!(
        drain_bundle.residual_sink.drain_all_chunks().is_empty(),
        "drain residual sink should have no partial chunk left either"
    );

    let drained = received.into_inner();
    assert_eq!(
        drained.len(),
        reference_stream.len(),
        "drain path must deliver the same number of instructions"
    );
    for (i, (d, r)) in drained.iter().zip(reference_stream.iter()).enumerate() {
        assert_eq!(
            format!("{d:?}"),
            format!("{r:?}"),
            "instruction {i} diverges between drain and streaming-sink paths"
        );
    }
}

#[test]
fn streaming_sink_path_leaves_metadata_empty() {
    // Contract pin: the streaming entry points
    // (`instantiate_lysis_sink`, `instantiate_lysis_sink_with_outputs`)
    // drop the four metadata maps before the Walker runs. The bundle's
    // metadata fields are exposed for type-shape compatibility with the
    // reassembly bundle and must be empty on this path — restoring them
    // would coexist with the executor working set on multi-million-
    // variable circuits and reintroduce the pre-execute peak.
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    // Same fixture as the sibling test: confirm the maps would have been
    // populated on the reassembly path before checking the streaming path
    // empties them.
    let extended = prove_ir
        .instantiate_extended::<F>(&HashMap::new())
        .expect("instantiate_extended");
    assert!(
        !extended.var_names.is_empty(),
        "fixture precondition: extended.var_names must be populated"
    );
    let bundle = prove_ir
        .instantiate_lysis_sink::<F>(&HashMap::new())
        .expect("instantiate_lysis_sink");
    assert!(
        bundle.var_names.is_empty(),
        "streaming sink path must leave var_names empty"
    );
    assert!(
        bundle.var_types.is_empty(),
        "streaming sink path must leave var_types empty"
    );
    assert!(
        bundle.var_spans.is_empty(),
        "streaming sink path must leave var_spans empty"
    );
    assert!(
        bundle.input_spans.is_empty(),
        "streaming sink path must leave input_spans empty"
    );
}

#[test]
fn lean_lysis_materialize_matches_full_instruction_stream() {
    // Contract pin for the lean materializing entry points: identical
    // instruction stream and watermark, empty metadata maps. Prove-bound
    // callers rely on the stream identity for bit-identical constraint
    // output across the lean and full instantiates.
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");

    let full = prove_ir
        .instantiate_lysis::<F>(&HashMap::new())
        .expect("instantiate_lysis");
    let lean = prove_ir
        .instantiate_lysis_lean::<F>(&HashMap::new())
        .expect("instantiate_lysis_lean");

    assert_eq!(lean.instructions.len(), full.instructions.len());
    for (l, f) in lean.instructions.iter().zip(full.instructions.iter()) {
        assert_eq!(format!("{l:?}"), format!("{f:?}"));
    }
    assert_eq!(lean.next_var, full.next_var);
    assert!(lean.var_names.is_empty(), "lean must skip var_names");
    assert!(lean.var_types.is_empty(), "lean must skip var_types");
    assert!(lean.var_spans.is_empty(), "lean must skip var_spans");
    assert!(lean.input_spans.is_empty(), "lean must skip input_spans");
}

#[test]
fn lean_lysis_materialize_with_outputs_matches_full_instruction_stream() {
    // Sibling pin for the public-output variant.
    let source = "public out\nwitness x\nlet s = x + x;\nassert(s == out)";
    let prove_ir = compile_circuit(source).expect("compile_circuit");
    let outputs: std::collections::HashSet<String> = std::iter::once("out".to_string()).collect();

    let full = prove_ir
        .instantiate_lysis_with_outputs::<F>(&HashMap::new(), &outputs)
        .expect("instantiate_lysis_with_outputs");
    let lean = prove_ir
        .instantiate_lysis_lean_with_outputs::<F>(&HashMap::new(), &outputs)
        .expect("instantiate_lysis_lean_with_outputs");

    assert_eq!(lean.instructions.len(), full.instructions.len());
    for (l, f) in lean.instructions.iter().zip(full.instructions.iter()) {
        assert_eq!(format!("{l:?}"), format!("{f:?}"));
    }
    assert_eq!(lean.next_var, full.next_var);
    assert!(lean.var_names.is_empty(), "lean must skip var_names");
    assert!(lean.var_types.is_empty(), "lean must skip var_types");
    assert!(lean.var_spans.is_empty(), "lean must skip var_spans");
    assert!(lean.input_spans.is_empty(), "lean must skip input_spans");
}
