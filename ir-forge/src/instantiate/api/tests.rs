use std::collections::HashMap;

use ir_core::{Instruction, SsaVar};
use memory::Bn254Fr;

use crate::extended::ExtendedInstruction;
use crate::test_utils::compile_circuit;

use super::direct_plain::drain_plain_extended_chunks_interned;
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
    let total = drain_plain_extended_chunks_interned(body, 8, 2, &mut |chunk| chunks.push(chunk));

    assert_eq!(total, 3);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].len(), 2);
    assert_eq!(chunks[1].len(), 1);
    assert!(matches!(chunks[0][0], lysis::InstructionKind::Const { .. }));
    assert!(matches!(chunks[0][1], lysis::InstructionKind::Add { .. }));
    assert!(matches!(chunks[1][0], lysis::InstructionKind::Mul { .. }));
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
