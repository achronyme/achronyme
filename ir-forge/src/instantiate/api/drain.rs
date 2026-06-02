use std::time::Instant;

use lysis::{
    execute, expected_family, ChunkDrainingSink, InstructionKind, InterningSink, LysisConfig,
};
use memory::FieldBackend;

use crate::extended::ExtendedInstruction;
use crate::extended_program::ExtendedIrProgram;
use crate::lysis_lift::Walker;
use crate::lysis_roundtrip::RoundTripError;

use super::bundles::LysisDrainBundle;
use super::direct_plain::{
    direct_plain_drain_enabled, direct_plain_validate_enabled,
    drain_plain_extended_chunks_interned, trace_first_plain_forward_ref,
};
use super::errors::LysisInstantiateError;
use super::profile::trace_lysis_program_profile;
use super::trace::{
    lysis_drain_trace, lysis_drain_trace_enabled, lysis_malloc_trim_enabled,
    positive_usize_or_default, trim_process_allocator,
};

/// Chunk-draining variant of [`lower_extended_to_sink`]. Walks
/// `extended` through Walker → optional encode/decode → executor,
/// using a [`ChunkDrainingSink`] backed by a chunked streaming
/// interner so each filled chunk is handed to `chunk_consumer` at
/// seal time. The metadata maps are dropped unconditionally on entry
/// (same rationale as the streaming sink path — the chunk consumer
/// does not consume semantic metadata).
///
/// The window/chunking selection bypasses the `LYSIS_STREAMING_WINDOW`
/// and `LYSIS_CHUNKED_OUTPUT` environment toggles: the drain path is
/// only meaningful under chunked streaming, so it always uses
/// chunked mode with the default window of 131072 (the same value
/// every chunked-streaming caller has picked in practice).
///
/// The wire-format encode/decode round-trip is **skipped** on this
/// path. The walker's `Program<F>` is consumed directly by `execute`,
/// and the encode/decode is structurally an identity (same `Program<F>`
/// in, same `Program<F>` out). On large fixtures the round-trip's
/// encoded `Vec<u8>` and decoded `Program<F>` coexist with the walker
/// output until execute begins, contributing ~1 GB of duplicated state
/// on ECDSAVerify-scale circuits. The schema-drift gate that the
/// round-trip used to provide is preserved by running
/// `lysis::bytecode::validate` directly on the walker output under
/// `cfg!(debug_assertions)`.
pub(crate) fn lower_extended_with_chunk_drain<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
    chunk_consumer: &mut dyn FnMut(Vec<InstructionKind<F>>),
) -> Result<LysisDrainBundle<F>, LysisInstantiateError> {
    let ExtendedIrProgram {
        body,
        next_var,
        var_names,
        var_types,
        var_spans,
        input_spans,
    } = extended;
    let trace = lysis_drain_trace_enabled();
    if trace {
        lysis_drain_trace(
            "before_lower",
            &format!(
                "extended_body_len={} extended_body_cap={} extended_inst_size={}",
                body.len(),
                body.capacity(),
                std::mem::size_of::<ExtendedInstruction<F>>()
            ),
        );
    }
    drop(var_names);
    drop(var_types);
    drop(var_spans);
    drop(input_spans);

    let window = positive_usize_or_default(
        std::env::var("LYSIS_STREAMING_WINDOW").ok().as_deref(),
        131_072,
    );
    let chunk_capacity = positive_usize_or_default(
        std::env::var("LYSIS_STREAMING_CHUNK_CAPACITY")
            .ok()
            .as_deref(),
        1_000_000,
    );
    if direct_plain_drain_enabled() {
        if body
            .iter()
            .all(|inst| matches!(inst, ExtendedInstruction::Plain(_)))
        {
            if direct_plain_validate_enabled() {
                trace_first_plain_forward_ref(&body);
            }
            let total_plain =
                drain_plain_extended_chunks_interned(body, window, chunk_capacity, chunk_consumer);
            if trace {
                lysis_drain_trace(
                    "direct_plain_drain",
                    &format!("total_plain={total_plain} chunk_capacity={chunk_capacity}"),
                );
            }
            return Ok(LysisDrainBundle {
                residual_sink: InterningSink::with_streaming_window_chunked_capacity(
                    window,
                    chunk_capacity,
                ),
                next_var,
            });
        } else if trace {
            lysis_drain_trace(
                "direct_plain_drain_fallback",
                "extended body contains non-plain instructions",
            );
        }
    }

    let walker = Walker::<F>::new(expected_family::<F>());
    let lower_start = trace.then(Instant::now);
    let decoded = walker.lower(body).map_err(RoundTripError::Walk)?;
    if trace {
        let elapsed_ms = lower_start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or_default();
        lysis_drain_trace(
            "after_lower",
            &format!(
                "elapsed_ms={elapsed_ms:.3} decoded_body_len={} decoded_body_cap={} instr_size={} templates_len={} templates_cap={} const_pool_len={} heap_size_hint={}",
                decoded.body.len(),
                decoded.body.capacity(),
                std::mem::size_of::<lysis::program::Instr>(),
                decoded.templates.len(),
                decoded.templates.capacity(),
                decoded.const_pool.len(),
                decoded.header.heap_size_hint,
            ),
        );
    }
    if std::env::var("ACH_LYSIS_PROFILE").as_deref() == Ok("1") {
        trace_lysis_program_profile(&decoded);
    }
    if lysis_malloc_trim_enabled() {
        let trimmed = trim_process_allocator();
        if trace {
            lysis_drain_trace("after_malloc_trim", &format!("trimmed={trimmed}"));
        }
    }
    if cfg!(debug_assertions) {
        lysis::bytecode::validate(&decoded, &LysisConfig::default())
            .map_err(RoundTripError::Lysis)?;
    }

    if trace {
        lysis_drain_trace(
            "before_execute",
            &format!("window={window} chunk_capacity={chunk_capacity}"),
        );
    }
    let mut sink = ChunkDrainingSink::<F>::with_streaming_window_chunked_capacity(
        window,
        chunk_capacity,
        chunk_consumer,
    );
    let execute_start = trace.then(Instant::now);
    execute(
        &decoded,
        &[],
        &LysisConfig::for_internal_replay(),
        &mut sink,
    )
    .map_err(RoundTripError::Lysis)?;
    if trace {
        let elapsed_ms = execute_start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or_default();
        lysis_drain_trace(
            "after_execute",
            &format!(
                "elapsed_ms={elapsed_ms:.3} pure_len={} effect_len={}",
                sink.inner().pure_len(),
                sink.inner().effect_len()
            ),
        );
    }
    let finalize_start = trace.then(Instant::now);
    let residual_sink = sink.finalize();
    if trace {
        let elapsed_ms = finalize_start
            .map(|start| start.elapsed().as_secs_f64() * 1000.0)
            .unwrap_or_default();
        lysis_drain_trace(
            "after_finalize",
            &format!(
                "elapsed_ms={elapsed_ms:.3} pure_len={} effect_len={}",
                residual_sink.pure_len(),
                residual_sink.effect_len()
            ),
        );
    }

    Ok(LysisDrainBundle {
        residual_sink,
        next_var,
    })
}
