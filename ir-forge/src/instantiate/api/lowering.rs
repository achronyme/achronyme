use std::collections::HashMap;

use lysis::{execute, expected_family, InterningSink, LysisConfig};
use memory::FieldBackend;

use ir_core::IrProgram;

use crate::extended_program::ExtendedIrProgram;
use crate::lysis_lift::Walker;
use crate::lysis_materialize::materialize_interning_sink;
use crate::lysis_roundtrip::RoundTripError;

use super::bundles::LysisSinkBundle;
use super::errors::LysisInstantiateError;

/// Drive a populated [`ExtendedIrProgram<F>`] through Walker →
/// encode → decode → executor and return the still-populated
/// [`InterningSink<F>`] together with (optionally) the metadata maps.
/// The `IrProgram` reassembly path ([`lower_extended_through_lysis`])
/// is one consumer; a streaming-to-backend path that never
/// materializes `Vec<Instruction<F>>` is the other.
///
/// `keep_metadata` controls the fate of the four metadata maps that
/// arrived inside `extended`. The reassembly path passes `true` —
/// those maps then ride alongside the sink into the reassembled
/// `IrProgram`. The streaming path passes `false` — the maps drop
/// immediately on entry, before the Walker runs, so the
/// multi-hundred-megabyte hash tables they hold do not coexist with
/// the bytecode + sink + executor working set during the dominant
/// pre-execute window. The returned bundle still carries empty
/// `HashMap`s in the dropped slots so the field shape is stable for
/// callers that hold the bundle by value.
pub(crate) fn lower_extended_to_sink<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
    keep_metadata: bool,
) -> Result<LysisSinkBundle<F>, LysisInstantiateError> {
    let ExtendedIrProgram {
        body,
        next_var,
        var_names,
        var_types,
        var_spans,
        input_spans,
    } = extended;
    let (var_names, var_types, var_spans, input_spans) = if keep_metadata {
        (var_names, var_types, var_spans, input_spans)
    } else {
        drop(var_names);
        drop(var_types);
        drop(var_spans);
        drop(input_spans);
        (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        )
    };
    let walker = Walker::<F>::new(expected_family::<F>());
    let bytecode = walker.lower(body).map_err(RoundTripError::Walk)?;

    // `LYSIS_SKIP_ROUNDTRIP=1` opts out of the wire-format encode →
    // decode round-trip on the trusted internal-replay path. The
    // round-trip is a serialization-correctness probe (validator is
    // already `cfg!(debug_assertions)`-gated; encode/decode is not),
    // structurally an identity on the walker's `Program<F>` output.
    // Skipping it releases the encoded `Vec<u8>` and the re-parsed
    // `Program<F>` — both alive alongside the walker output until
    // execute begins.
    let skip_roundtrip = std::env::var("LYSIS_SKIP_ROUNDTRIP").as_deref() == Ok("1");
    let decoded = if skip_roundtrip {
        bytecode
    } else {
        let bytes = lysis::encode(&bytecode);
        let decoded = lysis::decode::<F>(&bytes).map_err(RoundTripError::Lysis)?;
        if cfg!(debug_assertions) {
            lysis::bytecode::validate(&decoded, &LysisConfig::default())
                .map_err(RoundTripError::Lysis)?;
        }
        decoded
    };

    // The materialized stream's only consumer here is
    // `materialize_interning_sink`, which discards the interner's
    // span channels — span accumulation is skipped to avoid one
    // `SpanList` per interned node on fully-unrolled circuits.
    //
    // `LYSIS_STREAMING_WINDOW` selects between two storage strategies
    // for the interner. Unset (or "0") uses the eager strategy: the
    // pure-node table grows unbounded, full hash-consing applies, and
    // `materialize` replays an emission timeline at end. Set to a
    // positive integer N (e.g. 131072), the interner caps the pure
    // table at N entries with FIFO eviction, eternal `Const`-value
    // and `Mul(Const, Const)` tiers preserve long-range dedup for
    // those variant classes, and the materialized Vec is built
    // incrementally. The streaming strategy trades a small inflation
    // of the pre-`ir::passes::optimize` instruction count for the
    // elimination of the pure-node table, side-effect Vec, and
    // emission-timeline accumulators; post-O1 constraint count is
    // preserved exactly because `optimize` collapses the duplicate
    // instructions back to canonical form. Document new values
    // alongside `R1PP_ENABLED` in the workspace `CLAUDE.md`.
    let mut sink = match std::env::var("LYSIS_STREAMING_WINDOW")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
    {
        Some(window) => {
            // `LYSIS_CHUNKED_OUTPUT=1` selects a per-chunk emission
            // buffer instead of a single doubling Vec. Same dedup
            // contract; the worst-case single allocation drops from
            // the next Vec doubling target (multi-gigabyte at the
            // boss-fight) to one chunk.
            if std::env::var("LYSIS_CHUNKED_OUTPUT").as_deref() == Ok("1") {
                InterningSink::<F>::with_streaming_window_chunked(window)
            } else {
                InterningSink::<F>::with_streaming_window(window)
            }
        }
        None => InterningSink::<F>::without_span_tracking(),
    };
    execute(
        &decoded,
        &[],
        &LysisConfig::for_internal_replay(),
        &mut sink,
    )
    .map_err(RoundTripError::Lysis)?;

    Ok(LysisSinkBundle {
        sink,
        next_var,
        var_names,
        var_types,
        var_spans,
        input_spans,
    })
}
pub(super) fn lower_extended_through_lysis<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
) -> Result<IrProgram<F>, LysisInstantiateError> {
    lower_extended_through_lysis_with(extended, true)
}

/// Lean variant of [`lower_extended_through_lysis`]: the extended
/// program's metadata maps are dropped on entry instead of being
/// carried onto the output program, which comes back with empty
/// `var_names` / `var_types` / `var_spans` / `input_spans`. The
/// instruction stream is identical to the full variant's.
pub(super) fn lower_extended_through_lysis_lean<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
) -> Result<IrProgram<F>, LysisInstantiateError> {
    lower_extended_through_lysis_with(extended, false)
}

fn lower_extended_through_lysis_with<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
    keep_metadata: bool,
) -> Result<IrProgram<F>, LysisInstantiateError> {
    let bundle = lower_extended_to_sink(extended, keep_metadata)?;
    let instructions = materialize_interning_sink(bundle.sink);

    // Reassemble: the materialised stream replaces the body, but
    // metadata (var_names/var_types/var_spans/input_spans) carries
    // over from the ExtendedSink's parallel skeleton. SSA renumbering
    // by the interner means the metadata maps may reference vars that
    // no longer appear in the output — downstream passes treat
    // missing entries gracefully (Option<T> returns).
    let mut out = IrProgram::<F>::new();
    let watermark = ssa_watermark(&instructions);
    let final_next_var = watermark.max(bundle.next_var);
    out.set_instructions(instructions);
    out.set_next_var(final_next_var);
    out.var_names = bundle.var_names;
    out.var_types = bundle.var_types;
    out.var_spans = bundle.var_spans;
    out.input_spans = bundle.input_spans;
    Ok(out)
}

/// Highest result-var index across `insts` plus 1. Mirrors the
/// helper in `lysis_roundtrip.rs`; copied to avoid making the
/// internal helper public.
fn ssa_watermark<F: FieldBackend>(insts: &[ir_core::Instruction<F>]) -> u64 {
    let mut max: Option<u64> = None;
    let mut bump = |v: u64| match max {
        Some(m) if v <= m => {}
        _ => max = Some(v),
    };
    for inst in insts {
        bump(inst.result_var().0);
        for extra in inst.extra_result_vars() {
            bump(extra.0);
        }
    }
    max.map(|m| m + 1).unwrap_or(0)
}
