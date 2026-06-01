//! Public entry points for ProveIR instantiation.
//!
//! One pipeline, two pairs of entry points:
//!
//! **Extended IR (intermediate)**: [`ProveIR::instantiate_extended`] +
//! [`ProveIR::instantiate_with_outputs_extended`] return an
//! [`ExtendedIrProgram<F>`] whose body is `Vec<ExtendedInstruction<F>>`.
//! Built on top of [`ExtendedSink`]. Primarily an internal stepping-
//! stone: every `Lysis` entry point invokes one of these first, then
//! runs the result through the Walker → InterningSink → materialize
//! cable.
//!
//! **Lysis (production)**: [`ProveIR::instantiate_lysis`] +
//! [`ProveIR::instantiate_lysis_with_outputs`] return a flat
//! [`IrProgram<F>`] ready for the optimize → R1CS path. Internally:
//! `instantiate_extended → Walker → InterningSink → materialize →
//! IrProgram`.
//!
//! `*_with_outputs` differs only in step 2: for every input whose
//! name appears in `output_names`, it records the element-level SSA
//! vars in [`Instantiator::output_pub_vars`] so that downstream
//! `WitnessHint` / `Let` nodes reuse the public wire instead of
//! creating a duplicate witness wire. This is exclusively for the
//! Circom frontend, where `signal output` signals must appear on the
//! public R1CS boundary.

use std::collections::{HashMap, HashSet};

use lysis::{
    execute, expected_family, ChunkDrainingSink, InstructionKind, InterningSink, LysisConfig,
};
use memory::{FieldBackend, FieldElement};
use rustc_hash::FxHashMap;

use super::{ExtendedSink, InstEnvValue, Instantiator, InstrSink};
use crate::error::ProveIrError;
use crate::extended::ExtendedInstruction;
use crate::extended_program::ExtendedIrProgram;
use crate::lysis_lift::Walker;
use crate::lysis_materialize::materialize_interning_sink;
use crate::lysis_roundtrip::RoundTripError;
use crate::types::ProveIR;
use ir_core::{IrProgram, SsaVar, Visibility};

impl ProveIR {
    /// Extended-IR variant of [`Self::instantiate_lysis`] — produces a
    /// `Vec<ExtendedInstruction<F>>` body wrapped in an
    /// [`ExtendedIrProgram<F>`] for the Lysis lifter.
    ///
    /// Internal step in the Lysis pipeline. Compile-time-known loops
    /// emit a single `ExtendedInstruction::LoopUnroll` carrying the
    /// body once with `iter_var` bound symbolically; the Walker
    /// replays the body per-iteration.
    pub fn instantiate_extended<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<ExtendedIrProgram<F>, ProveIrError> {
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        run_walk(
            self,
            captures,
            Box::new(ExtendedSink::new(&mut body, &mut metadata)),
            None,
        )?;
        Ok(assemble_extended(body, metadata))
    }

    /// Extended-IR variant of [`Self::instantiate_lysis_with_outputs`].
    /// Same Circom-frontend output semantics, ExtendedInstruction body.
    pub fn instantiate_with_outputs_extended<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<ExtendedIrProgram<F>, ProveIrError> {
        if output_names.is_empty() {
            return self.instantiate_extended(captures);
        }
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        run_walk(
            self,
            captures,
            Box::new(ExtendedSink::new(&mut body, &mut metadata)),
            Some(output_names),
        )?;
        Ok(assemble_extended(body, metadata))
    }

    /// Lean counterpart of [`Self::instantiate_extended`] for callers
    /// that will immediately discard the name / input-span / per-var-
    /// span side-channels. The chunk-drain and streaming-sink paths
    /// drop the maps the moment they take ownership of the returned
    /// `ExtendedIrProgram`; this variant skips building them in the
    /// first place, sparing the peak-RSS cost of three multi-million-
    /// entry HashMaps that exist only to be freed. The returned
    /// program's metadata maps are empty. Type propagation still works
    /// during emission because the lean sink keeps a dense transient
    /// type table behind `set_type` / `get_type` and drops it at the
    /// boundary.
    pub(crate) fn instantiate_extended_lean<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<ExtendedIrProgram<F>, ProveIrError> {
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        run_walk(
            self,
            captures,
            Box::new(ExtendedSink::new_lean(&mut body, &mut metadata)),
            None,
        )?;
        Ok(assemble_extended(body, metadata))
    }

    /// Lean counterpart of [`Self::instantiate_with_outputs_extended`].
    /// See [`Self::instantiate_extended_lean`] for the side-channel
    /// contract; the only difference is the public-output projection.
    pub(crate) fn instantiate_with_outputs_extended_lean<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<ExtendedIrProgram<F>, ProveIrError> {
        if output_names.is_empty() {
            return self.instantiate_extended_lean(captures);
        }
        let mut body: Vec<ExtendedInstruction<F>> = Vec::new();
        let mut metadata = IrProgram::<F>::new();
        run_walk(
            self,
            captures,
            Box::new(ExtendedSink::new_lean(&mut body, &mut metadata)),
            Some(output_names),
        )?;
        Ok(assemble_extended(body, metadata))
    }

    /// **Lysis path** — production entry point. Instantiate this
    /// template through the `ExtendedInstruction` schema, then lower
    /// through Lysis (Walker → InterningSink → materialize) to
    /// produce a flat [`IrProgram<F>`] ready for the R1CS backend.
    ///
    /// Lysis's `LoopUnroll` opcode collapses N iterations of an
    /// identical sub-tree into a single shared body, eliminating the
    /// SHA-256(64) multiplicative amplification.
    pub fn instantiate_lysis<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<IrProgram<F>, LysisInstantiateError> {
        let extended = self.instantiate_extended::<F>(captures)?;
        lower_extended_through_lysis(extended)
    }

    /// Lysis variant of [`Self::instantiate_lysis`] with public-output
    /// support. Same Circom-frontend output semantics — `output_names`
    /// keeps `signal output` wires on the public R1CS boundary instead
    /// of duplicating them as witness wires.
    pub fn instantiate_lysis_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<IrProgram<F>, LysisInstantiateError> {
        let extended = self.instantiate_with_outputs_extended::<F>(captures, output_names)?;
        lower_extended_through_lysis(extended)
    }

    /// Streaming counterpart of [`Self::instantiate_lysis_with_outputs`]:
    /// return the populated [`InterningSink<F>`] (plus the metadata
    /// maps) directly, without materializing a `Vec<Instruction<F>>`
    /// or assembling an `IrProgram`. Lets callers feed the instruction
    /// stream straight into a constraint backend via
    /// [`crate::lysis_sink_instruction_stream`].
    pub fn instantiate_lysis_sink_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<LysisSinkBundle<F>, LysisInstantiateError> {
        let extended = self.instantiate_with_outputs_extended_lean::<F>(captures, output_names)?;
        lower_extended_to_sink(extended, false)
    }

    /// Streaming counterpart of [`Self::instantiate_lysis`]: same shape
    /// as [`Self::instantiate_lysis_sink_with_outputs`] without the
    /// `output_names` projection.
    pub fn instantiate_lysis_sink<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<LysisSinkBundle<F>, LysisInstantiateError> {
        let extended = self.instantiate_extended_lean::<F>(captures)?;
        lower_extended_to_sink(extended, false)
    }

    /// Chunk-draining counterpart of
    /// [`Self::instantiate_lysis_sink_with_outputs`]: instead of
    /// accumulating every sealed chunk in the interner's
    /// `streaming_chunks` Vec for the caller to drain after the
    /// executor returns, hands each sealed chunk to `chunk_consumer`
    /// the moment it fills. Peak resident footprint inside the
    /// executor stays at `dedup state + 1 chunk`, independent of the
    /// total emitted instruction count.
    ///
    /// `chunk_consumer` is invoked once per chunk, in emission order.
    /// The trailing partial chunk is delivered at the end of
    /// execution. The closure receives the chunk by value so the
    /// caller can drain it into a constraint backend and let the
    /// chunk's backing allocation return to the OS once the call
    /// returns.
    ///
    /// The returned [`LysisDrainBundle`] carries the interner's
    /// post-execute dedup state (eternal Const tier, sliding window)
    /// for diagnostics — the emission buffer is empty.
    pub fn instantiate_lysis_drain_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
        chunk_consumer: &mut dyn FnMut(Vec<InstructionKind<F>>),
    ) -> Result<LysisDrainBundle<F>, LysisInstantiateError> {
        let extended = self.instantiate_with_outputs_extended_lean::<F>(captures, output_names)?;
        lower_extended_with_chunk_drain(extended, chunk_consumer)
    }
}

/// Errors raised by the `instantiate_lysis*` family. Bridges
/// [`ProveIrError`] (instantiate side) and [`RoundTripError`] (Lysis
/// pipeline side) into one variant the caller can match against.
#[derive(Debug)]
pub enum LysisInstantiateError {
    /// Instantiate-side error: invalid captures, oversize loop range,
    /// missing array element, etc.
    Instantiate(ProveIrError),
    /// Lysis-side error: Walker rejection (unsupported variant),
    /// bytecode validation failure, executor abort.
    Lysis(RoundTripError),
}

impl std::fmt::Display for LysisInstantiateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Instantiate(e) => write!(f, "instantiate_lysis: instantiate-side error: {e}"),
            Self::Lysis(e) => write!(f, "instantiate_lysis: lysis-side error: {e}"),
        }
    }
}

impl std::error::Error for LysisInstantiateError {}

impl From<ProveIrError> for LysisInstantiateError {
    fn from(e: ProveIrError) -> Self {
        Self::Instantiate(e)
    }
}

impl From<RoundTripError> for LysisInstantiateError {
    fn from(e: RoundTripError) -> Self {
        Self::Lysis(e)
    }
}

/// Drive a populated [`ExtendedIrProgram<F>`] through the Lysis
/// pipeline: Walker → encode → decode → validate → execute against
/// an [`InterningSink`] → materialize to flat [`IrProgram<F>`].
///
/// The wire-format round-trip (encode → decode) stays unconditional —
/// it exercises the bytecode wire format on every call so any future
/// schema drift trips here, not at a downstream gate. The semantic
/// validator (`lysis::bytecode::validate`) is **debug-only**. It
/// checks the structural well-formedness rules (const bounds, jump
/// targets, register bounds, dataflow, reachability, call graph, heap
/// slots) — the executor backstops every one of those at runtime, so
/// skipping in release trades a ~741 ms cost on SHA-256(64) for a
/// debug-mode-only safety net. Schema drift detection moves to
/// `cargo test --workspace` (which runs in debug mode unless
/// `--release` is forced); the wire-format round-trip catches
/// encode/decode drift in either build.
/// Side-data carried alongside a populated [`InterningSink<F>`] when
/// the lifter splits the pipeline at the post-execute boundary. The
/// `IrProgram` reassembly path consumes this together with the
/// materialized instruction stream; the streaming path discards it.
///
/// The metadata maps (`var_names`, `var_types`, `var_spans`,
/// `input_spans`) are populated only on the reassembly path. The
/// streaming entry points ([`ProveIR::instantiate_lysis_sink`] and
/// [`ProveIR::instantiate_lysis_sink_with_outputs`]) leave them empty
/// — the streaming consumer drains the sink iterator into a
/// constraint backend that does not consume semantic metadata, so
/// keeping the maps alive across the executor run would waste peak
/// resident footprint on multi-million-variable circuits.
pub struct LysisSinkBundle<F: FieldBackend> {
    pub sink: InterningSink<F>,
    pub next_var: u64,
    pub var_names: HashMap<SsaVar, String>,
    pub var_types: HashMap<SsaVar, ir_core::IrType>,
    pub var_spans: HashMap<SsaVar, diagnostics::SpanRange>,
    pub input_spans: HashMap<String, diagnostics::SpanRange>,
}

/// Output of the chunk-draining entry point
/// ([`ProveIR::instantiate_lysis_drain_with_outputs`]). The emission
/// stream has already been delivered to the caller's consumer
/// closure; this bundle carries post-execute bookkeeping the caller
/// still needs after the chunks are gone — the `next_var` watermark
/// for any further SSA allocation, plus the underlying interning
/// sink whose dedup tier state (eternal Const table, sliding window,
/// node id counter) is preserved for diagnostics. The sink's
/// emission buffer is empty.
pub struct LysisDrainBundle<F: FieldBackend> {
    pub residual_sink: InterningSink<F>,
    pub next_var: u64,
}

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

    let walker = Walker::<F>::new(expected_family::<F>());
    let decoded = walker.lower(body).map_err(RoundTripError::Walk)?;
    if trace {
        lysis_drain_trace(
            "after_lower",
            &format!(
                "decoded_body_len={} decoded_body_cap={} instr_size={} templates_len={} templates_cap={} const_pool_len={} heap_size_hint={}",
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
    execute(
        &decoded,
        &[],
        &LysisConfig::for_internal_replay(),
        &mut sink,
    )
    .map_err(RoundTripError::Lysis)?;
    if trace {
        lysis_drain_trace(
            "after_execute",
            &format!(
                "pure_len={} effect_len={}",
                sink.inner().pure_len(),
                sink.inner().effect_len()
            ),
        );
    }
    let residual_sink = sink.finalize();
    if trace {
        lysis_drain_trace(
            "after_finalize",
            &format!(
                "pure_len={} effect_len={}",
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

#[derive(Default)]
struct LysisOpcodeProfile {
    load_capture: usize,
    load_const: usize,
    load_input: usize,
    enter_scope: usize,
    exit_scope: usize,
    jump: usize,
    jump_if: usize,
    return_: usize,
    halt: usize,
    trap: usize,
    loop_unroll: usize,
    loop_rolled: usize,
    loop_range: usize,
    loop_unroll_iters: u64,
    loop_unroll_body_bytes: u64,
    define_template: usize,
    instantiate_template: usize,
    template_output: usize,
    emit_const: usize,
    emit_add: usize,
    emit_sub: usize,
    emit_mul: usize,
    emit_neg: usize,
    emit_mux: usize,
    emit_decompose: usize,
    emit_decompose_bits: usize,
    emit_assert_eq: usize,
    emit_assert_eq_msg: usize,
    emit_range_check: usize,
    emit_witness_call: usize,
    emit_witness_call_inputs: usize,
    emit_witness_call_outputs: usize,
    emit_witness_call_heap: usize,
    emit_witness_call_heap_inputs: usize,
    emit_witness_call_heap_outputs: usize,
    emit_poseidon_hash: usize,
    emit_is_eq: usize,
    emit_is_lt: usize,
    emit_int_div: usize,
    emit_int_mod: usize,
    emit_div: usize,
    store_heap: usize,
    load_heap: usize,
    instantiate_targets: Vec<usize>,
}

fn trace_lysis_program_profile<F: FieldBackend>(program: &lysis::Program<F>) {
    use lysis::Opcode;

    let mut p = LysisOpcodeProfile::default();
    for instr in &program.body {
        match &instr.opcode {
            Opcode::LoadCapture { .. } => p.load_capture += 1,
            Opcode::LoadConst { .. } => p.load_const += 1,
            Opcode::LoadInput { .. } => p.load_input += 1,
            Opcode::EnterScope => p.enter_scope += 1,
            Opcode::ExitScope => p.exit_scope += 1,
            Opcode::Jump { .. } => p.jump += 1,
            Opcode::JumpIf { .. } => p.jump_if += 1,
            Opcode::Return => p.return_ += 1,
            Opcode::Halt => p.halt += 1,
            Opcode::Trap { .. } => p.trap += 1,
            Opcode::LoopUnroll {
                start,
                end,
                body_len,
                ..
            } => {
                p.loop_unroll += 1;
                p.loop_unroll_iters += u64::from(end.saturating_sub(*start));
                p.loop_unroll_body_bytes += u64::from(*body_len);
            }
            Opcode::LoopRolled { .. } => p.loop_rolled += 1,
            Opcode::LoopRange { .. } => p.loop_range += 1,
            Opcode::DefineTemplate { .. } => p.define_template += 1,
            Opcode::InstantiateTemplate { template_id, .. } => {
                p.instantiate_template += 1;
                let target = *template_id as usize;
                if target >= p.instantiate_targets.len() {
                    p.instantiate_targets.resize(target + 1, 0);
                }
                p.instantiate_targets[target] += 1;
            }
            Opcode::TemplateOutput { .. } => p.template_output += 1,
            Opcode::EmitConst { .. } => p.emit_const += 1,
            Opcode::EmitAdd { .. } => p.emit_add += 1,
            Opcode::EmitSub { .. } => p.emit_sub += 1,
            Opcode::EmitMul { .. } => p.emit_mul += 1,
            Opcode::EmitNeg { .. } => p.emit_neg += 1,
            Opcode::EmitMux { .. } => p.emit_mux += 1,
            Opcode::EmitDecompose { n_bits, .. } => {
                p.emit_decompose += 1;
                p.emit_decompose_bits += usize::from(*n_bits);
            }
            Opcode::EmitAssertEq { .. } => p.emit_assert_eq += 1,
            Opcode::EmitAssertEqMsg { .. } => p.emit_assert_eq_msg += 1,
            Opcode::EmitRangeCheck { .. } => p.emit_range_check += 1,
            Opcode::EmitWitnessCall {
                in_regs, out_regs, ..
            } => {
                p.emit_witness_call += 1;
                p.emit_witness_call_inputs += in_regs.len();
                p.emit_witness_call_outputs += out_regs.len();
            }
            Opcode::EmitWitnessCallHeap {
                inputs, out_slots, ..
            } => {
                p.emit_witness_call_heap += 1;
                p.emit_witness_call_heap_inputs += inputs.len();
                p.emit_witness_call_heap_outputs += out_slots.len();
            }
            Opcode::EmitPoseidonHash { .. } => p.emit_poseidon_hash += 1,
            Opcode::EmitIsEq { .. } => p.emit_is_eq += 1,
            Opcode::EmitIsLt { .. } => p.emit_is_lt += 1,
            Opcode::EmitIntDiv { .. } => p.emit_int_div += 1,
            Opcode::EmitIntMod { .. } => p.emit_int_mod += 1,
            Opcode::EmitDiv { .. } => p.emit_div += 1,
            Opcode::StoreHeap { .. } => p.store_heap += 1,
            Opcode::LoadHeap { .. } => p.load_heap += 1,
        }
    }
    let template_body_bytes: u64 = program
        .templates
        .iter()
        .map(|t| u64::from(t.body_len))
        .sum();
    let max_template_body_bytes = program
        .templates
        .iter()
        .map(|t| t.body_len)
        .max()
        .unwrap_or(0);
    eprintln!(
        "[lysis-profile] body_len={} templates={} template_body_bytes={} max_template_body_bytes={} heap_size_hint={} const_pool_len={}",
        program.body.len(),
        program.templates.len(),
        template_body_bytes,
        max_template_body_bytes,
        program.header.heap_size_hint,
        program.const_pool.len(),
    );
    eprintln!(
        "[lysis-profile] control load_capture={} load_const={} load_input={} enter={} exit={} jump={} jump_if={} return={} halt={} trap={} loop_unroll={} loop_unroll_iters={} loop_unroll_body_bytes={} loop_rolled={} loop_range={} define_template={} instantiate_template={} template_output={} store_heap={} load_heap={}",
        p.load_capture,
        p.load_const,
        p.load_input,
        p.enter_scope,
        p.exit_scope,
        p.jump,
        p.jump_if,
        p.return_,
        p.halt,
        p.trap,
        p.loop_unroll,
        p.loop_unroll_iters,
        p.loop_unroll_body_bytes,
        p.loop_rolled,
        p.loop_range,
        p.define_template,
        p.instantiate_template,
        p.template_output,
        p.store_heap,
        p.load_heap,
    );
    let top_targets = top_usize(&p.instantiate_targets, 8)
        .into_iter()
        .map(|(id, count)| format!("{id}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    eprintln!("[lysis-profile] instantiate_targets={top_targets}");
    let small_target_sites = small_instantiate_target_sites(program, 8, 24).join(",");
    eprintln!("[lysis-profile] small_instantiate_target_sites={small_target_sites}");
    eprintln!(
        "[lysis-profile] emit const={} add={} sub={} mul={} neg={} mux={} decompose={} decompose_bits={} asserteq={} asserteq_msg={} range={} witness_call={} witness_inputs={} witness_outputs={} witness_call_heap={} witness_heap_inputs={} witness_heap_outputs={} poseidon={} iseq={} islt={} intdiv={} intmod={} div={}",
        p.emit_const,
        p.emit_add,
        p.emit_sub,
        p.emit_mul,
        p.emit_neg,
        p.emit_mux,
        p.emit_decompose,
        p.emit_decompose_bits,
        p.emit_assert_eq,
        p.emit_assert_eq_msg,
        p.emit_range_check,
        p.emit_witness_call,
        p.emit_witness_call_inputs,
        p.emit_witness_call_outputs,
        p.emit_witness_call_heap,
        p.emit_witness_call_heap_inputs,
        p.emit_witness_call_heap_outputs,
        p.emit_poseidon_hash,
        p.emit_is_eq,
        p.emit_is_lt,
        p.emit_int_div,
        p.emit_int_mod,
        p.emit_div,
    );
}

fn small_instantiate_target_sites<F: FieldBackend>(
    program: &lysis::Program<F>,
    target_limit: u16,
    site_limit: usize,
) -> Vec<String> {
    use lysis::Opcode;

    let mut sites = Vec::new();
    for instr in &program.body {
        let Opcode::InstantiateTemplate { template_id, .. } = &instr.opcode else {
            continue;
        };
        if *template_id >= target_limit {
            continue;
        }
        let owner = program
            .templates
            .iter()
            .find(|template| {
                let start = template.body_offset;
                let end = start.saturating_add(template.body_len);
                instr.offset >= start && instr.offset < end
            })
            .map(|template| template.id.to_string())
            .unwrap_or_else(|| "root".to_string());
        sites.push(format!("{template_id}@{owner}:{}", instr.offset));
        if sites.len() >= site_limit {
            break;
        }
    }
    sites
}

fn top_usize(values: &[usize], limit: usize) -> Vec<(usize, usize)> {
    let mut pairs = values
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count > 0)
        .collect::<Vec<_>>();
    pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs.truncate(limit);
    pairs
}

fn lysis_drain_trace_enabled() -> bool {
    std::env::var("ACH_LYSIS_TRACE").is_ok()
}

fn positive_usize_or_default(value: Option<&str>, default: usize) -> usize {
    value
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn lysis_malloc_trim_enabled() -> bool {
    std::env::var("ACH_LYSIS_MALLOC_TRIM").as_deref() == Ok("1")
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim_process_allocator() -> bool {
    unsafe extern "C" {
        fn malloc_trim(pad: usize) -> i32;
    }
    unsafe { malloc_trim(0) != 0 }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn trim_process_allocator() -> bool {
    false
}

fn lysis_drain_trace(stage: &str, fields: &str) {
    let (rss_kib, vmsize_kib) = lysis_process_mem_kib().unwrap_or((0, 0));
    eprintln!("[lysis-drain] {stage} rss_kib={rss_kib} vmsize_kib={vmsize_kib} {fields}");
}

fn lysis_process_mem_kib() -> Option<(u64, u64)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let mut rss = None;
    let mut vmsize = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = rest.split_whitespace().next()?.parse::<u64>().ok();
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            vmsize = rest.split_whitespace().next()?.parse::<u64>().ok();
        }
        if rss.is_some() && vmsize.is_some() {
            break;
        }
    }
    Some((rss.unwrap_or(0), vmsize.unwrap_or(0)))
}

fn lower_extended_through_lysis<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
) -> Result<IrProgram<F>, LysisInstantiateError> {
    let bundle = lower_extended_to_sink(extended, true)?;
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

/// Shared body of all four entry points. Builds an `Instantiator`
/// holding the caller-provided `sink`, runs validate + declare +
/// emit, and lets the sink drop at scope end so the caller's
/// borrowed program (or body+metadata pair) is once again
/// exclusively borrowed for assembly into the return value.
fn run_walk<'a, F: FieldBackend>(
    prove_ir: &ProveIR,
    captures: &HashMap<String, FieldElement<F>>,
    sink: Box<dyn InstrSink<F> + 'a>,
    output_names: Option<&HashSet<String>>,
) -> Result<(), ProveIrError> {
    let mut inst = Instantiator {
        sink,
        env: FxHashMap::default(),
        captures: captures
            .iter()
            .map(|(name, value)| (name.clone(), *value))
            .collect(),
        current_span: None,
        output_pub_vars: FxHashMap::default(),
        const_cache: FxHashMap::default(),
        const_values: FxHashMap::default(),
        component_bodies: prove_ir
            .component_bodies
            .iter()
            .map(|(key, body)| (key.clone(), body.clone()))
            .collect(),
    };

    // 1. Validate all required captures are provided
    inst.validate_captures(prove_ir)?;

    // 2. Declare public inputs. For Circom-frontend callers (output_names
    //    is Some), record element-level SSA vars for outputs so body
    //    nodes reuse them instead of creating duplicate witness wires.
    for input in &prove_ir.public_inputs {
        inst.declare_input(input, Visibility::Public)?;

        if let Some(outputs) = output_names {
            if outputs.contains(&input.name) {
                match &input.array_size {
                    Some(array_size) => {
                        let size = inst.resolve_array_size(array_size)?;
                        for i in 0..size {
                            let elem_name = format!("{}_{i}", input.name);
                            if let Some(InstEnvValue::Scalar(v)) = inst.env.get(&elem_name) {
                                inst.output_pub_vars.insert(elem_name, *v);
                            }
                        }
                    }
                    None => {
                        if let Some(InstEnvValue::Scalar(v)) = inst.env.get(&input.name) {
                            inst.output_pub_vars.insert(input.name.clone(), *v);
                        }
                    }
                }
            }
        }
    }

    // 3. Declare witness inputs
    for input in &prove_ir.witness_inputs {
        inst.declare_input(input, Visibility::Witness)?;
    }

    // 4. Declare captures as circuit inputs or inline constants
    for cap in &prove_ir.captures {
        inst.declare_capture(cap)?;
    }

    // 4b. Reconstruct array env entries from capture_arrays.
    //     Individual element captures (path_0, path_1) were declared above;
    //     now assemble them into InstEnvValue::Array so array-consuming
    //     constructs (e.g. merkle_verify) can resolve the array by name.
    for arr in &prove_ir.capture_arrays {
        let elem_vars: Vec<SsaVar> = (0..arr.size)
            .map(|i| {
                let elem_name = format!("{}_{i}", arr.name);
                match inst.env.get(&elem_name) {
                    Some(InstEnvValue::Scalar(v)) => Ok(*v),
                    _ => Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "missing array element capture `{elem_name}` for array `{}`",
                            arr.name
                        ),
                        span: None,
                    }),
                }
            })
            .collect::<Result<_, _>>()?;
        inst.env
            .insert(arr.name.clone(), InstEnvValue::Array(elem_vars));
    }

    // 5. Emit all body nodes
    for node in &prove_ir.body {
        inst.emit_node(node)?;
    }

    // `inst` (and the sink it owns) drops here, releasing the
    // borrow on the caller's program / body+metadata.
    Ok(())
}

/// Assemble the `ExtendedSink`'s output (a body Vec + a metadata
/// IrProgram skeleton) into a single [`ExtendedIrProgram<F>`].
fn assemble_extended<F: FieldBackend>(
    body: Vec<ExtendedInstruction<F>>,
    metadata: IrProgram<F>,
) -> ExtendedIrProgram<F> {
    ExtendedIrProgram {
        body,
        next_var: metadata.next_var,
        var_names: metadata.var_names,
        var_types: metadata.var_types,
        input_spans: metadata.input_spans,
        var_spans: metadata.var_spans,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use memory::Bn254Fr;

    use crate::extended::ExtendedInstruction;
    use crate::test_utils::compile_circuit;

    type F = Bn254Fr;

    #[test]
    fn positive_usize_or_default_rejects_missing_zero_and_invalid_values() {
        assert_eq!(super::positive_usize_or_default(None, 17), 17);
        assert_eq!(super::positive_usize_or_default(Some("0"), 17), 17);
        assert_eq!(super::positive_usize_or_default(Some("nope"), 17), 17);
        assert_eq!(super::positive_usize_or_default(Some("42"), 17), 42);
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
        let outputs: std::collections::HashSet<String> =
            std::iter::once("out".to_string()).collect();
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
        let outputs: std::collections::HashSet<String> =
            std::iter::once("out".to_string()).collect();
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
        let outputs: std::collections::HashSet<String> =
            std::iter::once("out".to_string()).collect();

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
}
