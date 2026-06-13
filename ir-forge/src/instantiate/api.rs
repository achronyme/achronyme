//! Public entry points for ProveIR instantiation.
//!
//! One pipeline, two pairs of entry points:
//!
//! **Extended IR (intermediate)**: [`ProveIR::instantiate_extended`] +
//! [`ProveIR::instantiate_with_outputs_extended`] return an
//! [`ExtendedIrProgram<F>`] whose body is `Vec<ExtendedInstruction<F>>`.
//! Built on top of [`ExtendedSink`]. Primarily an internal stepping-
//! stone for the Walker → InterningSink → materialize cable. The
//! lean entries try the direct interning path first (see
//! [`direct_sink`]) and only build an extended body when the walk
//! emits symbolic nodes.
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

mod bundles;
mod direct_core;
mod direct_plain;
mod direct_sink;
mod drain;
mod errors;
mod lowering;
mod profile;
mod trace;
mod walk;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_direct;

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use lysis::InstructionKind;
use memory::{FieldBackend, FieldElement};

use super::ExtendedSink;
use crate::error::ProveIrError;
use crate::extended::ExtendedInstruction;
use crate::extended_program::ExtendedIrProgram;
use crate::types::ProveIR;
use ir_core::IrProgram;

pub use bundles::{LysisDrainBundle, LysisSinkBundle};
pub use errors::LysisInstantiateError;

use direct_sink::{instantiate_direct_lean, instantiate_direct_lean_sink};
use drain::lower_extended_with_chunk_drain;
use lowering::{
    lower_extended_through_lysis, lower_extended_through_lysis_lean, lower_extended_to_sink,
};
use trace::{lysis_drain_trace, lysis_drain_trace_enabled};
use walk::{assemble_extended, run_walk};

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

    /// Lean materializing variant of [`Self::instantiate_lysis`]: same
    /// instruction stream, but the program's metadata maps
    /// (`var_names`, `var_types`, `var_spans`, `input_spans`) are never
    /// built — they come back empty. Intended for prove-bound callers
    /// that emit constraints and drop the program without reading any
    /// metadata; on large circuits the maps are the dominant share of
    /// the materialized program's heap. Note that the maps on the full
    /// path are keyed by pre-interner variable ids (the interner
    /// renumbers), so consumers already tolerate missing entries.
    pub fn instantiate_lysis_lean<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<IrProgram<F>, LysisInstantiateError> {
        // All-Plain walks (every circom-frontend body) intern directly,
        // skipping the extended-body Vec and the Walker -> bytecode ->
        // executor cable; the stream is byte-identical. A walk that
        // emits symbolic nodes returns None and re-runs via the cable.
        if let Some(program) = instantiate_direct_lean::<F>(self, captures, None)? {
            return Ok(program);
        }
        let extended = self.instantiate_extended_lean::<F>(captures)?;
        lower_extended_through_lysis_lean(extended)
    }

    /// Lean materializing variant of
    /// [`Self::instantiate_lysis_with_outputs`]. See
    /// [`Self::instantiate_lysis_lean`] for the metadata contract; the
    /// only difference is the public-output projection.
    pub fn instantiate_lysis_lean_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<IrProgram<F>, LysisInstantiateError> {
        // See `instantiate_lysis_lean` — same direct path, plus the
        // public-output projection (None for an empty set mirrors the
        // extended entry's dispatch).
        let names = (!output_names.is_empty()).then_some(output_names);
        if let Some(program) = instantiate_direct_lean::<F>(self, captures, names)? {
            return Ok(program);
        }
        let extended = self.instantiate_with_outputs_extended_lean::<F>(captures, output_names)?;
        lower_extended_through_lysis_lean(extended)
    }

    /// Lean sink counterpart of
    /// [`Self::instantiate_lysis_lean_with_outputs`]: return the
    /// populated [`InterningSink<F>`] without materializing an
    /// `IrProgram`, taking the direct interning fast path on all-Plain
    /// walks and the extended-body cable otherwise. The bundle's
    /// metadata maps are empty (lean contract) and its `next_var` is
    /// the walk counter — materializing consumers must still apply
    /// the `ssa_watermark(..).max(next_var)` reassembly formula.
    pub fn instantiate_lysis_lean_sink_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<LysisSinkBundle<F>, LysisInstantiateError> {
        let names = (!output_names.is_empty()).then_some(output_names);
        if let Some((sink, next_var)) = instantiate_direct_lean_sink::<F>(self, captures, names)? {
            return Ok(LysisSinkBundle {
                sink,
                next_var,
                var_names: HashMap::new(),
                var_types: HashMap::new(),
                var_spans: HashMap::new(),
                input_spans: HashMap::new(),
            });
        }
        let extended = self.instantiate_with_outputs_extended_lean::<F>(captures, output_names)?;
        lower_extended_to_sink(extended, false)
    }

    /// Lean sink counterpart of [`Self::instantiate_lysis_lean`]. See
    /// [`Self::instantiate_lysis_lean_sink_with_outputs`] for the
    /// bundle contract; the only difference is the public-output
    /// projection.
    pub fn instantiate_lysis_lean_sink<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<LysisSinkBundle<F>, LysisInstantiateError> {
        if let Some((sink, next_var)) = instantiate_direct_lean_sink::<F>(self, captures, None)? {
            return Ok(LysisSinkBundle {
                sink,
                next_var,
                var_names: HashMap::new(),
                var_types: HashMap::new(),
                var_spans: HashMap::new(),
                input_spans: HashMap::new(),
            });
        }
        let extended = self.instantiate_extended_lean::<F>(captures)?;
        lower_extended_to_sink(extended, false)
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
        let trace = lysis_drain_trace_enabled();
        let start = trace.then(Instant::now);
        let extended = self.instantiate_with_outputs_extended_lean::<F>(captures, output_names)?;
        if let Some(start) = start {
            lysis_drain_trace(
                "after_instantiate_extended",
                &format!(
                    "elapsed_ms={:.3} body_len={} body_cap={}",
                    start.elapsed().as_secs_f64() * 1000.0,
                    extended.body.len(),
                    extended.body.capacity()
                ),
            );
        }
        lower_extended_with_chunk_drain(extended, chunk_consumer)
    }
}
