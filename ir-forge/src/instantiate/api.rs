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

mod bundles;
mod direct_plain;
mod drain;
mod errors;
mod lowering;
mod profile;
mod trace;
mod walk;

#[cfg(test)]
mod tests;

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

use drain::lower_extended_with_chunk_drain;
use lowering::{lower_extended_through_lysis, lower_extended_to_sink};
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
