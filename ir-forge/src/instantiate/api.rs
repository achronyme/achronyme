//! Public entry points for ProveIR instantiation.
//!
//! Two pipelines, four entry points:
//!
//! 1. **Legacy** (commit 2.2): [`ProveIR::instantiate`] +
//!    [`ProveIR::instantiate_with_outputs`] return a flat
//!    `IrProgram<F>` ready for the existing optimize → R1CS path.
//!    Built on top of [`LegacySink`].
//!
//! 2. **Extended** (commit 2.4): [`ProveIR::instantiate_extended`] +
//!    [`ProveIR::instantiate_with_outputs_extended`] return an
//!    [`ExtendedIrProgram<F>`] whose body is
//!    `Vec<ExtendedInstruction<F>>` (every entry wrapped as
//!    `Plain(_)` for now — `LoopUnroll` emission lands in commit
//!    2.5). Built on top of [`ExtendedSink`]. Used by Phase 3.C.6's
//!    Lysis path: `instantiate_extended → Walker → InterningSink →
//!    materialize → IrProgram → R1CS`.
//!
//! `*_with_outputs` differs only in step 2: for every input whose
//! name appears in `output_names`, it records the element-level SSA
//! vars in [`Instantiator::output_pub_vars`] so that downstream
//! `WitnessHint` / `Let` nodes reuse the public wire instead of
//! creating a duplicate witness wire. This is exclusively for the
//! Circom frontend, where `signal output` signals must appear on the
//! public R1CS boundary.

use std::collections::{HashMap, HashSet};

use lysis::{execute, expected_family, InterningSink, LysisConfig};
use memory::{FieldBackend, FieldElement};

use super::{ExtendedSink, InstEnvValue, Instantiator, InstrSink, LegacySink};
use crate::error::ProveIrError;
use crate::extended::ExtendedInstruction;
use crate::extended_program::ExtendedIrProgram;
use crate::lysis_lift::Walker;
use crate::lysis_materialize::materialize_interning_sink;
use crate::lysis_roundtrip::RoundTripError;
use crate::types::ProveIR;
use ir_core::{IrProgram, SsaVar, Visibility};

impl ProveIR {
    /// Instantiate this template with concrete capture values, producing a flat IrProgram.
    ///
    /// The resulting IrProgram is compatible with the existing optimize → R1CS/Plonkish
    /// pipeline (same format as `IrLowering::lower_circuit()`).
    pub fn instantiate<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<IrProgram<F>, ProveIrError> {
        let mut program = IrProgram::<F>::new();
        run_walk(
            self,
            captures,
            Box::new(LegacySink::new(&mut program)),
            None,
        )?;
        Ok(program)
    }

    /// Instantiate with public output support (Circom frontend).
    ///
    /// Output signals in Circom are always public R1CS wires. When the body
    /// encounters a `WitnessHint` or `Let` for an output signal, it reuses
    /// the public wire instead of creating a separate witness wire. This
    /// avoids duplicate wires and ensures constraints reference the public wire
    /// directly.
    ///
    /// `output_names` contains the base names of output signals (e.g. `{"c", "out"}`).
    pub fn instantiate_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<IrProgram<F>, ProveIrError> {
        if output_names.is_empty() {
            return self.instantiate(captures);
        }
        let mut program = IrProgram::<F>::new();
        run_walk(
            self,
            captures,
            Box::new(LegacySink::new(&mut program)),
            Some(output_names),
        )?;
        Ok(program)
    }

    /// Extended-IR variant of [`Self::instantiate`] — produces a
    /// `Vec<ExtendedInstruction<F>>` body wrapped in an
    /// [`ExtendedIrProgram<F>`] for the Lysis lifter.
    ///
    /// At commit 2.4, every emitted entry is
    /// `ExtendedInstruction::Plain(_)`. Commit 2.5 introduces
    /// `LoopUnroll` emission via the sink's `push_loop_unroll` hook
    /// — until then, loops in the body get unrolled in-line just
    /// like the legacy path, only wrapped as `Plain` per
    /// instruction.
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

    /// Extended-IR variant of [`Self::instantiate_with_outputs`].
    /// Same Circom-frontend semantics, ExtendedInstruction body.
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

    /// **Lysis path** — instantiate this template through the
    /// `ExtendedInstruction` schema, then lower through Lysis
    /// (Walker → InterningSink → materialize) to produce a flat
    /// [`IrProgram<F>`] ready for the R1CS backend.
    ///
    /// Differs from [`Self::instantiate`] in HOW the body is lowered,
    /// not WHAT comes out: both return `IrProgram<F>` with the same
    /// post-optimize R1CS multiset (validated by the
    /// `zkc::lysis_oracle`). The win is structural — Lysis's
    /// `LoopUnroll` opcode (commit 2.5) collapses N iterations of an
    /// identical sub-tree into a single shared body, eliminating the
    /// SHA-256(64) multiplicative amplification (the Phase 3 HARD
    /// GATE in commit 3.1).
    pub fn instantiate_lysis<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
    ) -> Result<IrProgram<F>, LysisInstantiateError> {
        let extended = self.instantiate_extended::<F>(captures)?;
        lower_extended_through_lysis(extended)
    }

    /// Lysis variant of [`Self::instantiate_with_outputs`]. Same
    /// Circom-frontend output semantics, Lysis-lowered body.
    pub fn instantiate_lysis_with_outputs<F: FieldBackend>(
        &self,
        captures: &HashMap<String, FieldElement<F>>,
        output_names: &HashSet<String>,
    ) -> Result<IrProgram<F>, LysisInstantiateError> {
        let extended = self.instantiate_with_outputs_extended::<F>(captures, output_names)?;
        lower_extended_through_lysis(extended)
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
/// validator (`lysis::bytecode::validate`) is **debug-only** (Phase
/// 1.C, BETA20-CLOSEOUT). It checks RFC §4.5 well-formedness rules
/// (const bounds, jump targets, register bounds, dataflow,
/// reachability, call graph, heap slots) — the executor backstops
/// every one of those at runtime, so skipping in release trades a
/// ~741 ms cost on SHA-256(64) for a debug-mode-only safety net.
/// Schema drift detection moves to `cargo test --workspace` (which
/// runs in debug mode unless `--release` is forced); the wire-format
/// round-trip catches encode/decode drift in either build.
fn lower_extended_through_lysis<F: FieldBackend>(
    extended: ExtendedIrProgram<F>,
) -> Result<IrProgram<F>, LysisInstantiateError> {
    let walker = Walker::<F>::new(expected_family::<F>());
    let bytecode = walker.lower(&extended.body).map_err(RoundTripError::Walk)?;

    let bytes = lysis::encode(&bytecode);
    let decoded = lysis::decode::<F>(&bytes).map_err(RoundTripError::Lysis)?;
    if cfg!(debug_assertions) {
        lysis::bytecode::validate(&decoded, &LysisConfig::default())
            .map_err(RoundTripError::Lysis)?;
    }

    let mut sink = InterningSink::<F>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink).map_err(RoundTripError::Lysis)?;
    let instructions = materialize_interning_sink(sink);

    // Reassemble: the materialised stream replaces the body, but
    // metadata (var_names/var_types/var_spans/input_spans) carries
    // over from the ExtendedSink's parallel skeleton. SSA renumbering
    // by the interner means the metadata maps may reference vars that
    // no longer appear in the output — downstream passes treat
    // missing entries gracefully (Option<T> returns).
    let mut out = IrProgram::<F>::new();
    let watermark = ssa_watermark(&instructions);
    let final_next_var = watermark.max(extended.next_var);
    out.set_instructions(instructions);
    out.set_next_var(final_next_var);
    out.var_names = extended.var_names;
    out.var_types = extended.var_types;
    out.var_spans = extended.var_spans;
    out.input_spans = extended.input_spans;
    Ok(out)
}

/// Highest result-var index across `insts` plus 1. Mirrors the
/// helper in `lysis_roundtrip.rs`; copied to avoid making the
/// internal helper public.
fn ssa_watermark<F: FieldBackend>(insts: &[ir_core::Instruction<F>]) -> u32 {
    let mut max: Option<u32> = None;
    let mut bump = |v: u32| match max {
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
        env: HashMap::new(),
        captures: captures.clone(),
        current_span: None,
        output_pub_vars: HashMap::new(),
        const_cache: HashMap::new(),
        const_values: HashMap::new(),
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

    /// Both pipelines should produce the same instruction stream when
    /// the source has no Lysis-specific structure (every emission is
    /// `Plain` at this commit).
    #[test]
    fn extended_matches_legacy_for_plain_only_source() {
        let source = "public z\nwitness x\nlet s = x + x;\nlet p = s * x;\nassert(p == z)";
        let prove_ir = compile_circuit(source).expect("compile_circuit");

        let legacy = prove_ir
            .instantiate::<F>(&HashMap::new())
            .expect("instantiate");
        let extended = prove_ir
            .instantiate_extended::<F>(&HashMap::new())
            .expect("instantiate_extended");

        assert_eq!(legacy.len(), extended.body.len());
        assert!(extended.is_fully_plain());
        assert_eq!(legacy.next_var(), extended.next_var);

        // `try_into_ir_program` should succeed and yield the same
        // instruction shape as the legacy path.
        let projected = extended
            .try_into_ir_program()
            .expect("all entries are Plain");
        assert_eq!(projected.len(), legacy.len());
        for (a, b) in projected.iter().zip(legacy.iter()) {
            assert_eq!(format!("{a}"), format!("{b}"));
        }
    }

    #[test]
    fn extended_emits_loop_unroll_for_for_loops() {
        // Post-2.5: loops emit a single LoopUnroll node containing the
        // body, instead of N inlined copies. The extended program is no
        // longer fully Plain.
        //
        // Phase 1.B note: the body must NOT carry a mut accumulator,
        // because carry-set loops eager-unroll at lower time and never
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
}
