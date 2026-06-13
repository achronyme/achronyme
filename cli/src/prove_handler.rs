use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use akron::{ProveError, ProveHandler, ProveResult, VerifyHandler};
use memory::FieldElement;
use zkc::plonkish_backend::PlonkishCompiler;
use zkc::r1cs_backend::R1CSCompiler;

use memory::field::PrimeId;

use crate::commands::ErrorFormat;
use crate::style::{format_number, Styler};

/// Backend selection for prove blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveBackend {
    R1cs,
    Plonkish,
}

/// Default implementation of `ProveHandler` that compiles and verifies
/// prove blocks using the IR pipeline, generating native proofs via
/// ark-groth16 (R1CS) or halo2 KZG (Plonkish).
pub struct DefaultProveHandler {
    cache_dir: PathBuf,
    backend: ProveBackend,
    prime_id: PrimeId,
    style: Styler,
    verbose: bool,
    circuit_stats: bool,
    collected_stats: RefCell<Vec<ir::stats::CircuitStats>>,
}

impl DefaultProveHandler {
    pub fn new(
        backend: ProveBackend,
        prime_id: PrimeId,
        error_format: ErrorFormat,
        circuit_stats: bool,
    ) -> Self {
        let cache_dir = crate::cache_dir();
        let style = Styler::from_env(&error_format);
        let verbose = style.is_verbose(&error_format);
        Self {
            cache_dir,
            backend,
            prime_id,
            style,
            verbose,
            circuit_stats,
            collected_stats: RefCell::new(Vec::new()),
        }
    }

    /// Print all collected circuit stats to stderr.
    pub fn print_circuit_stats(&self) {
        let stats = self.collected_stats.borrow();
        if stats.is_empty() {
            return;
        }
        for s in stats.iter() {
            eprintln!("{s}");
        }
        if stats.len() > 1 {
            let total: usize = stats.iter().map(|s| s.total_constraints).sum();
            eprintln!(
                "  Total across {} circuits: {} constraints",
                stats.len(),
                total
            );
        }
    }
}

impl ProveHandler for DefaultProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        // 1. Deserialize ProveIR from bytes
        let (prove_ir, _prime_id) = ir_forge::ProveIR::from_bytes(prove_ir_bytes)
            .map_err(|e| ProveError::IrLowering(format!("ProveIR deserialization: {e}")))?;

        // 2. Instantiate with scope values (captures resolved here)
        //    via Lysis (Walker → InterningSink → materialise). The R1CS
        //    backend drops the program right after constraint emission
        //    and reads none of its metadata maps, so it takes the lean
        //    instantiate — on large circuits the maps are the dominant
        //    share of the materialized program's heap. Flows that keep
        //    the program (Plonkish compile, circuit stats) stay on the
        //    full instantiate.
        let lean = matches!(self.backend, ProveBackend::R1cs) && !self.circuit_stats;
        let program = if lean {
            // Fused pipeline: the pass pipeline runs against the
            // interner's emission events and the program materializes
            // once, already optimized — the unoptimized instruction
            // Vec never exists.
            let bundle = prove_ir
                .instantiate_lysis_lean_sink(scope_values)
                .map_err(|e| ProveError::IrLowering(format!("{e}")))?;
            ir::passes::fused::optimize_lean_sink(bundle).program
        } else {
            let mut program = prove_ir
                .instantiate_lysis(scope_values)
                .map_err(|e| ProveError::IrLowering(format!("{e}")))?;
            ir::passes::optimize(&mut program);
            program
        };

        // 3b. Collect circuit stats if enabled
        if self.circuit_stats {
            let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
            let name = prove_ir.name.as_deref();
            let stats = ir::stats::CircuitStats::from_program(&program, &proven, name);
            self.collected_stats.borrow_mut().push(stats);
        }

        // 4. Build input map from scope_values (public + witness + capture names).
        //    Validate that all required values are present.
        let mut inputs = HashMap::new();
        for input in prove_ir
            .public_inputs
            .iter()
            .chain(prove_ir.witness_inputs.iter())
        {
            match &input.array_size {
                Some(ir_forge::ArraySize::Literal(n)) => {
                    for i in 0..*n {
                        let elem_name = format!("{}_{i}", input.name);
                        let fe = scope_values.get(&elem_name).ok_or_else(|| {
                            ProveError::IrLowering(format!(
                                "variable `{elem_name}` not found in scope"
                            ))
                        })?;
                        inputs.insert(elem_name, *fe);
                    }
                }
                None => {
                    let fe = scope_values.get(&input.name).ok_or_else(|| {
                        ProveError::IrLowering(format!(
                            "variable `{}` not found in scope",
                            input.name
                        ))
                    })?;
                    inputs.insert(input.name.clone(), *fe);
                }
                Some(ir_forge::ArraySize::Capture(_)) => {
                    // Capture-sized arrays: elements were expanded during instantiation.
                    // The individual element names are already in scope_values.
                }
            }
        }
        for cap in &prove_ir.captures {
            let fe = scope_values.get(&cap.name).ok_or_else(|| {
                ProveError::IrLowering(format!("capture `{}` not found in scope", cap.name))
            })?;
            inputs.insert(cap.name.clone(), *fe);
        }

        // 4b. Circom witness hints: templates imported via `import { T } from "x.circom"`
        //     may produce `CircuitNode::WitnessHint { name, hint }` nodes for intermediate
        //     signals that are witness-only (e.g., `IsZero`'s `inv <-- 1/in`). The IR
        //     evaluator treats these as `Instruction::Input { Witness }` wires, so their
        //     values must be computed off-circuit and supplied in the inputs map before
        //     R1CS / Plonkish compilation. Reuses the same `compute_witness_hints` helper
        //     that `ach circom` uses for standalone circuits.
        //
        //     `compute_witness_hints` walks the whole ProveIR body, including the
        //     library-mode wiring `Let`s emitted by `instantiate_template_into`, so the
        //     mangled `{prefix}.sig` names in hint expressions resolve against the
        //     caller-supplied values. The returned map supersets `inputs`; we merge it
        //     back, keeping existing keys authoritative so explicit public / witness
        //     values always win over hint-computed ones.
        //     The same big-integer `<--` hints are lifted into Artik programs
        //     that the R1CS witness fill re-executes. Routing this hint walk
        //     through a shared `ArtikMemo` lets the fill reuse these results
        //     instead of recomputing them; the cache is content-addressed, so
        //     the witness is byte-identical with or without it.
        //
        //     The R1CS path runs the walk after constraint emission (the
        //     hint env then never coexists with the program); the Plonkish
        //     compiler reads the full input map up front, so its walk stays
        //     here.
        match self.backend {
            ProveBackend::R1cs => self.prove_r1cs(program, &prove_ir, inputs),
            ProveBackend::Plonkish => {
                let mut artik_memo = artik::ArtikMemo::<memory::Bn254Fr>::new();
                walk_circom_hints(&prove_ir, &mut inputs, &mut artik_memo)?;
                self.prove_plonkish(&program, &inputs)
            }
        }
    }
}

/// Evaluate the circom `<--` witness hints for `prove_ir` and merge the
/// results into `inputs` (existing keys stay authoritative). The Artik
/// executions performed by the walk land in `artik_memo` for the witness
/// fill to reuse.
fn walk_circom_hints(
    prove_ir: &ir_forge::ProveIR,
    inputs: &mut HashMap<String, FieldElement>,
    artik_memo: &mut artik::ArtikMemo<memory::Bn254Fr>,
) -> Result<(), ProveError> {
    match circom::witness::compute_witness_hints_with_captures_memo::<memory::Bn254Fr>(
        prove_ir,
        inputs,
        &HashMap::new(),
        artik_memo,
    ) {
        Ok(hint_env) => {
            for (name, fe) in hint_env {
                inputs.entry(name).or_insert(fe);
            }
            Ok(())
        }
        Err(e) => Err(ProveError::IrLowering(format!(
            "circom witness hint computation failed: {e}"
        ))),
    }
}

/// Wrapper to share a `DefaultProveHandler` via `Arc` while satisfying
/// the orphan rule (cannot impl foreign trait for `Arc<LocalType>`).
pub struct SharedProveHandler(pub Rc<DefaultProveHandler>);

impl ProveHandler for SharedProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        self.0.execute_prove_ir(prove_ir_bytes, scope_values)
    }
}

impl VerifyHandler for DefaultProveHandler {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        match self.prime_id {
            PrimeId::Bn254 => proving::groth16_bn254::verify_proof_from_json(
                &proof.proof_json,
                &proof.public_json,
                &proof.vkey_json,
            ),
            PrimeId::Bls12_381 => proving::groth16_bls12_381::verify_proof_from_json(
                &proof.proof_json,
                &proof.public_json,
                &proof.vkey_json,
            ),
            other => Err(format!(
                "proof verification not supported for prime `{}`",
                other.name()
            )),
        }
    }
}

impl VerifyHandler for SharedProveHandler {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        self.0.verify_proof(proof)
    }
}

impl DefaultProveHandler {
    fn prove_r1cs(
        &self,
        program: ir::IrProgram,
        prove_ir: &ir_forge::ProveIR,
        mut inputs: HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        // Prover constructor: identical constraint surface, but skips the
        // per-constraint origin log — this path never reads origins (they
        // are cleared by the linear optimizer before the verify below).
        let mut r1cs = R1CSCompiler::new_prover();
        r1cs.prime_id = self.prime_id;
        let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
        r1cs.set_proven_boolean(proven);
        // The explicit `cs.verify` below validates the witness, so the costly
        // up-front IR evaluation of the fused compile-and-fill entry point is
        // redundant.
        r1cs.set_skip_eval_validation(true);
        r1cs.compile_ir(&program)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;
        // The IR program and the emission lookup state are dead once
        // constraints are emitted; shed them before the witness fill and the
        // memory-heavy proof setup.
        drop(program);
        r1cs.release_emission_state();

        // Hint walk after emission: the multi-million-entry hint env never
        // coexists with the program plus the emission working set. The
        // witness fill below re-runs the same big-integer programs the walk
        // executes, and the shared cache turns those into hits.
        let mut artik_memo = artik::ArtikMemo::<memory::Bn254Fr>::new();
        walk_circom_hints(prove_ir, &mut inputs, &mut artik_memo)?;
        r1cs.set_artik_memo(artik_memo);

        let mut witness = r1cs
            .fill_witness(&inputs)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;
        drop(inputs);

        // This path proves exactly once: the witness-op trace is never
        // replayed after the fill. Shed it (and the Artik cache) before the
        // optimizer's transient peak.
        r1cs.witness_ops = Default::default();
        let _ = r1cs.take_artik_memo();

        // Finalize the R1CS before proving. Linear-constraint elimination
        // shrinks the system the proof is generated over — a smaller proving
        // key and faster setup / proof generation — without changing the
        // statement. Wires eliminated by substitution are re-derived from the
        // substitution map, then the optimized system is verified. This mirrors
        // the R1CS serialize path, which already finalizes before emitting.
        let _ = r1cs.optimize_r1cs();
        if let Some(subs) = &r1cs.substitution_map {
            for (var_idx, lc) in subs {
                witness[*var_idx] = lc
                    .evaluate(&witness)
                    .map_err(|e| ProveError::Compilation(format!("witness fixup failed: {e}")))?;
            }
        }

        r1cs.cs
            .verify(&witness)
            .map_err(|e| ProveError::Verification(format!("{e}")))?;

        let n_constraints = r1cs.cs.num_constraints();
        // Proof generation needs only the constraint system and the witness;
        // drop the rest of the compile working set before the SNARK setup.
        let cs = r1cs.into_constraint_system();

        // Dispatch to the correct Groth16 prover based on prime
        let result = match self.prime_id {
            PrimeId::Bn254 => {
                proving::groth16_bn254::generate_proof(&cs, &witness, &self.cache_dir)
                    .map_err(ProveError::ProofGeneration)?
            }
            PrimeId::Bls12_381 => {
                proving::groth16_bls12_381::generate_proof(&cs, &witness, &self.cache_dir)
                    .map_err(ProveError::ProofGeneration)?
            }
            other => {
                return Err(ProveError::ProofGeneration(format!(
                    "Groth16 proof generation not supported for prime `{}`",
                    other.name()
                )));
            }
        };

        if self.verbose {
            if let ProveResult::Proof { ref proof_json, .. } = result {
                eprintln!(
                    "{} (Groth16, {} bytes)",
                    self.style.success("Proof generated"),
                    format_number(proof_json.len())
                );
                eprintln!(
                    "{} — {} constraints",
                    self.style.green("Proof verified"),
                    format_number(n_constraints)
                );
            }
        }

        Ok(result)
    }

    fn prove_plonkish(
        &self,
        program: &ir::IrProgram,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        let mut compiler = PlonkishCompiler::new();
        let proven = ir::passes::bool_prop::compute_proven_boolean(program);
        compiler.set_proven_boolean(proven);
        compiler
            .compile_ir_with_witness(program, inputs)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;

        let n_rows = compiler.num_circuit_rows();

        compiler
            .system
            .verify()
            .map_err(|e| ProveError::Verification(format!("plonkish: {e}")))?;

        let result = proving::halo2_proof::generate_plonkish_proof(compiler, &self.cache_dir)
            .map_err(ProveError::ProofGeneration)?;

        if self.verbose {
            if let ProveResult::Proof { ref proof_json, .. } = result {
                eprintln!(
                    "{} (PlonK/halo2, {} bytes)",
                    self.style.success("Proof generated"),
                    format_number(proof_json.len())
                );
                eprintln!(
                    "{} — {} rows",
                    self.style.green("Proof verified"),
                    format_number(n_rows)
                );
            }
        }

        Ok(result)
    }
}
