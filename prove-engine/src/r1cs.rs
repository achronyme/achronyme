use std::collections::HashMap;

use akron::{ProveError, ProveResult};
use memory::field::PrimeId;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

use crate::{walk_circom_hints, ProofEvent, ProveBackend, ProveEngine};

impl ProveEngine {
    pub(crate) fn prove_r1cs(
        &self,
        program: ir::IrProgram,
        prove_ir: &ir_forge::ProveIR,
        mut inputs: HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        // Prover constructor: identical constraint surface, but skips the
        // per-constraint origin log — this path never reads origins (they
        // are cleared by the linear optimizer before the verify below).
        let mut r1cs = R1CSCompiler::new_prover();
        r1cs.prime_id = self.opts.prime_id;
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
        let result = match self.opts.prime_id {
            PrimeId::Bn254 => {
                proving::groth16_bn254::generate_proof(&cs, &witness, &self.opts.cache_dir)
                    .map_err(ProveError::ProofGeneration)?
            }
            PrimeId::Bls12_381 => {
                proving::groth16_bls12_381::generate_proof(&cs, &witness, &self.opts.cache_dir)
                    .map_err(ProveError::ProofGeneration)?
            }
            other => {
                return Err(ProveError::ProofGeneration(format!(
                    "Groth16 proof generation not supported for prime `{}`",
                    other.name()
                )));
            }
        };

        if let ProveResult::Proof { ref proof_json, .. } = result {
            self.observer.on_proof_generated(&ProofEvent {
                backend: ProveBackend::R1cs,
                count: n_constraints,
                proof_len: proof_json.len(),
            });
        }

        Ok(result)
    }
}
