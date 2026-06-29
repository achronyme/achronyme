use std::collections::HashMap;

use akron::{ProveError, ProveResult};
use memory::FieldElement;
use zkc::plonkish_backend::PlonkishCompiler;

use crate::{ProofEvent, ProveBackend, ProveEngine};

impl ProveEngine {
    pub(crate) fn prove_plonkish(
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

        let result = proving::halo2_proof::generate_plonkish_proof(compiler, &self.opts.cache_dir)
            .map_err(ProveError::ProofGeneration)?;

        if let ProveResult::Proof { ref proof_json, .. } = result {
            self.observer.on_proof_generated(&ProofEvent {
                backend: ProveBackend::Plonkish,
                count: n_rows,
                proof_len: proof_json.len(),
            });
        }

        Ok(result)
    }
}
