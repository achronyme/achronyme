use std::collections::HashMap;
use std::path::PathBuf;

use compiler::plonkish_backend::PlonkishCompiler;
use compiler::r1cs_backend::R1CSCompiler;
use ir::IrLowering;
use memory::FieldElement;
use vm::{ProveError, ProveHandler, ProveResult, VerifyHandler};

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
    style: Styler,
    verbose: bool,
}

impl DefaultProveHandler {
    pub fn new(backend: ProveBackend, error_format: ErrorFormat) -> Self {
        let cache_dir = crate::cache_dir();
        let style = Styler::from_env(&error_format);
        let verbose = style.is_verbose(&error_format);
        Self {
            cache_dir,
            backend,
            style,
            verbose,
        }
    }
}

impl ProveHandler for DefaultProveHandler {
    fn execute_prove(
        &self,
        source: &str,
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        // 1. Strip braces: source comes as "{ witness s\npublic h\n... }"
        let inner = source
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(source);

        // 2. Lower IR (self-contained: extracts public/witness from source)
        let (pub_names, wit_names, mut program) = IrLowering::lower_self_contained(inner)
            .map_err(|e| ProveError::IrLowering(format!("{e}")))?;

        // 3. Optimize
        ir::passes::optimize(&mut program);

        // 4. Build input map from scope_values
        let mut inputs = HashMap::new();
        for name in pub_names.iter().chain(wit_names.iter()) {
            let val = scope_values.get(name).ok_or_else(|| {
                ProveError::IrLowering(format!("variable `{name}` not found in scope"))
            })?;
            inputs.insert(name.clone(), *val);
        }

        match self.backend {
            ProveBackend::R1cs => self.prove_r1cs(&program, &inputs),
            ProveBackend::Plonkish => self.prove_plonkish(&program, &inputs),
        }
    }
}

impl VerifyHandler for DefaultProveHandler {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        crate::groth16::verify_proof_from_json(
            &proof.proof_json,
            &proof.public_json,
            &proof.vkey_json,
        )
    }
}

impl DefaultProveHandler {
    fn prove_r1cs(
        &self,
        program: &ir::IrProgram,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        let mut r1cs = R1CSCompiler::new();
        let proven = ir::passes::bool_prop::compute_proven_boolean(program);
        r1cs.set_proven_boolean(proven);
        let witness = r1cs
            .compile_ir_with_witness(program, inputs)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;

        r1cs.cs
            .verify(&witness)
            .map_err(|e| ProveError::Verification(format!("{e}")))?;

        let n_constraints = r1cs.cs.num_constraints();

        let result = crate::groth16::generate_proof(&r1cs.cs, &witness, &self.cache_dir)
            .map_err(ProveError::ProofGeneration)?;

        if self.verbose {
            if let ProveResult::Proof { ref proof_json, .. } = result {
                eprintln!(
                    "{} ({}, {} bytes)",
                    self.style.success("Proof generated"),
                    "Groth16",
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

        let result = crate::halo2_proof::generate_plonkish_proof(compiler, &self.cache_dir)
            .map_err(ProveError::ProofGeneration)?;

        if self.verbose {
            if let ProveResult::Proof { ref proof_json, .. } = result {
                eprintln!(
                    "{} ({}, {} bytes)",
                    self.style.success("Proof generated"),
                    "PlonK/halo2",
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
