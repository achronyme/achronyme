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
        //    via Lysis (Walker → InterningSink → materialise).
        let mut program = prove_ir
            .instantiate_lysis(scope_values)
            .map_err(|e| ProveError::IrLowering(format!("{e}")))?;

        // 3. Optimize
        ir::passes::optimize(&mut program);

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
        match circom::witness::compute_witness_hints::<memory::Bn254Fr>(&prove_ir, &inputs) {
            Ok(hint_env) => {
                for (name, fe) in hint_env {
                    inputs.entry(name).or_insert(fe);
                }
            }
            Err(e) => {
                return Err(ProveError::IrLowering(format!(
                    "circom witness hint computation failed: {e}"
                )));
            }
        }

        match self.backend {
            ProveBackend::R1cs => self.prove_r1cs(&program, &inputs),
            ProveBackend::Plonkish => self.prove_plonkish(&program, &inputs),
        }
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
        program: &ir::IrProgram,
        inputs: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        let mut r1cs = R1CSCompiler::new();
        r1cs.prime_id = self.prime_id;
        let proven = ir::passes::bool_prop::compute_proven_boolean(program);
        r1cs.set_proven_boolean(proven);
        let witness = r1cs
            .compile_ir_with_witness(program, inputs)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;

        r1cs.cs
            .verify(&witness)
            .map_err(|e| ProveError::Verification(format!("{e}")))?;

        let n_constraints = r1cs.cs.num_constraints();

        // Dispatch to the correct Groth16 prover based on prime
        let result = match self.prime_id {
            PrimeId::Bn254 => {
                proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &self.cache_dir)
                    .map_err(ProveError::ProofGeneration)?
            }
            PrimeId::Bls12_381 => {
                proving::groth16_bls12_381::generate_proof(&r1cs.cs, &witness, &self.cache_dir)
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
