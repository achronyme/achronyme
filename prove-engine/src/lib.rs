//! Reusable compile→prove→verify engine for Achronyme `prove {}` blocks.
//!
//! This is the single source of truth for the prove pipeline: deserialize
//! a `ProveIR`, instantiate it with the captured scope, compile to the
//! selected backend (R1CS/Groth16 via ark-groth16, or Plonkish via halo2
//! KZG), fill the witness, prove, and verify. The CLI binary and any
//! external embedder drive it through this same code path, so there is no
//! second, drift-prone re-implementation of the proving logic.
//!
//! The engine owns no presentation concern: progress is reported through
//! the [`ProveObserver`] callback, and the key cache directory is supplied
//! via [`ProveOptions`]. An embedder that wants none of that uses
//! [`ProveEngine::new`] (a silent [`NoopObserver`]).

use std::collections::HashMap;
use std::path::PathBuf;

use akron::{ProveError, VerifyHandler};
use memory::field::PrimeId;
use memory::FieldElement;

mod execute;
mod plonkish;
mod r1cs;

/// Backend selection for prove blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProveBackend {
    R1cs,
    Plonkish,
}

/// Configuration for a [`ProveEngine`].
#[derive(Clone, Debug)]
pub struct ProveOptions {
    /// Directory the Groth16 / KZG key cache lives in.
    pub cache_dir: PathBuf,
    /// Which backend `prove {}` blocks compile to.
    pub backend: ProveBackend,
    /// Curve / prime the proof is generated over.
    pub prime_id: PrimeId,
    /// Collect [`ir::stats::CircuitStats`] (keeps the full instantiate path).
    pub circuit_stats: bool,
}

/// A post-proof milestone: a proof was generated and verified.
#[derive(Clone, Copy, Debug)]
pub struct ProofEvent {
    pub backend: ProveBackend,
    /// R1CS constraint count, or Plonkish circuit-row count.
    pub count: usize,
    /// Length in bytes of the serialized proof JSON.
    pub proof_len: usize,
}

/// Observer for engine-internal milestones. Every method defaults to a
/// no-op, so an embedder overrides only what it needs (e.g. the CLI
/// renders styled progress; a server collects the events into a response).
pub trait ProveObserver {
    /// A proof was generated and verified.
    fn on_proof_generated(&self, _event: &ProofEvent) {}
    /// Circuit stats were computed (only when [`ProveOptions::circuit_stats`]).
    fn on_circuit_stats(&self, _stats: ir::stats::CircuitStats) {}
}

/// A [`ProveObserver`] that does nothing.
pub struct NoopObserver;
impl ProveObserver for NoopObserver {}

/// Compiles, proves, and verifies `prove {}` blocks via the IR pipeline.
///
/// Implements [`akron::ProveHandler`] + [`akron::VerifyHandler`], so it can
/// be installed directly into a VM as the prove/verify handler.
pub struct ProveEngine {
    opts: ProveOptions,
    observer: Box<dyn ProveObserver>,
}

impl ProveEngine {
    /// Build an engine with a silent ([`NoopObserver`]) observer.
    pub fn new(opts: ProveOptions) -> Self {
        Self {
            opts,
            observer: Box::new(NoopObserver),
        }
    }

    /// Build an engine with a custom observer.
    pub fn with_observer(opts: ProveOptions, observer: Box<dyn ProveObserver>) -> Self {
        Self { opts, observer }
    }

    /// Verify a proof object against the engine's configured prime.
    pub fn verify(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        match self.opts.prime_id {
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

impl VerifyHandler for ProveEngine {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        self.verify(proof)
    }
}

/// Evaluate the circom `<--` witness hints for `prove_ir` and merge the
/// results into `inputs` (existing keys stay authoritative). The Artik
/// executions performed by the walk land in `artik_memo` for the witness
/// fill to reuse.
pub(crate) fn walk_circom_hints(
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
