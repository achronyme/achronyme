use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use akron::{ProveError, ProveHandler, ProveResult, VerifyHandler};
use memory::field::PrimeId;
use memory::FieldElement;
use prove_engine::{ProofEvent, ProveEngine, ProveObserver, ProveOptions};

use crate::commands::ErrorFormat;
use crate::style::{format_number, Styler};

/// Backend selection for prove blocks (re-exported so existing callers
/// keep importing it from this module).
pub use prove_engine::ProveBackend;

/// Renders the engine's proof milestones to stderr in the CLI's styled
/// format and collects circuit stats for a later `print_circuit_stats`.
/// This is the only CLI-specific presentation concern; the proving logic
/// itself lives in the shared `prove_engine` crate.
struct CliObserver {
    style: Styler,
    verbose: bool,
    collected_stats: Rc<RefCell<Vec<ir::stats::CircuitStats>>>,
}

impl ProveObserver for CliObserver {
    fn on_proof_generated(&self, event: &ProofEvent) {
        if !self.verbose {
            return;
        }
        match event.backend {
            ProveBackend::R1cs => {
                eprintln!(
                    "{} (Groth16, {} bytes)",
                    self.style.success("Proof generated"),
                    format_number(event.proof_len)
                );
                eprintln!(
                    "{} — {} constraints",
                    self.style.green("Proof verified"),
                    format_number(event.count)
                );
            }
            ProveBackend::Plonkish => {
                eprintln!(
                    "{} (PlonK/halo2, {} bytes)",
                    self.style.success("Proof generated"),
                    format_number(event.proof_len)
                );
                eprintln!(
                    "{} — {} rows",
                    self.style.green("Proof verified"),
                    format_number(event.count)
                );
            }
        }
    }

    fn on_circuit_stats(&self, stats: ir::stats::CircuitStats) {
        self.collected_stats.borrow_mut().push(stats);
    }
}

/// Default implementation of `ProveHandler` that compiles and verifies
/// prove blocks via the shared `prove_engine`, generating native proofs
/// (ark-groth16 for R1CS, halo2 KZG for Plonkish) and rendering styled
/// CLI progress.
pub struct DefaultProveHandler {
    engine: ProveEngine,
    collected_stats: Rc<RefCell<Vec<ir::stats::CircuitStats>>>,
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
        let collected_stats = Rc::new(RefCell::new(Vec::new()));
        let observer = CliObserver {
            style,
            verbose,
            collected_stats: Rc::clone(&collected_stats),
        };
        let engine = ProveEngine::with_observer(
            ProveOptions {
                cache_dir,
                backend,
                prime_id,
                circuit_stats,
            },
            Box::new(observer),
        );
        Self {
            engine,
            collected_stats,
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
        self.engine.execute_prove_ir(prove_ir_bytes, scope_values)
    }
}

impl VerifyHandler for DefaultProveHandler {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        self.engine.verify(proof)
    }
}

/// Wrapper to share a `DefaultProveHandler` via `Rc` while satisfying
/// the orphan rule (cannot impl foreign trait for `Rc<LocalType>`).
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

impl VerifyHandler for SharedProveHandler {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        self.0.verify_proof(proof)
    }
}
