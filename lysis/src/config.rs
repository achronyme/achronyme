//! Lysis execution / validation configuration.
//!
//! Currently carries a single knob — `max_call_depth` — that the
//! validator enforces via the longest-path analysis of RFC §4.5
//! rule 11 and the executor enforces at runtime as a safety net.
//! Future phases will grow this struct with an instruction budget,
//! array-memory budget, and optimization toggles.

/// Validator / executor limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LysisConfig {
    /// Maximum `InstantiateTemplate` depth reached during execution.
    /// Statically enforced via longest-path on the acyclic call graph
    /// (RFC §4.5 rule 11). Default 64 per the RFC; raised via
    /// `achronyme.toml [lysis] max_call_depth = 128` for deep-Merkle
    /// circuits.
    pub max_call_depth: u32,

    /// Hard cap on instructions executed per [`crate::execute`] call.
    /// Matches the Artik analogue; prevents infinite loops in
    /// data-dependent bodies from hanging the compiler.
    pub instruction_budget: u64,
}

impl Default for LysisConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 64,
            instruction_budget: 8_000_000,
        }
    }
}
