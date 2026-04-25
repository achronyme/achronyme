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
    /// (RFC §4.5 rule 11) and re-checked at runtime as a safety net.
    ///
    /// The RFC's nominal default was 64, which assumed walker output
    /// where each split chained at most a handful of templates. Phase 4
    /// changed that assumption: SHA-256(64) emits ~1287 chained
    /// templates and a longest-path of ~870 because each split
    /// instantiates the next template tail-call style. The default
    /// here was raised to 8192 to cover SHA-256-class circuits with
    /// margin. Lower it via `achronyme.toml` when tighter bounds
    /// matter (e.g. `[lysis] max_call_depth = 128` for small
    /// circuits to catch recursion bugs early).
    pub max_call_depth: u32,

    /// Hard cap on instructions executed per [`crate::execute`] call.
    /// Matches the Artik analogue; prevents infinite loops in
    /// data-dependent bodies from hanging the compiler.
    pub instruction_budget: u64,
}

impl Default for LysisConfig {
    fn default() -> Self {
        Self {
            max_call_depth: 8192,
            instruction_budget: 8_000_000,
        }
    }
}
