//! Lysis execution / validation configuration.
//!
//! Currently carries a single knob — `max_call_depth` — that the
//! validator enforces via the longest-path analysis of
//! rule 11 and the executor enforces at runtime as a safety net.
//! Future phases will grow this struct with an instruction budget,
//! array-memory budget, and optimization toggles.

/// Validator / executor limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LysisConfig {
    /// Maximum `InstantiateTemplate` depth reached during execution.
    /// Statically enforced via longest-path on the acyclic call graph
    /// and re-checked at runtime as a safety net.
    ///
    /// The RFC's nominal default was 64, which assumed walker output
    /// where each split chained at most a handful of templates. The
    /// heap-spill walker invalidates that: SHA-256(64) emits ~1287
    /// chained templates and a longest-path of ~870 because each
    /// split instantiates the next template tail-call style. The
    /// default here is 8192 to cover SHA-256-class circuits with
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

impl LysisConfig {
    /// Config for the compiler-internal replay of walker-generated
    /// bytecode (the instantiate / round-trip path that encodes,
    /// decodes and executes a program produced by the walker within
    /// one call).
    ///
    /// On that path termination is guaranteed structurally, so the
    /// `instruction_budget` — whose only purpose is to bound a
    /// non-terminating data-dependent body — does not apply and is
    /// lifted (`u64::MAX`, no cap):
    ///
    /// - the only backward control flow is `LoopUnroll`, whose bounds
    ///   are compile-time `u32` constants baked into the opcode (no
    ///   runtime value can extend an iteration count);
    /// - `JumpIf` always falls through and `Jump` is a static offset,
    ///   so no field value can redirect control flow;
    /// - the call graph is acyclic with a bounded longest path,
    ///   enforced statically and re-checked at runtime via
    ///   `max_call_depth`.
    ///
    /// The instruction budget therefore only ever truncated
    /// legitimate emission of large-but-finite circuits on this path.
    /// `max_call_depth` is retained unchanged: it is the structural
    /// guard for the call-graph axis. [`LysisConfig::default`] keeps
    /// the finite `instruction_budget` as the backstop for any other
    /// (e.g. adversarial-bytecode) executor caller.
    pub fn for_internal_replay() -> Self {
        Self {
            instruction_budget: u64::MAX,
            ..Self::default()
        }
    }
}
