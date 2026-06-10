//! Memory-release hooks for the proving flow.
//!
//! Constraint emission retains several large lookup structures that later
//! pipeline stages never read (the SSA -> LC cache alone is hundreds of MB
//! on circuits with millions of instructions). The methods here let the
//! prove flow shed that state at the two natural boundaries — after
//! emission, and right before key generation — so the SNARK setup runs on
//! the constraint system + witness alone instead of the whole compile
//! working set.

use super::*;

impl<F: FieldBackend> R1CSCompiler<F> {
    /// Drop the emission-only lookup state once constraint emission is
    /// complete.
    ///
    /// Frees the SSA -> LC cache, the SSA use-tracking bitset, the proven
    /// range bounds, the divmod gadget cache, and the boolean-knowledge sets
    /// (proven + already-enforced). None of these are read by
    /// `fill_witness`, `optimize_r1cs*`, `cs.verify`, or proof generation —
    /// they exist only to resolve operands and skip redundant constraints
    /// while instructions are being compiled. A later `compile_ir` /
    /// `compile_instructions` call on the same instance stays correct
    /// because those entry points clear the operand caches on entry anyway
    /// (a fresh proven-boolean set would need `set_proven_boolean` again,
    /// as with any new program).
    ///
    /// Callers feeding one program in multiple batches via
    /// `compile_instructions_streaming` must not call this between batches:
    /// operand lookup state has to survive until the last batch is emitted.
    pub fn release_emission_state(&mut self) {
        self.lc_map.clear();
        self.used_ssa.clear();
        self.range_bounds = HashMap::new();
        self.divmod_cache = HashMap::new();
        self.bool_enforced = std::collections::HashSet::new();
        self.proven_boolean = std::collections::HashSet::new();
    }

    /// Consume the compiler and return only its constraint system.
    ///
    /// Everything else — the witness-op trace, the Artik caches, the
    /// substitution map, input-name metadata, and the emission lookup state —
    /// drops here. Proof generation needs only the constraint system and the
    /// (already filled and fixed-up) witness vector, so the prove flow calls
    /// this right before key generation to shed the dead working set.
    ///
    /// Callers that still need witness replay for further input sets (the
    /// compile-once / prove-many flow) must capture a
    /// [`WitnessGenerator`](crate::witness::WitnessGenerator) first.
    pub fn into_constraint_system(self) -> ConstraintSystem<F> {
        self.cs
    }
}
