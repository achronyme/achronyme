//! Lysis oracle — semantic-equivalence checker for the Phase 3 hard gate.
//!
//! Given two `IrProgram<F>` produced by different paths (the legacy
//! `instantiate` pipeline and the new Lysis lifter), the oracle decides
//! whether they describe the same circuit. Lives in `ir` for the same
//! reason the lifter does: the input type is `ir::IrProgram<F>` and a
//! reverse `lysis → ir` dep would cycle through the Phase 3.A bridge.
//!
//! ## Submodules
//!
//! | Module | Deliverable | RFC |
//! |---|---|---|
//! | [`canonicalize`] | `canonicalize_ssa` — topological renaming of SsaVars to `0..N` so structurally-equivalent programs produce identical Vec-shaped IR | §9.1 step 1 |
//! | `compare` (3.C.2) | `semantic_equivalence` — 4-step pipeline (canonicalize → partition → multiset compare → witness compare) | §9.1 |

pub mod canonicalize;

pub use canonicalize::canonicalize_ssa;
