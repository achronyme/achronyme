//! fold-known-array-index pass: post-substitute known-array index fold.
//!
//! Sibling pass to [`crate::lowering::loop_var_subst`]. Where
//! `substitute_loop_var` is strictly env-free, this pass is
//! **env-coupled**: it consults a snapshot of
//! `LoweringEnv::known_array_values` to resolve `ArrayIndex` reads
//! whose `array` is a compile-time `EvalValue::Array` (e.g. Poseidon's
//! `C[i+r]`, BabyJubjub's coefficient tables, etc.) once their `index`
//! has folded to a single `Const`.
//!
//! ## Why this pass exists
//!
//! Memoizing a loop body whose strategy is `LoopLowering::KnownArrayRefs`
//! requires emitting `CircuitExpr::ArrayIndex { array, index: <symbolic
//! with LoopVar(token)> }` during iter-0 capture so that
//! `substitute_loop_var` can rewrite the `LoopVar(token)` leaf per
//! replay iteration. Without this fold the substituted node would carry
//! `ArrayIndex { array: "C", index: BinOp(Const(N), Const(r)) }` into
//! instantiate, which would then fail because `C` has no instantiate-env
//! binding (it lives only in lowering's `known_array_values`). The
//! legacy unroll path collapses `C[i+r]` to `Const(fc)` directly via
//! `lower_index` Case 0; this pass mirrors that collapse late, AFTER
//! `substitute_loop_var` makes the index foldable.
//!
//! ## Contract
//!
//! - **1-D and uniformly-dimensioned 2-D shapes.** The pass folds
//!   `ArrayIndex { array, index }` nodes whose `index` constant-folds to
//!   a single `FieldConst` representing a row-major linearised index. For
//!   1-D `EvalValue::Array([scalar0, scalar1, ...])` the linearised
//!   index is just the array position. For 2-D `EvalValue::Array([
//!   Array([s00, ..]), Array([s10, ..]), ...])` with uniform inner
//!   length, the linearised index `linear` decomposes to `arr[linear /
//!   inner_len][linear % inner_len]`, mirroring `lower_multi_index`'s
//!   row-major linearisation via row strides. Non-uniform 2-D shapes,
//!   3-D+ shapes, and missing-key / non-foldable indices are passthrough.
//! - **Why 2-D matters.** memoization admit/soundness check admits Mix's outer-i
//!   body for memoization, which reads `M[j][i]` with `M` a uniform t×t
//!   matrix in `known_array_values` (no `env.strides` registered, but
//!   `lower_multi_index` derives strides from the kav structure on the
//!   spot). After substitute, the residual `ArrayIndex { array: "M",
//!   index: Const(j*t + i) }` reaches this pass; the 2-D linearisation
//!   below collapses it to the scalar leaf.
//! - **Pass-through on missing keys / non-foldable indices.** A node
//!   whose `array` isn't in `kav`, or whose `index` doesn't constant-
//!   fold, is left structurally unchanged. Defence-in-depth phantom-
//!   guards (E213) catch the symbolic-residual case at the lowering
//!   site upstream.
//! - **Exhaustive match style.** Walker mirrors `loop_var_subst.rs`'s
//!   exhaustive-no-wildcard match so any future `CircuitNode` /
//!   `CircuitExpr` variant forces a compile-time review of fold
//!   semantics.
//!
//! ## Invocation
//!
//! Called from `memoize_loop` (`statements/loops.rs`) once per
//! captured iteration body — both the in-place iter-`start`
//! substitution and each per-iter replay — immediately after
//! `substitute_loop_var`.
//!
//! ## Commit history
//!
//! - `3b4a3707` Edits 1+2 — module + walker + unit tests.
//! - `41538cc0` Edits 3+4+5 — E213 phantom-`ArrayIndex` guards
//!   relaxed at single-dim (`expressions/mod.rs`) and multi-dim
//!   (`expressions/indexing.rs`) lowering sites so the symbolic
//!   `ArrayIndex` flows through to this fold pass instead of erroring.
//! - `f4488f7e` Edit 6 — `substitute_then_fold_matches_hand_unrolled_iter_n`
//!   composition contract pin in the unit-test module below.
//! - `2bd57034` Edits 7+8 — `is_memoizable` strategy gate drop
//!   accepts `KnownArrayRefs` alongside `IndexedAssignmentLoop`, plus
//!   the `memoize_loop` wire-up that calls this fold pass after both
//!   `substitute_loop_var` invocations.

mod fold;

pub use fold::fold_known_array_indices;

#[cfg(test)]
mod tests;
