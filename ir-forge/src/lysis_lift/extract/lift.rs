use rustc_hash::FxHashSet as HashSet;

use fixedbitset::FixedBitSet;
use memory::{FieldBackend, FieldElement};

use super::super::bta::{classify_loop_unroll, BindingTime};
use super::super::symbolic::{SymbolicNode, SymbolicTree};
use super::error::{ExtractError, MAX_FRAME_SIZE};
use super::layout::{compute_frame_size, CaptureKind, CaptureLayout};
use super::registry::{TemplateRegistry, TemplateSpec};
use crate::ExtendedInstruction;
use ir_core::SsaVar;

// =====================================================================
// Gap 2 Stage 1 — bottom-up lift pass
// =====================================================================
//
// Walks an `ExtendedInstruction` body and, for every `LoopUnroll`
// classified as `BindingTime::Uniform` by BTA, replaces it with a
// `TemplateBody` + `TemplateCall` pair. The lift uses **Option B**
// semantics: the original `LoopUnroll` becomes the body of the new
// template, so the loop runs *inside* the template's frame. Iter_var
// stays local to the template; only outer-scope `SsaVar` references
// (BTA's `OuterRef` skeleton nodes) become captures.
//
// Why Option B instead of Option A (one TemplateCall per iteration):
//
// - Each template gets its own 255-slot frame, so wide single
//   instructions like `Decompose(254)` have room.
// - Symbolic indexed reads/writes (Gap 1 + 1.5) keep working: the
//   per-iteration walker materialisation runs *inside* the template
//   frame, with `walker_const[iter_var]` populated by the local
//   iter_var. No runtime-indexed memory ops needed.
// - Multiple Uniform loops with identical skeletons can share a
//   template body via canonical-bytecode dedup (today every lift
//   gets a fresh id; a future pass will hash bytecode and merge
//   matches).

/// Walk `body` bottom-up; replace each Uniform `LoopUnroll` with a
/// `TemplateBody` + `TemplateCall` pair allocated in `registry`. Loops
/// classified `DataDependent` (or whose nested bodies fail to lift)
/// stay verbatim. Pass-through for non-`LoopUnroll` instructions.
///
/// The closure used for BTA probe-value conversion is fixed to
/// `from_u64(i.unsigned_abs())`. Negative loop bounds are filtered by
/// `classify_loop_unroll` itself (returns `DataDependent` for any
/// range with fewer than 2 valid iterations), so the conversion never
/// sees a negative value in practice.
pub fn lift_uniform_loops<F: FieldBackend>(
    body: Vec<ExtendedInstruction<F>>,
    registry: &mut TemplateRegistry<F>,
    outer_refs: &FixedBitSet,
) -> Result<Vec<ExtendedInstruction<F>>, ExtractError> {
    // For each position `i`, `lift_one(body[i])` needs the set of
    // `SsaVar`s referenced by `body[i+1..]` ∪ `outer_refs`. A Uniform
    // candidate at `i` may not seal any of those vars inside a
    // sibling-invisible template frame, or downstream uses fault.
    //
    // Naive shape — pre-materialise `Vec<FixedBitSet>` of length
    // `body.len()` — costs `body.len() × max_var` bits of live heap.
    // On SHA-256(64) that was ~230k positions × ~480k vars ≈ 13.7 GB.
    //
    // Instead, walk the body in reverse with a single accumulator
    // bitset `acc` representing exactly "vars referenced strictly
    // after the current position". The forward output order is
    // restored by appending each `lift_one` group in reverse and
    // reversing the whole result vector once at the end.
    //
    // Folding refs into `acc` from the rewritten (post-lift) group
    // rather than the original instruction is intentional: a Uniform
    // body's interior `SsaVar`s are sealed inside the template
    // frame and don't escape, so the lifted form references a subset
    // of what the unlifted form would have. Keeping `acc` aligned
    // with the rewritten body is both correct and may unlock
    // additional sibling lifts that would have been blocked by a
    // stale pre-lift over-approximation.
    let mut max_var: usize = outer_refs.len();
    {
        let mut tmp: HashSet<SsaVar> = HashSet::default();
        for inst in &body {
            super::super::walker::collect_in_extinst(inst, &mut tmp);
        }
        for v in &tmp {
            let idx = v.0 as usize;
            if idx >= max_var {
                max_var = idx + 1;
            }
        }
    }
    let outer_refs_padded = pad_to(outer_refs, max_var);

    let mut acc = FixedBitSet::with_capacity(max_var);
    let mut local_set: HashSet<SsaVar> = HashSet::default();
    let mut out_rev: Vec<ExtendedInstruction<F>> = Vec::with_capacity(body.len());
    for inst in body.into_iter().rev() {
        // Computing `total = acc | outer_refs_padded` is only needed
        // when `lift_one` actually consults `outer_refs` — that is,
        // for `LoopUnroll` candidates. The pass-through arm ignores
        // its `outer_refs` argument entirely. Materialising the union
        // for every other ExtendedInstruction was the dominant cost
        // here on heavy circuits (per-instruction clone of an
        // `O(max_var)`-bit bitset over a body in the hundreds of
        // thousands of positions); skip it on the common non-loop
        // path and only build `total` for the rare loop case.
        let lifted = if matches!(inst, ExtendedInstruction::LoopUnroll { .. }) {
            let mut total = acc.clone();
            total.union_with(&outer_refs_padded);
            lift_one(inst, registry, &total)?
        } else {
            vec![inst]
        };
        for new_inst in lifted.into_iter().rev() {
            local_set.clear();
            super::super::walker::collect_in_extinst(&new_inst, &mut local_set);
            for v in &local_set {
                acc.insert(v.0 as usize);
            }
            out_rev.push(new_inst);
        }
    }
    out_rev.reverse();
    Ok(out_rev)
}

/// Return a clone of `bs` grown to at least `len` bits. Used to keep
/// successive bitset operations size-matched without mutating the
/// caller's set in place.
fn pad_to(bs: &FixedBitSet, len: usize) -> FixedBitSet {
    let mut out = bs.clone();
    if out.len() < len {
        out.grow(len);
    }
    out
}

fn lift_one<F: FieldBackend>(
    inst: ExtendedInstruction<F>,
    registry: &mut TemplateRegistry<F>,
    outer_refs: &FixedBitSet,
) -> Result<Vec<ExtendedInstruction<F>>, ExtractError> {
    match inst {
        ExtendedInstruction::LoopUnroll {
            iter_var,
            start,
            end,
            body,
        } => {
            // Bottom-up: lift inner body first so nested Uniform loops
            // become templates inside the outer body before the outer
            // is itself classified. The inner pass threads `outer_refs`
            // through unchanged so its own escape check sees this
            // loop's enclosing-scope references too.
            let inner_lifted = lift_uniform_loops(body, registry, outer_refs)?;
            let loop_unroll = ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body: inner_lifted,
            };

            let details = classify_loop_unroll(&loop_unroll, |i| {
                FieldElement::<F>::from_u64(i.unsigned_abs())
            });

            match details.binding_time {
                BindingTime::Uniform {
                    skeleton,
                    captures: _slot_caps,
                } => {
                    // Escape check: if any SsaVar defined inside the
                    // loop body is consumed by code in any enclosing
                    // scope, lifting to TemplateBody + TemplateCall
                    // with the current empty-`outputs` shape would
                    // seal that var inside the template frame.
                    // `emit_template_body` saves and restores
                    // `ssa_to_reg` around the call, so the parent
                    // frame would lose the binding on return and a
                    // downstream `resolve` would fault with
                    // `walker: undefined SsaVar`. Keep the loop
                    // verbatim instead — the rolled-loop path
                    // preserves bindings in the parent frame.
                    let body_inner = match &loop_unroll {
                        ExtendedInstruction::LoopUnroll { body, .. } => body.as_slice(),
                        _ => unreachable!("loop_unroll constructed above as LoopUnroll"),
                    };
                    let body_defined = super::super::walker::collect_defined_ssa_vars(body_inner);
                    let intersects = body_defined.iter().any(|v| {
                        let idx = v.0 as usize;
                        idx < outer_refs.len() && outer_refs.contains(idx)
                    });
                    if intersects {
                        return Ok(vec![loop_unroll]);
                    }

                    // Clone before the move — if the lift overflows the
                    // frame budget we fall back to the original loop.
                    let fallback = loop_unroll.clone();
                    match lift_uniform_to_template(loop_unroll, skeleton, registry) {
                        Ok(lifted) => Ok(lifted),
                        // Graceful degradation: a Uniform body whose
                        // symbolic skeleton would need more than
                        // `MAX_FRAME_SIZE = 255` producing slots can't
                        // fit one template frame (u8 cap on
                        // `InstantiateTemplate.frame_size`). Rather
                        // than erroring out the whole compile — which
                        // for SHA-256-class circuits would block at
                        // the first oversized Σ helper — keep the
                        // loop inline as if it had classified
                        // `DataDependent`. The walker's per-iter
                        // unroll path handles wide bodies via the
                        // top-level `do_split` mechanism.
                        // Other lift errors (e.g.
                        // `TemplateSpaceExhausted`) are real failures
                        // and propagate.
                        Err(ExtractError::FrameOverflow { .. }) => Ok(vec![fallback]),
                        Err(other) => Err(other),
                    }
                }
                BindingTime::DataDependent => Ok(vec![loop_unroll]),
            }
        }
        // Non-loop instructions pass through unchanged. Nested
        // LoopUnrolls inside `LoopUnroll.body` are handled by the
        // recursive `lift_uniform_loops` call above; loops inside
        // `TemplateBody.body` are reached when the Walker emits the
        // template body (it calls `lift_uniform_loops` on the body
        // before emission via Stage 4 wiring). Here, leave alone.
        other => Ok(vec![other]),
    }
}

/// Build the (`TemplateBody`, `TemplateCall`) pair for one Uniform
/// `LoopUnroll`. The skeleton's `OuterRef` SsaVars become the
/// template's captures (in first-appearance order); slot captures
/// (i.e. iter_var positions) are dropped because the loop runs
/// internally so iter_var is allocated locally by the LoopUnroll arm
/// of `Walker::emit`.
fn lift_uniform_to_template<F: FieldBackend>(
    loop_unroll: ExtendedInstruction<F>,
    skeleton: SymbolicTree<F>,
    registry: &mut TemplateRegistry<F>,
) -> Result<Vec<ExtendedInstruction<F>>, ExtractError> {
    // OuterRef captures only — slots map to the (internal) iter_var.
    let mut outer_refs: Vec<SsaVar> = Vec::new();
    let mut seen: HashSet<SsaVar> = HashSet::default();
    for node in &skeleton.nodes {
        if let SymbolicNode::OuterRef(v) = node {
            if seen.insert(*v) {
                outer_refs.push(*v);
            }
        }
    }
    let n_params = u8::try_from(outer_refs.len()).map_err(|_| ExtractError::FrameOverflow {
        requested: outer_refs.len() as u32,
    })?;

    // Conservative `frame_size` budget: skeleton's producing-node
    // count + n_params from an OuterRef-only layout. The Walker's
    // own LoopUnroll arm allocates the actual iter_var slot at
    // emission time inside the template frame — that consumes one
    // additional slot, so reserve it here. This is over-approximate
    // (true live-set frame sizing is future work) but tight enough that
    // SHA-256-shaped bodies fit within `MAX_FRAME_SIZE = 255`.
    let layout = CaptureLayout {
        entries: outer_refs
            .iter()
            .copied()
            .map(CaptureKind::OuterRef)
            .collect(),
    };
    let producing_plus_params = compute_frame_size(&skeleton, &layout)?;
    // +1 for iter_var allocated locally inside the template.
    let frame_total = u32::from(producing_plus_params).saturating_add(1);
    if frame_total > MAX_FRAME_SIZE {
        return Err(ExtractError::FrameOverflow {
            requested: frame_total,
        });
    }
    let frame_size = frame_total as u8;

    let template_id = registry.allocate_fresh()?;

    // Stash a spec so downstream tooling (diagnostics, future dedup,
    // tests) can introspect what was lifted. The walker reads the
    // template body from the IR stream's `TemplateBody` node, not
    // from this spec.
    registry.insert(TemplateSpec {
        id: template_id,
        frame_size,
        layout,
        skeleton,
    });

    Ok(vec![
        ExtendedInstruction::TemplateBody {
            id: template_id,
            frame_size,
            n_params,
            captures: outer_refs.clone(),
            body: vec![loop_unroll],
        },
        ExtendedInstruction::TemplateCall {
            template_id,
            captures: outer_refs,
            outputs: vec![],
        },
    ])
}
