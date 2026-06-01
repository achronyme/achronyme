use super::*;

pub(super) fn partition_live_set<F: FieldBackend>(
    live: &[SsaVar],
    upcoming_body: &[ExtendedInstruction<F>],
    force_hot: &HashSet<SsaVar>,
) -> (Vec<SsaVar>, Vec<SsaVar>) {
    // Scan window: bound at 256 to amortise O(N) over the whole
    // walker pass. SHA-256(64) round bodies are well under 256
    // instructions; for circuits with longer prologues the cap means
    // we under-promote a few late-referenced hot vars to cold, which
    // costs one LoadHeap each (≤ 1ms in the SHA-256 measurement).
    const SCAN_WINDOW: usize = 256;
    let scan = &upcoming_body[..upcoming_body.len().min(SCAN_WINDOW)];

    // Build first-use index. usize::MAX = "never seen in window".
    let mut first_use: HashMap<SsaVar, usize> =
        HashMap::with_capacity_and_hasher(live.len(), FxBuildHasher);
    for (i, inst) in scan.iter().enumerate() {
        collect_operands_extinst(inst, &mut |v| {
            first_use.entry(v).or_insert(i);
        });
    }

    // Sort the live set by (force_hot first, then first_use, then SsaVar.0).
    // `force_hot` is collapsed to first_use=0 to push them to the front.
    let mut sorted = live.to_vec();
    sorted.sort_by_key(|v| {
        let key0 = if force_hot.contains(v) { 0 } else { 1 };
        let key1 = first_use.get(v).copied().unwrap_or(usize::MAX);
        (key0, key1, v.0)
    });

    let cap = MAX_CAPTURES_HOT.min(sorted.len());
    let cold = sorted.split_off(cap);
    let mut hot = sorted;
    // hot must come back sorted by SsaVar.0 to match the existing
    // capture-slot stability contract (compute_live_set sorts that
    // way before partition; perform_split assigns slot i = hot[i]).
    // The first-use ordering above is just for selection; once we've
    // picked `cap` hot vars, re-sort them by SsaVar.0 so capture
    // slots are deterministic.
    hot.sort_unstable_by_key(|v| v.0);
    let mut cold = cold;
    cold.sort_unstable_by_key(|v| v.0);
    (hot, cold)
}

/// Walk an `ExtendedInstruction` slice (recursing into LoopUnroll
/// bodies) and collect every SSA var that appears as an *operand*
/// — `result` slots are ignored because they are produced by the
/// instruction, not consumed. Used by [`Walker::do_split`] to
/// compute the live capture set at a top-level boundary.
///
/// Returns the FULL referenced set; never early-returns. The
/// previous early-return at `MAX_CAPTURES` was unsound: when a body
/// referenced more than `MAX_CAPTURES` distinct vars, vars that
/// happened to first appear after the cap were silently dropped from
/// the set. `compute_live_set` then filtered `ssa_to_reg` against an
/// incomplete set, dropping live vars from the post-split frame and
/// surfacing later as `UndefinedSsaVar` at the unbound consumer
/// (canonical case: SHA-256(64), where ~250 vars span any do_split).
/// Scanning the full body is O(N); the caller decides whether the
/// result fits via `compute_live_set`.
pub(crate) fn collect_referenced_ssa_vars<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> HashSet<SsaVar> {
    let mut out = HashSet::default();
    for inst in body {
        collect_in_extinst(inst, &mut out);
    }
    out
}

/// Collect every `SsaVar` *defined* (as a `result` / output) anywhere in
/// `body`. Mirrors [`collect_referenced_ssa_vars`] on the write side and
/// recurses through nested `LoopUnroll` / `TemplateBody` bodies so a
/// SsaVar produced N levels deep is still reported as body-defined at
/// the top level.
///
/// Used by [`Walker::emit_loop_unroll_per_iter_inner`] to strip
/// body-defined entries from `ssa_to_heap` at every iter restore: each
/// per-iter walk re-binds these vars to fresh values, so any prior
/// spill-and-dedup would silently forward iter-0's stale value to
/// iter-1+. Stripping forces the next mid-iter split to allocate a
/// fresh slot per iter, preserving the single-static-store invariant
/// (one `StoreHeap` per slot, globally) *and* the per-iter
/// SSA-after-unroll semantics (each iter's body-defined values are
/// distinct).
pub(crate) fn collect_defined_ssa_vars<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> HashSet<SsaVar> {
    let mut out = HashSet::default();
    for inst in body {
        collect_defined_in_extinst(inst, &mut out);
    }
    out
}

pub(crate) fn collect_defined_in_extinst<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    out: &mut HashSet<SsaVar>,
) {
    match inst {
        ExtendedInstruction::Plain(i) => {
            out.insert(i.result_var());
            for v in i.extra_result_vars() {
                out.insert(*v);
            }
        }
        ExtendedInstruction::LoopUnroll { body, .. } => {
            for nested in body {
                collect_defined_in_extinst(nested, out);
            }
        }
        ExtendedInstruction::TemplateBody { body, .. } => {
            for nested in body {
                collect_defined_in_extinst(nested, out);
            }
        }
        ExtendedInstruction::TemplateCall { outputs, .. } => {
            for v in outputs {
                out.insert(*v);
            }
        }
        ExtendedInstruction::SymbolicArrayRead { result_var, .. } => {
            out.insert(*result_var);
        }
        ExtendedInstruction::SymbolicShift { result_var, .. } => {
            out.insert(*result_var);
        }
        ExtendedInstruction::SymbolicIndexedEffect { .. } => {
            // Side-effect-only — writes into a slot the parent template
            // owns. No new SsaVar produced at this level.
        }
    }
}

/// Precompute, for every SSA var referenced anywhere in `body`, the
/// highest top-level body index at which it is referenced. The
/// `do_split` predicate `v ∈ referenced(body[next_idx..])` is then
/// equivalent to `last_use_idx[v] >= next_idx`.
///
/// The recursion mirrors [`collect_in_extinst`] exactly: references
/// inside a `LoopUnroll.body` count as references at the **outer**
/// body index that contains the LoopUnroll, because that is the
/// boundary at which a top-level split decides whether to capture
/// them.
///
/// Replaces the per-`do_split` rebuild that scanned `body[next_idx..]`
/// from scratch on every split (148 M instruction visits across 1,288
/// SHA-256(64) splits → 5.96 s in `walker.lower`). One forward pass
/// here is O(N) and the per-split cost drops to O(|ssa_to_reg|).
pub(super) fn compute_last_use_idx<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
) -> HashMap<SsaVar, usize> {
    let mut out: HashMap<SsaVar, usize> = HashMap::default();
    for (i, inst) in body.iter().enumerate() {
        record_last_use_in_extinst(inst, i, &mut out);
    }
    out
}

pub(super) fn record_last_use_in_extinst<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    idx: usize,
    out: &mut HashMap<SsaVar, usize>,
) {
    match inst {
        ExtendedInstruction::Plain(i) => record_last_use_in_instruction(i, idx, out),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            for nested in body {
                record_last_use_in_extinst(nested, idx, out);
            }
        }
        ExtendedInstruction::TemplateCall { captures, .. } => {
            for v in captures {
                bump_last_use(out, *v, idx);
            }
        }
        ExtendedInstruction::TemplateBody { .. } => {}
        ExtendedInstruction::SymbolicIndexedEffect {
            array_slots,
            index_var,
            value_var,
            ..
        } => {
            // Mirrors `collect_in_extinst`: every slot in
            // `array_slots` is an enclosing-scope SsaVar (the parent
            // template's signal-element wire) and must survive any
            // top-level split between the LoopUnroll and its parent.
            // Without this, the live-set drops them and
            // `emit_symbolic_indexed_effect`'s synth-on-demand
            // fallback fires inside the post-split template,
            // creating a fresh witness wire that diverges from the
            // parent's `Public`-visibility binding.
            for slot in array_slots {
                bump_last_use(out, *slot, idx);
            }
            bump_last_use(out, *index_var, idx);
            if let Some(v) = value_var {
                bump_last_use(out, *v, idx);
            }
        }
        ExtendedInstruction::SymbolicArrayRead {
            array_slots,
            index_var,
            ..
        } => {
            for slot in array_slots {
                bump_last_use(out, *slot, idx);
            }
            bump_last_use(out, *index_var, idx);
        }
        ExtendedInstruction::SymbolicShift {
            operand_var,
            shift_var,
            ..
        } => {
            bump_last_use(out, *operand_var, idx);
            bump_last_use(out, *shift_var, idx);
        }
    }
}

pub(super) fn record_last_use_in_instruction<F: FieldBackend>(
    inst: &Instruction<F>,
    idx: usize,
    out: &mut HashMap<SsaVar, usize>,
) {
    match inst {
        Instruction::Const { .. } | Instruction::Input { .. } => {}
        Instruction::Add { lhs, rhs, .. }
        | Instruction::Sub { lhs, rhs, .. }
        | Instruction::Mul { lhs, rhs, .. }
        | Instruction::Div { lhs, rhs, .. }
        | Instruction::And { lhs, rhs, .. }
        | Instruction::Or { lhs, rhs, .. }
        | Instruction::IsEq { lhs, rhs, .. }
        | Instruction::IsLt { lhs, rhs, .. }
        | Instruction::IsNeq { lhs, rhs, .. }
        | Instruction::IsLe { lhs, rhs, .. }
        | Instruction::IsLtBounded { lhs, rhs, .. }
        | Instruction::IsLeBounded { lhs, rhs, .. }
        | Instruction::AssertEq { lhs, rhs, .. }
        | Instruction::IntDiv { lhs, rhs, .. }
        | Instruction::IntMod { lhs, rhs, .. } => {
            bump_last_use(out, *lhs, idx);
            bump_last_use(out, *rhs, idx);
        }
        Instruction::Neg { operand, .. }
        | Instruction::Not { operand, .. }
        | Instruction::Assert { operand, .. }
        | Instruction::RangeCheck { operand, .. }
        | Instruction::Decompose { operand, .. } => {
            bump_last_use(out, *operand, idx);
        }
        Instruction::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => {
            bump_last_use(out, *cond, idx);
            bump_last_use(out, *if_true, idx);
            bump_last_use(out, *if_false, idx);
        }
        Instruction::PoseidonHash { left, right, .. } => {
            bump_last_use(out, *left, idx);
            bump_last_use(out, *right, idx);
        }
        Instruction::WitnessCall(call) => {
            for v in &call.inputs {
                bump_last_use(out, *v, idx);
            }
        }
    }
}

#[inline]
pub(super) fn bump_last_use(out: &mut HashMap<SsaVar, usize>, v: SsaVar, idx: usize) {
    out.entry(v)
        .and_modify(|j| {
            if idx > *j {
                *j = idx;
            }
        })
        .or_insert(idx);
}

pub(crate) fn collect_in_extinst<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    out: &mut HashSet<SsaVar>,
) {
    collect_operands_extinst(inst, &mut |v| {
        out.insert(v);
    });
}

pub(crate) fn collect_operands_extinst<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    visit: &mut impl FnMut(SsaVar),
) {
    match inst {
        ExtendedInstruction::Plain(i) => collect_operands_instruction(i, visit),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            for nested in body {
                collect_operands_extinst(nested, visit);
            }
        }
        // TemplateCall.captures are uses in the parent scope — must
        // cross any top-level split between the call and its
        // surrounding template.
        ExtendedInstruction::TemplateCall { captures, .. } => {
            for v in captures {
                visit(*v);
            }
        }
        // TemplateBody emits sideways into its own template frame
        // and references its captures internally via reg 0..n_params.
        // The captures already appear in the matching TemplateCall's
        // capture list (guaranteed by the lift), so the live-set scan
        // doesn't need to add them again here.
        ExtendedInstruction::TemplateBody { .. } => {}
        // The variant references `index_var`, (for Let) `value_var`,
        // AND every SSA var in `array_slots` — the slots are sibling
        // `Plain(Input)` emissions in the parent template (for public
        // signal outputs the slots are pre-emitted; for internal
        // signals the symbolic emit path synthesizes them) and must
        // cross any top-level split that lands between the parent
        // template and the LoopUnroll. The collector therefore
        // includes `array_slots` so `perform_split` spills them to
        // heap and the post-split `resolve()` auto-faults them via
        // `LoadHeap`. Without this, the synth-on-demand fallback at
        // `emit_symbolic_indexed_effect`'s `ssa_to_reg.get(target)
        //.is_none()` branch would mint a fresh `LoadInput` wire
        // inside the post-split template, turning e.g.
        // `paddedIn_X (Public)` into `__lysis_sym_slot_X (Witness)`
        // and leaving the public output wire unconstrained. The
        // synthesis branch still survives as a fallback for
        // genuinely-internal signal slots that were never backed by
        // a `Plain(Input)` — those are witness wires by design.
        ExtendedInstruction::SymbolicIndexedEffect {
            array_slots,
            index_var,
            value_var,
            ..
        } => {
            for slot in array_slots {
                visit(*slot);
            }
            visit(*index_var);
            if let Some(v) = value_var {
                visit(*v);
            }
        }
        // Read-side mirrors the write-side rationale; see above.
        ExtendedInstruction::SymbolicArrayRead {
            array_slots,
            index_var,
            ..
        } => {
            for slot in array_slots {
                visit(*slot);
            }
            visit(*index_var);
        }
        // Both `operand_var` and `shift_var` are enclosing-scope uses
        // that must cross any top-level split between the LoopUnroll's
        // parent template and the LoopUnroll itself. `result_var` is
        // a definition produced by the shift expansion, so it isn't
        // an operand.
        ExtendedInstruction::SymbolicShift {
            operand_var,
            shift_var,
            ..
        } => {
            visit(*operand_var);
            visit(*shift_var);
        }
    }
}

pub(crate) fn collect_operands_instruction<F: FieldBackend>(
    inst: &Instruction<F>,
    visit: &mut impl FnMut(SsaVar),
) {
    match inst {
        Instruction::Const { .. } | Instruction::Input { .. } => {}
        Instruction::Add { lhs, rhs, .. }
        | Instruction::Sub { lhs, rhs, .. }
        | Instruction::Mul { lhs, rhs, .. }
        | Instruction::Div { lhs, rhs, .. }
        | Instruction::And { lhs, rhs, .. }
        | Instruction::Or { lhs, rhs, .. }
        | Instruction::IsEq { lhs, rhs, .. }
        | Instruction::IsLt { lhs, rhs, .. }
        | Instruction::IsNeq { lhs, rhs, .. }
        | Instruction::IsLe { lhs, rhs, .. }
        | Instruction::IsLtBounded { lhs, rhs, .. }
        | Instruction::IsLeBounded { lhs, rhs, .. }
        | Instruction::AssertEq { lhs, rhs, .. }
        | Instruction::IntDiv { lhs, rhs, .. }
        | Instruction::IntMod { lhs, rhs, .. } => {
            visit(*lhs);
            visit(*rhs);
        }
        Instruction::Neg { operand, .. }
        | Instruction::Not { operand, .. }
        | Instruction::Assert { operand, .. }
        | Instruction::RangeCheck { operand, .. }
        | Instruction::Decompose { operand, .. } => {
            visit(*operand);
        }
        Instruction::Mux {
            cond,
            if_true,
            if_false,
            ..
        } => {
            visit(*cond);
            visit(*if_true);
            visit(*if_false);
        }
        Instruction::PoseidonHash { left, right, .. } => {
            visit(*left);
            visit(*right);
        }
        Instruction::WitnessCall(call) => {
            for v in &call.inputs {
                visit(*v);
            }
        }
    }
}
