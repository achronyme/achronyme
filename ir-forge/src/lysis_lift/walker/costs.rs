use super::*;

/// `true` iff `body` (recursively, including nested `LoopUnroll`
/// bodies) contains at least one symbolic-index op — either a
/// `SymbolicIndexedEffect` (write) or a `SymbolicArrayRead` (read).
/// Drives the per-iteration unrolling decision in `emit_loop_unroll`:
/// the rolled runtime `LoopUnroll` opcode can't symbolic-resolve an
/// index against a literal `iter_var`, so any loop that contains
/// either op gets per-iter walker materialisation. Stops at the
/// first hit — short-circuits via `iter::any`.
pub(super) fn body_has_symbolic_op<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    body.iter().any(|inst| match inst {
        ExtendedInstruction::SymbolicIndexedEffect { .. }
        | ExtendedInstruction::SymbolicArrayRead { .. }
        | ExtendedInstruction::SymbolicShift { .. } => true,
        ExtendedInstruction::LoopUnroll { body: nested, .. } => body_has_symbolic_op(nested),
        ExtendedInstruction::Plain(_)
        | ExtendedInstruction::TemplateCall { .. }
        | ExtendedInstruction::TemplateBody { .. } => false,
    })
}

/// Returns `true` when emitting `body` as a single rolled
/// `LoopUnroll` opcode would exceed the frame cap (>= `FRAME_CAP
/// minus FRAME_MARGIN` slots in one body emission). Used to force
/// the per-iter unroll path (`emit_loop_unroll_per_iter`) for loops
/// whose bodies are too wide for the rolled form even when they
/// don't carry symbolic ops. Per-iter unroll then chains the body
/// across mid-iter splits, keeping each chunk under cap.
///
/// Threshold is `FRAME_CAP - FRAME_MARGIN`: a body whose estimated
/// reg cost crosses that line would trigger `Alloc(FrameOverflow)`
/// during a fresh-frame emit, since cost saturates against the cap.
/// Sums recursively into nested LoopUnroll bodies so an outer rolled
/// loop containing a wide inner LoopUnroll also takes the per-iter
/// path. SHA-256(64)'s outer round loop trips this — body cost
/// estimate ≈ 1779 regs for a single rolled emission.
pub(super) fn body_too_wide_for_rolled<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    let mut total: u32 = 0;
    for inst in body {
        total = total.saturating_add(reg_cost_of_extinst(inst));
        if total.saturating_add(FRAME_MARGIN) >= FRAME_CAP {
            return true;
        }
    }
    false
}

/// Best-effort `FieldElement → i64` conversion for walker-side
/// const-prop. Returns `Some(v)` only when `value`'s canonical limbs
/// fit in a non-negative `i64`. Negative values (stored as
/// `field_modulus - x`) are not recovered — they wouldn't fit anyway
/// and indices are non-negative by construction.
pub(super) fn field_to_i64<F: FieldBackend>(value: &FieldElement<F>) -> Option<i64> {
    let limbs = value.to_canonical();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    i64::try_from(limbs[0]).ok()
}

/// Returns `true` iff the body (recursively) contains at least one
/// instruction whose desugaring references the `one` constant register.
/// Used by [`Walker::lower`] to decide whether to eagerly emit a
/// top-level `LoadConst(1)`.
pub(super) fn body_needs_one_const<F: FieldBackend>(body: &[ExtendedInstruction<F>]) -> bool {
    body.iter().any(|inst| match inst {
        ExtendedInstruction::Plain(i) => instruction_needs_one(i),
        ExtendedInstruction::LoopUnroll { body, .. } => body_needs_one_const(body),
        ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => {
            false
        }
        // The variant doesn't desugar through `one` directly. Stage 3
        // unfolds it into a `Plain(Instruction)` whose `instruction_
        // needs_one` is what actually matters; until then `false` is
        // safe (the variant only reaches a frame whose other
        // instructions already drove the answer).
        ExtendedInstruction::SymbolicIndexedEffect { .. } => false,
        // Read-side never desugars through `one` — the walker rebinds
        // an existing slot reg with no extra ops.
        ExtendedInstruction::SymbolicArrayRead { .. } => false,
        // Shift desugars to Decompose + Const/Mul/Add — none of those
        // touch the `one` register either.
        ExtendedInstruction::SymbolicShift { .. } => false,
    })
}

/// Compact trace summary used by the `LYSIS_WALKER_TRACE`
/// diagnostic. Returns a one-line description that surfaces the
/// instruction kind plus the most cost-relevant operand width.
pub(super) fn extinst_summary<F: FieldBackend>(inst: &ExtendedInstruction<F>) -> String {
    match inst {
        ExtendedInstruction::Plain(i) => match i {
            Instruction::Decompose { num_bits, .. } => format!("Decompose({num_bits})"),
            Instruction::WitnessCall(call) => {
                format!("WitnessCall(out={})", call.outputs.len())
            }
            Instruction::Or { .. } => "Or".into(),
            Instruction::IsNeq { .. } => "IsNeq".into(),
            Instruction::IsLe { .. } => "IsLe".into(),
            Instruction::IsLeBounded { .. } => "IsLeBounded".into(),
            Instruction::IntDiv { max_bits, .. } => format!("IntDiv(max_bits={max_bits})"),
            Instruction::IntMod { max_bits, .. } => format!("IntMod(max_bits={max_bits})"),
            Instruction::Div { .. } => "Div".into(),
            other => std::any::type_name_of_val(other).to_string(),
        },
        ExtendedInstruction::LoopUnroll {
            start, end, body, ..
        } => {
            format!("LoopUnroll[{start}..{end}, body_len={}]", body.len())
        }
        ExtendedInstruction::TemplateCall { template_id, .. } => {
            format!("TemplateCall({})", template_id.0)
        }
        ExtendedInstruction::TemplateBody { .. } => "TemplateBody".into(),
        ExtendedInstruction::SymbolicIndexedEffect {
            kind,
            array_slots,
            index_var,
            ..
        } => {
            format!(
                "SymbolicIndexedEffect({:?}, slots={}, idx_var={})",
                kind,
                array_slots.len(),
                index_var
            )
        }
        ExtendedInstruction::SymbolicArrayRead {
            result_var,
            array_slots,
            index_var,
            ..
        } => {
            format!(
                "SymbolicArrayRead(result={}, slots={}, idx_var={})",
                result_var,
                array_slots.len(),
                index_var
            )
        }
        ExtendedInstruction::SymbolicShift {
            result_var,
            operand_var,
            shift_var,
            num_bits,
            direction,
            ..
        } => {
            format!(
                "SymbolicShift({:?}, result={}, op={}, shift_var={}, num_bits={})",
                direction, result_var, operand_var, shift_var, num_bits
            )
        }
    }
}

/// Estimate how many fresh registers an `ExtendedInstruction` would
/// allocate if [`Walker::emit`] handled it under the current
/// per-template allocator. Used by [`Walker::lower`] to decide
/// whether to chain a new template *before* the next emission rather
/// than letting an oversized single instruction blow past the frame
/// cap.
///
/// The numbers must over-approximate, never under-approximate — an
/// underestimate would let `emit_plain` overflow during the alloc
/// loop with no graceful split. Conservative bounds:
///
/// - Most arithmetic ops cost 1 reg (the destination).
/// - `Or` desugars to Add+Mul+Sub ⇒ 3 regs.
/// - `IsNeq`/`IsLe`/`IsLeBounded` desugar to two ops ⇒ 2 regs.
/// - `Decompose(num_bits)` allocates `num_bits` consecutive slots.
/// - `WitnessCall` allocates one reg per output.
/// - `LoopUnroll` body bodies are emitted *once* (regs shared across
///   iterations); cost is the body's cost plus 1 (iter_var).
/// - Side-effect-only ops (`AssertEq`, `Assert`, `RangeCheck`, plain
///   `Input`) consume no destination — but `Input`/`Const` do (they
///   bind the result to a fresh reg).
pub(super) fn reg_cost_of_extinst<F: FieldBackend>(inst: &ExtendedInstruction<F>) -> u32 {
    match inst {
        ExtendedInstruction::Plain(i) => reg_cost_of_instruction(i),
        ExtendedInstruction::LoopUnroll { body, .. } => {
            // 1 for iter_var + sum of body costs (body emits once).
            let mut total: u32 = 1;
            for nested in body {
                total = total.saturating_add(reg_cost_of_extinst(nested));
            }
            total
        }
        // TemplateCall emits one InstantiateTemplate opcode in the
        // parent frame; captures resolve to existing regs without
        // allocating fresh ones. TemplateBody emits sideways into
        // its own template buffer, so it contributes nothing to the
        // parent frame's reg pressure.
        ExtendedInstruction::TemplateCall { .. } | ExtendedInstruction::TemplateBody { .. } => 0,
        // Stage 3 will materialize one synthesized scalar op per
        // iteration of the enclosing LoopUnroll. The body emits
        // ONCE in bytecode (regs shared across iterations), so the
        // per-iteration alloc count is what matters: 1 for the dst
        // wire (the array element binding) plus 0-1 for an Input
        // (WitnessHint kind only). Use 2 as a safe upper bound — it
        // over-approximates and prevents a wide indexed effect from
        // overflowing pre-emit.
        ExtendedInstruction::SymbolicIndexedEffect { .. } => 2,
        // Read-side allocates no fresh reg — the walker rebinds
        // `result_var` to the slot's already-bound register. Cost 0
        // is exact, not over-approximated.
        ExtendedInstruction::SymbolicArrayRead { .. } => 0,
        // Stage 3 emits a Decompose + recompose chain per iteration.
        // The Decompose allocates `num_bits` consecutive slots; the
        // recompose chain accumulates into one further reg. Mirror
        // `Instruction::Decompose`'s cost (which also returns
        // `num_bits`) plus one for the accumulator. The body emits
        // ONCE inside the per-iter walker loop (regs shared across
        // iterations), so this is the exact alloc count, not an
        // over-approximation.
        ExtendedInstruction::SymbolicShift { num_bits, .. } => num_bits.saturating_add(1),
    }
}

/// Count the operand SsaVars that will trigger a `LoadHeap` emit
/// plus a fresh reg alloc inside [`Walker::resolve`] when this
/// instruction is emitted. Each cold operand costs 1 reg on top of
/// the instruction's own [`reg_cost_of_extinst`].
///
/// Without this count, the split-trigger underestimates: a single
/// emit can pull 3 cold operands and a result, costing 4 regs while
/// `reg_cost_of_extinst` reports 1. That mismatch is what surfaces
/// as SHA-256(64)'s `FrameOverflow { requested: 255 }` after a few
/// successful splits.
///
/// "Cold" means: in `ssa_to_heap` (was spilled at some prior split)
/// and not in `ssa_to_reg` (not currently materialised in the frame).
/// A var that is in *both* maps was already lazy-loaded in this
/// template body and the reg slot is reused; it does not re-allocate.
#[allow(clippy::doc_lazy_continuation)] // false positive: docstring is fresh, not continuing the previous fn's bullet list
pub(super) fn cold_load_cost<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    ssa_to_heap: &HashMap<SsaVar, u32>,
    ssa_to_reg: &HashMap<SsaVar, RegId>,
) -> u32 {
    if ssa_to_heap.is_empty() {
        // Fast path: no spilled vars exist program-wide yet, so no
        // operand can be cold. Shortcut for the corpus baseline.
        return 0;
    }
    // Heap-output `WitnessCall` reads its inputs directly from heap
    // slots via `InputSrc::Slot` — no `LoadHeap` is emitted for cold
    // inputs, so cold operands cost 0 frame regs. Mirror the walker's
    // emit-time branch in `emit_plain` so the split-trigger doesn't
    // over-estimate and fragment the program unnecessarily.
    if let ExtendedInstruction::Plain(Instruction::WitnessCall(call)) = inst {
        if call.outputs.len() > MAX_WITNESS_OUTPUTS_INLINE {
            return 0;
        }
    }
    if let ExtendedInstruction::Plain(inst) = inst {
        return cold_load_cost_instruction(inst, ssa_to_heap, ssa_to_reg);
    }
    let mut refs = HashSet::default();
    collect_in_extinst(inst, &mut refs);
    refs.iter()
        .filter(|v| ssa_to_heap.contains_key(v) && !ssa_to_reg.contains_key(v))
        .count() as u32
}

pub(super) fn cold_load_cost_instruction<F: FieldBackend>(
    inst: &Instruction<F>,
    ssa_to_heap: &HashMap<SsaVar, u32>,
    ssa_to_reg: &HashMap<SsaVar, RegId>,
) -> u32 {
    let mut seen = Vec::with_capacity(4);
    let mut count = 0u32;
    collect_operands_instruction(inst, &mut |v| {
        if seen.contains(&v) {
            return;
        }
        seen.push(v);
        if ssa_to_heap.contains_key(&v) && !ssa_to_reg.contains_key(&v) {
            count += 1;
        }
    });
    count
}

pub(super) fn reg_cost_of_instruction<F: FieldBackend>(inst: &Instruction<F>) -> u32 {
    match inst {
        // Side-effect-only — no destination reg.
        Instruction::AssertEq { .. }
        | Instruction::Assert { .. }
        | Instruction::RangeCheck { .. } => 0,

        // Single-destination ops.
        Instruction::Const { .. }
        | Instruction::Input { .. }
        | Instruction::Add { .. }
        | Instruction::Sub { .. }
        | Instruction::Mul { .. }
        | Instruction::Div { .. }
        | Instruction::Neg { .. }
        | Instruction::Not { .. }
        | Instruction::And { .. }
        | Instruction::Mux { .. }
        | Instruction::IsEq { .. }
        | Instruction::IsLt { .. }
        | Instruction::IsLtBounded { .. }
        | Instruction::PoseidonHash { .. }
        | Instruction::IntDiv { .. }
        | Instruction::IntMod { .. } => 1,

        // Multi-step desugarings.
        Instruction::Or { .. } => 3,
        Instruction::IsNeq { .. } | Instruction::IsLe { .. } | Instruction::IsLeBounded { .. } => 2,

        // Variable-cost ops.
        Instruction::Decompose { num_bits, .. } => *num_bits,
        Instruction::WitnessCall(call) => {
            // Outputs above the threshold land in heap slots, not
            // regs. The cost estimator must mirror the walker's
            // emit-time branch: heap-output variant is `cost = 0`
            // for the frame, classic variant is `cost = outputs.len()`.
            if call.outputs.len() > MAX_WITNESS_OUTPUTS_INLINE {
                0
            } else {
                call.outputs.len() as u32
            }
        }
    }
}

pub(super) fn instruction_needs_one<F: FieldBackend>(inst: &Instruction<F>) -> bool {
    matches!(
        inst,
        Instruction::Not { .. }
            | Instruction::Assert { .. }
            | Instruction::IsNeq { .. }
            | Instruction::IsLe { .. }
            | Instruction::IsLeBounded { .. }
    )
}

/// Env-gated tracer for [`Walker::compute_live_set`] outcomes.
///
/// Set `LYSIS_DUMP_LIVESET=1` to emit one stderr line per accepted
/// split (rejected splits trace inside `compute_live_set` itself,
/// since they short-circuit before the caller sees the live count).
/// The output format is stable and grep-friendly:
///
/// ```text
/// [walker] live_set kind=top_level live=12 body=24 template=3
/// [walker] live_set kind=mid_iter  live=7  body=18 template=5
/// [walker] live_set kind=rejected  live=250 cap=64
/// ```
///
/// Intended for corpus analysis: pipe a test run's stderr through
/// `grep '\[walker\] live_set' | awk '{print $3}' | sort | uniq -c`
/// to build a per-corpus histogram of accepted/rejected splits.
pub(super) fn dump_live_set_trace(
    kind: &str,
    live_count: usize,
    body_len: usize,
    template_id: usize,
) {
    if std::env::var("LYSIS_DUMP_LIVESET").is_ok() {
        eprintln!(
            "[walker] live_set kind={kind} live={live_count} body={body_len} template={template_id}"
        );
    }
}
