//! Bytecode validator — the pre-execution well-formedness gate
//! (RFC §4.5).
//!
//! The validator consumes a [`Program`] that has already been
//! structurally decoded (opcodes parsed, body byte-length matches
//! header, const pool entries are tag-dispatched) and enforces the
//! eleven semantic invariants from the RFC. After `validate` returns
//! `Ok`, the executor can run the program without re-checking any of
//! these properties — the bytecode is *trusted* at that point.
//!
//! # Rule coverage
//!
//! | Rule | Where |
//! |-----:|---|
//! |  1 | `LysisHeader::decode` (magic + version) |
//! |  2 | caller passes `family` to `validate_against_runtime` (Phase 1: off by default; executor invokes it) |
//! |  3 | `bytecode::decode` (`BodyLenMismatch`) |
//! |  4 | [`check_const_bounds`] |
//! |  5 | runtime — [`crate::execute`] (depends on captures slice) |
//! |  6 | [`check_jump_targets`] |
//! |  7 | [`check_templates_defined`] |
//! |  8 | [`check_register_bounds`] |
//! |  9 | [`check_forward_dataflow`] (linear-only; skipped when jumps present, flagged for Phase 2) |
//! | 10 | [`check_reachable_return`] |
//! | 11 | [`check_call_graph`] |
//! | 12 | [`check_heap_slot_bounds`] (Phase 4 — slot < heap_size_hint) |
//! | 13 | [`check_heap_single_static_store`] (Phase 4 — at most one StoreHeap per slot) |
//!
//! Rules 1, 3 are enforced before this module even gets a chance to
//! look at the program, so there is nothing here for them. Rule 5
//! needs the runtime captures slice; it lives in the executor.
//!
//! # Phase 1 simplifications
//!
//! Two rules admit rigorous implementations that the scaffolding
//! Phase 1 defers:
//!
//! - **Rule 9** (no uninitialized register use). Implemented as a
//!   linear scan: a register is considered initialized once written
//!   by an opcode with [`Opcode::writes_register`]. When the body
//!   contains any `Jump`/`JumpIf`, the check bails out with `Ok(())`
//!   — back-edges would require SSA-ish dataflow and the runtime
//!   [`LysisError::ReadUndefinedRegister`] safety net backstops the
//!   executor. Phase 2 replaces this with a proper forward
//!   dataflow.
//!
//! - **Rule 10** (`Return` reachable from every code path). Phase 1
//!   demands that the last instruction of every template body (and
//!   the top-level stream) is a terminator (`Return` / `Halt` /
//!   `Trap`). Bodies with forward jumps are still accepted — the
//!   control-flow analysis that proves all paths reach the
//!   terminator lands in Phase 2.
//!
//! - **Top-level frame size**. The RFC specifies `frame_size` only
//!   for `DefineTemplate`; the top-level body has no explicit frame
//!   size. Phase 1 treats the top-level body as having implicit
//!   `frame_size = 256` (the maximum u8 can address), so rule 8 is a
//!   tautology at top level. Inside a template body, rule 8 is
//!   enforced against that template's declared `frame_size`. Phase 2
//!   may thread an explicit `root_frame_size` through the header.

use std::collections::{HashMap, HashSet};

use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::program::Program;

/// Run every RFC §4.5 rule that is *statically* decidable (i.e., that
/// does not depend on runtime captures). Rule 5 and rule 2 are the
/// executor's responsibility.
pub fn validate<F: FieldBackend>(
    program: &Program<F>,
    config: &LysisConfig,
) -> Result<(), LysisError> {
    check_const_bounds(program)?;
    check_register_bounds(program)?;
    check_jump_targets(program)?;
    check_templates_defined(program)?;
    check_forward_dataflow(program)?;
    check_reachable_return(program)?;
    check_call_graph(program, config)?;
    check_heap_slot_bounds(program)?;
    check_heap_single_static_store(program)?;
    Ok(())
}

// ---------------------------------------------------------------------
// Rule 4 — `LoadConst idx < const_pool_len`
// and the related `EmitWitnessCall bytecode_const_idx`.
// ---------------------------------------------------------------------

fn check_const_bounds<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let pool_len = program.const_pool.len() as u32;
    for instr in &program.body {
        match &instr.opcode {
            Opcode::LoadConst { idx, .. } => {
                if (*idx as u32) >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *idx as u32,
                        len: pool_len,
                    });
                }
            }
            Opcode::LoadInput { name_idx, .. } => {
                if (*name_idx as u32) >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *name_idx as u32,
                        len: pool_len,
                    });
                }
            }
            Opcode::EmitAssertEqMsg { msg_idx, .. } => {
                if (*msg_idx as u32) >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *msg_idx as u32,
                        len: pool_len,
                    });
                }
            }
            Opcode::EmitWitnessCall {
                bytecode_const_idx, ..
            } => {
                if (*bytecode_const_idx as u32) >= pool_len {
                    return Err(LysisError::ConstIdxOutOfRange {
                        at_offset: instr.offset,
                        idx: *bytecode_const_idx as u32,
                        len: pool_len,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Rule 8 — register operand `r < frame_size`.
// Top-level frame_size is 256 (tautology for u8); template bodies use
// their declared frame_size.
// ---------------------------------------------------------------------

fn check_register_bounds<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    for instr in &program.body {
        let frame_size = frame_size_at_offset(program, instr.offset);
        for reg in opcode_registers(&instr.opcode) {
            if (reg as u32) >= frame_size {
                return Err(LysisError::RegisterOutOfRange {
                    at_offset: instr.offset,
                    reg,
                    frame_size,
                });
            }
        }
    }
    Ok(())
}

/// The frame size active at the given offset. Returns 256 when the
/// offset does not fall inside any `DefineTemplate`-declared body.
fn frame_size_at_offset<F: FieldBackend>(program: &Program<F>, offset: u32) -> u32 {
    for t in &program.templates {
        let end = t.body_offset.saturating_add(t.body_len);
        if offset >= t.body_offset && offset < end {
            return t.frame_size as u32;
        }
    }
    256
}

/// Every register operand this opcode reads or writes. Used by the
/// register-bounds and forward-dataflow checks.
fn opcode_registers(op: &Opcode) -> Vec<u8> {
    match op {
        Opcode::LoadCapture { dst, .. }
        | Opcode::LoadConst { dst, .. }
        | Opcode::LoadInput { dst, .. } => vec![*dst],
        Opcode::EnterScope
        | Opcode::ExitScope
        | Opcode::Return
        | Opcode::Halt
        | Opcode::Trap { .. }
        | Opcode::Jump { .. } => Vec::new(),
        Opcode::JumpIf { cond, .. } => vec![*cond],
        Opcode::LoopUnroll { iter_var, .. } | Opcode::LoopRolled { iter_var, .. } => {
            vec![*iter_var]
        }
        Opcode::LoopRange {
            iter_var, end_reg, ..
        } => vec![*iter_var, *end_reg],
        Opcode::DefineTemplate { .. } => Vec::new(),
        Opcode::InstantiateTemplate {
            capture_regs,
            output_regs,
            ..
        } => {
            let mut v = capture_regs.clone();
            v.extend_from_slice(output_regs);
            v
        }
        Opcode::TemplateOutput { src_reg, .. } => vec![*src_reg],
        Opcode::EmitConst { dst, src_reg } => vec![*dst, *src_reg],
        Opcode::EmitAdd { dst, lhs, rhs }
        | Opcode::EmitSub { dst, lhs, rhs }
        | Opcode::EmitMul { dst, lhs, rhs }
        | Opcode::EmitIsEq { dst, lhs, rhs }
        | Opcode::EmitIsLt { dst, lhs, rhs }
        | Opcode::EmitDiv { dst, lhs, rhs } => vec![*dst, *lhs, *rhs],
        Opcode::EmitNeg { dst, operand } => vec![*dst, *operand],
        Opcode::EmitMux {
            dst,
            cond,
            then_v,
            else_v,
        } => vec![*dst, *cond, *then_v, *else_v],
        Opcode::EmitDecompose { dst_arr, src, .. } => vec![*dst_arr, *src],
        Opcode::EmitAssertEq { lhs, rhs } => vec![*lhs, *rhs],
        Opcode::EmitAssertEqMsg { lhs, rhs, .. } => vec![*lhs, *rhs],
        Opcode::EmitRangeCheck { var, .. } => vec![*var],
        Opcode::EmitWitnessCall {
            in_regs, out_regs, ..
        } => {
            let mut v = in_regs.clone();
            v.extend_from_slice(out_regs);
            v
        }
        Opcode::EmitPoseidonHash { dst, in_regs } => {
            let mut v = vec![*dst];
            v.extend_from_slice(in_regs);
            v
        }
        Opcode::EmitIntDiv { dst, lhs, rhs, .. } | Opcode::EmitIntMod { dst, lhs, rhs, .. } => {
            vec![*dst, *lhs, *rhs]
        }
        Opcode::StoreHeap { src_reg, .. } => vec![*src_reg],
        Opcode::LoadHeap { dst_reg, .. } => vec![*dst_reg],
        // Outputs go to heap slots; inputs are mixed reg/slot.
        // Only `Reg(_)` inputs contribute to register-bounds checks.
        Opcode::EmitWitnessCallHeap { inputs, .. } => inputs
            .iter()
            .filter_map(|src| match src {
                crate::bytecode::opcode::InputSrc::Reg(r) => Some(*r),
                crate::bytecode::opcode::InputSrc::Slot(_) => None,
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------
// Rule 6 — `Jump`/`JumpIf` targets land on opcode boundaries inside
// the same template body (no cross-template jumps).
// ---------------------------------------------------------------------

fn check_jump_targets<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let offsets: HashSet<u32> = program.body.iter().map(|i| i.offset).collect();

    for instr in &program.body {
        let rel = match &instr.opcode {
            Opcode::Jump { offset } | Opcode::JumpIf { offset, .. } => *offset as i64,
            _ => continue,
        };

        // Jump is relative to the end of the current opcode per RFC
        // §4.3.2 (`pc += offset`). We can compute the expected
        // absolute offset from the current instruction's offset plus
        // its own encoded length. For this Phase 1 check we simply
        // require the target to land on *some* opcode boundary
        // inside the same template region.
        let target = instr.offset as i64 + rel;
        if target < 0 {
            return Err(LysisError::BadJumpTarget {
                at_offset: instr.offset,
                target_offset: target,
            });
        }
        let target_u32 = target as u32;
        if !offsets.contains(&target_u32) {
            return Err(LysisError::BadJumpTarget {
                at_offset: instr.offset,
                target_offset: target,
            });
        }
        if !same_template_body(program, instr.offset, target_u32) {
            return Err(LysisError::BadJumpTarget {
                at_offset: instr.offset,
                target_offset: target,
            });
        }
    }
    Ok(())
}

fn same_template_body<F: FieldBackend>(program: &Program<F>, src: u32, dst: u32) -> bool {
    let host = program.templates.iter().find(|t| {
        let end = t.body_offset.saturating_add(t.body_len);
        src >= t.body_offset && src < end
    });
    match host {
        Some(t) => {
            let end = t.body_offset.saturating_add(t.body_len);
            dst >= t.body_offset && dst < end
        }
        None => {
            // src lives in top-level body; dst must also be top-level.
            !program.templates.iter().any(|t| {
                let end = t.body_offset.saturating_add(t.body_len);
                dst >= t.body_offset && dst < end
            })
        }
    }
}

// ---------------------------------------------------------------------
// Rule 7 — every InstantiateTemplate references a previously
// DefineTemplate-d id.
// ---------------------------------------------------------------------

fn check_templates_defined<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let known: HashSet<u16> = program.templates.iter().map(|t| t.id).collect();
    for instr in &program.body {
        if let Opcode::InstantiateTemplate { template_id, .. } = &instr.opcode {
            if !known.contains(template_id) {
                return Err(LysisError::UndefinedTemplate {
                    at_offset: instr.offset,
                    template_id: *template_id,
                });
            }
        }
        if let Opcode::LoopRolled {
            body_template_id, ..
        }
        | Opcode::LoopRange {
            body_template_id, ..
        } = &instr.opcode
        {
            if !known.contains(body_template_id) {
                return Err(LysisError::UndefinedTemplate {
                    at_offset: instr.offset,
                    template_id: *body_template_id,
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Rule 9 — forward dataflow: no register read before it is written.
// Linear approximation for Phase 1.
// ---------------------------------------------------------------------

fn check_forward_dataflow<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let has_jumps = program
        .body
        .iter()
        .any(|i| matches!(i.opcode, Opcode::Jump { .. } | Opcode::JumpIf { .. }));
    if has_jumps {
        return Ok(()); // Phase 2: full dataflow analysis.
    }

    // Per-template-body initialized-register tracking. Key = template
    // id, or `None` for the top-level body. When a template body
    // first appears, its `n_params` capture registers (0..n_params)
    // are pre-initialized — the executor's `InstantiateTemplate`
    // handler populates them from the caller's `capture_regs` slice
    // before the body runs. The validator must mirror that contract;
    // otherwise any read from a capture-reg surfaces as a false
    // `UninitializedRegister` rule-9 violation. This matters most
    // post-Phase-4, when the walker emits hundreds of split-driven
    // templates whose first opcodes typically read from captures.
    let mut init: HashMap<Option<u16>, HashSet<u8>> = HashMap::new();
    init.insert(None, HashSet::new());

    for instr in &program.body {
        let host = hosting_template(program, instr.offset);
        let set = init.entry(host).or_insert_with(|| {
            let mut s = HashSet::new();
            if let Some(template_id) = host {
                if let Some(t) = program.templates.iter().find(|t| t.id == template_id) {
                    for i in 0..t.n_params {
                        s.insert(i);
                    }
                }
            }
            s
        });

        let reads = reads_of(&instr.opcode);
        let writes = writes_of(&instr.opcode);

        for r in reads {
            if !set.contains(&r) {
                return Err(LysisError::UninitializedRegister {
                    at_offset: instr.offset,
                    reg: r,
                });
            }
        }
        for w in writes {
            set.insert(w);
        }
    }
    Ok(())
}

fn hosting_template<F: FieldBackend>(program: &Program<F>, offset: u32) -> Option<u16> {
    program
        .templates
        .iter()
        .find(|t| {
            let end = t.body_offset.saturating_add(t.body_len);
            offset >= t.body_offset && offset < end
        })
        .map(|t| t.id)
}

fn reads_of(op: &Opcode) -> Vec<u8> {
    match op {
        Opcode::JumpIf { cond, .. } => vec![*cond],
        Opcode::LoopRange { end_reg, .. } => vec![*end_reg],
        Opcode::InstantiateTemplate { capture_regs, .. } => capture_regs.clone(),
        Opcode::TemplateOutput { src_reg, .. } => vec![*src_reg],
        Opcode::EmitConst { src_reg, .. } => vec![*src_reg],
        Opcode::EmitAdd { lhs, rhs, .. }
        | Opcode::EmitSub { lhs, rhs, .. }
        | Opcode::EmitMul { lhs, rhs, .. }
        | Opcode::EmitIsEq { lhs, rhs, .. }
        | Opcode::EmitIsLt { lhs, rhs, .. }
        | Opcode::EmitDiv { lhs, rhs, .. } => vec![*lhs, *rhs],
        Opcode::EmitNeg { operand, .. } => vec![*operand],
        Opcode::EmitMux {
            cond,
            then_v,
            else_v,
            ..
        } => vec![*cond, *then_v, *else_v],
        Opcode::EmitDecompose { src, .. } => vec![*src],
        Opcode::EmitAssertEq { lhs, rhs } => vec![*lhs, *rhs],
        Opcode::EmitAssertEqMsg { lhs, rhs, .. } => vec![*lhs, *rhs],
        Opcode::EmitRangeCheck { var, .. } => vec![*var],
        Opcode::EmitWitnessCall { in_regs, .. } => in_regs.clone(),
        Opcode::EmitWitnessCallHeap { inputs, .. } => inputs
            .iter()
            .filter_map(|src| match src {
                crate::bytecode::opcode::InputSrc::Reg(r) => Some(*r),
                crate::bytecode::opcode::InputSrc::Slot(_) => None,
            })
            .collect(),
        Opcode::EmitPoseidonHash { in_regs, .. } => in_regs.clone(),
        // StoreHeap reads its src_reg before writing it to the heap;
        // LoadHeap reads from the heap, not from regs (its read-side
        // is governed by Rules 12+13, not Rule 9).
        Opcode::StoreHeap { src_reg, .. } => vec![*src_reg],
        Opcode::EmitIntDiv { lhs, rhs, .. } | Opcode::EmitIntMod { lhs, rhs, .. } => {
            vec![*lhs, *rhs]
        }
        _ => Vec::new(),
    }
}

fn writes_of(op: &Opcode) -> Vec<u8> {
    match op {
        Opcode::LoadCapture { dst, .. }
        | Opcode::LoadConst { dst, .. }
        | Opcode::LoadInput { dst, .. }
        | Opcode::EmitConst { dst, .. }
        | Opcode::EmitAdd { dst, .. }
        | Opcode::EmitSub { dst, .. }
        | Opcode::EmitMul { dst, .. }
        | Opcode::EmitNeg { dst, .. }
        | Opcode::EmitMux { dst, .. }
        | Opcode::EmitPoseidonHash { dst, .. }
        | Opcode::EmitIsEq { dst, .. }
        | Opcode::EmitIsLt { dst, .. }
        | Opcode::EmitIntDiv { dst, .. }
        | Opcode::EmitIntMod { dst, .. }
        | Opcode::EmitDiv { dst, .. } => vec![*dst],
        Opcode::LoopUnroll { iter_var, .. }
        | Opcode::LoopRolled { iter_var, .. }
        | Opcode::LoopRange { iter_var, .. } => vec![*iter_var],
        Opcode::InstantiateTemplate { output_regs, .. } => output_regs.clone(),
        Opcode::EmitDecompose {
            dst_arr, n_bits, ..
        } => (*dst_arr..dst_arr.saturating_add(*n_bits)).collect(),
        Opcode::EmitWitnessCall { out_regs, .. } => out_regs.clone(),
        // LoadHeap materialises a heap entry into dst_reg — that's a
        // write from Rule 9's perspective. Without this, downstream
        // reads of the loaded reg fire false `UninitializedRegister`
        // errors.
        Opcode::LoadHeap { dst_reg, .. } => vec![*dst_reg],
        // EmitWitnessCallHeap outputs go to heap slots, not regs;
        // it writes nothing register-visible.
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------
// Rule 10 — `Return` reachable from every code path.
// Phase 1: each body must end in a terminator.
// ---------------------------------------------------------------------

fn check_reachable_return<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    // Check the top-level body.
    if let Some(last) = program
        .body
        .iter()
        .rfind(|i| hosting_template(program, i.offset).is_none())
    {
        if !is_terminator(&last.opcode) {
            return Err(LysisError::UnreachableReturn {
                at_offset: last.offset,
            });
        }
    }

    // Check each template body.
    for t in &program.templates {
        let last = program.body.iter().rfind(|i| {
            i.offset >= t.body_offset && i.offset < t.body_offset.saturating_add(t.body_len)
        });
        match last {
            None => {
                // Empty template body — technically unreachable on
                // call. Reject: every DefineTemplate must have at
                // least a Return.
                return Err(LysisError::UnreachableReturn {
                    at_offset: t.body_offset,
                });
            }
            Some(i) if !is_terminator(&i.opcode) => {
                return Err(LysisError::UnreachableReturn {
                    at_offset: i.offset,
                });
            }
            _ => {}
        }
    }

    Ok(())
}

fn is_terminator(op: &Opcode) -> bool {
    matches!(
        op,
        Opcode::Return | Opcode::Halt | Opcode::Trap { .. } | Opcode::Jump { .. }
    )
}

// ---------------------------------------------------------------------
// Rule 11 — acyclic call graph + longest-path ≤ max_call_depth.
// ---------------------------------------------------------------------

fn check_call_graph<F: FieldBackend>(
    program: &Program<F>,
    config: &LysisConfig,
) -> Result<(), LysisError> {
    // Nodes: `None` (root/top-level) + each template id.
    //
    // Edges: for every InstantiateTemplate at offset `off`, add an
    // edge `hosting_template(off) -> target_template`. The same rule
    // applies to LoopRolled / LoopRange, which dispatch to a template
    // body per iteration.
    let mut graph: HashMap<Option<u16>, Vec<u16>> = HashMap::new();
    graph.entry(None).or_default();
    for t in &program.templates {
        graph.entry(Some(t.id)).or_default();
    }
    for instr in &program.body {
        let host = hosting_template(program, instr.offset);
        let target = match &instr.opcode {
            Opcode::InstantiateTemplate { template_id, .. }
            | Opcode::LoopRolled {
                body_template_id: template_id,
                ..
            }
            | Opcode::LoopRange {
                body_template_id: template_id,
                ..
            } => Some(*template_id),
            _ => None,
        };
        if let Some(t) = target {
            graph.entry(host).or_default().push(t);
        }
    }

    // DFS with in-progress set to catch cycles, depth tracking to
    // reject chains above the limit. Only one start node (the root),
    // but inaccessible template bodies must still be checked for
    // self-loops, so iterate over every node.
    for start in graph.keys() {
        let mut stack: HashSet<Option<u16>> = HashSet::new();
        let longest = dfs_longest(*start, &graph, &mut stack, config.max_call_depth)?;
        if longest > config.max_call_depth {
            return Err(LysisError::MaxCallDepthExceeded {
                longest,
                max: config.max_call_depth,
            });
        }
    }

    Ok(())
}

fn dfs_longest(
    node: Option<u16>,
    graph: &HashMap<Option<u16>, Vec<u16>>,
    stack: &mut HashSet<Option<u16>>,
    max_depth: u32,
) -> Result<u32, LysisError> {
    if stack.contains(&node) {
        return Err(LysisError::CircularTemplateCall {
            template_id: node.unwrap_or(0),
        });
    }
    stack.insert(node);
    let mut best = 0u32;
    if let Some(edges) = graph.get(&node) {
        for &child in edges {
            let depth = dfs_longest(Some(child), graph, stack, max_depth)?.saturating_add(1);
            if depth > best {
                best = depth;
            }
            if best > max_depth {
                // Early bail — we already know we're over the limit.
                stack.remove(&node);
                return Ok(best);
            }
        }
    }
    stack.remove(&node);
    Ok(best)
}

// ---------------------------------------------------------------------
// Rule 12 — heap slot < heap_size_hint (Phase 4 §6.3).
// ---------------------------------------------------------------------

fn check_heap_slot_bounds<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let cap = program.header.heap_size_hint;
    for instr in &program.body {
        match &instr.opcode {
            Opcode::StoreHeap { slot, .. } | Opcode::LoadHeap { slot, .. } => {
                if *slot >= cap {
                    return Err(LysisError::ValidationFailed {
                        rule: 12,
                        location: instr.offset,
                        detail: "heap slot exceeds header heap_size_hint",
                    });
                }
            }
            Opcode::EmitWitnessCallHeap {
                inputs, out_slots, ..
            } => {
                for src in inputs {
                    if let crate::bytecode::opcode::InputSrc::Slot(slot) = src {
                        if *slot >= cap {
                            return Err(LysisError::ValidationFailed {
                                rule: 12,
                                location: instr.offset,
                                detail:
                                    "EmitWitnessCallHeap input Slot exceeds header heap_size_hint",
                            });
                        }
                    }
                }
                for slot in out_slots {
                    if *slot >= cap {
                        return Err(LysisError::ValidationFailed {
                            rule: 12,
                            location: instr.offset,
                            detail: "EmitWitnessCallHeap out_slot exceeds header heap_size_hint",
                        });
                    }
                }
            }
            _ => continue,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Rule 13 — single-static-store invariant (Phase 4 §7.3).
//
// Every heap slot is written exactly once before any read. The
// SlotState lattice is binary in v1: `Unwritten → Written`. v1.1 will
// add a `Sealed` state once `FreeHeap` is wired (research report
// §7.3) — keeping the enum binary in v1 simplifies the validator
// and avoids a "dead state" landmine for future readers.
//
// Soundness of this forward linear scan depends on the **walker
// emission-position invariant** (§6.4):
//
//  1. The walker emits zero `Jump` / `JumpIf` opcodes (zero matches
//     in `ir-forge/src/lysis_lift/walker.rs`).
//  2. `StoreHeap` is emitted only in straight-line template prologue
//     position, never inside an inline `LoopUnroll` body or under a
//     conditional branch (which the walker never produces in v1).
//
// Together these mean "earlier in the byte stream" implies
// "dominates in execution order"; a forward linear scan over the
// body is path-safe by construction. **A future Phase 3 walker
// change that introduces real conditional branches around
// `StoreHeap` requires this validator to be upgraded to a CFG-based
// dominance check** — v2 future work, not v1.
//
// Slots that end the program in state `Unwritten` are legal: the
// walker may legitimately reserve a slot via lookahead and then
// have the using path pruned by const-folding. Rejection only fires
// on illegal *transitions*, never on the absence of transitions.
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeapSlotState {
    Unwritten,
    Written,
}

fn check_heap_single_static_store<F: FieldBackend>(program: &Program<F>) -> Result<(), LysisError> {
    let cap = program.header.heap_size_hint as usize;
    if cap == 0 {
        // No heap declared. Rule 12 has already rejected any heap
        // opcode whose slot is outside this empty range, so a
        // surviving program at this point has zero heap opcodes.
        // Skip the allocation entirely.
        return Ok(());
    }
    let mut state = vec![HeapSlotState::Unwritten; cap];
    for instr in &program.body {
        match &instr.opcode {
            Opcode::StoreHeap { slot, .. } => {
                let s = *slot as usize;
                // Rule 12 already bounded this; defensive guard.
                if s >= state.len() {
                    continue;
                }
                if state[s] == HeapSlotState::Written {
                    return Err(LysisError::ValidationFailed {
                        rule: 13,
                        location: instr.offset,
                        detail: "double StoreHeap to the same slot",
                    });
                }
                state[s] = HeapSlotState::Written;
            }
            Opcode::LoadHeap { slot, .. } => {
                let s = *slot as usize;
                if s >= state.len() {
                    continue;
                }
                if state[s] != HeapSlotState::Written {
                    return Err(LysisError::ValidationFailed {
                        rule: 13,
                        location: instr.offset,
                        detail: "LoadHeap from unwritten slot",
                    });
                }
            }
            Opcode::EmitWitnessCallHeap {
                inputs, out_slots, ..
            } => {
                // Read-side inputs (Slot variant): each slot must be
                // Written. Same contract as LoadHeap.
                for src in inputs {
                    if let crate::bytecode::opcode::InputSrc::Slot(slot) = src {
                        let s = *slot as usize;
                        if s >= state.len() {
                            continue;
                        }
                        if state[s] != HeapSlotState::Written {
                            return Err(LysisError::ValidationFailed {
                                rule: 13,
                                location: instr.offset,
                                detail: "EmitWitnessCallHeap reads from unwritten input Slot",
                            });
                        }
                    }
                }
                // Write-side outputs: each slot must be Unwritten,
                // transitions to Written.
                for slot in out_slots {
                    let s = *slot as usize;
                    if s >= state.len() {
                        continue;
                    }
                    if state[s] == HeapSlotState::Written {
                        return Err(LysisError::ValidationFailed {
                            rule: 13,
                            location: instr.offset,
                            detail: "EmitWitnessCallHeap writes a slot already written",
                        });
                    }
                    state[s] = HeapSlotState::Written;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::field::{Bn254Fr, FieldElement};
    use memory::FieldFamily;

    use crate::builder::ProgramBuilder;
    use crate::intern::Visibility;

    fn default_config() -> LysisConfig {
        LysisConfig::default()
    }

    fn b() -> ProgramBuilder<Bn254Fr> {
        ProgramBuilder::new(FieldFamily::BnLike256)
    }

    // -----------------------------------------------------------------
    // Rule 4 — const bounds
    // -----------------------------------------------------------------

    #[test]
    fn rule4_load_const_in_range_passes() {
        let mut builder = b();
        builder.intern_field(memory::field::FieldElement::<Bn254Fr>::from_canonical([
            0, 0, 0, 0,
        ]));
        builder.load_const(0, 0).halt();
        validate(&builder.finish(), &default_config()).unwrap();
    }

    #[test]
    fn rule4_load_const_out_of_range_rejects() {
        let mut builder = b();
        builder.load_const(0, 5).halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(
            err,
            LysisError::ConstIdxOutOfRange { idx: 5, len: 0, .. }
        ));
    }

    #[test]
    fn rule4_load_input_index_out_of_range_rejects() {
        let mut builder = b();
        builder.load_input(0, 3, Visibility::Witness).halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(err, LysisError::ConstIdxOutOfRange { .. }));
    }

    #[test]
    fn rule4_witness_call_idx_out_of_range_rejects() {
        let mut builder = b();
        builder.emit_witness_call(9, vec![0], vec![1]).halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(err, LysisError::ConstIdxOutOfRange { idx: 9, .. }));
    }

    // -----------------------------------------------------------------
    // Rule 6 — jump targets
    // -----------------------------------------------------------------

    #[test]
    fn rule6_jump_to_next_instr_is_ok() {
        let mut builder = b();
        builder.jump(3); // jump +3 from offset 0 → offset 3
        builder.halt(); // offset 3
        validate(&builder.finish(), &default_config()).unwrap();
    }

    #[test]
    fn rule6_jump_to_negative_rejects() {
        let mut builder = b();
        builder.jump(-10);
        builder.halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(err, LysisError::BadJumpTarget { .. }));
    }

    #[test]
    fn rule6_jump_to_non_opcode_boundary_rejects() {
        let mut builder = b();
        builder.jump(2); // lands in the middle of the next opcode
        builder.halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(err, LysisError::BadJumpTarget { .. }));
    }

    // -----------------------------------------------------------------
    // Rule 7 — templates defined
    // -----------------------------------------------------------------

    #[test]
    fn rule7_instantiate_undefined_rejects() {
        let mut builder = b();
        builder.instantiate_template(99, vec![], vec![]).halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(
            err,
            LysisError::UndefinedTemplate {
                template_id: 99,
                ..
            }
        ));
    }

    #[test]
    fn rule7_loop_rolled_undefined_rejects() {
        let mut builder = b();
        builder.loop_rolled(0, 0, 5, 42).halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(
            err,
            LysisError::UndefinedTemplate {
                template_id: 42,
                ..
            }
        ));
    }

    // -----------------------------------------------------------------
    // Rule 9 — forward dataflow
    // -----------------------------------------------------------------

    #[test]
    fn rule9_write_then_read_is_ok() {
        let mut builder = b();
        builder.intern_string("x");
        builder.load_input(0, 0, Visibility::Witness);
        builder.emit_range_check(0, 8);
        builder.halt();
        validate(&builder.finish(), &default_config()).unwrap();
    }

    #[test]
    fn rule9_read_without_write_rejects() {
        let mut builder = b();
        builder.emit_range_check(5, 8); // r5 never written
        builder.halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(
            err,
            LysisError::UninitializedRegister { reg: 5, .. }
        ));
    }

    #[test]
    fn rule9_skipped_when_jumps_present() {
        // Linear dataflow bails out at the first Jump — rule 9 becomes
        // a no-op when the program can branch. Phase 2 replaces this
        // with a proper CFG-based analysis.
        let mut builder = b();
        builder.jump(3); // valid jump to halt at offset 3
        builder.halt();
        check_forward_dataflow(&builder.finish()).unwrap();
    }

    // -----------------------------------------------------------------
    // Rule 10 — reachable return
    // -----------------------------------------------------------------

    #[test]
    fn rule10_body_ends_in_halt_is_ok() {
        let mut builder = b();
        builder.halt();
        validate(&builder.finish(), &default_config()).unwrap();
    }

    #[test]
    fn rule10_body_missing_terminator_rejects() {
        // EnterScope neither reads nor writes registers, so rule 9
        // passes; this lets us actually reach rule 10 and exercise
        // the "no terminator at the end" branch.
        let mut builder = b();
        builder.enter_scope();
        let err = check_reachable_return(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::UnreachableReturn { .. }));
    }

    // -----------------------------------------------------------------
    // Rule 11 — call graph
    // -----------------------------------------------------------------

    #[test]
    fn rule11_small_acyclic_graph_passes() {
        // Program where rule 11's graph is root → T1, a 1-hop acyclic
        // chain. Called directly: rule 10 would otherwise reject the
        // synthetic template whose body_offset lies inside the
        // DefineTemplate bytes themselves (a consequence of crafting
        // tiny fixtures).
        let mut builder = b();
        builder.define_template(1, 8, 0, 1, 1);
        builder.instantiate_template(1, vec![], vec![]);
        builder.halt();
        check_call_graph(&builder.finish(), &default_config()).unwrap();
    }

    #[test]
    fn rule11_self_loop_rejects() {
        // Craft a program where template 1's body slice covers the
        // very InstantiateTemplate(1) that follows DefineTemplate.
        //
        // Offsets:
        //   0  DefineTemplate(1, bo=13, bl=6)  [13 bytes]
        //   13 InstantiateTemplate(1, [], [])  [5 bytes, inside T1]
        //   18 Halt                            [1 byte, inside T1]
        let mut builder = b();
        builder.define_template(1, 8, 0, 13, 6);
        builder.instantiate_template(1, vec![], vec![]);
        builder.halt();
        let err = check_call_graph(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(err, LysisError::CircularTemplateCall { .. }));
    }

    #[test]
    fn rule11_small_chain_within_limit_passes() {
        let cfg = LysisConfig {
            max_call_depth: 4,
            ..Default::default()
        };
        let mut builder = b();
        builder.define_template(1, 4, 0, 100, 1);
        builder.define_template(2, 4, 0, 200, 1);
        builder.instantiate_template(1, vec![], vec![]);
        builder.halt();
        check_call_graph(&builder.finish(), &cfg).unwrap();
    }

    #[test]
    fn rule11_depth_exceeded_rejects() {
        // Root → T1 → T2 is depth 2, exceeds max_call_depth = 1.
        //
        // Offsets:
        //   0  DefineTemplate(1, bo=26, bl=6)  [13 bytes]
        //   13 DefineTemplate(2, bo=32, bl=1)  [13 bytes]
        //   26 InstantiateTemplate(2, [], [])  [5 bytes, inside T1]
        //   31 Halt                            [1 byte, terminates T1]
        //   32 Halt                            [1 byte, T2 body]
        //   33 InstantiateTemplate(1, [], [])  [5 bytes, root level]
        //   38 Halt                            [1 byte, terminates root]
        let cfg = LysisConfig {
            max_call_depth: 1,
            ..Default::default()
        };
        let mut builder = b();
        builder.define_template(1, 4, 0, 26, 6);
        builder.define_template(2, 4, 0, 32, 1);
        builder.instantiate_template(2, vec![], vec![]);
        builder.halt();
        builder.halt();
        builder.instantiate_template(1, vec![], vec![]);
        builder.halt();
        let err = check_call_graph(&builder.finish(), &cfg).unwrap_err();
        assert!(matches!(err, LysisError::MaxCallDepthExceeded { .. }));
    }

    // -----------------------------------------------------------------
    // Happy path — a realistic Num2Bits-like program
    // -----------------------------------------------------------------

    #[test]
    fn realistic_num2bits_program_passes() {
        let mut builder = b();
        builder.intern_string("in");
        builder
            .load_input(0, 0, Visibility::Witness)
            .emit_decompose(1, 0, 4)
            .emit_range_check(1, 1)
            .emit_range_check(2, 1)
            .emit_range_check(3, 1)
            .emit_range_check(4, 1)
            .halt();
        validate(&builder.finish(), &default_config()).unwrap();
    }

    // -----------------------------------------------------------------
    // Rule 12 — heap slot < heap_size_hint
    // -----------------------------------------------------------------

    fn one_const() -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0])
    }

    #[test]
    fn rule12_heap_size_zero_rejects_any_heap_op() {
        // No heap declared → any slot is out of bounds.
        let mut builder = b();
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 0) // slot 0 vs cap 0
            .halt();
        let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
    }

    #[test]
    fn rule12_store_oob_rejects() {
        let mut builder = b().with_heap_size_hint(4);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 4) // slot 4 vs cap 4 → out of bounds
            .halt();
        let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
    }

    #[test]
    fn rule12_load_oob_rejects() {
        let mut builder = b().with_heap_size_hint(2);
        builder.load_heap(0, 99).halt();
        let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
    }

    #[test]
    fn rule12_in_bounds_passes() {
        let mut builder = b().with_heap_size_hint(8);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 7) // top-of-range still valid
            .halt();
        check_heap_slot_bounds(&builder.finish()).unwrap();
    }

    // -----------------------------------------------------------------
    // Rule 13 — single-static-store
    // -----------------------------------------------------------------

    #[test]
    fn rule13_load_before_store_rejects() {
        let mut builder = b().with_heap_size_hint(4);
        builder.load_heap(0, 1).halt();
        let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
    }

    #[test]
    fn rule13_double_store_same_slot_rejects() {
        let mut builder = b().with_heap_size_hint(4);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 2)
            .store_heap(0, 2) // second store to slot 2 → reject
            .halt();
        let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
    }

    #[test]
    fn rule13_store_then_load_passes() {
        let mut builder = b().with_heap_size_hint(4);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 2)
            .load_heap(1, 2)
            .halt();
        check_heap_single_static_store(&builder.finish()).unwrap();
    }

    #[test]
    fn rule13_stores_to_different_slots_pass() {
        let mut builder = b().with_heap_size_hint(8);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 1)
            .store_heap(0, 3)
            .store_heap(0, 7)
            .load_heap(1, 1)
            .load_heap(2, 3)
            .load_heap(3, 7)
            .halt();
        check_heap_single_static_store(&builder.finish()).unwrap();
    }

    #[test]
    fn rule13_unwritten_slot_at_end_is_legal() {
        // Slots that end the program in `Unwritten` are legal — the
        // walker may reserve a slot via lookahead and then have the
        // using path pruned. Validator only catches illegal
        // *transitions*.
        let mut builder = b().with_heap_size_hint(8);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 0)
            .load_heap(1, 0)
            .halt(); // slots 1..7 never touched — fine
        check_heap_single_static_store(&builder.finish()).unwrap();
    }

    #[test]
    fn rule13_passes_when_no_heap_declared() {
        // heap_size_hint = 0 → no heap → no rule 13 to check (and the
        // function short-circuits on the cap == 0 fast path).
        let mut builder = b();
        builder.intern_field(one_const());
        builder.load_const(0, 0).halt();
        check_heap_single_static_store(&builder.finish()).unwrap();
    }

    #[test]
    fn full_validate_accepts_well_formed_heap_program() {
        // Smoke that `validate()` itself wires both rules in.
        let mut builder = b().with_heap_size_hint(4);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 1)
            .load_heap(2, 1)
            .halt();
        validate(&builder.finish(), &default_config()).unwrap();
    }

    #[test]
    fn full_validate_rejects_double_store_via_rule_13() {
        let mut builder = b().with_heap_size_hint(4);
        builder.intern_field(one_const());
        builder
            .load_const(0, 0)
            .store_heap(0, 1)
            .store_heap(0, 1)
            .halt();
        let err = validate(&builder.finish(), &default_config()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
    }

    // -----------------------------------------------------------------
    // Phase 4 follow-up — rules 12 + 13 cover EmitWitnessCallHeap too.
    // -----------------------------------------------------------------

    #[test]
    fn rule12_witness_call_heap_oob_slot_rejects() {
        let mut builder = b().with_heap_size_hint(4);
        let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
        builder
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![99]) // 99 ≥ 4
            .halt();
        let err = check_heap_slot_bounds(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 12, .. }));
    }

    #[test]
    fn rule12_witness_call_heap_in_bounds_passes() {
        let mut builder = b().with_heap_size_hint(8);
        let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
        builder
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![0, 1, 2, 7])
            .halt();
        check_heap_slot_bounds(&builder.finish()).unwrap();
    }

    #[test]
    fn rule13_witness_call_heap_double_writes_same_slot_rejects() {
        // Two heap-output WitnessCalls writing the same slot must
        // be rejected at the second one (single-static-store).
        let mut builder = b().with_heap_size_hint(4);
        let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
        builder
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![1])
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![1])
            .halt();
        let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
    }

    #[test]
    fn rule13_witness_call_heap_overlap_with_store_heap_rejects() {
        // A StoreHeap to slot 1 followed by a WitnessCallHeap that
        // also writes slot 1 must reject — both consume the same slot.
        let mut builder = b().with_heap_size_hint(4);
        let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
        builder.intern_field(one_const());
        let const_idx_one = builder.intern_artik_bytecode(vec![]); // dummy to not shift
        let _ = const_idx_one;
        builder
            .load_const(0, 0)
            .store_heap(0, 1)
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![1, 2])
            .halt();
        let err = check_heap_single_static_store(&builder.finish()).unwrap_err();
        assert!(matches!(err, LysisError::ValidationFailed { rule: 13, .. }));
    }

    #[test]
    fn rule13_witness_call_heap_distinct_slots_pass() {
        let mut builder = b().with_heap_size_hint(8);
        let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
        builder
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![0, 1, 2])
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![3, 4, 5])
            .halt();
        check_heap_single_static_store(&builder.finish()).unwrap();
    }

    #[test]
    fn full_validate_accepts_witness_call_heap_program() {
        let mut builder = b().with_heap_size_hint(4);
        let blob_idx = builder.intern_artik_bytecode(vec![0u8]);
        builder
            .emit_witness_call_heap(blob_idx as u16, vec![], vec![0, 1, 2, 3])
            .halt();
        validate(&builder.finish(), &default_config()).unwrap();
    }
}
