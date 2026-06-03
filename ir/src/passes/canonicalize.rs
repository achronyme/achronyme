//! `canonicalize_ssa` — topological renaming of SsaVars to `0..N`.
//!
//! Two `IrProgram<F>` produced by different paths (legacy `instantiate`
//! vs Lysis lifter) often describe the same circuit but allocate SSA ids
//! in different orders — fresh-var counters are non-deterministic across
//! independent emitters. The oracle's first job is to fold that
//! difference away so downstream comparison can rely on positional
//! identity.
//!
//! Algorithm: walk `instructions` (already in topological / SSA order)
//! and assign each defined SsaVar a fresh id in visitation order. Then
//! rebuild the program with every SsaVar — both definition sites and
//! operand reads — substituted via the renamer. Side-band metadata
//! keyed by SsaVar (`var_names`, `var_types`, `var_spans`) gets its
//! keys remapped; `input_spans` is keyed by name and copies as-is.
//!
//! Properties (validated by tests below):
//!
//! - **Pure**: takes `&IrProgram<F>`, returns a fresh program. Input is
//!   not mutated.
//! - **Idempotent**: `canonicalize(canonicalize(p)) == canonicalize(p)`.
//! - **Permissive on undefined operands**: if an operand SsaVar is not
//!   in the renamer (use-before-def — a malformed program), it is left
//!   unchanged. Detection of malformed IR is the responsibility of the
//!   IR validator, not the oracle.

use std::collections::HashMap;

use memory::FieldBackend;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Canonical form of `p` — every SsaVar renamed to its visitation
/// index in `0..N` (instructions in order, with `Decompose::bit_results`
/// and `WitnessCall::outputs` extras taking subsequent ids before the
/// next instruction's primary).
pub fn canonicalize_ssa<F: FieldBackend>(p: &IrProgram<F>) -> IrProgram<F> {
    let mut renamer: HashMap<SsaVar, SsaVar> = HashMap::with_capacity(p.next_var as usize);
    let mut next: u64 = 0;

    for inst in &p.instructions {
        renamer.insert(inst.result_var(), SsaVar(next));
        next += 1;
        for &extra in inst.extra_result_vars() {
            renamer.insert(extra, SsaVar(next));
            next += 1;
        }
    }

    let mut out = IrProgram::new();
    out.next_var = next;
    out.instructions.reserve(p.instructions.len());

    for inst in &p.instructions {
        let mut new_inst = inst.clone();
        rewrite_all_vars(&mut new_inst, &renamer);
        out.instructions.push(new_inst);
    }

    for (old_var, name) in &p.var_names {
        if let Some(&new_var) = renamer.get(old_var) {
            out.var_names.insert(new_var, name.clone());
        }
    }
    for (old_var, ty) in &p.var_types {
        if let Some(&new_var) = renamer.get(old_var) {
            out.var_types.insert(new_var, *ty);
        }
    }
    for (old_var, span) in &p.var_spans {
        if let Some(&new_var) = renamer.get(old_var) {
            out.var_spans.insert(new_var, span.clone());
        }
    }

    out.input_spans = p.input_spans.clone();

    out
}

/// Rewrite every SsaVar in `inst` — both the def slots (result, extra
/// results) and the operand reads — via `renamer`. Variants without
/// SsaVars (Const value, Input name/visibility) are left intact.
fn rewrite_all_vars<F: FieldBackend>(inst: &mut Instruction<F>, renamer: &HashMap<SsaVar, SsaVar>) {
    let r = |v: &mut SsaVar| {
        if let Some(&new) = renamer.get(v) {
            *v = new;
        }
    };
    match inst {
        Instruction::Const { result, .. } => {
            r(result);
        }
        Instruction::Input { result, .. } => {
            r(result);
        }
        Instruction::Add { result, lhs, rhs }
        | Instruction::Sub { result, lhs, rhs }
        | Instruction::Mul { result, lhs, rhs }
        | Instruction::Div { result, lhs, rhs } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::Neg { result, operand } | Instruction::Not { result, operand } => {
            r(result);
            r(operand);
        }
        Instruction::Assert {
            result, operand, ..
        }
        | Instruction::RangeCheck {
            result, operand, ..
        } => {
            r(result);
            r(operand);
        }
        Instruction::And { result, lhs, rhs }
        | Instruction::Or { result, lhs, rhs }
        | Instruction::IsEq { result, lhs, rhs }
        | Instruction::IsNeq { result, lhs, rhs }
        | Instruction::IsLt { result, lhs, rhs }
        | Instruction::IsLe { result, lhs, rhs } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::IsLtBounded {
            result, lhs, rhs, ..
        }
        | Instruction::IsLeBounded {
            result, lhs, rhs, ..
        }
        | Instruction::IntDiv {
            result, lhs, rhs, ..
        }
        | Instruction::IntMod {
            result, lhs, rhs, ..
        } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::Mux {
            result,
            cond,
            if_true,
            if_false,
        } => {
            r(result);
            r(cond);
            r(if_true);
            r(if_false);
        }
        Instruction::AssertEq {
            result, lhs, rhs, ..
        } => {
            r(result);
            r(lhs);
            r(rhs);
        }
        Instruction::PoseidonHash {
            result,
            left,
            right,
        } => {
            r(result);
            r(left);
            r(right);
        }
        Instruction::Decompose {
            result,
            operand,
            bit_results,
            ..
        } => {
            r(result);
            r(operand);
            for b in bit_results.iter_mut() {
                r(b);
            }
        }
        Instruction::WitnessCall(call) => {
            for o in call.outputs.iter_mut() {
                r(o);
            }
            for i in call.inputs.iter_mut() {
                r(i);
            }
        }
    }
}

#[cfg(test)]
mod tests;
