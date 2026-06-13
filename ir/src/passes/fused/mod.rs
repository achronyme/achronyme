//! Fused optimizer over an eager lysis interner.
//!
//! The lean prove path used to materialize the interner into a
//! `Vec<Instruction<F>>` and then run [`crate::passes::optimize`]
//! over it — a second full materialization plus several rewriting
//! re-traversals of a multi-million-instruction Vec. This module
//! computes the same pass pipeline as dense overlays against the
//! interner's own emission events and writes the **post-optimize**
//! instruction Vec exactly once.
//!
//! Output contract: [`optimize_lean_sink`]'s program + stats equal
//! `materialize → optimize()` byte-for-byte (per-instruction Debug
//! equality, `next_var`, and every stats field). The reference
//! pipeline stays the semantic spec; the fused parity tests gate the
//! equality on the template corpus.
//!
//! Streams the reference handles via degenerate-input fallbacks
//! (duplicate definitions — which every `Decompose` produces, since
//! its result aliases its operand) and the windowed interner modes
//! take [`reference_fallback`]: materialize + `optimize()` verbatim.
//! `cse` needs no fused counterpart: hash-consing guarantees no two
//! pure instructions share `(kind, operands)`, and constant folding
//! never rewrites operands, so CSE is structurally zero on interner
//! output (the parity tests pin `cse_eliminated == 0`).

mod dce;
mod facts;
mod scan;

#[cfg(test)]
mod tests;

use ir_forge::instantiate::LysisSinkBundle;
use ir_forge::lysis_bridge::{instruction_from_kind_owned, ssa_var_from_node_id};
use ir_forge::lysis_materialize::materialize_interner;
use lysis::intern::{EmissionEvent, NodeInterner, NodeKey};
use memory::FieldBackend;

use crate::passes::OptimizeStats;
use crate::types::{Instruction, IrProgram};

/// Result of the fused pipeline.
pub struct FusedOutcome<F: FieldBackend> {
    /// The optimized program (post const-fold / bound-inference /
    /// taut-filter / DCE), metadata maps carried over from the bundle.
    pub program: IrProgram<F>,
    /// Same shape `optimize()` returns on the materialized program.
    pub stats: OptimizeStats,
    /// `true` when the stream took the materialize + `optimize()`
    /// reference path (windowed interner, duplicate definitions,
    /// `Decompose`-bearing streams).
    pub used_fallback: bool,
}

/// Optimize a lean instantiate sink without materializing the
/// unoptimized instruction Vec. See the module docs for the output
/// contract; `bundle.next_var` must be the walk counter (the entry
/// applies the `ssa_watermark(..).max(next_var)` reassembly formula
/// internally, mirroring the materializing entries).
pub fn optimize_lean_sink<F: FieldBackend>(bundle: LysisSinkBundle<F>) -> FusedOutcome<F> {
    let LysisSinkBundle {
        sink,
        next_var,
        var_names,
        var_types,
        var_spans,
        input_spans,
    } = bundle;
    let interner = sink.into_interner();
    if !interner.is_eager() {
        return reference_fallback(
            interner,
            next_var,
            (var_names, var_types, var_spans, input_spans),
        );
    }
    let mut scan = match scan::scan(&interner) {
        Ok(scan) => scan,
        Err(_) => {
            return reference_fallback(
                interner,
                next_var,
                (var_names, var_types, var_spans, input_spans),
            )
        }
    };
    let facts = facts::analyze(&interner, &scan, &var_types);

    // A bound rewrite that lands on a pre-existing bounded compare's
    // key (same kind, operands and bitwidth) makes the reference
    // pipeline CSE the duplicate after bound inference — the only
    // post-fold key collision the hash-consed stream can produce.
    // No current frontend emits that shape; hand it to the reference.
    let rewrite_collides = scan.cmps.iter().any(|site| {
        facts.rewrites.get(&site.event).is_some_and(|&w| {
            scan.bounded_keys
                .contains(&(site.is_le, site.lhs, site.rhs, w))
        })
    });
    if rewrite_collides {
        return reference_fallback(
            interner,
            next_var,
            (var_names, var_types, var_spans, input_spans),
        );
    }

    let (dead, dead_count) = dce::liveness(&interner, &mut scan);

    let total_before = scan.event_count;
    let total_after = total_before - scan.taut_count - dead_count;
    let mut instructions: Vec<Instruction<F>> = Vec::with_capacity(total_after);
    let events = interner
        .into_emission_events()
        .unwrap_or_else(|_| unreachable!("eager-mode checked above"));
    for (e, event) in events.enumerate() {
        if dead[e] || scan.taut[e] {
            continue;
        }
        let e32 = e as u32;
        match event {
            EmissionEvent::Pure { id, key } => {
                let result = ssa_var_from_node_id(id);
                if let Some(&value) = scan.folded.get(&e32) {
                    instructions.push(Instruction::Const { result, value });
                    continue;
                }
                if let Some(&bitwidth) = facts.rewrites.get(&e32) {
                    match key {
                        NodeKey::IsLt(lhs, rhs) => {
                            instructions.push(Instruction::IsLtBounded {
                                result,
                                lhs: ssa_var_from_node_id(lhs),
                                rhs: ssa_var_from_node_id(rhs),
                                bitwidth,
                            });
                            continue;
                        }
                        NodeKey::IsLe(lhs, rhs) => {
                            instructions.push(Instruction::IsLeBounded {
                                result,
                                lhs: ssa_var_from_node_id(lhs),
                                rhs: ssa_var_from_node_id(rhs),
                                bitwidth,
                            });
                            continue;
                        }
                        // Rewrite sites are only ever IsLt/IsLe.
                        _ => {}
                    }
                }
                instructions.push(instruction_from_kind_owned(key.into_instruction(id)));
            }
            EmissionEvent::Effect(eff) => {
                instructions.push(instruction_from_kind_owned(eff.into_instruction::<F>()));
            }
        }
    }

    let mut program = IrProgram::<F>::new();
    program.set_instructions(instructions);
    program.set_next_var(scan.watermark.max(next_var));
    program.var_names = var_names;
    program.var_types = var_types;
    program.var_spans = var_spans;
    program.input_spans = input_spans;

    let stats = OptimizeStats {
        total_before,
        const_fold_converted: scan.folded.len(),
        cse_eliminated: 0,
        dce_eliminated: dead_count,
        tautological_asserts_eliminated: scan.taut_count,
        total_after,
        bound_inference: facts.bound_inference,
        bit_pattern_bounds: facts.bit_bounds,
        bit_pattern_booleans: facts.booleans_detected,
    };
    FusedOutcome {
        program,
        stats,
        used_fallback: false,
    }
}

type MetadataMaps = (
    std::collections::HashMap<ir_core::SsaVar, String>,
    std::collections::HashMap<ir_core::SsaVar, ir_core::IrType>,
    std::collections::HashMap<ir_core::SsaVar, diagnostics::SpanRange>,
    std::collections::HashMap<String, diagnostics::SpanRange>,
);

/// The reference path: materialize the interner and run the standard
/// pass pipeline. Used for streams the fused fast path refuses; its
/// output IS the spec, so equality is by construction.
fn reference_fallback<F: FieldBackend>(
    interner: NodeInterner<F>,
    next_var: u64,
    (var_names, var_types, var_spans, input_spans): MetadataMaps,
) -> FusedOutcome<F> {
    let instructions = materialize_interner(interner);
    // Mirror of the reassembly watermark formula used by the
    // materializing instantiate entries.
    let mut watermark: u64 = 0;
    for inst in &instructions {
        watermark = watermark.max(inst.result_var().0 + 1);
        for extra in inst.extra_result_vars() {
            watermark = watermark.max(extra.0 + 1);
        }
    }
    let mut program = IrProgram::<F>::new();
    program.set_instructions(instructions);
    program.set_next_var(watermark.max(next_var));
    program.var_names = var_names;
    program.var_types = var_types;
    program.var_spans = var_spans;
    program.input_spans = input_spans;
    let stats = crate::passes::optimize(&mut program);
    FusedOutcome {
        program,
        stats,
        used_fallback: true,
    }
}
