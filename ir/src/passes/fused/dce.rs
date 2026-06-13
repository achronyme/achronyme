//! Liveness over the post-fold, taut-filtered event stream — mirror
//! of `crate::passes::dce::dead_code_elimination`'s use-count
//! worklist (the duplicate-definition round-based fallback never
//! runs here: the scan poisons duplicate defs and the caller takes
//! the reference path instead). Same MIRROR CONTRACT as `scan.rs`.

use lysis::intern::{EmissionEventRef, NodeInterner};
use memory::FieldBackend;

use super::scan::{for_each_key_operand, Scan, NO_EVENT};

/// Compute the dead-event set. Consumes `scan.counts` (the cascade
/// decrements them in place). Returns the per-event dead flags plus
/// the dead count.
pub(super) fn liveness<F: FieldBackend>(
    interner: &NodeInterner<F>,
    scan: &mut Scan<F>,
) -> (Vec<bool>, usize) {
    let n = scan.event_count;
    let mut dead = vec![false; n];
    let mut work: Vec<u32> = Vec::new();

    // Seed: pure instructions whose result no retained instruction
    // reads. Pure events stay pure post-fold (a folded node is a
    // `Const`), and tautological asserts are effects, so the seed
    // domain is exactly the Pure timeline events.
    let events = interner
        .emission_events()
        .expect("liveness is only called on eager interners");
    for (e, event) in events.enumerate() {
        if let EmissionEventRef::Pure { id, .. } = event {
            if scan.counts[id.index()] == 0 {
                dead[e] = true;
                work.push(e as u32);
            }
        }
    }

    // Cascade: removing an instruction decrements its operands'
    // counts, which can newly orphan their defining instructions.
    // A folded event's post-fold form is a `Const` — no operands.
    let mut ops: Vec<u64> = Vec::new();
    while let Some(e) = work.pop() {
        if scan.folded.contains_key(&e) {
            continue;
        }
        ops.clear();
        if let Some(EmissionEventRef::Pure { key, .. }) = interner.emission_event_at(e as usize) {
            for_each_key_operand(key, |v| ops.push(v));
        }
        for &v in &ops {
            let c = &mut scan.counts[v as usize];
            *c -= 1;
            if *c == 0 {
                let j = scan.def_event.get(v as usize).copied().unwrap_or(NO_EVENT);
                if j != NO_EVENT
                    && !dead[j as usize]
                    && matches!(
                        interner.emission_event_at(j as usize),
                        Some(EmissionEventRef::Pure { .. })
                    )
                {
                    dead[j as usize] = true;
                    work.push(j);
                }
            }
        }
    }

    let dead_count = dead.iter().filter(|&&d| d).count();
    (dead, dead_count)
}
