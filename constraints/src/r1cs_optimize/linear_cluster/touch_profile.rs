use memory::FieldBackend;

use crate::r1cs::Constraint;
use crate::r1cs_optimize::types::SubstitutionMap;

pub(super) fn log_substitution_touch<F: FieldBackend>(
    round: usize,
    constraints: &[Constraint<F>],
    skip_mask: &[bool],
    residuals: &[Constraint<F>],
    subs: &SubstitutionMap<F>,
) {
    let mut unmasked_total = 0usize;
    let mut unmasked_touched = 0usize;
    for (constraint, skip) in constraints.iter().zip(skip_mask) {
        if *skip {
            continue;
        }
        unmasked_total += 1;
        if constraint_references_any_substitution_var(constraint, subs) {
            unmasked_touched += 1;
        }
    }

    let residual_total = residuals.len();
    let residual_touched = residuals
        .iter()
        .filter(|constraint| constraint_references_any_substitution_var(constraint, subs))
        .count();
    eprintln!(
        "[O1] round {round} substitution_touch unmasked={unmasked_touched}/{unmasked_total} \
         residual={residual_touched}/{residual_total} total={}/{}",
        unmasked_touched + residual_touched,
        unmasked_total + residual_total,
    );
}

fn constraint_references_any_substitution_var<F: FieldBackend>(
    constraint: &Constraint<F>,
    subs: &SubstitutionMap<F>,
) -> bool {
    constraint
        .a
        .terms()
        .iter()
        .chain(constraint.b.terms().iter())
        .chain(constraint.c.terms().iter())
        .any(|(var, _)| subs.contains_key(&var.index()))
}
