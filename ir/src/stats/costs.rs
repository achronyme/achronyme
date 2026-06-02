use std::collections::HashMap;

use crate::types::SsaVar;

pub(super) fn is_lt_cost(range_bounds: &HashMap<SsaVar, u32>, lhs: &SsaVar, rhs: &SsaVar) -> usize {
    let bound_a = range_bounds.get(lhs).copied();
    let bound_b = range_bounds.get(rhs).copied();

    match (bound_a, bound_b) {
        (Some(ba), Some(bb)) => {
            let effective = ba.max(bb);
            // 1 materialize + (effective+1) boolean + 1 sum
            (effective as usize) + 3
        }
        _ => {
            let mut cost = 0usize;
            // enforce_252_range per missing bound = enforce_n_range(252) = 252+1 = 253
            if bound_a.is_none() {
                cost += 253;
            }
            if bound_b.is_none() {
                cost += 253;
            }
            // 1 materialize + 253 boolean + 1 sum = 255
            cost += 255;
            cost
        }
    }
}
