use std::collections::HashSet;

use crate::types::SsaVar;

fn empty_proven() -> HashSet<SsaVar> {
    HashSet::new()
}

mod behavior;
mod costs;
