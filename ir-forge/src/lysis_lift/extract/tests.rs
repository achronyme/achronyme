use std::collections::BTreeSet;

use fixedbitset::FixedBitSet;
use memory::{Bn254Fr, FieldElement};

use super::*;
use crate::lysis_lift::bta::{classify, BindingTime};
use crate::lysis_lift::symbolic::{SlotId, SymbolicNode, SymbolicTree};
use crate::{ExtendedInstruction, TemplateId};
use ir_core::{Instruction, SsaVar};

mod capture_layout;
mod extraction;
mod frame_size;
mod lift;
mod registry;

fn fe(n: i64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n as u64, 0, 0, 0])
}

fn ssa(i: u32) -> SsaVar {
    SsaVar(i.into())
}
