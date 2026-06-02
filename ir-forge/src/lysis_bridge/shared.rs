use ir_core::{SsaVar, Visibility as IrVisibility};
use lysis_types::{NodeId, Visibility as LysisVisibility};

/// Convert a Lysis `NodeId` into the SSA var numbering the IR uses.
#[inline]
pub fn ssa_var_from_node_id(id: NodeId) -> SsaVar {
    SsaVar(id.index() as u64)
}

#[inline]
pub(super) fn map_visibility(v: LysisVisibility) -> IrVisibility {
    match v {
        LysisVisibility::Public => IrVisibility::Public,
        LysisVisibility::Witness => IrVisibility::Witness,
    }
}

#[inline]
pub(super) fn map_vec_ids(ids: &[NodeId]) -> Vec<SsaVar> {
    ids.iter().copied().map(ssa_var_from_node_id).collect()
}

#[inline]
pub(super) fn map_vec_ids_owned(ids: Vec<NodeId>) -> Vec<SsaVar> {
    ids.into_iter().map(ssa_var_from_node_id).collect()
}
