use std::collections::{HashMap, HashSet};

use constraints::plonkish::{CellRef, Column, PlonkishSystem};
use constraints::poseidon::PoseidonParams;
use ir::types::SsaVar;
use memory::{Bn254Fr, FieldBackend};

use super::types::{PlonkVal, PlonkWitnessOp};

mod api;
mod dispatch;
mod logic;

// ============================================================================
// PlonkishCompiler
// ============================================================================

pub struct PlonkishCompiler<F: FieldBackend = Bn254Fr> {
    pub system: PlonkishSystem<F>,
    // Standard column refs
    pub col_s_arith: Column,
    pub col_constant: Column,
    pub col_zero: Column,
    pub col_a: Column,
    pub col_b: Column,
    pub col_c: Column,
    pub col_d: Column,
    pub col_instance: Column,
    // SSA → PlonkVal mapping
    pub(super) val_map: HashMap<SsaVar, PlonkVal<F>>,
    // Named inputs
    pub bindings: HashMap<String, CellRef>,
    pub public_inputs: Vec<String>,
    pub witnesses: Vec<String>,
    pub(super) instance_row: usize,
    pub(super) current_row: usize,
    // Witness ops trace
    pub witness_ops: Vec<PlonkWitnessOp<F>>,
    // Poseidon params (lazy)
    pub(super) poseidon_params: Option<PoseidonParams<F>>,
    // Range table bits already created (maps bits → lookup_table index)
    pub(super) range_tables: HashMap<u32, usize>,
    // Per-bit-width range selector columns
    pub range_selectors: HashMap<u32, Column>,
    // SSA variables proven to be boolean by bool_prop analysis
    pub(super) proven_boolean: HashSet<SsaVar>,
    // Proven bit-width bounds from RangeCheck, used by IsLt/IsLe.
    // Populated as the compiler walks the IR; reset at the start of every
    // `compile_ir` call.
    range_bounds: HashMap<SsaVar, u32>,
}
