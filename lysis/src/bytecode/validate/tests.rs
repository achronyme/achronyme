use super::call_graph::check_call_graph;
use super::dataflow::check_forward_dataflow;
use super::heap::{check_heap_single_static_store, check_heap_slot_bounds};
use super::reachability::check_reachable_return;
use super::*;
use memory::field::{Bn254Fr, FieldElement};
use memory::FieldFamily;

use crate::builder::ProgramBuilder;
use crate::bytecode::Opcode;
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::intern::Visibility;
use crate::program::Program;

fn default_config() -> LysisConfig {
    LysisConfig::default()
}

fn b() -> ProgramBuilder<Bn254Fr> {
    ProgramBuilder::new(FieldFamily::BnLike256)
}

fn one_const() -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0])
}

mod basic;
mod call_graph;
mod heap;
