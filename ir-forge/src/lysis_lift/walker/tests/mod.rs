use lysis::{execute, InterningSink, LysisConfig};
use memory::{Bn254Fr, FieldElement};

use super::*;
use ir_core::{Visibility as IrVisibility, WitnessCallBody};

fn fe(n: u64) -> FieldElement<Bn254Fr> {
    FieldElement::from_canonical([n, 0, 0, 0])
}

fn ssa(i: u32) -> SsaVar {
    SsaVar(i.into())
}

fn plain(inst: Instruction<Bn254Fr>) -> ExtendedInstruction<Bn254Fr> {
    ExtendedInstruction::Plain(inst)
}

/// Emit + execute the body through a fresh InterningSink; return
/// the materialized `Vec<InstructionKind>`.
fn run(body: &[ExtendedInstruction<Bn254Fr>]) -> Vec<lysis::InstructionKind<Bn254Fr>> {
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.to_vec()).expect("lower");
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&program, &[], &LysisConfig::default(), &mut sink).expect("exec");
    sink.materialize()
}

mod basic;
mod core_symbolic;
mod desugar;
mod heap;
mod partition;
mod shift_templates;
mod splitting;
mod witness;
