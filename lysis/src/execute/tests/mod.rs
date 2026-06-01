use memory::field::{Bn254Fr, FieldElement};
use memory::FieldFamily;

use crate::builder::ProgramBuilder;
use crate::bytecode::{ConstPool, Opcode};
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::header::LysisHeader;
use crate::intern::{InstructionKind, NodeId, Visibility};
use crate::program::{Instr, Program, Template};

use super::templates::{build_template_tables, exact_offset_idx, lower_bound_offset_idx};
use super::{execute, InterningSink, IrSink, StubSink};

fn run(program: &Program<Bn254Fr>, captures: &[FieldElement<Bn254Fr>]) -> StubSink<Bn254Fr> {
    let mut sink = StubSink::new();
    execute(program, captures, &LysisConfig::default(), &mut sink).unwrap();
    sink
}

fn b() -> ProgramBuilder<Bn254Fr> {
    ProgramBuilder::new(FieldFamily::BnLike256)
}

fn one() -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0])
}

fn seven() -> FieldElement<Bn254Fr> {
    FieldElement::<Bn254Fr>::from_canonical([7, 0, 0, 0])
}

fn offset_program(offsets: &[u32], templates: Vec<Template>) -> Program<Bn254Fr> {
    Program {
        header: LysisHeader::new(FieldFamily::BnLike256, 0, 0, 0),
        const_pool: ConstPool::new(FieldFamily::BnLike256),
        templates,
        body: offsets
            .iter()
            .copied()
            .map(|offset| Instr {
                opcode: Opcode::Halt,
                offset,
            })
            .collect(),
    }
}

mod basic_ops;
mod heap;
mod loops;
mod template_tables;
mod templates;
