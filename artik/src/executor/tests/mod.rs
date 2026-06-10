use super::*;
use crate::bytecode::{decode, encode};
use crate::ir::{ElemT, IntBinOp, IntW};
use crate::program::{FieldConstEntry, Program};
use memory::field::Bn254Fr;

type F = Bn254Fr;
type FE = FieldElement<F>;

fn run_bn(prog: &Program, signals: &[FE], slots: &mut [FE]) -> Result<(), ArtikError> {
    let mut ctx = ArtikContext::<F>::new(signals, slots);
    execute(prog, &mut ctx)
}

fn roundtrip(prog: Program) -> Program {
    let bytes = encode(&prog);
    decode(&bytes, Some(FieldFamily::BnLike256)).expect("decode")
}

mod array_id;
mod arrays;
mod control;
mod crypto;
mod field;
mod field_canonical;
mod int;
mod intrinsics_exec;
mod limits;
mod rotations;
mod semantic;
