use super::*;
use crate::bytecode::{decode, encode};
use crate::executor::{execute, ArtikContext};
use crate::ir::{IntW, RegType};
use crate::program::Program;
use memory::field::{Bn254Fr, FieldElement};

type F = Bn254Fr;
type FE = FieldElement<F>;

fn run(prog: &Program, signals: &[FE], slots: &mut [FE]) {
    let mut ctx = ArtikContext::<F>::new(signals, slots);
    execute(prog, &mut ctx).expect("execute");
}

fn roundtrip(prog: Program) -> Program {
    let bytes = encode(&prog);
    decode(&bytes, Some(FieldFamily::BnLike256)).expect("decode")
}

#[test]
fn builder_square_program() {
    // function sq(x) { return x * x; }  — witness lift.
    let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
    let x_sig = b.alloc_signal();
    let out_slot = b.alloc_witness_slot();
    let x = b.read_signal(x_sig);
    let sq = b.fmul(x, x);
    b.write_witness(out_slot, sq);
    b.ret();
    let prog = roundtrip(b.finish().unwrap());

    let mut slots = [FE::zero()];
    run(&prog, &[FE::from_u64(9)], &mut slots);
    assert_eq!(slots[0], FE::from_u64(81));
}

#[test]
fn builder_forward_jump_resolves_to_return() {
    // function skip(cond, x) {
    //     if (cond) { skip past return-of-double-x; }
    //     write witness[0] = x * 2;
    //     return;
    // }
    let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
    let cond_sig = b.alloc_signal();
    let x_sig = b.alloc_signal();
    let slot = b.alloc_witness_slot();
    let end = b.new_label();

    let cond_f = b.read_signal(cond_sig);
    let cond = b.int_from_field(IntW::U8, cond_f);
    let x = b.read_signal(x_sig);
    let two_x = b.fadd(x, x);
    b.jump_if_to(cond, end);
    b.write_witness(slot, two_x);
    b.place(end);
    b.ret();

    let prog = roundtrip(b.finish().unwrap());

    // cond=0 → write runs.
    let sig = [FE::zero(), FE::from_u64(21)];
    let mut slots = [FE::zero()];
    run(&prog, &sig, &mut slots);
    assert_eq!(slots[0], FE::from_u64(42));

    // cond=1 → write skipped, slot stays at initial value.
    let sig = [FE::from_u64(1), FE::from_u64(21)];
    let mut slots = [FE::from_u64(999)];
    run(&prog, &sig, &mut slots);
    assert_eq!(slots[0], FE::from_u64(999));
}

#[test]
fn builder_unplaced_label_errors() {
    let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
    let lbl = b.new_label();
    b.jump_to(lbl);
    b.ret();
    // `lbl` never placed.
    let err = b.finish().unwrap_err();
    assert_eq!(err, BuilderError::UnplacedLabel(0));
}

#[test]
fn builder_intern_const_roundtrip() {
    let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
    let slot = b.alloc_witness_slot();
    // A canonical field constant of value 42 (BN-like, 32 bytes LE).
    let cid = b.intern_const(vec![42]);
    let r = b.push_const(cid);
    b.write_witness(slot, r);
    b.ret();
    let prog = roundtrip(b.finish().unwrap());

    let mut slots = [FE::zero()];
    run(&prog, &[], &mut slots);
    assert_eq!(slots[0], FE::from_u64(42));
}

#[test]
fn builder_reserve_and_call_subprogram() {
    // Entry calls a reserved `square(x)` subprogram. The callee id
    // is handed out before its body exists, so the Call in the
    // entry can reference it; the callee body is filled in after.
    let mut b = ProgramBuilder::new(FieldFamily::BnLike256);
    let sq = b.reserve_subprogram(vec![RegType::Field], vec![RegType::Field]);

    // Entry body (active = 0).
    let x_sig = b.alloc_signal();
    let slot = b.alloc_witness_slot();
    let x = b.read_signal(x_sig);
    let rets = b.call(sq, &[x], &[RegType::Field]);
    b.write_witness(slot, rets[0]);
    b.ret();

    // Callee body: param is register 0.
    let prev = b.begin_subprogram(sq);
    let p = b.fmul(0, 0);
    b.ret_vals(&[p]);
    b.end_subprogram(prev);

    let prog = roundtrip(b.finish().unwrap());
    let mut slots = [FE::zero()];
    run(&prog, &[FE::from_u64(6)], &mut slots);
    assert_eq!(slots[0], FE::from_u64(36));
}
