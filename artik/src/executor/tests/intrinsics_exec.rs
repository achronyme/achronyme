use super::*;
use crate::intrinsics::{Intrinsic, IntrinsicAnnotation};
use crate::ir::RegType;
use crate::program::Subprogram;

/// Build a program whose entry fills two 2-digit arrays from signals,
/// calls subprogram 1 (annotated as `ModInv { n: 4, k: 2 }`), and
/// writes the first two digits of the result to witness slots.
///
/// The interpreted body of subprogram 1 deliberately computes
/// something else (a constant 42 in digit 0), so the witness values
/// prove which path ran: the native intrinsic on in-range inputs, the
/// interpreted body when a guard declines.
fn modinv_dispatch_program() -> Program {
    let consts = vec![
        FieldConstEntry { bytes: vec![0] },  // 0
        FieldConstEntry { bytes: vec![1] },  // 1
        FieldConstEntry { bytes: vec![42] }, // sentinel
    ];
    let entry_body = vec![
        // idx registers
        Instr::PushConst {
            dst: 0,
            const_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 1,
            src: 0,
        },
        Instr::PushConst {
            dst: 2,
            const_id: 1,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 3,
            src: 2,
        },
        // a = [sig0, sig1], p = [sig2, sig3]
        Instr::AllocArray {
            dst: 4,
            len: 2,
            elem: ElemT::Field,
        },
        Instr::ReadSignal {
            dst: 5,
            signal_id: 0,
        },
        Instr::StoreArr {
            arr: 4,
            idx: 1,
            val: 5,
        },
        Instr::ReadSignal {
            dst: 6,
            signal_id: 1,
        },
        Instr::StoreArr {
            arr: 4,
            idx: 3,
            val: 6,
        },
        Instr::AllocArray {
            dst: 7,
            len: 2,
            elem: ElemT::Field,
        },
        Instr::ReadSignal {
            dst: 8,
            signal_id: 2,
        },
        Instr::StoreArr {
            arr: 7,
            idx: 1,
            val: 8,
        },
        Instr::ReadSignal {
            dst: 9,
            signal_id: 3,
        },
        Instr::StoreArr {
            arr: 7,
            idx: 3,
            val: 9,
        },
        // scalar params n, k (values irrelevant to the native path —
        // the annotation carries the constants)
        Instr::PushConst {
            dst: 10,
            const_id: 1,
        },
        Instr::PushConst {
            dst: 11,
            const_id: 1,
        },
        Instr::Call {
            func_id: 1,
            args: vec![10, 11, 4, 7],
            rets: vec![12],
        },
        Instr::LoadArr {
            dst: 13,
            arr: 12,
            idx: 1,
        },
        Instr::WriteWitness {
            slot_id: 0,
            src: 13,
        },
        Instr::LoadArr {
            dst: 14,
            arr: 12,
            idx: 3,
        },
        Instr::WriteWitness {
            slot_id: 1,
            src: 14,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let callee_body = vec![
        Instr::AllocArray {
            dst: 4,
            len: 4,
            elem: ElemT::Field,
        },
        Instr::PushConst {
            dst: 5,
            const_id: 2,
        },
        Instr::PushConst {
            dst: 6,
            const_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 7,
            src: 6,
        },
        Instr::StoreArr {
            arr: 4,
            idx: 7,
            val: 5,
        },
        Instr::Return { srcs: vec![4] },
    ];
    let entry = Subprogram {
        frame_size: 16,
        params: Vec::new(),
        returns: Vec::new(),
        body: entry_body,
    };
    let callee = Subprogram {
        frame_size: 8,
        params: vec![
            RegType::Field,
            RegType::Field,
            RegType::Array(ElemT::Field),
            RegType::Array(ElemT::Field),
        ],
        returns: vec![RegType::Array(ElemT::Field)],
        body: callee_body,
    };
    let mut prog = Program::from_subprograms(FieldFamily::BnLike256, consts, vec![entry, callee]);
    prog.intrinsics.push(IntrinsicAnnotation {
        func_id: 1,
        intrinsic: Intrinsic::ModInv {
            n: 4,
            k: 2,
            ret_len: 4,
        },
    });
    prog
}

#[test]
fn annotated_call_runs_natively_on_in_range_inputs() {
    let prog = roundtrip(modinv_dispatch_program());
    // a = [3, 1] = 19, p = [1, 1] = 17 (prime). 19 mod 17 = 2,
    // 2^15 mod 17 = 9, so the inverse digits are [9, 0].
    let sig = [
        FE::from_u64(3),
        FE::from_u64(1),
        FE::from_u64(1),
        FE::from_u64(1),
    ];
    let mut slots = [FE::zero(), FE::zero()];
    run_bn(&prog, &sig, &mut slots).expect("execute");
    assert_eq!(slots[0], FE::from_u64(9), "native path must have run");
    assert_eq!(slots[1], FE::from_u64(0));
}

#[test]
fn annotated_call_falls_back_when_guard_declines() {
    let prog = roundtrip(modinv_dispatch_program());
    // Digit 255 is out of range for n = 4, so the native path must
    // decline and the interpreted body (sentinel 42) must run.
    let sig = [
        FE::from_u64(255),
        FE::from_u64(1),
        FE::from_u64(1),
        FE::from_u64(1),
    ];
    let mut slots = [FE::zero(), FE::zero()];
    run_bn(&prog, &sig, &mut slots).expect("execute");
    assert_eq!(slots[0], FE::from_u64(42), "interpreted body must have run");
    assert_eq!(slots[1], FE::from_u64(0));
}

#[test]
fn stripped_annotation_runs_interpreted_body() {
    let mut prog = modinv_dispatch_program();
    prog.intrinsics.clear();
    let prog = roundtrip(prog);
    let sig = [
        FE::from_u64(3),
        FE::from_u64(1),
        FE::from_u64(1),
        FE::from_u64(1),
    ];
    let mut slots = [FE::zero(), FE::zero()];
    run_bn(&prog, &sig, &mut slots).expect("execute");
    assert_eq!(slots[0], FE::from_u64(42));
}
