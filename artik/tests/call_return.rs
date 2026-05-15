//! Cross-frame `Call` / `Return` acceptance tests.
//!
//! These construct multi-subprogram programs by hand (the programmatic
//! builder is single-subprogram for now), round-trip them through
//! encode + decode + validate, and execute them. They are the gate for
//! the call/return frame stack: a scalar call, an array argument that
//! crosses frames as a bare handle into the program-global store, and
//! the validator rejections that protect the call ABI.

use artik::bytecode::{decode, encode};
use artik::executor::{execute, ArtikContext};
use artik::ir::{ElemT, Instr, IntW, RegType};
use artik::program::{FieldConstEntry, Program, Subprogram};
use artik::ArtikError;
use memory::field::{Bn254Fr, FieldElement};
use memory::FieldFamily;

type F = Bn254Fr;
type FE = FieldElement<F>;

fn fam() -> FieldFamily {
    FieldFamily::BnLike256
}

fn run(prog: &Program, signals: &[FE], slots: &mut [FE]) -> Result<(), ArtikError> {
    let mut ctx = ArtikContext::<F>::new(signals, slots);
    execute(prog, &mut ctx)
}

fn roundtrip(prog: Program) -> Result<Program, ArtikError> {
    let bytes = encode(&prog);
    decode(&bytes, Some(fam()))
}

/// Entry reads `x` from a signal, calls `square(x)`, and writes the
/// result to a witness slot. The scalar argument crosses the frame
/// boundary into the callee's parameter register and the result
/// crosses back into the caller's recorded destination.
#[test]
fn scalar_call_passes_arg_and_returns_value() {
    let entry = Subprogram {
        frame_size: 3,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::Call {
                func_id: 1,
                args: vec![0],
                rets: vec![1],
            },
            Instr::WriteWitness { slot_id: 0, src: 1 },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let square = Subprogram {
        frame_size: 2,
        params: vec![RegType::Field],
        returns: vec![RegType::Field],
        body: vec![
            Instr::FMul { dst: 1, a: 0, b: 0 },
            Instr::Return { srcs: vec![1] },
        ],
    };
    let prog = roundtrip(Program::from_subprograms(
        fam(),
        Vec::new(),
        vec![entry, square],
    ))
    .expect("decode");

    let mut slots = [FE::zero()];
    run(&prog, &[FE::from_u64(7)], &mut slots).expect("execute");
    assert_eq!(slots[0], FE::from_u64(49));
}

/// Entry allocates a Field array, writes `A[0]=5`, calls a subprogram
/// that writes `A[1]=9` and returns the same handle, then reads both
/// cells back. The array never leaves the program-global store: the
/// caller's pre-call write and the callee's write are both visible
/// after the call, proving the handle — not a copy — crosses frames
/// in both directions.
#[test]
fn array_handle_crosses_frames_through_the_global_store() {
    // Const pool, little-endian canonical (small values zero-pad).
    let pool = vec![
        FieldConstEntry { bytes: vec![5] }, // c0
        FieldConstEntry { bytes: vec![9] }, // c1
        FieldConstEntry { bytes: vec![0] }, // c2  (index 0)
        FieldConstEntry { bytes: vec![1] }, // c3  (index 1)
    ];

    let entry = Subprogram {
        frame_size: 12,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::AllocArray {
                dst: 0,
                len: 2,
                elem: ElemT::Field,
            },
            Instr::PushConst {
                dst: 1,
                const_id: 0,
            }, // 5
            Instr::PushConst {
                dst: 2,
                const_id: 2,
            }, // 0
            Instr::IntFromField {
                w: IntW::U32,
                dst: 3,
                src: 2,
            }, // idx 0
            Instr::StoreArr {
                arr: 0,
                idx: 3,
                val: 1,
            }, // A[0] = 5
            Instr::Call {
                func_id: 1,
                args: vec![0],
                rets: vec![4],
            }, // r4 = fill(A)
            Instr::LoadArr {
                dst: 5,
                arr: 4,
                idx: 3,
            }, // A[0] (still 5)
            Instr::WriteWitness { slot_id: 0, src: 5 },
            Instr::PushConst {
                dst: 6,
                const_id: 3,
            }, // 1
            Instr::IntFromField {
                w: IntW::U32,
                dst: 7,
                src: 6,
            }, // idx 1
            Instr::LoadArr {
                dst: 8,
                arr: 4,
                idx: 7,
            }, // A[1] (set by callee)
            Instr::WriteWitness { slot_id: 1, src: 8 },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let fill = Subprogram {
        frame_size: 4,
        params: vec![RegType::Array(ElemT::Field)],
        returns: vec![RegType::Array(ElemT::Field)],
        body: vec![
            Instr::PushConst {
                dst: 1,
                const_id: 1,
            }, // 9
            Instr::PushConst {
                dst: 2,
                const_id: 3,
            }, // 1
            Instr::IntFromField {
                w: IntW::U32,
                dst: 3,
                src: 2,
            }, // idx 1
            Instr::StoreArr {
                arr: 0,
                idx: 3,
                val: 1,
            }, // A[1] = 9
            Instr::Return { srcs: vec![0] },
        ],
    };
    let prog =
        roundtrip(Program::from_subprograms(fam(), pool, vec![entry, fill])).expect("decode");

    let mut slots = [FE::zero(), FE::zero()];
    run(&prog, &[], &mut slots).expect("execute");
    assert_eq!(
        slots[0],
        FE::from_u64(5),
        "caller's pre-call write survives"
    );
    assert_eq!(
        slots[1],
        FE::from_u64(9),
        "callee's write is visible to caller"
    );
}

#[test]
fn entry_with_params_is_rejected() {
    let entry = Subprogram {
        frame_size: 1,
        params: vec![RegType::Field],
        returns: Vec::new(),
        body: vec![Instr::Return { srcs: Vec::new() }],
    };
    let err = roundtrip(Program::from_subprograms(fam(), Vec::new(), vec![entry])).unwrap_err();
    assert!(matches!(err, ArtikError::EntryHasParamsOrReturns));
}

#[test]
fn signal_access_outside_entry_is_rejected() {
    let entry = Subprogram {
        frame_size: 1,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::Call {
                func_id: 1,
                args: Vec::new(),
                rets: Vec::new(),
            },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let callee = Subprogram {
        frame_size: 1,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let err = roundtrip(Program::from_subprograms(
        fam(),
        Vec::new(),
        vec![entry, callee],
    ))
    .unwrap_err();
    assert!(matches!(err, ArtikError::SignalsOutsideEntry));
}

#[test]
fn call_to_undefined_subprogram_is_rejected() {
    let entry = Subprogram {
        frame_size: 1,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::Call {
                func_id: 7,
                args: Vec::new(),
                rets: Vec::new(),
            },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let err = roundtrip(Program::from_subprograms(fam(), Vec::new(), vec![entry])).unwrap_err();
    assert!(matches!(err, ArtikError::UnknownSubprogram { func_id: 7 }));
}

#[test]
fn call_arity_mismatch_is_rejected() {
    let entry = Subprogram {
        frame_size: 1,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::Call {
                func_id: 1,
                args: Vec::new(), // callee wants 1 param
                rets: Vec::new(),
            },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let callee = Subprogram {
        frame_size: 1,
        params: vec![RegType::Field],
        returns: Vec::new(),
        body: vec![Instr::Return { srcs: Vec::new() }],
    };
    let err = roundtrip(Program::from_subprograms(
        fam(),
        Vec::new(),
        vec![entry, callee],
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        ArtikError::CallArityMismatch {
            func_id: 1,
            expected: 1,
            got: 0
        }
    ));
}

/// The validator has no static acyclicity check (circom forbids
/// recursion, so a correct lift never emits a cycle). Malformed
/// bytecode that does is caught at runtime by the call-depth guard
/// rather than overflowing the stack.
#[test]
fn unbounded_recursion_hits_the_depth_guard() {
    let entry = Subprogram {
        frame_size: 1,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::Call {
                func_id: 1,
                args: Vec::new(),
                rets: Vec::new(),
            },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let loop_sub = Subprogram {
        frame_size: 1,
        params: Vec::new(),
        returns: Vec::new(),
        body: vec![
            Instr::Call {
                func_id: 1,
                args: Vec::new(),
                rets: Vec::new(),
            },
            Instr::Return { srcs: Vec::new() },
        ],
    };
    let prog = roundtrip(Program::from_subprograms(
        fam(),
        Vec::new(),
        vec![entry, loop_sub],
    ))
    .expect("decode");

    let mut slots: [FE; 0] = [];
    let err = run(&prog, &[], &mut slots).unwrap_err();
    assert!(matches!(err, ArtikError::CallDepthExceeded { .. }));
}
