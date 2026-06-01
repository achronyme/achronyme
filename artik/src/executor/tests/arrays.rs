use super::*;

// ── Arrays + loops ─────────────────────────────────────────────

#[test]
fn array_allocate_store_load() {
    // arr : Field[2]
    // arr[0] = sig[0]; arr[1] = sig[1];
    // witness[0] = arr[1] + arr[0]
    let body = vec![
        Instr::AllocArray {
            dst: 0,
            len: 2,
            elem: ElemT::Field,
        },
        // idx0 = IntFromField(0)
        Instr::ReadSignal {
            dst: 1,
            signal_id: 2, // sig[2] == 0
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 2,
            src: 1,
        },
        Instr::ReadSignal {
            dst: 3,
            signal_id: 0,
        },
        Instr::StoreArr {
            arr: 0,
            idx: 2,
            val: 3,
        },
        Instr::ReadSignal {
            dst: 4,
            signal_id: 3, // sig[3] == 1
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 5,
            src: 4,
        },
        Instr::ReadSignal {
            dst: 6,
            signal_id: 1,
        },
        Instr::StoreArr {
            arr: 0,
            idx: 5,
            val: 6,
        },
        Instr::LoadArr {
            dst: 7,
            arr: 0,
            idx: 5,
        },
        Instr::LoadArr {
            dst: 8,
            arr: 0,
            idx: 2,
        },
        Instr::FAdd { dst: 9, a: 7, b: 8 },
        Instr::WriteWitness { slot_id: 0, src: 9 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 10, Vec::new(), body));
    let sig = [
        FE::from_u64(7),
        FE::from_u64(35),
        FE::zero(),
        FE::from_u64(1),
    ];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(42));
}

#[test]
fn array_oob_traps() {
    let body = vec![
        Instr::AllocArray {
            dst: 0,
            len: 1,
            elem: ElemT::IntU32,
        },
        // idx 5 via sig
        Instr::ReadSignal {
            dst: 1,
            signal_id: 0,
        },
        Instr::IntFromField {
            w: IntW::U32,
            dst: 2,
            src: 1,
        },
        Instr::LoadArr {
            dst: 3,
            arr: 0,
            idx: 2,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));
    let sig = [FE::from_u64(5)];
    let mut slots = [];
    let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
    assert!(matches!(
        err,
        ArtikError::ArrayIndexOutOfBounds { idx: 5, len: 1 }
    ));
}
