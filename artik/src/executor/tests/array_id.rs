use super::*;

// ── ArrayId / ArrayFromId (handle stash + reconstruct) ──────────

#[test]
fn array_id_roundtrips_a_handle_through_an_int_slot() {
    // Alloc A=[99], stash its handle id into a 1-cell IntU32 slot,
    // reload the id, reconstruct the handle, read A[0] back.
    let body = vec![
        Instr::AllocArray {
            dst: 0,
            len: 1,
            elem: ElemT::Field,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 0,
        }, // value 99
        Instr::ReadSignal {
            dst: 2,
            signal_id: 1,
        }, // index 0
        Instr::IntFromField {
            w: IntW::U32,
            dst: 3,
            src: 2,
        },
        Instr::StoreArr {
            arr: 0,
            idx: 3,
            val: 1,
        }, // A[0] = 99
        Instr::AllocArray {
            dst: 4,
            len: 1,
            elem: ElemT::IntU32,
        }, // hslot
        Instr::ArrayId { dst: 5, arr: 0 },
        Instr::StoreArr {
            arr: 4,
            idx: 3,
            val: 5,
        }, // hslot[0] = id(A)
        Instr::LoadArr {
            dst: 6,
            arr: 4,
            idx: 3,
        },
        Instr::ArrayFromId {
            dst: 7,
            id: 6,
            elem: ElemT::Field,
        },
        Instr::LoadArr {
            dst: 8,
            arr: 7,
            idx: 3,
        }, // A[0] via reconstructed handle
        Instr::WriteWitness { slot_id: 0, src: 8 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 9, Vec::new(), body));
    let sig = [FE::from_u64(99), FE::zero()];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(99));
}

#[test]
fn array_id_selects_the_runtime_taken_handle_across_a_branch() {
    // Mirrors the if/else array-merge: pre-init the int slot with
    // A's id, then a JumpIf-gated block overwrites it with B's id
    // only when `cond != 0`. Post-branch reconstruction must yield
    // the handle the runtime path actually selected.
    let lead = vec![
        Instr::AllocArray {
            dst: 0,
            len: 1,
            elem: ElemT::Field,
        }, // A
        Instr::AllocArray {
            dst: 1,
            len: 1,
            elem: ElemT::Field,
        }, // B
        Instr::ReadSignal {
            dst: 2,
            signal_id: 0,
        }, // a
        Instr::ReadSignal {
            dst: 3,
            signal_id: 1,
        }, // b
        Instr::ReadSignal {
            dst: 4,
            signal_id: 2,
        }, // index 0
        Instr::IntFromField {
            w: IntW::U32,
            dst: 5,
            src: 4,
        },
        Instr::StoreArr {
            arr: 0,
            idx: 5,
            val: 2,
        }, // A[0] = a
        Instr::StoreArr {
            arr: 1,
            idx: 5,
            val: 3,
        }, // B[0] = b
        Instr::AllocArray {
            dst: 6,
            len: 1,
            elem: ElemT::IntU32,
        }, // hslot
        Instr::ArrayId { dst: 7, arr: 0 },
        Instr::StoreArr {
            arr: 6,
            idx: 5,
            val: 7,
        }, // pre-init hslot = id(A)
        Instr::ReadSignal {
            dst: 8,
            signal_id: 3,
        }, // cond
        Instr::ReadSignal {
            dst: 9,
            signal_id: 4,
        }, // zero
        Instr::FEq {
            dst: 10,
            a: 8,
            b: 9,
        }, // is_zero = (cond == 0)
        Instr::JumpIf {
            cond: 10,
            target: 0,
        }, // if cond == 0, skip the then-block
        Instr::ArrayId { dst: 11, arr: 1 }, // then: id(B)
        Instr::StoreArr {
            arr: 6,
            idx: 5,
            val: 11,
        }, // hslot = id(B)
        Instr::LoadArr {
            dst: 12,
            arr: 6,
            idx: 5,
        }, // skip:
        Instr::ArrayFromId {
            dst: 13,
            id: 12,
            elem: ElemT::Field,
        },
        Instr::LoadArr {
            dst: 14,
            arr: 13,
            idx: 5,
        },
        Instr::WriteWitness {
            slot_id: 0,
            src: 14,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    // Patch the JumpIf to the byte offset of the `skip:` LoadArr
    // (instruction index 17).
    let mut offset = 0u32;
    let mut offs = Vec::new();
    for ins in &lead {
        offs.push(offset);
        offset += ins.encoded_size();
    }
    let skip_offset = offs[17];
    let mut body = lead;
    if let Instr::JumpIf { target, .. } = &mut body[14] {
        *target = skip_offset;
    }
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 15, Vec::new(), body));

    // cond != 0 → then-block runs → reconstruct B → 22.
    let sig = [
        FE::from_u64(11),
        FE::from_u64(22),
        FE::zero(),
        FE::from_u64(1),
        FE::zero(),
    ];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(22));

    // cond == 0 → then-block skipped → pre-init A preserved → 11.
    let sig = [
        FE::from_u64(11),
        FE::from_u64(22),
        FE::zero(),
        FE::zero(),
        FE::zero(),
    ];
    let mut slots = [FE::zero()];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(11));
}
