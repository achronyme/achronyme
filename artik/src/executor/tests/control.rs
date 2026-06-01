use super::*;

// ── Control flow (jumps, budgets, traps) ───────────────────────

#[test]
fn jump_if_taken_and_not_taken() {
    // Two-instruction program is not enough to exercise jumps
    // safely across encoded offsets, so we hand-build a loop-free
    // program: JumpIf skips one FAdd when cond != 0. We rely on
    // knowing the encoded target (by walking the instruction list).
    //
    // Layout:
    //   [0] ReadSignal dst=0 sig=0       ; x
    //   [1] ReadSignal dst=1 sig=1       ; cond
    //   [2] IntFromField U8 dst=2 src=1
    //   [3] FAdd dst=3 a=0 b=0           ; x + x
    //   [4] JumpIf cond=2 target=<off>   ; if cond skip WriteWitness 0
    //   [5] WriteWitness slot=0 src=3
    //   [6] Return
    //
    // If cond==1, we jump past WriteWitness to Return, leaving
    // slot 0 untouched. If cond==0, WriteWitness runs.

    // Compute byte offset of Return (instr 6).
    let lead: Vec<Instr> = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::ReadSignal {
            dst: 1,
            signal_id: 1,
        },
        Instr::IntFromField {
            w: IntW::U8,
            dst: 2,
            src: 1,
        },
        Instr::FAdd { dst: 3, a: 0, b: 0 },
        Instr::JumpIf {
            cond: 2,
            target: 0, // placeholder
        },
        Instr::WriteWitness { slot_id: 0, src: 3 },
        Instr::Return { srcs: Vec::new() },
    ];
    let mut offset = 0u32;
    let mut offs = Vec::new();
    for ins in &lead {
        offs.push(offset);
        offset += ins.encoded_size();
    }
    let return_offset = offs[6];

    let mut body = lead;
    if let Instr::JumpIf { target, .. } = &mut body[4] {
        *target = return_offset;
    }

    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 4, Vec::new(), body));

    // cond = 1 → skip WriteWitness, slot stays at initial value.
    let sig = [FE::from_u64(7), FE::from_u64(1)];
    let mut slots = [FE::from_u64(999)];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(999));

    // cond = 0 → run WriteWitness, slot becomes 14.
    let sig = [FE::from_u64(7), FE::from_u64(0)];
    let mut slots = [FE::from_u64(999)];
    run_bn(&prog, &sig, &mut slots).unwrap();
    assert_eq!(slots[0], FE::from_u64(14));
}

#[test]
fn budget_exhausted_on_tight_loop() {
    // Jump { target = 0 } creates an infinite loop back to the
    // first instruction. Budget must fire with the accurate
    // instructions-ran count.
    let body = vec![
        Instr::Jump { target: 0 },
        Instr::Return { srcs: Vec::new() }, // unreachable
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 0, Vec::new(), body));
    let mut ctx = ArtikContext::<F>::new(&[], &mut []);
    let err = execute_with_budget(&prog, &mut ctx, 10).unwrap_err();
    assert_eq!(err, ArtikError::BudgetExhausted { ran: 10 });
}

#[test]
fn trap_instruction_fires_exec_trap() {
    let body = vec![
        Instr::Trap { code: 0x01 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 0, Vec::new(), body));
    let err = run_bn(&prog, &[], &mut []).unwrap_err();
    assert_eq!(err, ArtikError::ExecTrap { code: 0x01 });
}

#[test]
fn signal_out_of_bounds_traps() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 10,
        },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), body));
    let sig = [FE::from_u64(1)];
    let mut slots = [];
    let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
    assert_eq!(
        err,
        ArtikError::SignalOutOfBounds {
            signal_id: 10,
            len: 1,
        }
    );
}

#[test]
fn witness_slot_out_of_bounds_traps() {
    let body = vec![
        Instr::ReadSignal {
            dst: 0,
            signal_id: 0,
        },
        Instr::WriteWitness { slot_id: 5, src: 0 },
        Instr::Return { srcs: Vec::new() },
    ];
    let prog = roundtrip(Program::new(FieldFamily::BnLike256, 1, Vec::new(), body));
    let sig = [FE::from_u64(1)];
    let mut slots = [FE::zero(), FE::zero()];
    let err = run_bn(&prog, &sig, &mut slots).unwrap_err();
    assert_eq!(
        err,
        ArtikError::WitnessSlotOutOfBounds { slot_id: 5, len: 2 }
    );
}
