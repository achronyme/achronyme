use super::*;

#[test]
fn load_const_idx_survives_when_const_pool_exceeds_u16_ceiling() {
    // The const pool is u32-indexed; `LoadConst.idx` (and the
    // sibling ConstPool-index opcode fields) must carry the full
    // u32 index. A circuit that interns more than 65 535 distinct
    // field constants would, with a u16 idx field/cast, silently
    // truncate the index: the wrapped value still passes the
    // `idx < pool_len` bounds check, so it resolves the WRONG
    // pool slot — a deep, scale-only miscompile (or a validation
    // failure when the wrong slot is not a field entry). Emit
    // > 65 536 distinct Consts so the last intern index exceeds
    // the old u16 ceiling, then assert the lowered LoadConst
    // carries the true index and that the program round-trips
    // (encode -> decode -> execute) resolving that slot to the
    // correct field value.
    const N: u32 = 65_700; // N - 1 > u16::MAX (65 535)
    let mut body: Vec<ExtendedInstruction<Bn254Fr>> = (0..N)
        .map(|i| {
            plain(Instruction::Const {
                result: ssa(i),
                value: fe(u64::from(i) + 1),
            })
        })
        .collect();
    // Consume the last const so its LoadConst is unquestionably
    // live (and the pin is non-vacuous).
    body.push(plain(Instruction::AssertEq {
        result: ssa(N),
        lhs: ssa(N - 1),
        rhs: ssa(N - 1),
        message: None,
    }));

    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body).expect("lower");

    // (a) Some emitted LoadConst must carry an idx beyond the old
    //     u16 ceiling — impossible if the field/cast truncates.
    let max_idx = program
        .body
        .iter()
        .filter_map(|i| match i.opcode {
            lysis::Opcode::LoadConst { idx, .. } => Some(idx),
            _ => None,
        })
        .max()
        .expect("at least one LoadConst was emitted");
    assert!(
        max_idx > u32::from(u16::MAX),
        "LoadConst.idx must carry the full u32 const-pool index \
             (got {max_idx}, must exceed {}); a u16 field or `as u16` \
             cast truncates this to a wrong slot",
        u16::MAX
    );
    // The slot that max-idx LoadConst points at must be exactly
    // the field it interned — proves no truncation / mis-pointing,
    // not merely that the value is in range.
    let expected = fe(u64::from(N)); // last distinct value = fe(N)
    match program.const_pool.get(max_idx as usize) {
        Some(lysis::ConstPoolEntry::Field(v)) => {
            assert_eq!(*v, expected, "max-idx slot holds the wrong field");
        }
        other => panic!("max-idx const-pool slot is not a Field: {other:?}"),
    }

    // (b) Round-trip the surface that actually changed: encode
    //     (4-byte idx) -> decode -> validate -> execute. This is
    //     where an over-65 535 program previously failed const
    //     bounds / resolved a non-field slot.
    let bytes = lysis::encode(&program);
    let decoded = lysis::decode::<Bn254Fr>(&bytes).expect("decode widened idx");
    lysis::bytecode::validate(&decoded, &LysisConfig::default())
        .expect("validate widened-idx program");
    let mut sink = InterningSink::<Bn254Fr>::new();
    execute(&decoded, &[], &LysisConfig::default(), &mut sink)
        .expect("execute must not hit a const-pool-index validation failure");
    // The unique last value materialises exactly once with its
    // true value (a truncated idx would have loaded a different
    // constant here).
    let last = sink
        .materialize()
        .iter()
        .filter(|n| matches!(n, lysis::InstructionKind::Const { value, .. } if *value == expected))
        .count();
    assert_eq!(
        last, 1,
        "the > u16-indexed field must materialise with its true value"
    );
}

#[test]
fn heap_slots_stay_distinct_when_spill_count_exceeds_u16_ceiling() {
    // The program-global heap-slot allocator (`heap_alloc`) and the
    // `StoreHeap.slot` / `heap_size_hint` it feeds are u32: the
    // number of distinct spilled cold vars scales with circuit
    // size, so a >1.5 M-constraint circuit spills well past 65 535.
    // With a u16 allocator the bump counter saturates at 65 535 and
    // every distinct var past the ceiling aliases slot 65 535 — a
    // silent slot-aliasing miscompile (a later `LoadHeap` reads the
    // wrong var's value), and `heap_size_hint` under-sizes the
    // executor heap. Drive >65 536 distinct cold-var spills through
    // a single split and assert every slot is distinct, the max
    // exceeds the old u16 ceiling, and the stamped `heap_size_hint`
    // covers them all.
    const N: u32 = 70_000; // N - 1 > u16::MAX (65 535)
    let cold: Vec<SsaVar> = (0..N).map(ssa).collect();

    let mut w = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    // `spill_cold_var` reads `ssa_to_reg[&var]` for the StoreHeap
    // src_reg; the reg value is irrelevant to slot allocation, so
    // bind them all to reg 0. An empty hot set keeps the split's
    // Step-2 O(1) (no capture forwarding).
    for &v in &cold {
        w.ssa_to_reg.insert(v, 0);
    }
    w.perform_split(&[], &cold)
        .expect("split must spill every cold var");
    let program = w.finalize().expect("finalize");

    // Every distinct cold var must get its own distinct slot.
    let slots: Vec<u32> = program
        .body
        .iter()
        .filter_map(|i| match i.opcode {
            lysis::Opcode::StoreHeap { slot, .. } => Some(slot),
            _ => None,
        })
        .collect();
    assert_eq!(
        slots.len() as u32,
        N,
        "every distinct cold var must emit one StoreHeap"
    );
    let distinct: std::collections::HashSet<u32> = slots.iter().copied().collect();
    assert_eq!(
        distinct.len() as u32,
        N,
        "slots must be all-distinct — a u16 allocator saturates at \
             65 535 and aliases every var past the ceiling onto one slot"
    );
    let max_slot = slots.iter().copied().max().expect("≥1 StoreHeap");
    assert!(
        max_slot > u32::from(u16::MAX),
        "max heap slot must exceed the old u16 ceiling (got {max_slot})"
    );
    assert_eq!(
        program.header.heap_size_hint, N,
        "heap_size_hint must size the executor heap for every \
             allocated slot, not the u16-saturated count"
    );
    // This pin owns the *walker* axis (the allocator emits distinct
    // u32 slots and stamps a matching hint instead of saturating at
    // 65 535). The wire + executor axis for a >u16 slot — encode
    // (4-byte slot) -> decode -> execute reading back the right
    // value — is owned by the layered companion
    // `heap_slot_above_u16_ceiling_round_trips_the_right_value`.
}

#[test]
fn witness_call_heap_outputs_lazy_load_via_resolve_on_first_use() {
    // After the heap-variant call, an instruction that consumes
    // an output must trigger a `LoadHeap` emit through resolve().
    let outputs: Vec<SsaVar> = (0..256u32).map(ssa).collect();
    let body = vec![
        plain(Instruction::WitnessCall(Box::new(WitnessCallBody {
            outputs,
            inputs: vec![],
            program_bytes: vec![0xFF],
        }))),
        // Reference output ssa(0) — should LoadHeap from slot 0
        // and then AssertEq it against itself (a trivial use).
        plain(Instruction::AssertEq {
            result: ssa(1000),
            lhs: ssa(0),
            rhs: ssa(0),
            message: None,
        }),
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");

    let load_heap_count = program
        .body
        .iter()
        .filter(|i| matches!(i.opcode, lysis::Opcode::LoadHeap { .. }))
        .count();
    assert!(
        load_heap_count >= 1,
        "expected at least one LoadHeap for ssa(0), got {load_heap_count}"
    );
}
