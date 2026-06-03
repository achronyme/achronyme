use super::*;

#[test]
fn lc_map_get_returns_none_for_unknown_var() {
    let map: LcMap<Bn254Fr> = LcMap::new();
    assert!(map.get(&SsaVar(0)).is_none());
    assert!(map.get(&SsaVar(42)).is_none());
}

#[test]
fn lc_map_keep_last_hides_old_entries_and_drops_segments() {
    let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
    map.set_keep_last_vars(Some(5));

    for i in 0..10 {
        map.insert(
            SsaVar(i),
            LinearCombination::from_variable(Variable(i as usize + 1)),
        );
    }

    assert!(
        map.get(&SsaVar(4)).is_none(),
        "entries outside the configured sliding window must not be readable"
    );
    assert!(map.get(&SsaVar(5)).is_some());
    assert!(map.get(&SsaVar(9)).is_some());
    assert_eq!(
        map.allocated_segment_count(),
        2,
        "segments wholly below the sliding window should be released"
    );
}

#[test]
fn lc_map_keep_prefix_survives_sliding_window() {
    let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
    map.set_keep_prefix_vars(2);
    map.set_keep_last_vars(Some(3));

    for i in 0..12 {
        map.insert(
            SsaVar(i),
            LinearCombination::from_variable(Variable(i as usize + 1)),
        );
    }

    assert!(map.get(&SsaVar(0)).is_some());
    assert!(map.get(&SsaVar(1)).is_some());
    assert!(
        map.get(&SsaVar(4)).is_none(),
        "non-prefix entries outside the sliding window should be hidden"
    );
    assert!(map.get(&SsaVar(9)).is_some());
    assert_eq!(
        map.allocated_segment_count(),
        2,
        "prefix segment plus current sliding segment should remain"
    );
}

#[test]
fn lc_map_keep_last_reports_undefined_for_evicted_operand() {
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let x = prog.fresh_var();
    prog.push(Instruction::Input {
        result: x,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    for i in 0..4 {
        let v = prog.fresh_var();
        prog.push(Instruction::Const {
            result: v,
            value: FieldElement::<Bn254Fr>::from_u64(i),
        });
    }
    let y = prog.fresh_var();
    prog.push(Instruction::Input {
        result: y,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let out = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: out,
        lhs: x,
        rhs: y,
    });

    let mut compiler = R1CSCompiler::new_direct_linear_mul();
    compiler.lc_map.set_keep_last_vars(Some(3));
    let err = compiler.compile_ir(&prog).unwrap_err();
    assert!(
        matches!(err, R1CSError::UnsupportedOperation(_, _)),
        "a too-small sliding LC map should fail loudly on old operand reuse"
    );
}

#[test]
fn used_ssa_keep_last_hides_old_marks_and_drops_segments() {
    let mut used = UsedSsaSet::with_segment_bits(64);
    used.set_keep_last_vars(Some(64));

    used.mark(SsaVar(1));
    used.mark(SsaVar(130));

    assert!(!used.contains(SsaVar(1)));
    assert!(used.contains(SsaVar(130)));
    assert_eq!(used.word_count(), 1);
}

#[test]
fn used_ssa_keep_prefix_survives_sliding_window() {
    let mut used = UsedSsaSet::with_segment_bits(64);
    used.set_keep_prefix_vars(64);
    used.set_keep_last_vars(Some(64));

    used.mark(SsaVar(1));
    used.mark(SsaVar(130));

    assert!(used.contains(SsaVar(1)));
    assert!(used.contains(SsaVar(130)));
    assert_eq!(used.word_count(), 2);
}

#[test]
fn lc_map_insert_at_contiguous_indices_round_trips() {
    let mut map: LcMap<Bn254Fr> = LcMap::new();
    for i in 0..16u64 {
        let mut lc = LinearCombination::<Bn254Fr>::zero();
        lc.add_term(Variable(i as usize + 1), FieldElement::<Bn254Fr>::one());
        map.insert(SsaVar(i), lc);
    }
    for i in 0..16u64 {
        let got = map.get(&SsaVar(i)).expect("var was just inserted");
        assert_eq!(got.terms().len(), 1);
        assert_eq!(got.terms()[0].0, Variable(i as usize + 1));
    }
}

#[test]
fn lc_map_clear_drops_all_entries_and_keeps_get_safe() {
    let mut map: LcMap<Bn254Fr> = LcMap::new();
    map.insert(SsaVar(0), LinearCombination::<Bn254Fr>::zero());
    map.insert(SsaVar(1), LinearCombination::<Bn254Fr>::zero());
    map.clear();
    assert!(map.get(&SsaVar(0)).is_none());
    assert!(map.get(&SsaVar(1)).is_none());
    // After clear, density-1.0 invariant restarts from idx 0.
    map.insert(SsaVar(0), LinearCombination::<Bn254Fr>::zero());
    assert!(map.get(&SsaVar(0)).is_some());
}

#[test]
fn lc_map_insert_overwrites_existing_idx() {
    let mut map: LcMap<Bn254Fr> = LcMap::new();
    let mut first = LinearCombination::<Bn254Fr>::zero();
    first.add_term(Variable(7), FieldElement::<Bn254Fr>::one());
    map.insert(SsaVar(0), first);
    let mut second = LinearCombination::<Bn254Fr>::zero();
    second.add_term(Variable(99), FieldElement::<Bn254Fr>::one());
    map.insert(SsaVar(0), second);
    let got = map.get(&SsaVar(0)).expect("just overwrote");
    assert_eq!(got.terms()[0].0, Variable(99));
}

#[test]
fn lc_map_insert_at_high_idx_fills_intermediate_with_none() {
    // Sparse insertion is permitted (the compile_ir path may hit
    // small holes when an upstream DCE pass drops instructions
    // without renumbering SSA ids). The segmented layout bounds
    // individual allocation size while preserving direct indexing.
    let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
    map.insert(SsaVar(5), LinearCombination::<Bn254Fr>::zero());
    assert!(map.get(&SsaVar(5)).is_some());
    for i in 0..5u64 {
        assert!(map.get(&SsaVar(i)).is_none());
    }
    assert_eq!(map.allocated_segment_count(), 1);
    assert_eq!(map.slot_count(), 4);
}

#[test]
fn lc_map_dense_growth_allocates_bounded_segments() {
    let mut map: LcMap<Bn254Fr> = LcMap::with_segment_len(4);
    for i in 0..9u64 {
        map.insert(SsaVar(i), LinearCombination::<Bn254Fr>::zero());
    }
    assert_eq!(map.allocated_segment_count(), 3);
    assert_eq!(map.slot_count(), 12);
    for i in 0..9u64 {
        assert!(map.get(&SsaVar(i)).is_some());
    }
}

#[test]
fn streaming_path_emits_contiguous_ssavar_ids_pin() {
    // Density-1.0 codification on the streaming path used by the
    // chunk-drain boss-fight wiring. Feed a small IR program
    // through `compile_instructions_streaming` and check every
    // result SsaVar landed in lc_map at the expected contiguous
    // index — same insert path that the chunk-drain consumer
    // exercises at million-instruction scale.
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::Add {
        result: v3,
        lhs: v2,
        rhs: v0,
    });

    let mut compiler: R1CSCompiler<Bn254Fr> = R1CSCompiler::new();
    compiler
        .compile_instructions_streaming(prog.iter().cloned())
        .unwrap();
    for i in 0..=3u64 {
        assert!(
            compiler.lc_map.get(&SsaVar(i)).is_some(),
            "SsaVar({i}) must be populated"
        );
    }
    assert_eq!(
        compiler.lc_map.slot_count(),
        LcMap::<Bn254Fr>::DEFAULT_SEGMENT_LEN
    );
}

#[test]
fn lc_map_insert_stores_terms_in_segment_arena() {
    // Pin the arena-backed storage path on a worst-case LC: built
    // via incremental `add_term` calls, which used to leave one
    // owned Vec allocation per lc_map entry.
    let mut lc = LinearCombination::<Bn254Fr>::zero();
    for i in 0..5u64 {
        lc.add_term(Variable(i as usize + 1), FieldElement::<Bn254Fr>::one());
    }
    assert!(
        lc.terms_capacity() > lc.terms().len(),
        "precondition: incremental add_term leaves doubling slack"
    );

    let mut map: LcMap<Bn254Fr> = LcMap::new();
    map.insert(SsaVar(0), lc);

    let stored = map.get(&SsaVar(0)).expect("just inserted");
    assert_eq!(stored.terms().len(), 5);
    let segment = map.segments[0].as_ref().expect("segment allocated");
    assert_eq!(LcTag::from_slot(segment.slots[0]), LcTag::Terms);
    assert_eq!(segment.term_starts[0], 0);
    assert_eq!(segment.term_lens[0], 5);
    assert_eq!(segment.terms.len(), 5);
}

#[test]
fn lc_map_stores_unit_variable_lcs_inline() {
    let mut map: LcMap<Bn254Fr> = LcMap::new();
    map.insert(
        SsaVar(0),
        LinearCombination::<Bn254Fr>::from_variable(Variable(7)),
    );

    assert!(matches!(
        map.get_entry(&SsaVar(0)),
        Some(LcMapEntry::Variable(Variable(7)))
    ));
    let restored = map.get(&SsaVar(0)).expect("just inserted");
    assert_eq!(restored.terms(), &[(Variable(7), FieldElement::ONE)]);
}

#[test]
fn lc_map_insert_handles_empty_lc_without_regression() {
    // Empty `Vec::new()` has capacity 0; the conditional shrink
    // gate must skip the allocator round-trip and the slot must
    // still be populated.
    let lc = LinearCombination::<Bn254Fr>::zero();
    assert_eq!(lc.terms_capacity(), 0);
    assert_eq!(lc.terms().len(), 0);

    let mut map: LcMap<Bn254Fr> = LcMap::new();
    map.insert(SsaVar(0), lc);
    assert!(matches!(map.get_entry(&SsaVar(0)), Some(LcMapEntry::Zero)));
    assert!(map
        .get(&SsaVar(0))
        .expect("just inserted")
        .terms()
        .is_empty());
}

#[test]
fn lc_map_streaming_path_pins_cap_eq_len_on_every_populated_slot() {
    // End-to-end version of the arena pin: feed a small IR
    // program through the same `compile_instructions_streaming`
    // entry that the boss-fight chunk-drain consumer hits, then
    // iterate every term slot in lc_map and assert the stored range
    // points into the owning segment's arena. Skips empty holes so the
    // pin also holds on the non-streaming path which may leave
    // sparse slots when upstream DCE drops instructions.
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let v0 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v0,
        name: "x".into(),
        visibility: IrVisibility::Witness,
    });
    let v1 = prog.fresh_var();
    prog.push(Instruction::Input {
        result: v1,
        name: "y".into(),
        visibility: IrVisibility::Witness,
    });
    let v2 = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: v2,
        lhs: v0,
        rhs: v1,
    });
    let v3 = prog.fresh_var();
    prog.push(Instruction::Add {
        result: v3,
        lhs: v2,
        rhs: v0,
    });
    let v4 = prog.fresh_var();
    prog.push(Instruction::Add {
        result: v4,
        lhs: v3,
        rhs: v1,
    });

    let mut compiler: R1CSCompiler<Bn254Fr> = R1CSCompiler::new();
    compiler
        .compile_instructions_streaming(prog.iter().cloned())
        .unwrap();
    for (segment_idx, segment) in compiler.lc_map.segments.iter().enumerate() {
        if let Some(segment) = segment {
            for (offset, slot) in segment.slots.iter().enumerate() {
                if LcTag::from_slot(*slot) == LcTag::Terms {
                    let idx = segment_idx * compiler.lc_map.segment_len + offset;
                    let payload = (*slot >> LcMapSegment::<Bn254Fr>::TAG_BITS) as usize;
                    let start = segment.term_starts[payload] as usize;
                    let len = segment.term_lens[payload] as usize;
                    assert!(len > 0, "lc_map slot {idx}: term range must be non-empty");
                    assert!(
                        start + len <= segment.terms.len(),
                        "lc_map slot {idx}: term range must stay inside segment arena"
                    );
                }
            }
        }
    }
}

#[test]
fn lc_map_compile_ir_path_pins_cap_eq_len_on_every_populated_slot() {
    // Cross-path coverage: same invariant, eager (non-streaming)
    // `compile_ir` entry. This is the legacy path that downstream
    // tooling (inspector, CLI provenance readers) still exercises.
    let mut prog: IrProgram<Bn254Fr> = IrProgram::new();
    let a = prog.fresh_var();
    prog.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: IrVisibility::Witness,
    });
    let b = prog.fresh_var();
    prog.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: IrVisibility::Witness,
    });
    let s = prog.fresh_var();
    prog.push(Instruction::Add {
        result: s,
        lhs: a,
        rhs: b,
    });
    let p = prog.fresh_var();
    prog.push(Instruction::Mul {
        result: p,
        lhs: s,
        rhs: a,
    });

    let mut compiler: R1CSCompiler<Bn254Fr> = R1CSCompiler::new();
    compiler.compile_ir(&prog).unwrap();
    for (segment_idx, segment) in compiler.lc_map.segments.iter().enumerate() {
        if let Some(segment) = segment {
            for (offset, slot) in segment.slots.iter().enumerate() {
                if LcTag::from_slot(*slot) == LcTag::Terms {
                    let idx = segment_idx * compiler.lc_map.segment_len + offset;
                    let payload = (*slot >> LcMapSegment::<Bn254Fr>::TAG_BITS) as usize;
                    let start = segment.term_starts[payload] as usize;
                    let len = segment.term_lens[payload] as usize;
                    assert!(len > 0, "lc_map slot {idx}: term range must be non-empty");
                    assert!(
                        start + len <= segment.terms.len(),
                        "lc_map slot {idx}: term range must stay inside segment arena"
                    );
                }
            }
        }
    }
}
