use super::*;

/// Even when no split is needed (small program), the walker still
/// wraps the body in Template 0. Verify the template count is 1.
#[test]
fn small_program_uses_exactly_one_template() {
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(7),
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(3),
        }),
        plain(Instruction::Add {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");
    assert_eq!(
        program.templates.len(),
        1,
        "small body should fit in Template 0 with no chain"
    );
}

// ---------------------------------------------------------------
// partition_live_set unit tests and heap-emission smoke.
// ---------------------------------------------------------------

#[test]
fn partition_under_hot_cap_all_hot() {
    let live: Vec<SsaVar> = (0..10).map(ssa).collect();
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let force = HashSet::default();
    let (hot, cold) = partition_live_set(&live, &body, &force);
    assert_eq!(hot.len(), 10);
    assert!(cold.is_empty());
}

#[test]
fn partition_above_hot_cap_splits_at_max_captures_hot() {
    let live: Vec<SsaVar> = (0..60).map(ssa).collect();
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let force = HashSet::default();
    let (hot, cold) = partition_live_set(&live, &body, &force);
    assert_eq!(hot.len(), MAX_CAPTURES_HOT);
    assert_eq!(cold.len(), 60 - MAX_CAPTURES_HOT);
}

#[test]
fn partition_first_use_drives_hot_selection() {
    // 100 live vars; only ssa(50)..=ssa(97) are referenced in the
    // upcoming body window (in ascending order). Those 48
    // referenced-earliest become hot; the rest (0..50, 98, 99) cold.
    let live: Vec<SsaVar> = (0..100).map(ssa).collect();
    let body: Vec<ExtendedInstruction<Bn254Fr>> = (50u32..=97u32)
        .map(|i| {
            plain(Instruction::Add {
                result: ssa(1000 + i),
                lhs: ssa(i),
                rhs: ssa(i),
            })
        })
        .collect();
    let force = HashSet::default();
    let (hot, cold) = partition_live_set(&live, &body, &force);
    assert_eq!(hot.len(), MAX_CAPTURES_HOT);
    let hot_set: HashSet<SsaVar> = hot.iter().copied().collect();
    for i in 50u32..=97 {
        assert!(hot_set.contains(&ssa(i)), "ssa({i}) should be hot");
    }
    // ssa(0..49) + ssa(98) + ssa(99) → all cold (52 items)
    assert_eq!(cold.len(), 100 - MAX_CAPTURES_HOT);
}

#[test]
fn partition_force_hot_overrides_first_use() {
    // ssa(99) has first_use = MAX (not in body) but is force_hot.
    let mut live: Vec<SsaVar> = (0..50).map(ssa).collect();
    live.push(ssa(99));
    let body: Vec<ExtendedInstruction<Bn254Fr>> = (0u32..50)
        .map(|i| {
            plain(Instruction::Add {
                result: ssa(1000 + i),
                lhs: ssa(i),
                rhs: ssa(i),
            })
        })
        .collect();
    let mut force = HashSet::default();
    force.insert(ssa(99));
    let (hot, cold) = partition_live_set(&live, &body, &force);
    assert!(
        hot.contains(&ssa(99)),
        "force_hot must override first-use ordering"
    );
    assert_eq!(hot.len(), MAX_CAPTURES_HOT);
    // 51 total - 48 hot = 3 cold
    assert_eq!(cold.len(), 51 - MAX_CAPTURES_HOT);
}

#[test]
fn partition_outputs_sorted_by_ssa_var_id() {
    // The capture-slot stability contract requires hot/cold both
    // be sorted by SsaVar.0; the first-use selection happens
    // internally but does not leak into the output ordering.
    let live: Vec<SsaVar> = (0..60).map(ssa).collect();
    let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
    let force = HashSet::default();
    let (hot, cold) = partition_live_set(&live, &body, &force);
    for w in hot.windows(2) {
        assert!(w[0].0 < w[1].0, "hot must be sorted by SsaVar.0");
    }
    for w in cold.windows(2) {
        assert!(w[0].0 < w[1].0, "cold must be sorted by SsaVar.0");
    }
}

/// First-use heuristic vs naive comparison.
///
/// Builds a synthetic post-split body where the live set has 100
/// vars and the body references ssa(60..=99) earliest, then
/// ssa(0..=59). With `MAX_CAPTURES_HOT=48`, the **first-use
/// heuristic** picks ssa(60..=99) plus 8 more (the 48 hot) and
/// spills 52 cold; the **naive ordering** picks ssa(0..=47) hot
/// and spills ssa(48..=99) cold.
///
/// Observed metric: `LoadHeap` emissions in the first half of
/// the body (the "early window"). The heuristic should always
/// produce a count less than or equal to naive there, since vars
/// referenced earliest stay hot.
///
/// This test prints the numbers and asserts the monotonicity
/// property (heuristic never *worse* than naive on this fixture).
#[test]
fn heuristic_vs_naive_first_use_advantage() {
    let live: Vec<SsaVar> = (0..100).map(ssa).collect();
    // Body: first half references ssa(60..=99) (40 vars), second
    // half references ssa(0..=59) (60 vars). The first-use
    // heuristic captures 60..=99 + ssa(0..=7) = 48; naive
    // captures 0..=47 = 48 (different set).
    let body: Vec<ExtendedInstruction<Bn254Fr>> = (60u32..100)
        .chain(0u32..60)
        .map(|i| {
            plain(Instruction::Add {
                result: ssa(1000 + i),
                lhs: ssa(i),
                rhs: ssa(i),
            })
        })
        .collect();
    let force = HashSet::default();

    let (heur_hot, heur_cold) = partition_live_set(&live, &body, &force);

    // Naive partition: sort live by SsaVar.0, take first 48 as hot.
    let mut sorted_live = live.clone();
    sorted_live.sort_unstable_by_key(|v| v.0);
    let naive_hot: Vec<SsaVar> = sorted_live[..MAX_CAPTURES_HOT].to_vec();
    let naive_cold: Vec<SsaVar> = sorted_live[MAX_CAPTURES_HOT..].to_vec();

    // For each strategy, count *unique* cold vars referenced
    // anywhere in the *first half* of the body (the early
    // window). Each unique cold var produces exactly one
    // `LoadHeap` per template body that references it (per
    // walker contract enforced by `Walker::resolve`).
    let count_loads_first_half = |cold: &[SsaVar]| -> usize {
        let cold_set: std::collections::HashSet<_> = cold.iter().copied().collect();
        let mut loaded: std::collections::HashSet<SsaVar> = std::collections::HashSet::default();
        for inst in body.iter().take(body.len() / 2) {
            let mut refs = std::collections::HashSet::default();
            collect_in_extinst(inst, &mut refs);
            for v in refs {
                if cold_set.contains(&v) {
                    loaded.insert(v);
                }
            }
        }
        loaded.len()
    };

    let heur_loads = count_loads_first_half(&heur_cold);
    let naive_loads = count_loads_first_half(&naive_cold);

    // Visible report — captured by `cargo test -- --nocapture`
    // for benchmark sign-off.
    eprintln!(
        "[lysis-spill-bench] heuristic_loads={heur_loads} \
             naive_loads={naive_loads} \
             win_pct={:.1}",
        if naive_loads == 0 {
            0.0
        } else {
            (naive_loads as f64 - heur_loads as f64) * 100.0 / naive_loads as f64
        }
    );

    // Sanity: hot and cold partition the live set in both cases.
    assert_eq!(heur_hot.len() + heur_cold.len(), live.len());
    assert_eq!(naive_hot.len() + naive_cold.len(), live.len());

    // Monotonicity: heuristic must not produce *more* LoadHeaps
    // in the early window than naive ordering. If this fails,
    // the heuristic has regressed and we should investigate
    // before keeping it.
    assert!(
            heur_loads <= naive_loads,
            "heuristic emitted {heur_loads} LoadHeaps in early window vs naive {naive_loads}; \
             expected heuristic ≤ naive (first-use ordering should never lose to SsaVar.0 ordering)"
        );
}

#[test]
fn small_body_emits_no_heap_ops() {
    // Sanity: a program that fits in MAX_CAPTURES_HOT ought to
    // emit zero heap opcodes and leave heap_size_hint at 0. This
    // is the "no regression for the existing corpus" gate.
    let body = vec![
        plain(Instruction::Const {
            result: ssa(0),
            value: fe(7),
        }),
        plain(Instruction::Const {
            result: ssa(1),
            value: fe(3),
        }),
        plain(Instruction::Add {
            result: ssa(2),
            lhs: ssa(0),
            rhs: ssa(1),
        }),
    ];
    let walker = Walker::<Bn254Fr>::new(FieldFamily::BnLike256);
    let program = walker.lower(body.clone()).expect("lower");
    assert_eq!(program.header.heap_size_hint, 0);
    let heap_ops = program
        .body
        .iter()
        .filter(|i| {
            matches!(
                i.opcode,
                lysis::Opcode::StoreHeap { .. } | lysis::Opcode::LoadHeap { .. }
            )
        })
        .count();
    assert_eq!(heap_ops, 0);
}
