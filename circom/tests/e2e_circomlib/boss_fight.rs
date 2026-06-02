use super::*;

/// secp256k1 ECDSA signature verification — boss-fight constraint
/// measurement against `0xPARC/circom-ecdsa`.
///
/// Tree-of-bigint emulation that does **not** route through
/// Num2Bits → CompConstant chains; the `proven_boolean`
/// cross-template lever that drives the Pointbits-derived advantage
/// in EdDSAVerifier should not fire here. This gate measures
/// whether achronyme reaches parity (or beats) circom on a circuit
/// shape the existing benchmark templates don't exercise: bigint
/// register arithmetic over secp256k1's 256-bit field emulated via
/// 4 × u64 limbs (n=64 bits/register, k=4 registers).
///
/// circom 2.2.3 baseline:
///   --O1: 1,640,623 constraints (~25 s on a modern desktop)
///   --O2: 1,508,904 constraints (~78 s) — DEDUCE only saves 8 %
///         because most constraints are bigint quadratic.
///
/// Heavy enough that `#[ignore]` — run with
/// `cargo test --release ecdsa_verify_boss_fight -- --ignored
/// --nocapture` to capture wall-clock + constraint shape.
#[test]
#[ignore = "ECDSAVerify(64, 4) is the heaviest probe in this file (>1.5M post-O1 constraints). Under an 11 GiB virtual-memory sandbox the chunk-drain consumer seals 24 chunks of ~365K witness ops each (cs.num_constraints ≈ 12.7M, witness_ops.len ≈ 9.0M at the end of chunk 24, RSS ≈ 10.5 GB / 91% of sandbox) before chunk 25 fails on a small-byte allocation (~70 KB at sandbox saturation) that no specific container is responsible for — the wall is the cumulative steady-state slope (~0.3 KB / IR-inst) rather than any single doubling transient. Per-chunk RSS growth is ~300 MB steady-state across the late chunks. Setup leaves RSS at ~3.7 GB (instantiate-extended on the lean path skips the `var_names`/`var_spans`/`input_spans` HashMaps because the chunk-drain caller would drop them anyway; only `var_types` is built since the ternary type-propagation reads it during emission). `constraint_origins` is skipped here via the lean compiler constructor — the inspector / CLI provenance readers are not exercised by this prove path. The R1CS backend also content-interns Artik bytecode payloads, so the ~99% byte-weighted dedup across the few unique witness-program templates does not cumulatively occupy `witness_ops`. `witness_ops` is a `SegmentedVec<WitnessOp<F>>` so the per-allocation cost is bounded by `SegmentedVec::DEFAULT_SEGMENT_MAX * size_of::<WitnessOp<F>>()` (~64 MB at the current layout) — the old `Vec` doubling-to-1 GiB failure class is gone. The `lc_map` operand cache is a `Vec<Option<LinearCombination<F>>>` indexed by `SsaVar.0` (the streaming path's contiguous dedup-canonical emission gives density 1.0, so `Option<LinearCombination<F>>` at 24 B/slot via the `Vec` `NonNull` niche replaces the prior 33 B/slot `HashMap<SsaVar, LinearCombination<F>>` — no rehash transient, smaller steady-state inline). Closing the boss-fight from here requires reducing the lysis-side residual (NodeInterner / ChunkDrainingSink / executor state) that dominates the unaccounted portion of RSS at chunk 22 (~4-5 GB at slope ~120-140 B/IR-inst), or moving `cs.constraints` off-heap entirely. The per-instruction enum layout is already at its minimum (`Box<WitnessCallBody>` keeps both `Instruction` and `InstructionKind` at 56 bytes, pinned by `instruction_size_pinned` and `instruction_kind_size_pinned`). The lysis-side closures remain pinned by `secp256k1_addunequal_loop_nested_lysis_frame_fit`, `witness_call_routes_to_heap_when_cold_inputs_would_overflow_classic`, `load_const_idx_survives_when_const_pool_exceeds_u16_ceiling`, `heap_slots_stay_distinct_when_spill_count_exceeds_u16_ceiling`, `heap_slot_above_u16_ceiling_round_trips_the_right_value`, `tail_chain_runs_in_constant_stack_past_max_call_depth`, `fresh_node_id_advances_past_u32_max`, and the cross-chunk operand refs by `compile_instructions_streaming_resolves_operands_across_batches`. The lean-instantiate contract (chunk-drain entry never populates `var_names`/`var_spans`/`input_spans`) is pinned by `lean_instantiate_extended_skips_name_and_span_maps` and `lean_instantiate_with_outputs_extended_skips_name_and_span_maps`. The lean-compiler contract (`new_lean` never populates `constraint_origins`) is pinned by `lean_compiler_skips_constraint_origins` and `lean_compiler_matches_eager_on_everything_except_origins`. The Artik content-interning contract is pinned by `artik_intern_shares_arc_for_identical_payloads`, `artik_intern_keeps_distinct_arcs_for_different_payloads`, and `artik_intern_survives_across_streaming_batches` (the last one guards the cross-chunk path this fixture uses). The `SegmentedVec` design contract is pinned by 13 unit tests in `zkc::segmented_vec::tests` covering segment-boundary push, retain compaction across segments, pre-allocation of subsequent segments, and natural-growth of the first segment. The `lc_map` direct-indexed container contract is pinned by `lc_map_get_returns_none_for_unknown_var`, `lc_map_insert_at_contiguous_indices_round_trips`, `lc_map_clear_drops_all_entries_and_keeps_get_safe`, `lc_map_insert_overwrites_existing_idx`, `lc_map_insert_at_high_idx_fills_intermediate_with_none`, and `streaming_path_emits_contiguous_ssavar_ids_pin`. Run with --ignored only."]
fn ecdsa_verify_boss_fight() {
    use std::time::Instant;

    fn boss_mem_kib() -> Option<(u64, u64)> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let mut rss = None;
        let mut vmsize = None;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                rss = rest.split_whitespace().next()?.parse::<u64>().ok();
            } else if let Some(rest) = line.strip_prefix("VmSize:") {
                vmsize = rest.split_whitespace().next()?.parse::<u64>().ok();
            }
        }
        Some((rss?, vmsize?))
    }

    fn boss_trace(label: &str, chunk_idx: usize, chunk_len: usize, rc: &R1CSCompiler<Bn254Fr>) {
        if std::env::var("ACH_BOSS_TRACE_CHUNKS").as_deref() != Ok("1") {
            return;
        }
        let (rss_kib, vmsize_kib) = boss_mem_kib().unwrap_or((0, 0));
        eprintln!(
            "[ECDSAVerify] [chunk {chunk_idx:>4}] {label:<6} len={chunk_len:<8} rss_kib={rss_kib:<10} vmsize_kib={vmsize_kib:<10} constraints={} vars={} witness_ops={}",
            rc.cs.num_constraints(),
            rc.cs.num_variables(),
            rc.witness_ops.len(),
        );
        if std::env::var("ACH_BOSS_TRACE_LCMAP_SHAPES").as_deref() == Ok("1") {
            let shapes = rc.lc_map_shape_counts();
            eprintln!(
                "[ECDSAVerify] [chunk {chunk_idx:>4}] lcmap empty={} zero={} unit_var={} single_term={} multi_term={} stored_terms={}",
                shapes.empty_slots,
                shapes.zero_entries,
                shapes.unit_variable_entries,
                shapes.single_term_entries,
                shapes.multi_term_entries,
                shapes.stored_terms,
            );
        }
        if std::env::var("ACH_BOSS_TRACE_R1CS_STATS").as_deref() == Ok("1") {
            let stats = rc.retained_stats();
            eprintln!(
                "[ECDSAVerify] [chunk {chunk_idx:>4}] r1cs-retained lc_empty={} lc_zero={} lc_unit_var={} lc_single_term={} lc_multi_term={} lc_stored_terms={} used_ssa_words={} proven_boolean={} bool_enforced={} range_bounds={} divmod_cache={} artik_programs={}",
                stats.lc_empty_slots,
                stats.lc_zero_entries,
                stats.lc_unit_variable_entries,
                stats.lc_single_term_entries,
                stats.lc_multi_term_entries,
                stats.lc_stored_terms,
                stats.used_ssa_words,
                stats.proven_boolean_len,
                stats.bool_enforced_len,
                stats.range_bounds_len,
                stats.divmod_cache_len,
                stats.artik_program_intern_len,
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn boss_trim_allocator() -> bool {
        unsafe extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        unsafe { malloc_trim(0) != 0 }
    }

    #[cfg(not(target_os = "linux"))]
    fn boss_trim_allocator() -> bool {
        false
    }

    fn boss_count_kinds(chunk: &[lysis::InstructionKind<Bn254Fr>]) -> ([usize; 25], usize, usize) {
        let mut counts = [0usize; 25];
        let mut decompose_bits = 0usize;
        let mut witness_outputs = 0usize;
        for inst in chunk {
            use lysis::InstructionKind as K;
            let idx = match inst {
                K::Const { .. } => 0,
                K::Input { .. } => 1,
                K::Add { .. } => 2,
                K::Sub { .. } => 3,
                K::Mul { .. } => 4,
                K::Div { .. } => 5,
                K::Neg { .. } => 6,
                K::Mux { .. } => 7,
                K::PoseidonHash { .. } => 8,
                K::Not { .. } => 9,
                K::And { .. } => 10,
                K::Or { .. } => 11,
                K::Decompose { bit_results, .. } => {
                    decompose_bits += bit_results.len();
                    12
                }
                K::IsEq { .. } => 13,
                K::IsNeq { .. } => 14,
                K::IsLt { .. } => 15,
                K::IsLe { .. } => 16,
                K::IsLtBounded { .. } => 17,
                K::IsLeBounded { .. } => 18,
                K::IntDiv { .. } => 19,
                K::IntMod { .. } => 20,
                K::AssertEq { .. } => 21,
                K::Assert { .. } => 22,
                K::RangeCheck { .. } => 23,
                K::WitnessCall(call) => {
                    witness_outputs += call.outputs.len();
                    24
                }
            };
            counts[idx] += 1;
        }
        (counts, decompose_bits, witness_outputs)
    }

    fn boss_trace_kind_counts(chunk_idx: usize, chunk: &[lysis::InstructionKind<Bn254Fr>]) {
        if std::env::var("ACH_BOSS_TRACE_KIND_COUNTS").as_deref() != Ok("1") {
            return;
        }
        let (counts, decompose_bits, witness_outputs) = boss_count_kinds(chunk);
        eprintln!(
            "[ECDSAVerify] [chunk {chunk_idx:>4}] kinds const={} input={} add={} sub={} mul={} div={} neg={} mux={} poseidon={} not={} and={} or={} decompose={} decomp_bits={} iseq={} isneq={} islt={} isle={} isltb={} isleb={} intdiv={} intmod={} asserteq={} assert={} range={} witness_call={} witness_outputs={}",
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            counts[4],
            counts[5],
            counts[6],
            counts[7],
            counts[8],
            counts[9],
            counts[10],
            counts[11],
            counts[12],
            decompose_bits,
            counts[13],
            counts[14],
            counts[15],
            counts[16],
            counts[17],
            counts[18],
            counts[19],
            counts[20],
            counts[21],
            counts[22],
            counts[23],
            counts[24],
            witness_outputs,
        );
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/ecdsa_verify_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let total = Instant::now();

    let t0 = Instant::now();
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("ECDSAVerify compile failed: {e}"));
    eprintln!("[ECDSAVerify] [compile]      {:?}", t0.elapsed());

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    // Interleaved-drain entry point: the lysis executor's chunked
    // emission buffer never accumulates past one chunk. Each sealed
    // chunk is delivered to the consumer closure at seal time, drained
    // into the R1CS backend, then dropped — so peak resident footprint
    // inside execute stays at `interner dedup state + 1 chunk + R1CS
    // state` instead of growing with the total emission count.
    //
    // The consumer routes each chunk through
    // `R1CSCompiler::compile_instructions_streaming` (NOT the single-
    // batch `compile_instructions`) so the per-program operand-lookup
    // caches survive the chunk-seal boundary: a `Mul` in chunk N may
    // reference an operand `SsaVar` first defined in chunk M<N when the
    // interner's dedup tiers return a cross-chunk `NodeId`, and that
    // lookup must still succeed against the surviving `lc_map`.
    //
    // Compile errors from the consumer cannot be returned through the
    // executor's sink trait (the `IrSink` methods are infallible), so
    // the consumer absorbs them into a side-channel that this fixture
    // checks once the executor returns.
    let t1 = Instant::now();
    // Opt into incremental linear collapse (fold elimination into emission so
    // the constraint set never fully materializes) with
    // ACH_INCREMENTAL_COLLAPSE=1. Default off keeps the lean baseline so
    // cross-run measurements stay comparable. With collapse on, the post-build
    // count below is the collapse-survivor count (the emission-resident
    // bound), and optimize_r1cs finalizes it to the same fixpoint as baseline.
    let collapse_on = std::env::var("ACH_INCREMENTAL_COLLAPSE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let direct_mul_on = std::env::var("ACH_DIRECT_LINEAR_MUL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let compile_only_on = std::env::var("ACH_COMPILE_ONLY_R1CS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let count_only_on = std::env::var("ACH_BOSS_COUNT_ONLY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut rc = if compile_only_on {
        R1CSCompiler::<Bn254Fr>::new_compile_only_direct_linear_mul()
    } else if direct_mul_on {
        R1CSCompiler::<Bn254Fr>::new_direct_linear_mul()
    } else if collapse_on {
        R1CSCompiler::<Bn254Fr>::new_incremental()
    } else {
        R1CSCompiler::<Bn254Fr>::new_lean()
    };
    eprintln!(
        "[ECDSAVerify] [collapse]     {}",
        if compile_only_on {
            "COMPILE-ONLY DIRECT-LC-MUL (skip witness-op retention)"
        } else if direct_mul_on {
            "DIRECT-LC-MUL (emit post-O1-style LC products)"
        } else if collapse_on {
            "ON (incremental linear collapse during emission)"
        } else {
            "OFF (lean baseline)"
        }
    );
    let drain_err: std::cell::RefCell<Option<zkc::error::R1CSError>> =
        std::cell::RefCell::new(None);
    let mut chunk_idx = 0usize;
    let mut total_ir = 0usize;
    let mut total_counts = [0usize; 25];
    let mut total_decompose_bits = 0usize;
    let mut total_witness_outputs = 0usize;
    let mut consumer = |chunk: Vec<lysis::InstructionKind<Bn254Fr>>| {
        if drain_err.borrow().is_some() {
            return;
        }
        chunk_idx += 1;
        let chunk_len = chunk.len();
        total_ir += chunk_len;
        let (counts, decompose_bits, witness_outputs) = boss_count_kinds(&chunk);
        for (dst, src) in total_counts.iter_mut().zip(counts) {
            *dst += src;
        }
        total_decompose_bits += decompose_bits;
        total_witness_outputs += witness_outputs;
        boss_trace_kind_counts(chunk_idx, &chunk);
        boss_trace("before", chunk_idx, chunk_len, &rc);
        if count_only_on {
            boss_trace("after", chunk_idx, chunk_len, &rc);
            return;
        }
        let stream = chunk.into_iter().map(ir_forge::instruction_from_kind_owned);
        if let Err(e) = rc.compile_instructions_streaming(stream) {
            if std::env::var("ACH_BOSS_ABORT_ON_COMPILE_ERR").as_deref() == Ok("1") {
                panic!("ECDSAVerify R1CS compile (chunk {chunk_idx}): {e}");
            }
            *drain_err.borrow_mut() = Some(e);
        }
        if std::env::var("ACH_BOSS_TRIM_AFTER_CHUNK").as_deref() == Ok("1") {
            let trimmed = boss_trim_allocator();
            if std::env::var("ACH_BOSS_TRACE_CHUNKS").as_deref() == Ok("1") {
                let (rss_kib, vmsize_kib) = boss_mem_kib().unwrap_or((0, 0));
                eprintln!(
                    "[ECDSAVerify] [chunk {chunk_idx:>4}] trim   trimmed={trimmed} rss_kib={rss_kib:<10} vmsize_kib={vmsize_kib:<10}"
                );
            }
        }
        boss_trace("after", chunk_idx, chunk_len, &rc);
    };
    result
        .prove_ir
        .instantiate_lysis_drain_with_outputs(&fe_captures, &result.output_names, &mut consumer)
        .unwrap_or_else(|e| panic!("ECDSAVerify instantiate-drain failed: {e}"));
    if let Some(e) = drain_err.into_inner() {
        panic!("ECDSAVerify R1CS compile (mid-stream): {e}");
    }
    eprintln!("[ECDSAVerify] [instantiate+drain] {:?}", t1.elapsed());
    if count_only_on {
        eprintln!(
            "[ECDSAVerify] [count-only] chunks={chunk_idx} total_ir={total_ir} const={} input={} add={} sub={} mul={} div={} neg={} mux={} poseidon={} not={} and={} or={} decompose={} decomp_bits={} iseq={} isneq={} islt={} isle={} isltb={} isleb={} intdiv={} intmod={} asserteq={} assert={} range={} witness_call={} witness_outputs={}",
            total_counts[0],
            total_counts[1],
            total_counts[2],
            total_counts[3],
            total_counts[4],
            total_counts[5],
            total_counts[6],
            total_counts[7],
            total_counts[8],
            total_counts[9],
            total_counts[10],
            total_counts[11],
            total_counts[12],
            total_decompose_bits,
            total_counts[13],
            total_counts[14],
            total_counts[15],
            total_counts[16],
            total_counts[17],
            total_counts[18],
            total_counts[19],
            total_counts[20],
            total_counts[21],
            total_counts[22],
            total_counts[23],
            total_counts[24],
            total_witness_outputs,
        );
        eprintln!("[ECDSAVerify] [total]        {:?}", total.elapsed());
        return;
    }

    let t3 = Instant::now();
    let pre_o1 = rc.cs.num_constraints();
    eprintln!(
        "[ECDSAVerify] [r1cs build done] {:?}  constraints={pre_o1}{}",
        t3.elapsed(),
        if collapse_on {
            " (collapse survivors; emission-resident bound)"
        } else {
            ""
        }
    );
    if compile_only_on {
        eprintln!("[ECDSAVerify] [total]        {:?}", total.elapsed());
        return;
    }

    let t4 = Instant::now();
    let stats = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();
    eprintln!(
        "[ECDSAVerify] [r1cs O1]      {:?}  constraints={post_o1}  vars_eliminated={}  rounds={}",
        t4.elapsed(),
        stats.variables_eliminated,
        stats.rounds,
    );

    eprintln!("[ECDSAVerify] [total]        {:?}", total.elapsed());
    eprintln!("[ECDSAVerify] [circom 2.2.3 baseline]  --O1 1,640,623, --O2 1,508,904");
    eprintln!(
        "[ECDSAVerify] [Δ vs circom O2]  {:+} constraints ({:+.2}%)",
        post_o1 as i64 - 1_508_904,
        (post_o1 as f64 / 1_508_904.0 - 1.0) * 100.0
    );
}
