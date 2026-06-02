use super::*;

/// Dump every `IrInstruction::Decompose` in the SHA-256(64) IR
/// program with its `num_bits`, comparing standalone
/// `Sha256compression(1)` to the full `Sha256(64)`. The wrapper-only
/// new Decomposes pinpoint where the per-input-bit bool-checks
/// originate.
#[test]
#[ignore = "Decompose dump for SHA-256 wrapper analysis. Run with `--ignored sha256_decompose_dump -- --nocapture`."]
fn sha256_decompose_dump() {
    use std::collections::{BTreeMap, HashSet};

    fn compile_decompose_hist(
        label: &str,
        fixture_path: &str,
        nbits_capture: Option<u64>,
    ) -> BTreeMap<u32, usize> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(fixture_path);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];
        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("{label} compile failed: {e}"));

        let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        if let Some(n) = nbits_capture {
            captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
        }
        let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
        let mut program = compile_result
            .prove_ir
            .instantiate_lysis_with_outputs(&captures, &outs)
            .unwrap_or_else(|e| panic!("{label} instantiate: {e}"));
        ir::passes::optimize(&mut program);

        let mut hist: BTreeMap<u32, usize> = BTreeMap::new();
        for inst in &program.instructions {
            if let ir::types::Instruction::Decompose { num_bits, .. } = inst {
                *hist.entry(*num_bits).or_insert(0) += 1;
            }
        }
        eprintln!(
            "[{label}] {} Decompose instructions, num_bits histogram: {:?}",
            hist.values().sum::<usize>(),
            hist
        );
        hist
    }

    let standalone = compile_decompose_hist(
        "Sha256comp(1)",
        "test/circomlib/sha256compression_test.circom",
        None,
    );
    let s8 = compile_decompose_hist("Sha256(8)", "test/circomlib/sha256_8_test.circom", Some(8));
    let s64 = compile_decompose_hist("Sha256(64)", "test/circomlib/sha256_test.circom", Some(64));

    eprintln!("\n=== Decompose num_bits diff (wrapper-only) ===");
    let mut all_keys: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    all_keys.extend(standalone.keys().copied());
    all_keys.extend(s8.keys().copied());
    all_keys.extend(s64.keys().copied());
    eprintln!(
        "{:>10} {:>14} {:>10} {:>10} {:>14} {:>14}",
        "num_bits", "standalone", "Sha256(8)", "Sha256(64)", "wrapper(8)", "wrapper(64)"
    );
    for k in all_keys {
        let std_v = standalone.get(&k).copied().unwrap_or(0);
        let s8_v = s8.get(&k).copied().unwrap_or(0);
        let s64_v = s64.get(&k).copied().unwrap_or(0);
        let w8 = s8_v as i64 - std_v as i64;
        let w64 = s64_v as i64 - std_v as i64;
        if w8 != 0 || w64 != 0 || std_v > 0 {
            eprintln!(
                "{:>10} {:>14} {:>10} {:>10} {:>+14} {:>+14}",
                k, std_v, s8_v, s64_v, w8, w64
            );
        }
    }
}

/// Per-call-site bool-check counter localiser.
///
/// Compiles `Sha256compression(1)`, `Sha256(8)`, and `Sha256(64)`
/// in sequence, snapshots the bool-check emission counters from
/// `zkc::r1cs_backend` (one per call site: RangeCheck, Decompose,
/// And.lhs/rhs, Or.lhs/rhs, Not, Mux.cond, Assert) after each
/// compile, and prints the per-site delta.
///
/// The call site whose delta scales with `nBits` between Sha256(8)
/// and Sha256(64) is the per-input-bit emission site responsible
/// for the +N (1,2,0) constraints in the outer wrapper. Run with
/// the standalone `Sha256compression(1)` baseline subtracted to
/// isolate the wrapper's contribution.
#[test]
#[ignore = "Per-call-site bool-check localiser. Run with `--ignored sha256_boolcheck_site_localiser -- --nocapture`."]
fn sha256_boolcheck_site_localiser() {
    use std::collections::HashSet;
    use zkc::r1cs_backend::{reset_boolcheck_counters, snapshot_boolcheck_counters};

    fn compile_and_snapshot(
        label: &str,
        fixture_path: &str,
        nbits_capture: Option<u64>,
    ) -> [(&'static str, u64); 12] {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(fixture_path);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];
        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("{label} compile failed: {e}"));

        let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        if let Some(n) = nbits_capture {
            captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
        }
        let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
        let mut program = compile_result
            .prove_ir
            .instantiate_lysis_with_outputs(&captures, &outs)
            .unwrap_or_else(|e| panic!("{label} instantiate: {e}"));
        ir::passes::optimize(&mut program);

        reset_boolcheck_counters();
        let mut rc = R1CSCompiler::<Bn254Fr>::new();
        rc.compile_ir(&program).expect("R1CS compile");
        // optimize is post-emission; counters reflect emission only.
        let _ = rc.optimize_r1cs();
        snapshot_boolcheck_counters()
    }

    let standalone = compile_and_snapshot(
        "Sha256comp(1)",
        "test/circomlib/sha256compression_test.circom",
        None,
    );
    let sha256_8 =
        compile_and_snapshot("Sha256(8)", "test/circomlib/sha256_8_test.circom", Some(8));
    let sha256_64 =
        compile_and_snapshot("Sha256(64)", "test/circomlib/sha256_test.circom", Some(64));

    eprintln!("\n=== bool-check emission counters by call site ===");
    eprintln!(
        "{:>14} {:>14} {:>10} {:>10} {:>14} {:>14}",
        "site", "standalone", "Sha256(8)", "Sha256(64)", "wrapper(8)", "wrapper(64)"
    );
    eprintln!(
        "{:>14} {:>14} {:>10} {:>10} {:>14} {:>14}",
        "----", "----------", "---------", "----------", "----------", "----------"
    );

    for i in 0..12 {
        let (site, std_v) = standalone[i];
        let (_, s8_v) = sha256_8[i];
        let (_, s64_v) = sha256_64[i];
        let w8 = s8_v as i64 - std_v as i64;
        let w64 = s64_v as i64 - std_v as i64;
        eprintln!(
            "{:>14} {:>14} {:>10} {:>10} {:>+14} {:>+14}",
            site, std_v, s8_v, s64_v, w8, w64
        );
    }

    eprintln!("\n=== look for: site where wrapper(64) - wrapper(8) ≈ 56 ===");
    eprintln!("That's the per-variable-input-bit emission site.");
    for i in 0..12 {
        let (site, std_v) = standalone[i];
        let (_, s8_v) = sha256_8[i];
        let (_, s64_v) = sha256_64[i];
        let w8 = s8_v as i64 - std_v as i64;
        let w64 = s64_v as i64 - std_v as i64;
        let scaling = w64 - w8;
        if scaling.abs() >= 5 {
            eprintln!(
                "  {site}: wrapper(64)-wrapper(8) = {scaling:+}  ({} c per extra input bit)",
                scaling as f64 / (64.0 - 8.0)
            );
        }
    }
}
