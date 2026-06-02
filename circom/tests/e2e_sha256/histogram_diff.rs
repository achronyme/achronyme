use super::*;

/// SHA-256(64) circom-O2-vs-achronyme-O1 constraint shape diff.
///
/// Read-only diagnostic. Compares the symmetrized
/// `(min(|A|,|B|), max(|A|,|B|), |C|)` histogram of achronyme's
/// post-O1 R1CS against circom 2.2.3's `--O2` output for the same
/// circuit. Surfaces whether the +112c residual is concentrated in
/// any single shape bucket (or one shape family) or spread thinly
/// across many.
///
/// Prerequisite: a circom O2 dump in JSON form. Generate with:
///
/// ```text
/// mkdir -p /tmp/cir-sha256-o2 && \
///   circom test/circomlib/sha256_test.circom --r1cs --O2 \
///     -l test/circomlib -o /tmp/cir-sha256-o2/ && \
///   snarkjs r1cs export json /tmp/cir-sha256-o2/sha256_test.r1cs \
///     /tmp/cir-sha256-o2/sha256_test.json
/// ```
///
/// Decision thresholds (printed at end of run):
/// - `largest_single_bucket >= 50 c` -> ship-relevant lever; drill
///   into the gadget that owns that shape (D4 follow-up).
/// - `top family combined >= 50 c` -> family-level lever; same
///   path.
/// - `spread thinly across >=5 buckets at <=20 c each` -> seventh
///   null pre-flight; archive the chase.
#[test]
#[ignore = "SHA-256(64) histogram-diff vs circom --O2. Prerequisite: snarkjs JSON dump at /tmp/cir-sha256-o2/sha256_test.json (see test docstring). Run with `--ignored sha256_64_circom_o2_histogram_diff -- --nocapture`."]
fn sha256_64_circom_o2_histogram_diff() {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::fs;

    const CIRCOM_O2_JSON: &str = "/tmp/cir-sha256-o2/sha256_test.json";

    let json_path = PathBuf::from(CIRCOM_O2_JSON);
    if !json_path.exists() {
        panic!(
            "circom O2 JSON dump not found at {CIRCOM_O2_JSON}.\n\
             Generate via:\n  \
             mkdir -p /tmp/cir-sha256-o2 && circom test/circomlib/sha256_test.circom \
             --r1cs --O2 -l test/circomlib -o /tmp/cir-sha256-o2/ && snarkjs r1cs \
             export json /tmp/cir-sha256-o2/sha256_test.r1cs /tmp/cir-sha256-o2/sha256_test.json"
        );
    }

    let raw = fs::read_to_string(&json_path).expect("read circom JSON");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse circom JSON");
    let constraints_v = v["constraints"].as_array().expect("constraints array");

    let mut circom_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in constraints_v {
        let arr = c.as_array().expect("constraint triple [A,B,C]");
        let an = arr[0].as_object().map(|m| m.len()).unwrap_or(0);
        let bn = arr[1].as_object().map(|m| m.len()).unwrap_or(0);
        let cn = arr[2].as_object().map(|m| m.len()).unwrap_or(0);
        let key = (an.min(bn), an.max(bn), cn);
        *circom_hist.entry(key).or_insert(0) += 1;
    }
    let circom_total: usize = circom_hist.values().sum();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("SHA-256 compile failed: {e}"));
    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(64));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let _ = rc.optimize_r1cs();

    let mut ach_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in rc.cs.constraints() {
        let a = c.a.simplify();
        let b = c.b.simplify();
        let cc = c.c.simplify();
        let an = a.terms().len();
        let bn = b.terms().len();
        let cn = cc.terms().len();
        let key = (an.min(bn), an.max(bn), cn);
        *ach_hist.entry(key).or_insert(0) += 1;
    }
    let ach_total: usize = ach_hist.values().sum();

    type ShapeKey = (usize, usize, usize);
    type DiffRow = (ShapeKey, usize, usize, i64);

    let mut all_keys: BTreeSet<ShapeKey> = BTreeSet::new();
    all_keys.extend(circom_hist.keys().copied());
    all_keys.extend(ach_hist.keys().copied());

    let mut rows: Vec<DiffRow> = all_keys
        .iter()
        .map(|&k| {
            let cir = *circom_hist.get(&k).unwrap_or(&0);
            let ach = *ach_hist.get(&k).unwrap_or(&0);
            (k, cir, ach, ach as i64 - cir as i64)
        })
        .collect();
    rows.sort_by(|x, y| y.3.abs().cmp(&x.3.abs()).then(x.0.cmp(&y.0)));

    eprintln!("\n=== SHA-256(64) post-O1 vs circom --O2 (symmetrized A,B order) ===");
    eprintln!("achronyme post-O1 total = {ach_total}");
    eprintln!("circom --O2     total  = {circom_total}");
    eprintln!(
        "net residual           = {:+} c\n",
        ach_total as i64 - circom_total as i64
    );

    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "(min|A|,max,|C|)", "circomO2", "achO1", "delta(ach-cir)"
    );
    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "----------------", "--------", "-----", "--------------"
    );
    for (k, cir, ach, delta) in rows.iter().take(40) {
        eprintln!(
            "  ({:>2},{:>2},{:>2})    {:>12} {:>10} {:>+15}",
            k.0, k.1, k.2, cir, ach, delta
        );
    }

    let total_abs_delta: i64 = rows.iter().map(|r| r.3.abs()).sum();
    let largest = rows[0];
    let top3_pos: i64 = rows.iter().filter(|r| r.3 > 0).take(3).map(|r| r.3).sum();
    let top3_neg: i64 = rows.iter().filter(|r| r.3 < 0).take(3).map(|r| r.3).sum();
    let buckets_with_excess_ge_20 = rows.iter().filter(|r| r.3 >= 20).count();
    let buckets_with_excess_ge_50 = rows.iter().filter(|r| r.3 >= 50).count();

    eprintln!("\n=== divergence summary ===");
    eprintln!(
        "largest_single_bucket  : ({:>2},{:>2},{:>2}) -> delta = {:+} c",
        largest.0 .0, largest.0 .1, largest.0 .2, largest.3
    );
    eprintln!("top_3_positive (we have more)  : Σ = {:+} c", top3_pos);
    eprintln!("top_3_negative (we have fewer) : Σ = {:+} c", top3_neg);
    eprintln!("buckets where excess >= 20 c   : {buckets_with_excess_ge_20}");
    eprintln!("buckets where excess >= 50 c   : {buckets_with_excess_ge_50}");
    eprintln!("Σ |delta| across all buckets   : {} c", total_abs_delta);
    eprintln!(
        "net residual                  : {:+} c",
        ach_total as i64 - circom_total as i64
    );

    eprintln!("\n=== decision threshold ===");
    eprintln!(
        "  largest_single_bucket >= 50 c  -> ship-relevant lever; drill gadget owning shape (D4)"
    );
    eprintln!("  multiple buckets >= 50 c, same family (e.g. all (1,N,*))  -> family-level lever");
    eprintln!(
        "  spread thinly: >=5 buckets at <=20 c each  -> seventh null pre-flight, archive chase"
    );
}

/// Sha256(8) variant of the histogram-diff. Used to test the
/// per-input-bit hypothesis: if the wrapper-only `(1,2,0)` excess
/// scales with `nBits`, achronyme is over-emitting bool-checks
/// proportional to the number of variable input bits.
#[test]
#[ignore = "Sha256(8) histogram diff. Prerequisite: snarkjs JSON dump at /tmp/cir-sha256_8-o2/sha256_8_test.json. Run with `--ignored sha256_8_circom_o2_histogram_diff -- --nocapture`."]
fn sha256_8_circom_o2_histogram_diff() {
    use std::collections::{BTreeMap, HashSet};
    use std::fs;

    const CIRCOM_O2_JSON: &str = "/tmp/cir-sha256_8-o2/sha256_8_test.json";

    let json_path = PathBuf::from(CIRCOM_O2_JSON);
    if !json_path.exists() {
        panic!("circom O2 dump not found at {CIRCOM_O2_JSON}");
    }
    let raw = fs::read_to_string(&json_path).expect("read circom JSON");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse circom JSON");
    let constraints_v = v["constraints"].as_array().expect("constraints array");

    let mut circom_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in constraints_v {
        let arr = c.as_array().expect("constraint triple [A,B,C]");
        let an = arr[0].as_object().map(|m| m.len()).unwrap_or(0);
        let bn = arr[1].as_object().map(|m| m.len()).unwrap_or(0);
        let cn = arr[2].as_object().map(|m| m.len()).unwrap_or(0);
        let key = (an.min(bn), an.max(bn), cn);
        *circom_hist.entry(key).or_insert(0) += 1;
    }
    let circom_total: usize = circom_hist.values().sum();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/sha256_8_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Sha256(8) compile failed: {e}"));
    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    captures.insert("nBits".to_string(), FieldElement::<Bn254Fr>::from_u64(8));
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let _ = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();

    let mut ach_hist: BTreeMap<(usize, usize, usize), usize> = BTreeMap::new();
    for c in rc.cs.constraints() {
        let an = c.a.simplify().terms().len();
        let bn = c.b.simplify().terms().len();
        let cn = c.c.simplify().terms().len();
        *ach_hist.entry((an.min(bn), an.max(bn), cn)).or_insert(0) += 1;
    }

    let bool_check_circom = circom_hist.get(&(1, 2, 0)).copied().unwrap_or(0);
    let bool_check_ach = ach_hist.get(&(1, 2, 0)).copied().unwrap_or(0);

    eprintln!("\n=== Sha256(8) — achronyme post-O1 vs circom --O2 ===");
    eprintln!("achronyme post-O1   = {post_o1}");
    eprintln!("circom    --O2      = {circom_total}");
    eprintln!(
        "net residual        = {:+} c",
        post_o1 as i64 - circom_total as i64
    );
    eprintln!();
    eprintln!("(1,2,0) bool-check-shape:");
    eprintln!("  circom    --O2 = {bool_check_circom}");
    eprintln!("  achronyme O1   = {bool_check_ach}");
    eprintln!(
        "  delta          = {:+}",
        bool_check_ach as i64 - bool_check_circom as i64
    );
    eprintln!();
    eprintln!("=== reference (from prior runs) ===");
    eprintln!("Sha256(64) full:        ach (1,2,0) = 10309, circom = 10160, Δ = +149");
    eprintln!("Sha256comp(1) standalone: ach (1,2,0) = 10245, circom = 10160, Δ = +85");
    eprintln!("                          wrapper-only Δ on (1,2,0) for nBits=64 = +64");
    eprintln!();
    eprintln!("=== per-input-bit hypothesis ===");
    eprintln!("  if Sha256(8) (1,2,0) Δ ≈ +85+8 = +93  -> hypothesis CONFIRMED (1c per bit)");
    eprintln!("  if Sha256(8) (1,2,0) Δ ≈ +85+0 = +85  -> wrapper effect is constant, not per-bit");
    eprintln!("  if Sha256(8) (1,2,0) Δ ≈ +85+64 = +149 -> wrapper effect is constant 64, masked by nBits coincidence");
}
