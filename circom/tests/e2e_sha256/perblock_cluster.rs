use super::*;

/// Per-block differential: compile `Sha256compression()` standalone
/// (one block, no padding) in achronyme and compare to circom
/// `--O2`. Isolates the cost of the Sha256compression round body
/// from the cost of the outer Sha256 wrapper (input padding,
/// length encoding, paddedIn fan-out).
///
/// `Sha256(64) = padding/length-encoding overhead + Sha256compression(1) + output unpack`.
/// If achronyme matches circom on Sha256compression(1) standalone,
/// the +112 c residual on Sha256(64) lives in the outer wrapper.
/// If achronyme is +N on Sha256compression(1) standalone, the gap
/// is per-block and `n_blocks × N` should match the full-circuit
/// residual.
///
/// Prerequisite: a circom O2 dump in JSON form. Generate with:
///
/// ```text
/// mkdir -p /tmp/cir-sha256comp-o2 && \
///   circom test/circomlib/sha256compression_test.circom --r1cs --O2 \
///     -l test/circomlib -o /tmp/cir-sha256comp-o2/ && \
///   snarkjs r1cs export json \
///     /tmp/cir-sha256comp-o2/sha256compression_test.r1cs \
///     /tmp/cir-sha256comp-o2/sha256compression_test.json
/// ```
#[test]
#[ignore = "Sha256compression(1) per-block differential vs circom --O2. Prerequisite: snarkjs JSON dump at /tmp/cir-sha256comp-o2/sha256compression_test.json. Run with `--ignored sha256compression_perblock_diff -- --nocapture`."]
fn sha256compression_perblock_diff() {
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::fs;

    const CIRCOM_O2_JSON: &str = "/tmp/cir-sha256comp-o2/sha256compression_test.json";

    let json_path = PathBuf::from(CIRCOM_O2_JSON);
    if !json_path.exists() {
        panic!(
            "circom O2 JSON dump not found at {CIRCOM_O2_JSON}.\n\
             Generate via:\n  \
             mkdir -p /tmp/cir-sha256comp-o2 && circom \
             test/circomlib/sha256compression_test.circom --r1cs --O2 \
             -l test/circomlib -o /tmp/cir-sha256comp-o2/ && snarkjs r1cs \
             export json /tmp/cir-sha256comp-o2/sha256compression_test.r1cs \
             /tmp/cir-sha256comp-o2/sha256compression_test.json"
        );
    }

    let raw = fs::read_to_string(&json_path).expect("read circom JSON");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse circom JSON");
    let constraints_v = v["constraints"].as_array().expect("constraints array");

    type ShapeKey = (usize, usize, usize);
    type DiffRow = (ShapeKey, usize, usize, i64);

    let mut circom_hist: BTreeMap<ShapeKey, usize> = BTreeMap::new();
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
    let path = manifest_dir.join("test/circomlib/sha256compression_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Sha256compression compile failed: {e}"));
    // Sha256compression() takes no template parameters.
    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let outs: HashSet<String> = compile_result.output_names.iter().cloned().collect();
    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &outs)
        .expect("instantiate_lysis");
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.compile_ir(&program).expect("R1CS compile");
    let pre_opt = rc.cs.num_constraints();
    let _ = rc.optimize_r1cs();
    let post_o1 = rc.cs.num_constraints();

    let mut ach_hist: BTreeMap<ShapeKey, usize> = BTreeMap::new();
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

    eprintln!("\n=== Sha256compression(1) standalone — achronyme post-O1 vs circom --O2 ===");
    eprintln!("achronyme pre-opt    = {pre_opt}");
    eprintln!("achronyme post-O1    = {post_o1}");
    eprintln!("circom    --O2       = {circom_total}");
    eprintln!(
        "per-block residual   = {:+} c   (achronyme - circom)",
        post_o1 as i64 - circom_total as i64
    );
    eprintln!();
    eprintln!("=== Reference: full SHA-256(64) residual = +112 c ===");
    eprintln!("If per-block residual matches +112, the gap is in Sha256compression itself.");
    eprintln!(
        "If per-block residual is 0, the gap is in the outer Sha256 wrapper (padding/length/output)."
    );
    eprintln!("If per-block residual is < 0, the wrapper-only delta = +112 - (per-block) c.");
    eprintln!();
    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "(min,max,|C|)", "circomO2", "achO1", "delta(ach-cir)"
    );
    eprintln!(
        "{:>14} {:>12} {:>10} {:>15}",
        "-------------", "--------", "-----", "--------------"
    );
    for (k, cir, ach, delta) in rows.iter().take(25) {
        eprintln!(
            "  ({:>2},{:>2},{:>2})    {:>12} {:>10} {:>+15}",
            k.0, k.1, k.2, cir, ach, delta
        );
    }
}

/// Cluster size diagnostic: for each circomlib template, build the
/// raw R1CS, partition the linear constraints by shared signal, and
/// dump the cluster size histogram. Validates whether
/// `CLUSTER_FALLBACK_THRESHOLD = 500` actually matters in practice
/// (i.e. there exist clusters in the (500, 5000) range that get
/// routed to the greedy fallback).
///
/// Stays `#[ignore]`d so it does not run in the default test pass;
/// invoke with `--ignored cluster_size_diagnostic -- --nocapture`.
#[test]
#[ignore = "Diagnostic-only: run with --ignored cluster_size_diagnostic -- --nocapture to inspect cluster size distributions per circuit."]
fn cluster_size_diagnostic() {
    use std::collections::{BTreeMap, HashSet};

    fn compile(name: &str, file: &str, inputs: HashMap<String, FieldElement<Bn254Fr>>) {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let path = manifest_dir.join(file);
        let lib_dirs = vec![manifest_dir.join("test/circomlib")];

        let compile_result = circom::compile_file(&path, &lib_dirs)
            .unwrap_or_else(|e| panic!("compile {name} failed: {e}"));
        let prove_ir = &compile_result.prove_ir;
        let capture_values = &compile_result.capture_values;
        let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();

        let mut program = prove_ir
            .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
            .unwrap_or_else(|e| panic!("instantiate {name} failed: {e}"));
        ir::passes::optimize(&mut program);

        let mut all_signals =
            circom::witness::compute_witness_hints_with_captures(prove_ir, &inputs, capture_values)
                .unwrap_or_else(|e| panic!("witness {name} failed: {e}"));
        for (cname, fe) in &fe_captures {
            all_signals.entry(cname.clone()).or_insert(*fe);
        }

        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        compiler
            .compile_ir_with_witness(&program, &all_signals)
            .unwrap_or_else(|e| panic!("r1cs {name} failed: {e}"));

        // Re-implement the clustering logic here (build_clusters_by_signal
        // is pub(super), not exposed) to inspect raw cluster sizes
        // before any optimization.
        let raw = compiler.cs.constraints();
        let num_pub_inputs = compiler.cs.num_pub_inputs();
        let protected: HashSet<usize> = (0..=num_pub_inputs).collect();

        // Walk linear constraints, build first-owner Union-Find by signal.
        // Same logic as build_clusters_by_signal.
        let mut linear_indices: Vec<usize> = Vec::new();
        for (i, c) in raw.iter().enumerate() {
            let a = c.a.simplify();
            let b = c.b.simplify();
            let a_const = a.is_constant();
            let b_const = b.is_constant();
            if a_const || b_const {
                linear_indices.push(i);
            }
        }
        let n = linear_indices.len();
        let mut parent: Vec<usize> = (0..n).collect();
        fn find(parent: &mut [usize], mut x: usize) -> usize {
            let mut r = x;
            while parent[r] != r {
                r = parent[r];
            }
            while parent[x] != r {
                let n = parent[x];
                parent[x] = r;
                x = n;
            }
            r
        }
        let mut first_owner: HashMap<usize, usize> = HashMap::new();
        for (loc_idx, &orig_idx) in linear_indices.iter().enumerate() {
            let c = &raw[orig_idx];
            for lc in [&c.a, &c.b, &c.c] {
                for (var, _) in lc.terms() {
                    let sig = var.index();
                    if sig == 0 || protected.contains(&sig) {
                        continue;
                    }
                    match first_owner.get(&sig) {
                        Some(&owner) => {
                            let ra = find(&mut parent, loc_idx);
                            let rb = find(&mut parent, owner);
                            if ra != rb {
                                parent[ra] = rb;
                            }
                        }
                        None => {
                            first_owner.insert(sig, loc_idx);
                        }
                    }
                }
            }
        }
        let mut buckets: HashMap<usize, usize> = HashMap::new();
        for i in 0..n {
            *buckets.entry(find(&mut parent, i)).or_insert(0) += 1;
        }
        let mut sizes: Vec<usize> = buckets.values().copied().collect();
        sizes.sort_unstable();

        let total_linear = n;
        let max_size = sizes.last().copied().unwrap_or(0);
        let n_clusters = sizes.len();

        // Bucket counts for histogram thresholds.
        let mut histo: BTreeMap<&str, usize> = BTreeMap::new();
        for &s in &sizes {
            let bucket = match s {
                1 => "1",
                2..=10 => "2-10",
                11..=100 => "11-100",
                101..=350 => "101-350",
                351..=500 => "351-500",
                501..=1_000 => "501-1000",
                1_001..=5_000 => "1001-5000",
                _ => "5000+",
            };
            *histo.entry(bucket).or_insert(0) += 1;
        }

        let raw_total = raw.len();
        eprintln!("\n[{name}]");
        eprintln!(
            "  raw constraints = {raw_total}, linear = {total_linear}, clusters = {n_clusters}, max cluster = {max_size}"
        );
        eprintln!("  cluster size histogram:");
        for (bucket, count) in &histo {
            eprintln!("    {bucket:>10} : {count}");
        }
    }

    fn fe(v: u64) -> FieldElement<Bn254Fr> {
        FieldElement::<Bn254Fr>::from_u64(v)
    }
    let one = |k: &str, v: u64| -> HashMap<String, FieldElement<Bn254Fr>> {
        std::iter::once((k.to_string(), fe(v))).collect()
    };

    compile(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        one("in", 13),
    );
    compile("IsZero", "test/circom/iszero.circom", one("in", 0));
    compile(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        [("in_0", fe(3)), ("in_1", fe(10))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
    compile(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        (0..8).map(|i| (format!("in_{i}"), fe(i % 2))).collect(),
    );
    compile(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        (0..253).map(|i| (format!("e_{i}"), fe(0))).collect(),
    );
    let mut ema_inputs: HashMap<String, FieldElement<Bn254Fr>> =
        (0..254).map(|i| (format!("e_{i}"), fe(0))).collect();
    ema_inputs.insert("p_0".to_string(), fe(0));
    ema_inputs.insert("p_1".to_string(), fe(1));
    compile(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        ema_inputs,
    );
    compile(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        [("inputs_0", fe(1)), ("inputs_1", fe(2))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
    compile(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        [("ins_0", fe(1)), ("ins_1", fe(2)), ("k", fe(0))]
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    );
}
