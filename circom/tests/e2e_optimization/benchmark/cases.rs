use std::collections::HashMap;

use memory::{Bn254Fr, FieldElement};

use super::helpers::{compile_and_measure, compile_and_measure_witnessless, print_row};

pub(super) fn run_core_circuits(
    sparse_summary: &mut Vec<(&'static str, usize, usize, &'static str)>,
) {
    // Num2Bits(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        &[("in", 13)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Num2Bits(8)",
        b,
        a,
        "9",
        "9",
        "9",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Num2Bits(8)", a, asp, "9"));

    // IsZero
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "IsZero",
        "test/circom/iszero.circom",
        &[("in", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "IsZero",
        b,
        a,
        "2",
        "2",
        "2",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("IsZero", a, asp, "2"));

    // LessThan(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        &[("in_0", 3), ("in_1", 10)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "LessThan(8)",
        b,
        a,
        "12",
        "12",
        "9",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("LessThan(8)", a, asp, "9"));

    // Pedersen(8)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &(0..8)
            .map(|i| (format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(i % 2)))
            .collect(),
    );
    print_row(
        "Pedersen(8)",
        b,
        a,
        "243",
        "95",
        "13",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Pedersen(8)", a, asp, "13"));

    // EscalarMulFix(253)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        &(0..253)
            .map(|i| (format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0)))
            .collect(),
    );
    print_row(
        "EscalarMulFix(253)",
        b,
        a,
        "153",
        "62",
        "11",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EscalarMulFix(253)", a, asp, "11"));

    // EscalarMulAny(254)
    let t = std::time::Instant::now();
    let mut ema_inputs = HashMap::new();
    for i in 0..254 {
        ema_inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    ema_inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    ema_inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    let (b, a, asp) = compile_and_measure(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        &ema_inputs,
    );
    print_row(
        "EscalarMulAny(254)",
        b,
        a,
        "7907",
        "2312",
        "2310",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EscalarMulAny(254)", a, asp, "2310"));

    // Poseidon(2)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        &[("inputs_0", 1), ("inputs_1", 2)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Poseidon(2)",
        b,
        a,
        "765",
        "517",
        "240",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Poseidon(2)", a, asp, "240"));

    // MiMCSponge(2,220,1)
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        &[("ins_0", 1), ("ins_1", 2), ("k", 0)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "MiMCSponge(2,220,1)",
        b,
        a,
        "1767",
        "1321",
        "1320",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("MiMCSponge(2,220,1)", a, asp, "1320"));
}

pub(super) fn run_point_sha_eddsa(
    sparse_summary: &mut Vec<(&'static str, usize, usize, &'static str)>,
) {
    // Point2Bits_Strict (BabyJubjub Edwards point → 256-bit packing)
    // Identity point input — cross-template `proven_boolean` lever
    // surfaces here because Num2Bits feeds CompConstant + AliasCheck
    // chain in a single template, a pattern not present in the eight
    // legacy circuits above.
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Point2Bits_Strict",
        "test/circomlib/point2bits_test.circom",
        &[("in_0", 0), ("in_1", 1)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Point2Bits_Strict",
        b,
        a,
        "2838",
        "1301",
        "1293",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Point2Bits_Strict", a, asp, "1293"));

    // Bits2Point_Strict (256-bit packing → BabyJubjub Edwards point)
    // Inputs marked public via `{public [in]}` in the fixture so the
    // `in[254] === 0` and `signCalc.out === in[255]` constraints
    // survive optimisation rather than being lawfully substituted away.
    let t = std::time::Instant::now();
    let mut b2p_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    b2p_inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    for i in 1..256 {
        b2p_inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    let (b, a, asp) = compile_and_measure(
        "Bits2Point_Strict",
        "test/circomlib/bits2point_test.circom",
        &b2p_inputs,
    );
    print_row(
        "Bits2Point_Strict",
        b,
        a,
        "2589",
        "1050",
        "1043",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Bits2Point_Strict", a, asp, "1043"));

    // Sha256_2 (2 × 216-bit field-element inputs → 216-bit truncated
    // SHA-256 digest). Distinct shape from `Sha256(N)`: hardcoded
    // length encoding + 2× Num2Bits(216) + Bits2Num(216).
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure(
        "Sha256_2",
        "test/circomlib/sha256_2_test.circom",
        &[("a", 1), ("b", 2)]
            .iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect(),
    );
    print_row(
        "Sha256_2",
        b,
        a,
        "204462",
        "31699",
        "30134",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Sha256_2", a, asp, "30134"));

    // EdDSAPoseidon (Poseidon-hash variant of the EdDSA verifier).
    // Inherits the Pointbits cross-template advantage via its single
    // internal `Point2Bits_Strict` invocation on the hash output.
    let t = std::time::Instant::now();
    let fe = |s: &str| {
        FieldElement::<Bn254Fr>::from_decimal_str(s)
            .unwrap_or_else(|| panic!("bad field element: {s}"))
    };
    let mut eddsa_p_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    eddsa_p_inputs.insert("enabled".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    eddsa_p_inputs.insert(
        "Ax".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    eddsa_p_inputs.insert(
        "Ay".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    eddsa_p_inputs.insert("S".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    eddsa_p_inputs.insert(
        "R8x".to_string(),
        fe("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
    );
    eddsa_p_inputs.insert(
        "R8y".to_string(),
        fe("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    );
    eddsa_p_inputs.insert("M".to_string(), FieldElement::<Bn254Fr>::from_u64(42));
    let (b, a, asp) = compile_and_measure(
        "EdDSAPoseidon",
        "test/circomlib/eddsaposeidon_test.circom",
        &eddsa_p_inputs,
    );
    print_row(
        "EdDSAPoseidon",
        b,
        a,
        "21254",
        "8086",
        "4217",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EdDSAPoseidon", a, asp, "4217"));
}

pub(super) fn run_large_witnessless(
    sparse_summary: &mut Vec<(&'static str, usize, usize, &'static str)>,
) {
    // EdDSAVerifier(1) — Pedersen-hash variant. No `enabled` escape,
    // verifier always asserts a valid signature, so the benchmark
    // measures constraint shape via the witness-less path. Inherits
    // the Pointbits advantage 3× over (2× Bits2Point_Strict + 1×
    // Point2Bits_Strict in the verifier body).
    let t = std::time::Instant::now();
    let (b, a, asp) =
        compile_and_measure_witnessless("EdDSAVerifier(1)", "test/circomlib/eddsa_test.circom");
    print_row(
        "EdDSAVerifier(1)",
        b,
        a,
        "42919",
        "16498",
        "7417",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("EdDSAVerifier(1)", a, asp, "7417"));

    // Tornado Cash Withdraw(20) — vendored from tornadocash/tornado-core,
    // ported to circom 2.0. Tree depth 20 (mainnet). Body: 2× Pedersen +
    // 2× Num2Bits(248) + 20× MiMCSponge + 20× DualMux + 4 binding
    // squares. Witness-less because constructing a valid Pedersen-MiMC
    // merkle proof witness requires running the deposit ceremony off-line.
    let t = std::time::Instant::now();
    let (b, a, asp) = compile_and_measure_witnessless(
        "Tornado Withdraw(20)",
        "test/circomlib/tornado_test.circom",
    );
    print_row(
        "Tornado Withdraw(20)",
        b,
        a,
        "59009",
        "36451",
        "28275",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Tornado Withdraw(20)", a, asp, "28275"));

    // Semaphore(32) — semaphore-protocol/semaphore v4 main circuit.
    // Body: LessThan(251) + BabyPbk + 2× Poseidon(2) +
    // BinaryMerkleRoot(32) (32× Poseidon(2) inside). Witness-less
    // because constructing a valid (secret, merkle proof) pair requires
    // the Semaphore identity setup off-line.
    let t = std::time::Instant::now();
    let (b, a, asp) =
        compile_and_measure_witnessless("Semaphore(32)", "test/circomlib/semaphore_test.circom");
    print_row(
        "Semaphore(32)",
        b,
        a,
        "37044",
        "22216",
        "9383",
        t.elapsed().as_secs_f64() * 1000.0,
    );
    sparse_summary.push(("Semaphore(32)", a, asp, "9383"));
}

pub(super) fn run_poseidon_sweep(
    sparse_summary: &mut Vec<(&'static str, usize, usize, &'static str)>,
) {
    // Poseidon arity sweep (t = 3, 4, 8, 16). The existing benchmark
    // already covers t=2; this sweep tests how the optimiser scales
    // with the t×t MDS-matrix multiplication and the
    // `(t * nRoundsF + nRoundsP)`-element round-constant vector at
    // wider hashes. Witness uses small consecutive integers.
    for t in [3usize, 4, 8, 16] {
        let label = format!("Poseidon({t})");
        let circ = format!("test/circomlib/poseidon_{t}_test.circom");
        let inputs: HashMap<String, FieldElement<Bn254Fr>> = (0..t)
            .map(|i| {
                (
                    format!("inputs_{i}"),
                    FieldElement::<Bn254Fr>::from_u64((i as u64) + 1),
                )
            })
            .collect();
        let t_w = std::time::Instant::now();
        let (b, a, asp) = compile_and_measure(&label, &circ, &inputs);
        let (cir_o0, cir_o1, cir_o2) = match t {
            3 => ("931", "605", "261"),
            4 => ("1163", "736", "297"),
            8 => ("1965", "1171", "402"),
            16 => ("3675", "2092", "609"),
            _ => unreachable!(),
        };
        print_row(
            &label,
            b,
            a,
            cir_o0,
            cir_o1,
            cir_o2,
            t_w.elapsed().as_secs_f64() * 1000.0,
        );
        // Leak the label into a 'static slice via Box::leak so the
        // benchmark summary table can hold a stable &str. Fine in a
        // test run — the leak lives until process exit.
        let label_static: &'static str = Box::leak(label.into_boxed_str());
        sparse_summary.push((label_static, a, asp, cir_o2));
    }
}

pub(super) fn print_sparse_summary(sparse_summary: &[(&str, usize, usize, &str)]) {
    // Second table: O1 vs O2-sparse vs circom O2.
    //
    // Validates the hypothesis "sparse DEDUCE recovers constraints O1
    // misses, even on circuits where achronyme already matches or beats
    // circom O2". `gain` is achO1 - achO2s (constraints removed by the
    // sparse pass over O1 alone). `delta` is achO2s - cirO2 (positive
    // means achronyme remains behind, negative means we beat circom).
    eprintln!("+--- DEDUCE-sparse vs circom O2 ----------------------------------+");
    eprintln!(
        "| {:24} | {:>6} | {:>6} | {:>6} | {:>+6} | {:>5} |",
        "Circuit", "achO1", "achO2s", "cirO2", "delta", "gain"
    );
    eprintln!("+--------------------------+--------+--------+--------+--------+-------+");
    for (name, a_o1, a_o2s, cir_o2_str) in sparse_summary {
        let cir_o2: i64 = cir_o2_str.parse().unwrap_or(0);
        let delta: i64 = *a_o2s as i64 - cir_o2;
        let gain: i64 = *a_o1 as i64 - *a_o2s as i64;
        eprintln!(
            "| {:24} | {:>6} | {:>6} | {:>6} | {:>+6} | {:>5} |",
            name, a_o1, a_o2s, cir_o2_str, delta, gain
        );
    }
    eprintln!("+------------------------------------------------------------------+");
    eprintln!();
}
