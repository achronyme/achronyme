use super::*;

/// CompConstant standalone R1CS verify — isolates the 1<<128 BigVal fix.
#[test]
fn compconstant_standalone() {
    let mut inputs = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(42));

    let n = circomlib_e2e_verify_fe(
        "CompConstant standalone",
        "test/circomlib/compconstant_test.circom",
        &inputs,
    );
    eprintln!("  Constraints: {n}");
}

// ── Circomlib compatibility: simple gadgets ──────────────────────

/// Switcher: conditional swap (sel=0 → pass-through, sel=1 → swap).
#[test]
fn switcher_circomlib() {
    // sel=0: outL=L=10, outR=R=20
    let n = circomlib_e2e_verify(
        "Switcher (sel=0)",
        "test/circomlib/switcher_test.circom",
        &[("sel", 0), ("L", 10), ("R", 20)],
    );
    eprintln!("  Constraints: {n}");

    // sel=1: outL=R=20, outR=L=10
    let n = circomlib_e2e_verify(
        "Switcher (sel=1)",
        "test/circomlib/switcher_test.circom",
        &[("sel", 1), ("L", 10), ("R", 20)],
    );
    eprintln!("  Constraints: {n}");
}

/// Mux3: select one of 8 values with 3-bit selector.
/// Tests MultiMux3 with pre-computed linear combinations.
#[test]
fn mux3_circomlib() {
    // c = [10,20,30,40,50,60,70,80], s = [1,0,1] → index=5 → c[5]=60
    let n = circomlib_e2e_verify(
        "Mux3 (sel=5)",
        "test/circomlib/mux3_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 1),
            ("s_1", 0),
            ("s_2", 1),
        ],
    );
    eprintln!("  Constraints: {n}");
}

/// Mux4: select one of 16 values with 4-bit selector.
#[test]
fn mux4_circomlib() {
    // s = [1,1,0,0] → index=3 → c[3]
    let mut inputs: Vec<(&str, u64)> = Vec::new();
    // c[0..16] = 100, 200, ... 1600
    let c_names: Vec<String> = (0..16).map(|i| format!("c_{i}")).collect();
    for (i, name) in c_names.iter().enumerate() {
        inputs.push((name, (i as u64 + 1) * 100));
    }
    inputs.push(("s_0", 1)); // bit 0
    inputs.push(("s_1", 1)); // bit 1
    inputs.push(("s_2", 0)); // bit 2
    inputs.push(("s_3", 0)); // bit 3
                             // index = 1 + 2 = 3 → c[3] = 400

    let n = circomlib_e2e_verify(
        "Mux4 (sel=3)",
        "test/circomlib/mux4_test.circom",
        &inputs.iter().map(|&(n, v)| (n, v)).collect::<Vec<_>>(),
    );
    eprintln!("  Constraints: {n}");
}

/// BinSum(4,2): compile-only test.
///
/// TODO: BinSum uses `var lin += signal * e2` with `<-- (lin >> k) & 1`,
/// a mixed var/signal pattern where `lin` accumulates signal expressions
/// and then bit-extracts via witness hint. Needs var-as-linear-combination
/// tracking in the lowering to generate correct constraints.
#[test]
fn binsum_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/binsum_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("BinSum compilation failed: {e}"));
    eprintln!(
        "  BinSum(4,2) — {} nodes — COMPILED ✓",
        result.prove_ir.body.len()
    );
}

/// Multiplexer(2,3): compile-only test.
///
/// TODO: 2D signal input arrays (`inp[nIn][wIn]`) need flattened
/// naming support in the witness evaluator for full E2E verify.
#[test]
fn multiplexer_circomlib_compile() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/multiplexer_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Multiplexer compilation failed: {e}"));
    eprintln!(
        "  Multiplexer(2,3) — {} nodes — COMPILED ✓",
        result.prove_ir.body.len()
    );
}
