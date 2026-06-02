use std::collections::HashMap;
use std::process::Command;

use constraints::{write_r1cs, write_wtns};
use ir::IrLowering;
use memory::field::PrimeId;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

// ============================================================================
// snarkjs infrastructure (mirrors export_test.rs pattern)
// ============================================================================

pub(super) fn snarkjs_available() -> bool {
    // snarkjs --version exits with code 99 (usage) but prints version to stdout.
    // Check for stdout containing "snarkjs" rather than exit code.
    Command::new("snarkjs")
        .arg("--version")
        .output()
        .map(|o| o.status.success() || String::from_utf8_lossy(&o.stdout).contains("snarkjs"))
        .unwrap_or(false)
        || Command::new("npx")
            .args(["snarkjs", "--version"])
            .output()
            .map(|o| o.status.success() || String::from_utf8_lossy(&o.stdout).contains("snarkjs"))
            .unwrap_or(false)
}

fn snarkjs_cmd() -> (&'static str, bool) {
    if Command::new("snarkjs")
        .arg("--version")
        .output()
        .map(|o| o.status.success() || String::from_utf8_lossy(&o.stdout).contains("snarkjs"))
        .unwrap_or(false)
    {
        ("snarkjs", true)
    } else {
        ("npx", false)
    }
}

pub(super) fn run_snarkjs(args: &[&str]) -> String {
    let (cmd, direct) = snarkjs_cmd();
    let effective_args = if direct { &args[1..] } else { args };
    let output = Command::new(cmd)
        .args(effective_args)
        .output()
        .unwrap_or_else(|e| panic!("{cmd} failed: {e}"));
    assert!(
        output.status.success(),
        "snarkjs command failed: {}\nstdout: {}\nstderr: {}",
        effective_args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

// ============================================================================
// Pipeline helper
// ============================================================================

pub(super) struct CrossValidationResult {
    /// Number of R1CS constraints (from Achronyme).
    pub(super) constraint_count: usize,
    /// Wire values exported via `snarkjs wtns export json`.
    pub(super) wire_values: Vec<String>,
    /// Whether `snarkjs wtns check` passed.
    pub(super) wtns_check_passed: bool,
}

/// Compile a circuit, export .r1cs/.wtns, and run snarkjs cross-validation.
pub(super) fn cross_validate(
    source: &str,
    public_names: &[&str],
    witness_names: &[&str],
    inputs: &HashMap<String, FieldElement>,
) -> CrossValidationResult {
    // 1. Compile with Achronyme
    let program =
        IrLowering::lower_circuit(source, public_names, witness_names).expect("IR lowering failed");
    let mut compiler = R1CSCompiler::new();
    compiler
        .compile_ir(&program)
        .expect("R1CS compilation failed");
    let constraint_count = compiler.cs.num_constraints();

    // 2. Generate witness
    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg.generate(inputs).expect("witness generation failed");
    compiler
        .cs
        .verify(&witness)
        .expect("internal verification failed");

    // 3. Export to temp files
    let dir = tempfile::tempdir().unwrap();
    let r1cs_path = dir.path().join("circuit.r1cs");
    let wtns_path = dir.path().join("witness.wtns");
    let wtns_json_path = dir.path().join("witness.json");

    std::fs::write(&r1cs_path, write_r1cs(&compiler.cs, PrimeId::Bn254)).unwrap();
    std::fs::write(&wtns_path, write_wtns(&witness, PrimeId::Bn254)).unwrap();

    let r1cs_str = r1cs_path.to_str().unwrap();
    let wtns_str = wtns_path.to_str().unwrap();
    let wtns_json_str = wtns_json_path.to_str().unwrap();

    // 4. snarkjs r1cs info — structural validation
    let info_output = run_snarkjs(&["snarkjs", "r1cs", "info", r1cs_str]);
    eprintln!("  snarkjs r1cs info: {}", info_output.trim());

    // 5. snarkjs wtns check — INDEPENDENT constraint satisfaction
    run_snarkjs(&["snarkjs", "wtns", "check", r1cs_str, wtns_str]);
    let wtns_check_passed = true; // If we get here, it passed (run_snarkjs panics on failure)
    eprintln!("  snarkjs wtns check: VALID ✓");

    // 6. snarkjs wtns export json — extract wire values
    run_snarkjs(&["snarkjs", "wtns", "export", "json", wtns_str, wtns_json_str]);
    let json_content = std::fs::read_to_string(&wtns_json_path).unwrap();
    let wire_values: Vec<String> = serde_json::from_str(&json_content).unwrap();

    CrossValidationResult {
        constraint_count,
        wire_values,
        wtns_check_passed,
    }
}

/// Convert a FieldElement to its decimal string representation for comparison.
pub(super) fn fe_to_decimal(fe: FieldElement) -> String {
    let limbs = fe.to_canonical();
    // Convert [u64; 4] little-endian limbs to a big integer decimal string
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    // Convert to decimal using simple big integer arithmetic
    if limbs == [0, 0, 0, 0] {
        return "0".to_string();
    }
    let mut result = Vec::new();
    let mut val = bytes.to_vec();
    while val.iter().any(|&b| b != 0) {
        let mut remainder = 0u32;
        for byte in val.iter_mut().rev() {
            let dividend = remainder * 256 + *byte as u32;
            *byte = (dividend / 10) as u8;
            remainder = dividend % 10;
        }
        result.push((remainder as u8) + b'0');
    }
    result.reverse();
    String::from_utf8(result).unwrap()
}

pub(super) fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

// ============================================================================
