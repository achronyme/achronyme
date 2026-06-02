use super::*;

/// Point2Bits_Strict at the identity point (0, 1).
///
/// The identity point is degenerate: x = 0 collapses every bit of
/// `Num2Bits(x)` to 0, alias-check becomes trivial, CompConstant on
/// all-zero bits short-circuits. This probe exists *because* of that
/// degeneracy — it surfaces how aggressively each compiler folds
/// dead constraints when an input is statically known.
#[test]
#[ignore = "Pointbits compile + instantiate + R1CS — moderate. Run with --ignored point2bits_strict_identity."]
fn point2bits_strict_identity() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    inputs.insert("in_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));

    let n = circomlib_e2e_optimized(
        "Point2Bits_Strict (identity)",
        "test/circomlib/point2bits_test.circom",
        &inputs,
    );
    assert!(
        n > 0,
        "Point2Bits_Strict must produce non-empty constraint set"
    );
}

/// Point2Bits_Strict at the BabyJubjub generator (Gx, Gy).
///
/// Non-degenerate input — every bit of `Num2Bits(Gx)` is meaningful
/// and the AliasCheck / CompConstant constraints can't be statically
/// folded away. Provides a clean apples-to-apples comparison vs
/// circom's O2 baseline; any constraint-count gap here is structural,
/// not an artifact of the test's input choice.
///
/// Generator coordinates from circomlib `babyjub.circom`.
#[test]
#[ignore = "Pointbits compile + instantiate + R1CS — moderate. Run with --ignored point2bits_strict_generator."]
fn point2bits_strict_generator() {
    let gx = FieldElement::<Bn254Fr>::from_decimal_str(
        "5299619240641551281634865583518297030282874472190772894086521144482721001553",
    )
    .expect("Gx parse");
    let gy = FieldElement::<Bn254Fr>::from_decimal_str(
        "16950150798460657717958625567821834550301663161624707787222815936182638968203",
    )
    .expect("Gy parse");

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in_0".to_string(), gx);
    inputs.insert("in_1".to_string(), gy);

    let n = circomlib_e2e_optimized(
        "Point2Bits_Strict (generator)",
        "test/circomlib/point2bits_test.circom",
        &inputs,
    );
    assert!(
        n > 0,
        "Point2Bits_Strict must produce non-empty constraint set"
    );
}

/// Bits2Point_Strict: 256-bit packed → Edwards curve point.
///
/// Inverse of Point2Bits_Strict. Adds two pattern classes the
/// existing benchmark doesn't cover:
///   - **Witness hint via `<--`**: x is computed at witness time as
///     `sqrt((1-y²)/(a-d·y²))` with a sign flip from in[255]. The
///     `<--` operator is a free assignment — the constraint that
///     pins x to a valid value is `BabyCheck(x, y)`, a quadratic
///     constraint on the Edwards curve equation.
///   - **Conditional sign negation in witness logic**: the witness
///     algorithm has to honour `if (in[255] == 1) x = -x`; if the
///     witness path didn't, BabyCheck would still verify against
///     the unsigned x but the sign-bit assertion at the end would
///     reject. This test surfaces any drift between the witness
///     pipeline and the constraint pipeline.
///
/// Test point: identity (0, 1) packed. Bits 0=1 (y=1 lsb), 1..253=0,
/// 254=0 (hardcoded), 255=0 (x=0 sign).
#[test]
#[ignore = "Pointbits compile + instantiate + R1CS — moderate. Run with --ignored bits2point_strict_real_circomlib."]
fn bits2point_strict_real_circomlib() {
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    // bit 0 = lsb of y = 1
    inputs.insert("in_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    // bits 1..253 = 0
    for i in 1..254 {
        inputs.insert(format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
    }
    // bit 254 hardcoded to 0
    inputs.insert("in_254".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
    // bit 255 sign of x (x=0 → 0)
    inputs.insert("in_255".to_string(), FieldElement::<Bn254Fr>::from_u64(0));

    let n = circomlib_e2e_optimized(
        "Bits2Point_Strict (identity)",
        "test/circomlib/bits2point_test.circom",
        &inputs,
    );
    assert!(
        n > 0,
        "Bits2Point_Strict must produce non-empty constraint set"
    );
}
