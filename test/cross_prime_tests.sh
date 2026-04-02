#!/usr/bin/env bash
# Cross-prime test matrix for Achronyme
#
# Tests the same circuits and prove blocks across multiple prime fields.
#
# Matrix:
#   BN254     + R1CS     -> circuit + prove (Groth16) [already in run_tests.sh]
#   BN254     + Plonkish -> circuit (PlonK)           [already in run_tests.sh]
#   BLS12-381 + R1CS     -> circuit + prove (Groth16) [THIS SCRIPT]
#
# The circuit compilation pipeline (`ach circuit`) is fully generic over
# FieldBackend since Fase 6. All operations (including division, comparison,
# inequality, and Poseidon) work natively in BLS12-381.
#
# The prove pipeline (`ach run`) uses BN254 arithmetic internally in the VM,
# with cross-field conversion at proof generation time via fe_to_ark. This
# works for most operations but Poseidon prove tests require BLS12-381-specific
# expected hash values (the VM computes with BN254 params).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ACH="$REPO_ROOT/target/release/ach"

# Build once
echo "Building ach (release)..."
cargo build --release --manifest-path="$REPO_ROOT/Cargo.toml" 2>/dev/null

PASS=0
FAIL=0
ERRORS=()

run_test() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo "  PASS  $name"
    else
        FAIL=$((FAIL + 1))
        ERRORS+=("$name")
        echo "  FAIL  $name"
    fi
}

run_fail_test() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        FAIL=$((FAIL + 1))
        ERRORS+=("$name (expected failure but succeeded)")
        echo "  FAIL  $name"
    else
        PASS=$((PASS + 1))
        echo "  PASS  $name"
    fi
}

TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# ============================================================================
# BLS12-381 + R1CS -- Circuit tests (constraint generation + witness)
# All circuit tests work natively in BLS12-381 (generic pipeline).
# Poseidon circuit generates correct BLS12-381 constraints (no witness test
# since the expected hash value differs from BN254).
# ============================================================================

echo ""
echo "=== BLS12-381 Circuit tests (R1CS) ==="

run_test "bls12-381/circuit/basic_arithmetic" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_basic.r1cs" --wtns "$TMP_DIR/bls_basic.wtns" \
    --inputs "out=42,a=6,b=7"

run_test "bls12-381/circuit/mux" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/mux.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_mux.r1cs" --wtns "$TMP_DIR/bls_mux.wtns" \
    --inputs "out=42,cond=1,a=42,b=99"

run_test "bls12-381/circuit/boolean_ops" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/boolean_ops.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_bool.r1cs" --wtns "$TMP_DIR/bls_bool.wtns" \
    --inputs "x=3,y=5"

run_test "bls12-381/circuit/range_check" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/range_check.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_range.r1cs" --wtns "$TMP_DIR/bls_range.wtns" \
    --inputs "x=200,y=65000"

run_test "bls12-381/circuit/power" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/power.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_pow.r1cs" --wtns "$TMP_DIR/bls_pow.wtns" \
    --inputs "x=3,x2=9,x3=27,x4=81"

run_test "bls12-381/circuit/nested_functions" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/nested_functions.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_nested_fn.r1cs" --wtns "$TMP_DIR/bls_nested_fn.wtns" \
    --inputs "result=25,x=3"

run_test "bls12-381/circuit/for_loop_unroll" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/for_loop_unroll.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_for_loop.r1cs" --wtns "$TMP_DIR/bls_for_loop.wtns" \
    --inputs "total=100,vals_0=10,vals_1=20,vals_2=30,vals_3=40"

run_test "bls12-381/circuit/deep_functions" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/deep_functions.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_deep_fn.r1cs" --wtns "$TMP_DIR/bls_deep_fn.wtns" \
    --inputs "out=44,a=10"

run_test "bls12-381/circuit/complex_boolean" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/complex_boolean.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_complex_bool.r1cs" --wtns "$TMP_DIR/bls_complex_bool.wtns" \
    --inputs "a=3,b=7,c=10,d=2,e=1,f=2"

run_test "bls12-381/circuit/nested_loops" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/nested_loops.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_nested_loops.r1cs" --wtns "$TMP_DIR/bls_nested_loops.wtns" \
    --inputs "out=36"

run_test "bls12-381/circuit/inner_product" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/inner_product.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_inner_product.r1cs" --wtns "$TMP_DIR/bls_inner_product.wtns" \
    --inputs "out=70,a_0=1,a_1=2,a_2=3,a_3=4,b_0=5,b_1=6,b_2=7,b_3=8"

run_test "bls12-381/circuit/arrays_and_functions" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/arrays_and_functions.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_arr.r1cs" --wtns "$TMP_DIR/bls_arr.wtns" \
    --inputs "expected_sum=60,vals_0=10,vals_1=20,vals_2=30"

# Typed circuit tests
run_test "bls12-381/circuit/typed_arithmetic" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_arithmetic.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_typed_arith.r1cs" --wtns "$TMP_DIR/bls_typed_arith.wtns" \
    --inputs "out=42,a=6,b=7"

run_test "bls12-381/circuit/typed_boolean_ops" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_boolean_ops.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_typed_bool.r1cs" --wtns "$TMP_DIR/bls_typed_bool.wtns" \
    --inputs "x=3,y=5"

run_test "bls12-381/circuit/typed_mux" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_mux.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_typed_mux.r1cs" --wtns "$TMP_DIR/bls_typed_mux.wtns" \
    --inputs "out=42,cond=1,a=42,b=99"

run_test "bls12-381/circuit/typed_arrays_and_functions" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_arrays_and_functions.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_typed_arr.r1cs" --wtns "$TMP_DIR/bls_typed_arr.wtns" \
    --inputs "expected_sum=60,vals_0=10,vals_1=20,vals_2=30"

# Division + comparison — native BLS12-381 field arithmetic (fixed in Fase 6)
run_test "bls12-381/circuit/division" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/division.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_div.r1cs" --wtns "$TMP_DIR/bls_div.wtns" \
    --inputs "q=3,a=42,b=14"

run_test "bls12-381/circuit/comparison_ops" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/comparison_ops.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_cmp.r1cs" --wtns "$TMP_DIR/bls_cmp.wtns" \
    --inputs "x=3,y=5"

# Poseidon constraints-only (no witness: expected hash differs from BN254)
run_test "bls12-381/circuit/poseidon_constraints" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/poseidon.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/bls_pos.r1cs"

# ============================================================================
# BLS12-381 + R1CS -- Prove tests (Groth16 proof generation + verification)
# Poseidon prove tests excluded: VM computes hash with BN254 params, circuit
# expects BLS12-381 params, causing a mismatch. Requires multi-field VM.
# ============================================================================

echo ""
echo "=== BLS12-381 Prove tests (Groth16) ==="

run_test "bls12-381/prove/basic_prove" \
    "$ACH" run "$SCRIPT_DIR/prove/basic_prove.ach" --prime bls12-381

run_test "bls12-381/prove/prove_power" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_power.ach" --prime bls12-381

run_test "bls12-381/prove/prove_capture" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_capture.ach" --prime bls12-381

run_test "bls12-381/prove/prove_range_check" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_range_check.ach" --prime bls12-381

run_test "bls12-381/prove/prove_boolean_mux" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_boolean_mux.ach" --prime bls12-381

run_test "bls12-381/prove/prove_array_sum" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_array_sum.ach" --prime bls12-381

run_test "bls12-381/prove/prove_assert_message" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_assert_message.ach" --prime bls12-381

run_test "bls12-381/prove/prove_outer_fn" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_outer_fn.ach" --prime bls12-381

run_test "bls12-381/prove/typed_prove" \
    "$ACH" run "$SCRIPT_DIR/prove/typed_prove.ach" --prime bls12-381

# ============================================================================
# Goldilocks + R1CS -- Circuit tests (constraint generation + witness)
# Goldilocks is a 64-bit field. No pairing-friendly prover exists, so proof
# generation is not supported. Constraint generation and witness work fully.
# ============================================================================

echo ""
echo "=== Goldilocks Circuit tests (R1CS, constraints only) ==="

run_test "goldilocks/circuit/basic_arithmetic" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --prime goldilocks \
    --r1cs "$TMP_DIR/gl_basic.r1cs" --wtns "$TMP_DIR/gl_basic.wtns" \
    --inputs "out=42,a=6,b=7"

run_test "goldilocks/circuit/division" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/division.ach" \
    --prime goldilocks \
    --r1cs "$TMP_DIR/gl_div.r1cs" --wtns "$TMP_DIR/gl_div.wtns" \
    --inputs "q=3,a=42,b=14"

run_test "goldilocks/circuit/range_check" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/range_check.ach" \
    --prime goldilocks \
    --r1cs "$TMP_DIR/gl_range.r1cs" --wtns "$TMP_DIR/gl_range.wtns" \
    --inputs "x=200,y=65000"

run_test "goldilocks/circuit/comparison_ops" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/comparison_ops.ach" \
    --prime goldilocks \
    --r1cs "$TMP_DIR/gl_cmp.r1cs" --wtns "$TMP_DIR/gl_cmp.wtns" \
    --inputs "x=3,y=5"

run_test "goldilocks/circuit/mux" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/mux.ach" \
    --prime goldilocks \
    --r1cs "$TMP_DIR/gl_mux.r1cs" --wtns "$TMP_DIR/gl_mux.wtns" \
    --inputs "out=42,cond=1,a=42,b=99"

run_test "goldilocks/circuit/poseidon_constraints" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/poseidon.ach" \
    --prime goldilocks \
    --r1cs "$TMP_DIR/gl_pos.r1cs"

# ============================================================================
# Validation tests -- unsupported combinations must fail gracefully
# ============================================================================

echo ""
echo "=== Validation tests (expected failures) ==="

# BLS12-381 + Plonkish -> not supported (halo2 PSE is BN254-only)
run_fail_test "bls12-381/plonkish/rejected" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --prime bls12-381 --backend plonkish \
    --r1cs /dev/null --wtns /dev/null \
    --inputs "out=42,a=6,b=7"

# Goldilocks + Plonkish -> not supported
run_fail_test "goldilocks/plonkish/rejected" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --prime goldilocks --backend plonkish \
    --r1cs /dev/null --wtns /dev/null \
    --inputs "out=42,a=6,b=7"

# Invalid prime name -> rejected
run_fail_test "invalid-prime/rejected" \
    "$ACH" run "$SCRIPT_DIR/prove/basic_prove.ach" --prime secp256k1

# BLS12-381 + Solidity -> rejected (EVM is BN254-only)
run_fail_test "bls12-381/solidity/rejected" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --prime bls12-381 \
    --r1cs "$TMP_DIR/sol_check.r1cs" --wtns "$TMP_DIR/sol_check.wtns" \
    --solidity "$TMP_DIR/should_not_exist.sol" \
    --inputs "out=42,a=6,b=7"

# ============================================================================
# BN254 regression -- verify existing tests still pass with explicit --prime
# ============================================================================

echo ""
echo "=== BN254 regression (explicit --prime bn254) ==="

run_test "bn254/circuit/basic_arithmetic" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --prime bn254 \
    --r1cs "$TMP_DIR/bn_basic.r1cs" --wtns "$TMP_DIR/bn_basic.wtns" \
    --inputs "out=42,a=6,b=7"

run_test "bn254/prove/basic_prove" \
    "$ACH" run "$SCRIPT_DIR/prove/basic_prove.ach" --prime bn254

# Poseidon works with explicit BN254 flag
run_test "bn254/circuit/poseidon" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/poseidon.ach" \
    --prime bn254 \
    --r1cs "$TMP_DIR/bn_poseidon.r1cs" --wtns "$TMP_DIR/bn_poseidon.wtns" \
    --inputs "expected=7853200120776062878684798364095072458815029376092732009249414926327459813530,a=1,b=2,c=3"

run_test "bn254/prove/prove_with_poseidon" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_with_poseidon.ach" --prime bn254

# Division and comparison work on BN254 (field-native arithmetic)
run_test "bn254/prove/prove_division" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_division.ach" --prime bn254

run_test "bn254/prove/prove_comparison" \
    "$ACH" run "$SCRIPT_DIR/prove/prove_comparison.ach" --prime bn254

# ============================================================================
# Summary
# ============================================================================

echo ""
TOTAL=$((PASS + FAIL))
echo "Cross-prime results: $PASS passed, $FAIL failed (out of $TOTAL)"
if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    for e in "${ERRORS[@]}"; do
        echo "  - $e"
    done
    exit 1
fi
