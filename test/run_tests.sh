#!/usr/bin/env bash
# Test runner for Achronyme .ach test files
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ACH="$REPO_ROOT/target/release/cli"

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

# --- VM tests ---
echo ""
echo "=== VM tests ==="
while IFS= read -r -d '' f; do
    name="${f#$SCRIPT_DIR/}"
    run_test "$name" "$ACH" run "$f"
done < <(find "$SCRIPT_DIR/vm" -name '*.ach' -not -path '*/errors/*' -print0 | sort -z)

# --- VM error tests (expected failures) ---
echo ""
echo "=== VM error tests (expected failures) ==="
while IFS= read -r -d '' f; do
    name="${f#$SCRIPT_DIR/}"
    run_fail_test "$name" "$ACH" run "$f"
done < <(find "$SCRIPT_DIR/vm/errors" -name '*.ach' -print0 2>/dev/null | sort -z)

# --- Circuit tests ---
echo ""
echo "=== Circuit tests ==="

R1CS_DIR=$(mktemp -d)
trap "rm -rf $R1CS_DIR" EXIT

run_test "circuit/basic_arithmetic.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --r1cs "$R1CS_DIR/basic.r1cs" --wtns "$R1CS_DIR/basic.wtns" \
    --inputs "out=42,a=6,b=7"

run_test "circuit/poseidon.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/poseidon.ach" \
    --r1cs "$R1CS_DIR/poseidon.r1cs" --wtns "$R1CS_DIR/poseidon.wtns" \
    --inputs "expected=7853200120776062878684798364095072458815029376092732009249414926327459813530,a=1,b=2,c=3"

run_test "circuit/mux.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/mux.ach" \
    --r1cs "$R1CS_DIR/mux.r1cs" --wtns "$R1CS_DIR/mux.wtns" \
    --inputs "out=42,cond=1,a=42,b=99"

run_test "circuit/range_check.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/range_check.ach" \
    --r1cs "$R1CS_DIR/range.r1cs" --wtns "$R1CS_DIR/range.wtns" \
    --inputs "x=200,y=65000"

run_test "circuit/boolean_ops.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/boolean_ops.ach" \
    --r1cs "$R1CS_DIR/bool.r1cs" --wtns "$R1CS_DIR/bool.wtns" \
    --inputs "x=3,y=5"

run_test "circuit/merkle.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/merkle.ach" \
    --r1cs "$R1CS_DIR/merkle.r1cs" --wtns "$R1CS_DIR/merkle.wtns" \
    --inputs "root=7853200120776062878684798364095072458815029376092732009249414926327459813530,leaf=1,path_0=2,indices_0=0"

run_test "circuit/arrays_and_functions.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/arrays_and_functions.ach" \
    --r1cs "$R1CS_DIR/arr.r1cs" --wtns "$R1CS_DIR/arr.wtns" \
    --inputs "expected_sum=60,vals_0=10,vals_1=20,vals_2=30"

run_test "circuit/power.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/power.ach" \
    --r1cs "$R1CS_DIR/pow.r1cs" --wtns "$R1CS_DIR/pow.wtns" \
    --inputs "x=3,x2=9,x3=27,x4=81"

run_test "circuit/division.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/division.ach" \
    --r1cs "$R1CS_DIR/div.r1cs" --wtns "$R1CS_DIR/div.wtns" \
    --inputs "q=6,a=42,b=7"

run_test "circuit/comparison_ops.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/comparison_ops.ach" \
    --r1cs "$R1CS_DIR/cmp.r1cs" --wtns "$R1CS_DIR/cmp.wtns" \
    --inputs "x=3,y=5"

run_test "circuit/nested_functions.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/nested_functions.ach" \
    --r1cs "$R1CS_DIR/nested_fn.r1cs" --wtns "$R1CS_DIR/nested_fn.wtns" \
    --inputs "result=25,x=3"

run_test "circuit/for_loop_unroll.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/for_loop_unroll.ach" \
    --r1cs "$R1CS_DIR/for_loop.r1cs" --wtns "$R1CS_DIR/for_loop.wtns" \
    --inputs "total=100,vals_0=10,vals_1=20,vals_2=30,vals_3=40"

# --- Complex circuit tests ---
echo ""
echo "=== Complex circuit tests ==="

run_test "circuit/nullifier.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/nullifier.ach" \
    --r1cs "$R1CS_DIR/nullifier.r1cs" --wtns "$R1CS_DIR/nullifier.wtns" \
    --inputs "nullifier=4736362406665208364747685732453189199131835045859587280506752441838311700156,secret=12345,leaf_index=7"

run_test "circuit/commitment.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/commitment.ach" \
    --r1cs "$R1CS_DIR/commitment.r1cs" --wtns "$R1CS_DIR/commitment.wtns" \
    --inputs "commitment=16301115570242784778765184033606574990417411247577491285886077462613734960794,value=1000,blinding=98765"

run_test "circuit/hash_chain.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/hash_chain.ach" \
    --r1cs "$R1CS_DIR/hash_chain.r1cs" --wtns "$R1CS_DIR/hash_chain.wtns" \
    --inputs "expected=21508756081070400358417640840024981277893390350656564165427487686097502392670,seed=0"

run_test "circuit/deep_functions.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/deep_functions.ach" \
    --r1cs "$R1CS_DIR/deep_fn.r1cs" --wtns "$R1CS_DIR/deep_fn.wtns" \
    --inputs "out=44,a=10"

run_test "circuit/complex_boolean.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/complex_boolean.ach" \
    --r1cs "$R1CS_DIR/complex_bool.r1cs" --wtns "$R1CS_DIR/complex_bool.wtns" \
    --inputs "a=3,b=7,c=10,d=2,e=1,f=2"

run_test "circuit/nested_loops.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/nested_loops.ach" \
    --r1cs "$R1CS_DIR/nested_loops.r1cs" --wtns "$R1CS_DIR/nested_loops.wtns" \
    --inputs "out=36"

run_test "circuit/inner_product.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/inner_product.ach" \
    --r1cs "$R1CS_DIR/inner_product.r1cs" --wtns "$R1CS_DIR/inner_product.wtns" \
    --inputs "out=70,a_0=1,a_1=2,a_2=3,a_3=4,b_0=5,b_1=6,b_2=7,b_3=8"

# --- Typed circuit tests (gradual type system) ---
echo ""
echo "=== Typed circuit tests ==="

run_test "circuit/typed_arithmetic.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_arithmetic.ach" \
    --r1cs "$R1CS_DIR/typed_arith.r1cs" --wtns "$R1CS_DIR/typed_arith.wtns" \
    --inputs "out=42,a=6,b=7"

run_test "circuit/typed_boolean_ops.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_boolean_ops.ach" \
    --r1cs "$R1CS_DIR/typed_bool.r1cs" --wtns "$R1CS_DIR/typed_bool.wtns" \
    --inputs "x=3,y=5"

run_test "circuit/typed_mux.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_mux.ach" \
    --r1cs "$R1CS_DIR/typed_mux.r1cs" --wtns "$R1CS_DIR/typed_mux.wtns" \
    --inputs "out=42,cond=1,a=42,b=99"

run_test "circuit/typed_arrays_and_functions.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_arrays_and_functions.ach" \
    --r1cs "$R1CS_DIR/typed_arr.r1cs" --wtns "$R1CS_DIR/typed_arr.wtns" \
    --inputs "expected_sum=60,vals_0=10,vals_1=20,vals_2=30"

run_test "circuit/typed_poseidon.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_poseidon.ach" \
    --r1cs "$R1CS_DIR/typed_poseidon.r1cs" --wtns "$R1CS_DIR/typed_poseidon.wtns" \
    --inputs "expected=7853200120776062878684798364095072458815029376092732009249414926327459813530,a=1,b=2,c=3"

run_test "circuit/typed_merkle.ach" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/typed_merkle.ach" \
    --r1cs "$R1CS_DIR/typed_merkle.r1cs" --wtns "$R1CS_DIR/typed_merkle.wtns" \
    --inputs "root=7853200120776062878684798364095072458815029376092732009249414926327459813530,leaf=1,path_0=2,indices_0=0"

# --- Solidity verifier test ---
echo ""
echo "=== Solidity verifier tests ==="

run_test "circuit/basic_arithmetic.ach (solidity)" \
    "$ACH" circuit "$SCRIPT_DIR/circuit/basic_arithmetic.ach" \
    --r1cs "$R1CS_DIR/basic_sol.r1cs" --wtns "$R1CS_DIR/basic_sol.wtns" \
    --inputs "out=42,a=6,b=7" \
    --solidity "$R1CS_DIR/verifier.sol"

# Validate the .sol file exists and contains the contract
if [ -f "$R1CS_DIR/verifier.sol" ] && grep -q "contract Groth16Verifier" "$R1CS_DIR/verifier.sol"; then
    PASS=$((PASS + 1))
    echo "  PASS  circuit/solidity_verifier_content"
else
    FAIL=$((FAIL + 1))
    ERRORS+=("circuit/solidity_verifier_content")
    echo "  FAIL  circuit/solidity_verifier_content"
fi

# --- Prove tests ---
echo ""
echo "=== Prove tests ==="
for f in "$SCRIPT_DIR"/prove/*.ach; do
    name="prove/$(basename "$f")"
    run_test "$name" "$ACH" run "$f"
done

# --- Summary ---
echo ""
TOTAL=$((PASS + FAIL))
echo "Results: $PASS passed, $FAIL failed (out of $TOTAL)"
if [ ${#ERRORS[@]} -gt 0 ]; then
    echo ""
    echo "Failed tests:"
    for e in "${ERRORS[@]}"; do
        echo "  - $e"
    done
    exit 1
fi
