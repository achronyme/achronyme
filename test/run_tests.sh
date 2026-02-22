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

# --- VM tests ---
echo ""
echo "=== VM tests ==="
for f in "$SCRIPT_DIR"/vm/*.ach; do
    name="vm/$(basename "$f")"
    run_test "$name" "$ACH" run "$f"
done

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
