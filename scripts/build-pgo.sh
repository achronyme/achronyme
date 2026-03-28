#!/usr/bin/env bash
# Build the ach binary with Profile-Guided Optimization (PGO).
#
# PGO uses runtime profile data to guide LLVM's optimization decisions
# (branch layout, inlining, register allocation). Typical speedup: 20-35%.
#
# Usage:
#   ./scripts/build-pgo.sh          # full PGO build
#   ./scripts/build-pgo.sh --clean  # remove PGO artifacts and rebuild
#
# The final binary is at target/release/ach (same as a normal release build).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PGO_DIR="$REPO_ROOT/target/pgo-data"
LLVM_PROFDATA="$(find "$(rustc --print sysroot)" -name llvm-profdata 2>/dev/null | head -1)"

if [[ -z "$LLVM_PROFDATA" ]]; then
    echo "Error: llvm-profdata not found. Install with: rustup component add llvm-tools"
    exit 1
fi

if [[ "${1:-}" == "--clean" ]]; then
    echo "Cleaning PGO artifacts..."
    rm -rf "$PGO_DIR"
    cargo clean --release 2>/dev/null || true
fi

echo "=== Step 1/3: Building instrumented binary ==="
rm -rf "$PGO_DIR"
mkdir -p "$PGO_DIR"
RUSTFLAGS="-Cprofile-generate=$PGO_DIR" cargo build --release \
    --manifest-path="$REPO_ROOT/Cargo.toml" 2>&1 | tail -1

echo "=== Step 2/3: Collecting profile data ==="
ACH="$REPO_ROOT/target/release/ach"

# Hot loop benchmark (primary optimization target)
echo 'mut counter = 0; forever { counter = counter + 1; if counter > 10000000 { break } }' > /tmp/_pgo_bench.ach
for _ in 1 2 3; do
    "$ACH" run /tmp/_pgo_bench.ach >/dev/null 2>&1
done
rm -f /tmp/_pgo_bench.ach

# VM test suite — exercises all code paths
PROFILE_COUNT=0
for f in "$REPO_ROOT"/test/vm/operators/*.ach \
         "$REPO_ROOT"/test/vm/control_flow/*.ach \
         "$REPO_ROOT"/test/vm/functions/*.ach \
         "$REPO_ROOT"/test/vm/collections/*.ach \
         "$REPO_ROOT"/test/vm/data_types/*.ach \
         "$REPO_ROOT"/test/vm/integration/*.ach \
         "$REPO_ROOT"/test/vm/variables/*.ach \
         "$REPO_ROOT"/test/vm/edgecases/*.ach; do
    "$ACH" run "$f" >/dev/null 2>&1 || true
    PROFILE_COUNT=$((PROFILE_COUNT + 1))
done

PROFRAW_COUNT=$(find "$PGO_DIR" -name "*.profraw" | wc -l)
echo "  Collected $PROFRAW_COUNT profiles from $((PROFILE_COUNT + 3)) workloads"

echo "=== Step 3/3: Building PGO-optimized binary ==="
"$LLVM_PROFDATA" merge -o "$PGO_DIR/merged.profdata" "$PGO_DIR"/*.profraw

RUSTFLAGS="-Cprofile-use=$PGO_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function=false" \
    cargo build --release --manifest-path="$REPO_ROOT/Cargo.toml" 2>&1 | tail -1

# Cleanup raw profiles (keep merged for reproducibility)
rm -f "$PGO_DIR"/*.profraw

echo ""
echo "Done. PGO-optimized binary: target/release/ach"
echo "Profile data: $PGO_DIR/merged.profdata ($(du -h "$PGO_DIR/merged.profdata" | cut -f1))"
