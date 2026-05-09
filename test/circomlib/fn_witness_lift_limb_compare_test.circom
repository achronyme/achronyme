pragma circom 2.0.0;

// Phase 1 lift extension: ordered comparisons (`<`, `<=`, `>`, `>=`)
// over field values demote to `IntW::U64` and dispatch through
// `IntBinOp::CmpLt`, inverting where necessary. U64 demote covers
// the bigint witness call graph at `n=64, k=4` where every limb is
// at most `2^64 - 1`.
//
// Without this widening, `long_gt(64, 4, a, b)` would silently
// truncate to U32 and miscompare values whose low 32 bits agree
// but high 32 bits differ.

function gt_u64_compare(a, b) {
    // Returns 1 if a > b, 0 otherwise — at U64 width, i.e. correct
    // for inputs up to 2^64 - 1.
    if (a > b) {
        return 1;
    }
    return 0;
}

template WitnessLimbCompare() {
    signal input a;
    signal input b;
    signal output out;
    out <-- gt_u64_compare(a, b);
    // Bind out ∈ {0, 1} via the standard boolean constraint; the
    // caller is responsible for supplying inputs that exercise the
    // U64 boundary.
    out * (out - 1) === 0;
}

component main = WitnessLimbCompare();
