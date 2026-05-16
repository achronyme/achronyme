pragma circom 2.0.0;

// Ordered comparisons (`<`, `<=`, `>`, `>=`) over field values are
// lifted at field precision (canonical-rep unsigned compare in
// `[0, p)`), not demoted to a machine width. A fixed-width demote
// would truncate operands that reach `2^64` and miscompare them —
// e.g. `2^64` vs `2^64 - 1`, the boundary the bigint witness call
// graph hits at `n = 64`.

function gt_compare(a, b) {
    // Returns 1 if a > b, 0 otherwise — exact for any field operands.
    if (a > b) {
        return 1;
    }
    return 0;
}

template WitnessLimbCompare() {
    signal input a;
    signal input b;
    signal output out;
    out <-- gt_compare(a, b);
    // Bind out ∈ {0, 1} via the standard boolean constraint.
    out * (out - 1) === 0;
}

component main = WitnessLimbCompare();
