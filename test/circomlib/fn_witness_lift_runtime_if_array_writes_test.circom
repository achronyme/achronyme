pragma circom 2.0.0;

// Phase 2 lift extension: runtime `if / else` whose arms write to
// arrays now routes through `lift_if_else_branching` instead of the
// mux path. Mux can't safely handle array writes (both arms would
// execute and corrupt the heap); branching emits a real `JumpIf` so
// only the taken arm's stores fire.
//
// Mirrors the inner shape of circomlib's `long_sub` from
// `bigint_func.circom`: per-iteration runtime compare, one of two
// stores into an array slot.

function abs_pair(a, b) {
    var diff[2];
    var marker[2];
    for (var i = 0; i < 2; i++) {
        if (a[i] >= b[i]) {
            diff[i] = a[i] - b[i];
            marker[i] = 0;
        } else {
            diff[i] = b[i] - a[i];
            marker[i] = 1;
        }
    }
    return diff;
}

template AbsPair() {
    signal input a[2];
    signal input b[2];
    signal output out[2];
    var d[2] = abs_pair(a, b);
    out[0] <-- d[0];
    out[1] <-- d[1];
    // Triangle-inequality-style sanity: out[i] is the larger minus
    // the smaller, so out[i] * (out[i] + 1) >= 0 holds vacuously over
    // BN254 (kept here as a no-op constraint to retain a public output).
    out[0] === out[0];
    out[1] === out[1];
}

component main = AbsPair();
