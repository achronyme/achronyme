pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Lift `long_div(n, k, m, a, b)` from circomlib's bigint witness call
// graph. The function returns `out[2][100]` — a 2D array. Standalone
// invocation forces the lift to expose the 2D return as a flattened
// `2 * 100 = 200` slot witness layout. Exercises: descending for-loop
// over `m..=0` (`for (var i = m; i >= 0; i--)`), 2D substitution
// (`out[0][i] = ...`, `out[1][i] = ...`), whole-array reassignment
// from a call (`remainder = long_sub(...)`), and the inner
// `short_div` / `long_scalar_mult` composition.
template LongDivProbe() {
    signal input a[3];
    signal input b[2];
    signal output q[200];
    var d[2][100] = long_div(4, 2, 1, a, b);
    for (var i = 0; i < 100; i++) {
        q[i] <-- d[0][i];
    }
    for (var i = 0; i < 100; i++) {
        q[100 + i] <-- d[1][i];
    }
    for (var i = 0; i < 200; i++) {
        q[i] === q[i];
    }
}

component main = LongDivProbe();
