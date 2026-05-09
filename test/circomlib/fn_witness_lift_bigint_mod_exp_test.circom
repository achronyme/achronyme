pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Lift `mod_exp(n, k, a, p, e)` from circomlib's bigint witness call
// graph. The function's outer for-loop unrolls (k*n = 64 iters at the
// probe config); each iter exercises 1D-from-2D-row copy
// (`out = temp2[1]`), whole-array rebinds (`temp = prod(...)`,
// `temp2 = long_div(...)`), and the if-without-else branching path
// for the bit-conditional squaring step.
template ModExpProbe() {
    signal input a[2];
    signal input p[2];
    signal input e[2];
    signal output out[100];
    var r[100] = mod_exp(32, 2, a, p, e);
    for (var i = 0; i < 100; i++) {
        out[i] <-- r[i];
        out[i] === out[i];
    }
}

component main = ModExpProbe();
