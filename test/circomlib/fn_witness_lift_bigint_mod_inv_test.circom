pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Lift `mod_inv(n, k, a, p)` from circomlib's bigint witness call
// graph. Composition of Phases 1-5: outer for + early-return
// branching, runtime if/else fold inside for-unroll, whole-array
// rebinds (`pMinusTwo = long_sub(...)`, `out = mod_exp(...)`), and
// the lifted `mod_exp` runtime while with hoisted body arrays.
template ModInvProbe() {
    signal input a[2];
    signal input p[2];
    signal output q[100];
    var r[100] = mod_inv(32, 2, a, p);
    for (var i = 0; i < 100; i++) {
        q[i] <-- r[i];
        q[i] === q[i];
    }
}

component main = ModInvProbe();
