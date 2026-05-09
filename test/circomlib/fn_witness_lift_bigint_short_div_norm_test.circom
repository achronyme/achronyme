pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Lift `short_div_norm(n, k, a, b)` from circomlib's bigint witness
// call graph. Exercises: runtime FIDiv on the qhat shape
// `(a[k] * (1 << n) + a[k-1]) \ b[k-1]` (non-power-of-2 divisor),
// runtime if/else with var assignment for the qhat clamp, whole-array
// reassignment from call (`mult = long_sub(...)`), and early-return
// branches with scalar return values.
template ShortDivNormProbe() {
    signal input a[3];
    signal input b[2];
    signal output q;
    q <-- short_div_norm(4, 2, a, b);
    q === q;
}

component main = ShortDivNormProbe();
