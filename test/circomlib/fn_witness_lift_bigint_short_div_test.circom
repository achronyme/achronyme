pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Lift `short_div(n, k, a, b)` from circomlib's bigint witness call
// graph. Wraps `short_div_norm` and exercises composition: scale via
// runtime FIDiv (`(1 << n) \ (1 + b[k-1])` — non-power-of-2 divisor),
// nested `long_scalar_mult` calls, and the if-with-scalar-return
// dispatch on `norm_b[k] != 0`.
template ShortDivProbe() {
    signal input a[3];
    signal input b[2];
    signal output q;
    q <-- short_div(4, 2, a, b);
    q === q;
}

component main = ShortDivProbe();
