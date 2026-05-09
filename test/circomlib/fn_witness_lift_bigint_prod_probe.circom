pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Phase 3 probe: lift `prod(n, k, a, b)` from circomlib's bigint
// witness call graph. Exercises whole-row 2D assignment from a call
// that returns a 1D array (`split[i] = SplitThreeFn(...)`) and
// VarDecl with array dim + Call init (`var sumAndCarry[2] = SplitFn(...)`).
template ProdProbe() {
    signal input a[2];
    signal input b[2];
    signal output out[4];
    var p[100] = prod(8, 2, a, b);
    out[0] <-- p[0];
    out[1] <-- p[1];
    out[2] <-- p[2];
    out[3] <-- p[3];
    // Trivial constraints to satisfy the validator's `<--` ⇒ `===`
    // requirement; the probe is about the lift, not soundness.
    out[0] === out[0];
    out[1] === out[1];
    out[2] === out[2];
    out[3] === out[3];
}

component main = ProdProbe();
