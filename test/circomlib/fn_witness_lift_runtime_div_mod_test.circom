pragma circom 2.0.0;

// Phase 2 lift extension: `\` and `%` with a runtime (non-power-of-2)
// divisor emit field-level FIDiv / FIRem on the canonical
// representative. The executor performs raw unsigned truncated
// division and traps on `b == 0`. Used by `short_div` and
// `short_div_norm` in circomlib's bigint witness call graph.

function divmod(x, y) {
    return [x \ y, x % y];
}

template DivModTest() {
    signal input x;
    signal input y;
    signal output q;
    signal output r;
    var dm[2] = divmod(x, y);
    q <-- dm[0];
    r <-- dm[1];
    // Quotient-remainder identity. `r` and `y` are signal-derived so
    // this constraint exercises the prove-side rather than asserting
    // anything about specific Artik output values.
    q * y + r === x;
}

component main = DivModTest();
