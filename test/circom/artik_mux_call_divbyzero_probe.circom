pragma circom 2.1.5;

// Minimal reproduction of the mux/call divisor-zero bug.
//
// `safe_div(x)` guards a potentially-faulting integer division behind
// `if (x != 0)`. The guarded computation `100 \ x` lives inside the
// helper `inner(x)` so the if/else arms are function-call
// substitutions — the exact shape that drove the secp256k1
// `long_sub_mod_p` lift to emit both arms via mux-style merge, then
// fault on the not-taken arm's FIDiv when the divisor is zero.
//
// Witness expectation: with input x == 0, the else-arm picks y = 0;
// no runtime FIDiv on zero must execute.

function inner(x) {
    return 100 \ x;
}

function safe_div(x) {
    var y;
    if (x != 0) {
        y = inner(x);
    } else {
        y = 0;
    }
    return y;
}

template MuxCallDivByZeroProbe() {
    signal input x;
    signal output out;
    out <-- safe_div(x);
    out === out;
}

component main = MuxCallDivByZeroProbe();
