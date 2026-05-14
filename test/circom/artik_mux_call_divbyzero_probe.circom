pragma circom 2.1.5;

// Minimal probe for the artik lift's branching path. `safe_div(x)`
// guards a potentially-faulting integer division behind `if (x != 0)`;
// the guarded computation `100 \ x` lives inside the helper
// `inner(x)`, so both arms of the if/else are function-call
// substitutions. The lift must route this shape through the branching
// path so the not-taken arm's FIDiv never executes.
//
// Witness expectation: with input x == 0 the else-arm picks y = 0
// and no runtime FIDiv on zero runs.

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
