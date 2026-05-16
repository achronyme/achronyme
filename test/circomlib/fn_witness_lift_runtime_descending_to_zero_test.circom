pragma circom 2.0.0;

// A descending `for (i = start - 1; i >= 0; i--)` whose bound is a
// runtime function argument, so the lift cannot unroll it and routes
// through the runtime loop path. The guard `i >= 0` is a tautology
// for a field counter, so a naive `while (i >= 0)` desugaring would
// underflow past zero (`i--` takes 0 to the field value `p - 1`) and
// loop on with a wrapped counter. The lift must rewrite it to a
// terminating form. Returns sum_{i=0}^{start-1} i = start*(start-1)/2.
function sum_down(start) {
    var acc = 0;
    for (var i = start - 1; i >= 0; i--) {
        acc = acc + i;
    }
    return acc;
}

template WitnessRuntimeDescending() {
    signal input in;
    signal output out;
    out <-- sum_down(in);
    out === out;
}

component main = WitnessRuntimeDescending();
