pragma circom 2.0.0;

// Row slice as nested-call argument: the caller declares a 2D local
// and passes one of its rows to a helper expecting a 1D array
// parameter. Exercises the argument-binding code in the artik lift's
// nested-call path — the lift must materialize the row as a fresh
// Flat1D and alias it under the callee's parameter name.

function sum_row(a) {
    var s = 0;
    for (var i = 0; i < 3; i++) {
        s = s + a[i];
    }
    return s;
}

function pick_and_sum(x) {
    var m[2][3];
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 3; j++) {
            m[i][j] = x + 10 * i + j;
        }
    }
    return sum_row(m[1]);
}

template WitnessRowSliceArg() {
    signal input in;
    signal output out;
    out <-- pick_and_sum(in);
    out === 3 * in + 33;
}

component main = WitnessRowSliceArg();
