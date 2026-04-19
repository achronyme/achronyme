pragma circom 2.0.0;

// Fase 5.1: array parameters in the Artik lift. A function with
// `arr[4]` as a parameter binds to 4 input signals (one per
// element, ordered by index) and can be indexed freely inside the
// body. The call site expands `inp` (a signal array) into one
// `CircuitExpr` per element, and the lift allocates an Artik
// AllocArray + 4× (ReadSignal + StoreArr) prelude so `inp[i]` in
// the body resolves to a `LoadArr` against the backing store.
//
//     array_sum(arr) = sum_{i=0..3} (arr[i] * (i + 1))
//                    = arr[0] + 2*arr[1] + 3*arr[2] + 4*arr[3]

function array_sum(arr) {
    var total = 0;
    for (var i = 0; i < 4; i++) {
        total += arr[i] * (i + 1);
    }
    return total;
}

template WitnessLiftArrayParam() {
    signal input inp[4];
    signal output out;
    out <-- array_sum(inp);
    out === inp[0] + 2 * inp[1] + 3 * inp[2] + 4 * inp[3];
}

component main = WitnessLiftArrayParam();
