pragma circom 2.0.0;

// Fase 2.1 lift extension: `var arr[N];` declares a backing array
// in the Artik program (via `AllocArray` with `ElemT::Field`);
// subsequent `arr[i] = expr` / `arr[i]` read through `StoreArr` /
// `LoadArr` after compile-time-folding `i`. Dimensions that don't
// fold to a literal still return `None` (E212 fallback).

function buffer_sum(x) {
    var arr[4];
    for (var i = 0; i < 4; i++) {
        arr[i] = x + i;
    }
    var total = 0;
    for (var i = 0; i < 4; i++) {
        total = total + arr[i];
    }
    return total;
}

template WitnessLiftArray() {
    signal input in;
    signal output out;
    out <-- buffer_sum(in);
    // sum_{i=0..3} (in + i) == 4 * in + 6
    out === 4 * in + 6;
}

component main = WitnessLiftArray();
