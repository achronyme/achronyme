pragma circom 2.0.0;

// A `while` loop whose counter `i` is slot-promoted to a runtime
// register (it lives in the runtime local map, not as a folded
// compile-time constant) and is then used as the index of an array
// *write*: `arr[i] = i * 2`. The 1D indexed-assignment lift must
// accept a runtime index — the symmetric mirror of the runtime-index
// array *read* — by lowering the index expression to a register and
// emitting `StoreArr`, with the out-of-bounds check deferred to the
// executor. If the runtime-index store were rejected the whole
// function would decline and the call would fall back to the E212
// "cannot be circuit-inlined" diagnostic, failing compilation.
//
// The const-bounds zero-init and summation loops keep the
// compile-time-index store/read paths exercised alongside the new
// one. Closed form: sum_{i=0}^{n-1} (2*i) = n*(n-1).
function fill_and_sum(n) {
    var arr[8];
    for (var z = 0; z < 8; z++) {
        arr[z] = 0;
    }
    var i = 0;
    while (i < n) {
        arr[i] = i * 2;
        i = i + 1;
    }
    var total = 0;
    for (var z = 0; z < 8; z++) {
        total = total + arr[z];
    }
    return total;
}

template WitnessRuntimeIndexStore() {
    signal input in;
    signal output out;
    out <-- fill_and_sum(in);
    out === out;
}

component main = WitnessRuntimeIndexStore();
