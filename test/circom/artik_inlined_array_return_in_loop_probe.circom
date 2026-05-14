pragma circom 2.1.5;

// Array-shaped analogue of `artik_inlined_return_in_loop_probe`. A
// function body whose for-loop carries a guarded array `return` must
// yield the array literal selected by the first iteration whose
// guard fires at runtime, not the trailing fall-through array.
//
// `outer` is non-trivial so the call to `inner` lifts as a nested
// expression rather than routing through the trivial-body path.
// With `(a=5, b=3)` the first iteration's `a > b` is true, so the
// witness must observe `out[0..2] = [1, 2, 3]`.

function inner(a, b) {
    for (var i = 1; i >= 0; i--) {
        if (a > b) return [1, 2, 3];
        if (a < b) return [4, 5, 6];
    }
    return [99, 99, 99];
}

function outer(a, b) {
    var x[3] = inner(a, b);
    return x;
}

template ProbeInlinedArrayReturnInLoop() {
    signal input a;
    signal input b;
    signal output out[3];
    var y[3] = outer(a, b);
    out[0] <-- y[0];
    out[1] <-- y[1];
    out[2] <-- y[2];
    out[0] === out[0];
    out[1] === out[1];
    out[2] === out[2];
}

component main = ProbeInlinedArrayReturnInLoop();
