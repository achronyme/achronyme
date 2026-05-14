pragma circom 2.1.5;

// Named-array analogue of the array-literal and scalar nested-return
// probes. A function whose for-loop body carries guarded
// `return <ident>` statements over locally-declared arrays must
// yield the array selected by the iteration that actually fires at
// runtime, not the trailing fall-through array.
//
// The dim `[3]` is a literal so the lift's pre-scan can fold it
// without needing parameter substitution; a follow-up probe should
// cover dims that depend on call-site param consts (e.g. `var ret[k]`
// where `k` is a function parameter).
//
// `outer` wraps the call so it lifts as a nested expression rather
// than routing through the trivial-body path. With `(a=5, b=3)` the
// first iteration's `a > b` is true so the witness must observe
// `out = [1, 2, 3]`.

function inner(a, b) {
    for (var i = 1; i >= 0; i--) {
        if (a > b) {
            var hit[3];
            hit[0] = 1;
            hit[1] = 2;
            hit[2] = 3;
            return hit;
        }
        if (a < b) {
            var lo[3];
            lo[0] = 4;
            lo[1] = 5;
            lo[2] = 6;
            return lo;
        }
    }
    var fallback[3];
    fallback[0] = 99;
    fallback[1] = 99;
    fallback[2] = 99;
    return fallback;
}

function outer(a, b) {
    var x[3] = inner(a, b);
    return x;
}

template ProbeInlinedNamedArrayReturnInLoop() {
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

component main = ProbeInlinedNamedArrayReturnInLoop();
