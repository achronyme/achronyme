pragma circom 2.1.5;

// Minimal probe for the artik lift's handling of an inlined `return`
// inside an unrolled for-loop when the lift is operating at
// `nested_depth > 0`. `outer(a, b)` introduces a non-trivial body so
// the call to `inner` is lifted as a nested expression rather than
// routed through the trivial-body path; in that context a
// `Stmt::Return` does not emit a halting opcode — it only records
// the captured value. When the body has the shape
//
//   for (var i = ...; ; i--) {
//       if (cond) return X;
//   }
//   return Y;
//
// the lift unrolls past each return and the recorded value is
// overwritten by the trailing return after the loop, so the
// caller observes `Y` regardless of which guard fired at runtime.
//
// With `(a=5, b=3)` the first iteration's `a > b` is true, so the
// expected witness is `out = 1`. If the lift overwrites the
// captured value with the trailing return, the witness comes back
// as `out = 99`.

function inner(a, b) {
    for (var i = 1; i >= 0; i--) {
        if (a > b) return 1;
        if (a < b) return 0;
    }
    return 99;
}

function outer(a, b) {
    var x = inner(a, b);
    var y = x + 0;
    return y;
}

template ProbeInlinedReturnInLoop() {
    signal input a;
    signal input b;
    signal output out;
    out <-- outer(a, b);
    out === out;
}

component main = ProbeInlinedReturnInLoop();
