pragma circom 2.0.0;

// Phase 1 lift extension: descending for-loops `for (i = N; i >= 0; i--)`
// and `for (i = N; i > 0; i--)` unroll at lift time, iterating the
// body in reverse order. The loop variable still binds in
// `const_locals` so body references fold to PushConst.
//
// `bigint_func.circom`'s `long_div` and `long_gt` from circom-ecdsa
// rely on this shape — the unroll order matters because outer iters
// populate the cells later iters read.

function reverse_acc(x) {
    // sum_{i=4..0} (x + i) == 5*x + 10. Equivalent to ascending,
    // but exercises the descending path explicitly.
    var total = 0;
    for (var i = 4; i >= 0; i--) {
        total = total + x + i;
    }
    return total;
}

template WitnessDescending() {
    signal input in;
    signal output out;
    out <-- reverse_acc(in);
    // 5 iterations × in + (4+3+2+1+0) = 5*in + 10.
    out === 5 * in + 10;
}

component main = WitnessDescending();
