pragma circom 2.0.0;

// Fase 2.1: the lift now unrolls compile-time-bounded `for` loops.
// The loop variable becomes a ConstInt in the lift state and every
// occurrence inside the body folds to `PushConst`. Step `i++` and
// `i += 1` are both accepted, as are `i < N` and `i <= N`.
//
// Body surface: var decls, compound assigns (+=, -=, *=, /=),
// reassignments, binary ops, `return`.

function triangle_sum(x) {
    var total = 0;
    for (var i = 0; i < 4; i++) {
        total += x * i;
    }
    return total;
}

template WitnessLiftLoop() {
    signal input in;
    signal output out;
    out <-- triangle_sum(in);
    // Re-derive the expected value inline to constrain the hint.
    // Sum_{i=0..3} i * in == 6 * in.
    out === 6 * in;
}

component main = WitnessLiftLoop();
