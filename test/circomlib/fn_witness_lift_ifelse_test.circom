pragma circom 2.0.0;

// Fase 2.1: compile-time-folded `if / else` inside an unrolled loop.
// The condition `i == 0` folds to `1` on the first iteration, `0`
// thereafter, so the then/else branches are pre-selected at lift
// time — no JumpIf is emitted. Runtime conditions still fall back
// to E212.
//
// Semantic: `result = x + 1 + x + x + x + x` = 5x + 1 when N=5.

function piecewise(x) {
    var acc = 0;
    for (var i = 0; i < 5; i++) {
        if (i == 0) {
            acc = x + 1;
        } else {
            acc = acc + x;
        }
    }
    return acc;
}

template WitnessLiftIfElse() {
    signal input in;
    signal output out;
    out <-- piecewise(in);
    // 5 * in + 1
    out === 5 * in + 1;
}

component main = WitnessLiftIfElse();
