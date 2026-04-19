pragma circom 2.0.0;

// Fase 2.4 mux extension: nested function calls are safe to appear
// on the RHS of assignments inside both arms of a runtime if/else.
// Each call inlines into the Artik program at nested_depth > 0, so
// the nested `return` is captured via `nested_result` (not a
// WriteWitness) — both arms emit their call's instructions, and
// the mux picks the taken arm's result.
//
//     select_scaled(cond, x) = cond ? triple(x) : quadruple(x)
//                            = 3x (cond=1) | 4x (cond=0)

function triple(a) {
    var r = a + a;
    return r + a;
}

function quadruple(a) {
    var r = a + a;
    return r + r;
}

function select_scaled(cond, x) {
    var out;
    if (cond) {
        out = triple(x);
    } else {
        out = quadruple(x);
    }
    return out;
}

template WitnessLiftMuxCalls() {
    signal input cond;
    signal input x;
    signal output out;
    out <-- select_scaled(cond, x);
    cond * (cond - 1) === 0;
    out === cond * (3 * x) + (1 - cond) * (4 * x);
}

component main = WitnessLiftMuxCalls();
