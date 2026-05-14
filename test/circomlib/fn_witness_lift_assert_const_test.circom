pragma circom 2.0.0;

// Assert statements inside a witness function are advisory checks
// (no constraints). When the predicate folds to a compile-time
// constant true, the lift drops it; when it folds to false the lift
// bails (so the gap is surfaced at compile time, not at prove time).
// A runtime predicate folds to a no-op since Artik has no assert
// opcode.

function with_const_assert(x) {
    assert(1 == 1);
    assert((2 > 1) || (5 == 0));
    var t = x + 7;
    return t;
}

template WitnessAssert() {
    signal input in;
    signal output out;
    out <-- with_const_assert(in);
    out === in + 7;
}

component main = WitnessAssert();
