pragma circom 2.0.0;

// Fase 2.1: the lift inlines nested function calls into the outer
// function's Artik program. The callee's body walks into the same
// builder with its params bound to argument-evaluated registers,
// its locals / arrays / const_locals scoped out, and its `return`
// captured via `nested_result` instead of emitting WriteWitness.
//
//   compute(in) = helper(in) + helper(in + 1)
//               = (2*in + 1) + (2*(in+1) + 1)
//               = 4*in + 4

function helper(y) {
    var tmp = y * 2;
    return tmp + 1;
}

function compute(x) {
    var a = helper(x);
    return a + helper(x + 1);
}

template WitnessLiftNested() {
    signal input in;
    signal output out;
    out <-- compute(in);
    out === 4 * in + 4;
}

component main = WitnessLiftNested();
