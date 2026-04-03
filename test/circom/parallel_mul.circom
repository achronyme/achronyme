pragma circom 2.0.0;

// Simple multiplier template
template Multiplier() {
    signal input a;
    signal input b;
    signal output out;
    out <== a * b;
}

// Uses a component array: component muls[n]
template ParallelMul(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n];

    component muls[n];

    for (var i = 0; i < n; i++) {
        muls[i] = Multiplier();
        muls[i].a <== a[i];
        muls[i].b <== b[i];
        out[i] <== muls[i].out;
    }
}

component main {public [a, b]} = ParallelMul(3);
