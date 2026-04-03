pragma circom 2.0.0;

template OR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b - a * b;
}

component main {public [a, b]} = OR();
