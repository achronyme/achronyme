pragma circom 2.0.0;

template NOR() {
    signal input a;
    signal input b;
    signal output out;

    out <== a * b + 1 - a - b;
}

component main {public [a, b]} = NOR();
