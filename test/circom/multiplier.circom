pragma circom 2.0.0;

// Classic intro circuit: prove knowledge of factors
template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

component main {public [c]} = Multiplier();
