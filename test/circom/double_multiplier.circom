pragma circom 2.0.0;

// Tests two levels of component composition:
// DoubleMultiplier uses two Multiplier components in sequence.

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    c <== a * b;
}

template DoubleMultiplier() {
    signal input x;
    signal input y;
    signal input z;
    signal output out;

    component m1 = Multiplier();
    component m2 = Multiplier();

    m1.a <== x;
    m1.b <== y;

    m2.a <== m1.c;
    m2.b <== z;

    m2.c ==> out;
}

component main {public [out]} = DoubleMultiplier();
