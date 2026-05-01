pragma circom 2.0.0;

include "circuits/mux2.circom";

// Mux2: select one of 4 values with a 2-bit selector.
// s = [s0, s1], index = s0 + 2*s1
template Mux2Test() {
    signal input c[4];
    signal input s[2];
    signal output out;

    component mux = Mux2();
    for (var i = 0; i < 4; i++) {
        mux.c[i] <== c[i];
    }
    for (var i = 0; i < 2; i++) {
        mux.s[i] <== s[i];
    }
    out <== mux.out;
}

component main = Mux2Test();
