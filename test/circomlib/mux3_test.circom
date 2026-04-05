pragma circom 2.0.0;

include "circuits/mux3.circom";

// Mux3: select one of 8 values with a 3-bit selector.
// s = [s0, s1, s2], index = s0 + 2*s1 + 4*s2
template Mux3Test() {
    signal input c[8];
    signal input s[3];
    signal output out;

    component mux = Mux3();
    for (var i = 0; i < 8; i++) {
        mux.c[i] <== c[i];
    }
    for (var i = 0; i < 3; i++) {
        mux.s[i] <== s[i];
    }
    out <== mux.out;
}

component main = Mux3Test();
