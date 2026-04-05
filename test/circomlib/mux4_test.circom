pragma circom 2.0.0;

include "circuits/mux4.circom";

// Mux4: select one of 16 values with a 4-bit selector.
template Mux4Test() {
    signal input c[16];
    signal input s[4];
    signal output out;

    component mux = Mux4();
    for (var i = 0; i < 16; i++) {
        mux.c[i] <== c[i];
    }
    for (var i = 0; i < 4; i++) {
        mux.s[i] <== s[i];
    }
    out <== mux.out;
}

component main = Mux4Test();
