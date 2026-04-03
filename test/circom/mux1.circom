pragma circom 2.0.0;

template Mux1() {
    signal input c[2];
    signal input s;
    signal output out;

    out <== (c[1] - c[0]) * s + c[0];
}

component main {public [c, s]} = Mux1();
