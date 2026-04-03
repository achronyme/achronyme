pragma circom 2.0.0;

template NOT() {
    signal input in;
    signal output out;

    out <== 1 + in - 2 * in;
}

component main {public [in]} = NOT();
