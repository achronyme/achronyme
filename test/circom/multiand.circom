pragma circom 2.0.0;

// Simplified MultiAND: computes AND of 4 binary inputs
// The real circomlib version is recursive with component arrays.
// This is a flat version to test the pattern.
template MultiAND4() {
    signal input in[4];
    signal output out;

    signal mid1;
    signal mid2;

    mid1 <== in[0] * in[1];
    mid2 <== in[2] * in[3];
    out <== mid1 * mid2;
}

component main {public [in]} = MultiAND4();
