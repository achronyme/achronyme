pragma circom 2.0.0;

include "circuits/binsum.circom";

// BinSum(4, 2): sum two 4-bit binary numbers.
// Output has nbits((2^4-1)*2) = nbits(30) = 5 bits.
template BinSumTest() {
    signal input a[4];
    signal input b[4];
    signal output out[5];

    component bs = BinSum(4, 2);
    for (var i = 0; i < 4; i++) {
        bs.in[0][i] <== a[i];
        bs.in[1][i] <== b[i];
    }
    for (var i = 0; i < 5; i++) {
        out[i] <== bs.out[i];
    }
}

component main = BinSumTest();
