pragma circom 2.0.0;

// Proves that a value is in range [0, 2^n)
// Uses Num2Bits: if decomposition succeeds, value fits in n bits
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1 = 0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }

    lc1 === in;
}

template RangeProof(n) {
    signal input in;
    signal output out;

    component n2b = Num2Bits(n);
    n2b.in <== in;

    // If we get here, the value fits in n bits → out = 1
    out <== 1;
}

component main {public [in]} = RangeProof(8);
