pragma circom 2.0.0;

// Simplified BinSum: adds two n-bit binary numbers
// circomlib uses `function` and `while`, which we may not support yet
template BinSum(n) {
    signal input a[n];
    signal input b[n];
    signal output out[n + 1];

    var lin = 0;
    var lout = 0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lin += a[i] * e2;
        lin += b[i] * e2;
        e2 = e2 + e2;
    }

    e2 = 1;
    for (var i = 0; i < n + 1; i++) {
        out[i] <-- (lin >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lout += out[i] * e2;
        e2 = e2 + e2;
    }

    lin === lout;
}

component main {public [a, b]} = BinSum(4);
