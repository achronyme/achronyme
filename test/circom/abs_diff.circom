pragma circom 2.0.0;

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

template LessThan(n) {
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n + 1);

    n2b.in <== in[0] + (1 << n) - in[1];
    out <== 1 - n2b.out[n];
}

// Absolute difference: |a - b|
template AbsDiff(n) {
    signal input a;
    signal input b;
    signal output out;

    component lt = LessThan(n);
    lt.in[0] <== a;
    lt.in[1] <== b;

    // if a < b: out = b - a, else: out = a - b
    // out = lt.out * (b - a) + (1 - lt.out) * (a - b)
    // out = lt.out * (b - a - a + b) + a - b
    // out = lt.out * (2b - 2a) + a - b
    out <== lt.out * (2 * b - 2 * a) + a - b;
}

component main {public [a, b]} = AbsDiff(8);
