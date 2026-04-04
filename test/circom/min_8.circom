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

template IsZero() {
    signal input in;
    signal output out;

    signal inv;

    inv <-- in != 0 ? 1/in : 0;

    out <== -in * inv + 1;
    in * out === 0;
}

template LessThan(n) {
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n + 1);

    n2b.in <== in[0] + (1 << n) - in[1];
    out <== 1 - n2b.out[n];
}

template Min(n) {
    signal input a;
    signal input b;
    signal output out;

    component lt = LessThan(n);
    lt.in[0] <== a;
    lt.in[1] <== b;

    // out = lt.out * a + (1 - lt.out) * b
    //     = lt.out * (a - b) + b
    out <== lt.out * (a - b) + b;
}

component main {public [a, b]} = Min(8);
