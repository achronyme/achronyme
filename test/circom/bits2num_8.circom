pragma circom 2.0.0;

template Bits2Num(n) {
    signal input in[n];
    signal output out;
    var lc1 = 0;

    var e2 = 1;
    for (var i = 0; i < n; i++) {
        lc1 += in[i] * e2;
        e2 = e2 + e2;
    }

    lc1 ==> out;
}

component main {public [in]} = Bits2Num(8);
