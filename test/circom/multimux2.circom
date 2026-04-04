pragma circom 2.0.0;

template MultiMux2(n) {
    signal input c[n][4];
    signal input s[2];
    signal output out[n];

    signal a10[n];
    signal a1[n];
    signal a0[n];
    signal a20[n];

    for (var i = 0; i < n; i++) {
        a10[i] <== (c[i][3] - c[i][2] - c[i][1] + c[i][0]) * s[1];
        a1[i] <== a10[i] + c[i][1] - c[i][0];
        a0[i] <== (c[i][2] - c[i][0]) * s[1];
        a20[i] <== a0[i] + c[i][0];
        out[i] <== a1[i] * s[0] + a20[i];
    }
}

template Mux2() {
    var i;
    signal input c[4];
    signal input s[2];
    signal output out;

    component mux = MultiMux2(1);

    for (i = 0; i < 4; i++) {
        mux.c[0][i] <== c[i];
    }

    mux.s[0] <== s[0];
    mux.s[1] <== s[1];

    out <== mux.out[0];
}

component main {public [c, s]} = Mux2();
