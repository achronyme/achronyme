pragma circom 2.0.0;

// MultiMux4: 4-bit selector, selects among 16 values per channel
template MultiMux4(n) {
    signal input c[n][16];
    signal input s[4];
    signal output out[n];

    signal a3210[n];
    signal a321[n];
    signal a320[n];
    signal a310[n];
    signal a31[n];
    signal a30[n];
    signal a3[n];
    signal a210[n];
    signal a21[n];
    signal a20[n];
    signal a10[n];
    signal a1[n];
    signal a0[n];
    signal a[n];

    for (var i = 0; i < n; i++) {
        // Layer 3 (s[3])
        a3210[i] <== (c[i][15] - c[i][14] - c[i][13] + c[i][12] - c[i][11] + c[i][10] + c[i][9] - c[i][8]
                     - c[i][7] + c[i][6] + c[i][5] - c[i][4] + c[i][3] - c[i][2] - c[i][1] + c[i][0]) * s[3];
        a321[i] <== a3210[i] + c[i][13] - c[i][12] - c[i][9] + c[i][8] - c[i][5] + c[i][4] + c[i][1] - c[i][0];
        a320[i] <== (c[i][14] - c[i][12] - c[i][10] + c[i][8] + c[i][6] - c[i][4] - c[i][2] + c[i][0]) * s[3];
        a310[i] <== (c[i][11] - c[i][10] - c[i][9] + c[i][8] - c[i][3] + c[i][2] + c[i][1] - c[i][0]) * s[3];
        a31[i] <== a310[i] + c[i][9] - c[i][8] - c[i][1] + c[i][0];
        a30[i] <== (c[i][10] - c[i][8] - c[i][2] + c[i][0]) * s[3];
        a3[i] <== (c[i][8] - c[i][0]) * s[3];

        // Layer 2 (s[2])
        a210[i] <== a321[i] * s[2];
        a21[i] <== a210[i] + a31[i];
        a20[i] <== a320[i] * s[2];
        a10[i] <== a30[i] * s[2];
        a1[i] <== a10[i] + a3[i] + c[i][0];
        a0[i] <== a20[i] + a1[i];

        // Layer 1 (s[1])
        a[i] <== a21[i] * s[1];

        // Output (s[0])
        out[i] <== (a[i] + a0[i]) * s[0] + a1[i];
    }
}

template Mux4() {
    var i;
    signal input c[16];
    signal input s[4];
    signal output out;

    component mux = MultiMux4(1);

    for (i = 0; i < 16; i++) {
        mux.c[0][i] <== c[i];
    }

    for (i = 0; i < 4; i++) {
        mux.s[i] <== s[i];
    }

    out <== mux.out[0];
}

component main {public [c, s]} = Mux4();
