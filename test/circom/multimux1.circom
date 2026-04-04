pragma circom 2.0.0;

template MultiMux1(n) {
    signal input c[n][2];
    signal input s;
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== (c[i][1] - c[i][0]) * s + c[i][0];
    }
}

template Mux1() {
    var i;
    signal input c[2];
    signal input s;
    signal output out;

    component mux = MultiMux1(1);

    for (i = 0; i < 2; i++) {
        mux.c[0][i] <== c[i];
    }

    s ==> mux.s;

    mux.out[0] ==> out;
}

component main {public [c, s]} = Mux1();
