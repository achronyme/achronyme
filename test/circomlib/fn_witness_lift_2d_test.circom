pragma circom 2.0.0;

// Phase 1 lift extension: `var arr[N][M]` is allocated as a flat
// row-major Artik field array of `N*M` cells. Index access
// `arr[i][j]` composes to the flat index `i*cols + j` at lift
// time. Both compile-time and runtime indices are supported; the
// runtime path lifts each index to a U32 register and combines via
// IBin Add/Mul.
//
// The function takes a signal-valued argument so the call routes
// through the witness lift (compile-time-only args would const-eval
// the body).

function fill_2d(x) {
    var arr[3][4];
    for (var i = 0; i < 3; i++) {
        for (var j = 0; j < 4; j++) {
            arr[i][j] = x + i * 4 + j;
        }
    }
    return arr[2][3];
}

template Witness2D() {
    signal input in;
    signal output out;
    out <-- fill_2d(in);
    // arr[2][3] = in + 2*4 + 3 = in + 11
    out === in + 11;
}

component main = Witness2D();
