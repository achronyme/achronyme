pragma circom 2.0.0;

function nbits(a) {
    var n = 1;
    var r = 0;
    while (n - 1 < a) {
        r++;
        n *= 2;
    }
    return r;
}

// Uses function result to determine output array size.
// nbits(255) = 8, so out has 8 elements.
template NbitsDecompose(maxval) {
    var nb = nbits(maxval);
    signal input in;
    signal output out[nb];

    var lc1 = 0;
    var e2 = 1;
    for (var i = 0; i < nb; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * e2;
        e2 = e2 + e2;
    }

    lc1 === in;
}

component main {public [in]} = NbitsDecompose(255);
