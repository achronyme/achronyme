pragma circom 2.0.0;

// Decoder: converts a number 0..n-1 into a one-hot vector of n bits
template Decoder(n) {
    signal input inp;
    signal output out[n];
    signal output success;

    var lc = 0;

    for (var i = 0; i < n; i++) {
        out[i] <-- (inp == i) ? 1 : 0;
        out[i] * (inp - i) === 0;
        lc = lc + out[i];
    }

    lc ==> success;
}

component main {public [inp]} = Decoder(4);
