pragma circom 2.0.0;

include "circuits/multiplexer.circom";

// Multiplexer(2, 3): select one of 3 inputs (each 2 elements wide).
// Uses Decoder + EscalarProduct internally.
template MultiplexerTest() {
    signal input inp[3][2];
    signal input sel;
    signal output out[2];

    component mux = Multiplexer(2, 3);
    for (var i = 0; i < 3; i++) {
        for (var j = 0; j < 2; j++) {
            mux.inp[i][j] <== inp[i][j];
        }
    }
    mux.sel <== sel;
    out[0] <== mux.out[0];
    out[1] <== mux.out[1];
}

component main = MultiplexerTest();
