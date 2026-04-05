pragma circom 2.0.0;

include "circuits/sign.circom";

// Sign: determine sign of a 254-bit field element.
// Returns 0 if in < (p-1)/2, 1 otherwise.
template SignTest() {
    signal input in[254];
    signal output sign;

    component s = Sign();
    for (var i = 0; i < 254; i++) {
        s.in[i] <== in[i];
    }
    sign <== s.sign;
}

component main = SignTest();
