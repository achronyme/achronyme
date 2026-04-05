pragma circom 2.0.0;

include "circuits/pedersen.circom";

// Pedersen(8): hash 8 bits using BabyJubjub curve.
// Small n to keep constraint count manageable for testing.
// Uses: Window4, MontgomeryAdd/Double, Edwards2Montgomery,
// Montgomery2Edwards, BabyAdd.
template PedersenTest() {
    signal input in[8];
    signal output out[2];

    component ped = Pedersen(8);
    for (var i = 0; i < 8; i++) {
        ped.in[i] <== in[i];
    }
    out[0] <== ped.out[0];
    out[1] <== ped.out[1];
}

component main = PedersenTest();
