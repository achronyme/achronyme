pragma circom 2.0.0;

include "circuits/escalarmulfix.circom";

// EscalarMulFix(3, BASE8): scalar multiplication of a 3-bit scalar
// against a fixed base point on BabyJubjub.
//
// Small instance (3 bits = 1 window) to test:
// - WindowMulFix with MultiMux3, MontgomeryDouble, MontgomeryAdd
// - SegmentMulFix orchestration
// - Edwards ↔ Montgomery coordinate conversion
// - Component arrays, 2D signal wiring
//
// Full BabyPbk would be EscalarMulFix(253, BASE8) ≈ 4000+ constraints.

template EscalarMulFixTest() {
    signal input e[3]; // 3-bit scalar
    signal output out[2]; // resulting point (x, y)

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component mulFix = EscalarMulFix(3, BASE8);
    for (var i = 0; i < 3; i++) {
        mulFix.e[i] <== e[i];
    }
    out[0] <== mulFix.out[0];
    out[1] <== mulFix.out[1];
}

component main = EscalarMulFixTest();
