pragma circom 2.0.0;

include "circuits/escalarmulany.circom";

// EscalarMulAny with n=254 — the real-world scalar size for EdDSA on BabyJubjub.
// nsegments = (254-1)\148 + 1 = 2, nlastsegment = 254 - 148 = 106.
// Both segments have n >= 2, so SegmentMulAny works correctly.

template EscalarMulAny254Test() {
    signal input e[254];
    signal input p[2];
    signal output out[2];

    component mul = EscalarMulAny(254);
    for (var i = 0; i < 254; i++) {
        mul.e[i] <== e[i];
    }
    mul.p[0] <== p[0];
    mul.p[1] <== p[1];

    out[0] <== mul.out[0];
    out[1] <== mul.out[1];
}

component main = EscalarMulAny254Test();
