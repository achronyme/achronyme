pragma circom 2.0.0;

include "circuits/escalarmulany.circom";

// Small test: EscalarMulAny with n=4 (enough for 2 segments to test multi-segment).
// With n=4: nsegments = (4-1)\148 + 1 = 1, so only 1 segment.
// With n=149: nsegments = (149-1)\148 + 1 = 2, tests segment chaining.

template EscalarMulAnyTest() {
    signal input e[149];
    signal input p[2];
    signal output out[2];

    component mul = EscalarMulAny(149);
    for (var i = 0; i < 149; i++) {
        mul.e[i] <== e[i];
    }
    mul.p[0] <== p[0];
    mul.p[1] <== p[1];

    out[0] <== mul.out[0];
    out[1] <== mul.out[1];
}

component main = EscalarMulAnyTest();
