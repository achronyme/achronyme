pragma circom 2.0.0;

include "circuits/switcher.circom";

// Switcher: conditional swap of two values.
// sel=0 → (outL, outR) = (L, R)
// sel=1 → (outL, outR) = (R, L)
template SwitcherTest() {
    signal input sel;
    signal input L;
    signal input R;
    signal output outL;
    signal output outR;

    component sw = Switcher();
    sw.sel <== sel;
    sw.L <== L;
    sw.R <== R;
    outL <== sw.outL;
    outR <== sw.outR;
}

component main = SwitcherTest();
