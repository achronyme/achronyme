pragma circom 2.0.0;

template Switcher() {
    signal input sel;
    signal input L;
    signal input R;
    signal output outL;
    signal output outR;

    signal aux;

    aux <== (R - L) * sel;
    outL <== aux + L;
    outR <== -aux + R;
}

component main {public [sel, L, R]} = Switcher();
