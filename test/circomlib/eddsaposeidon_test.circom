pragma circom 2.0.0;

include "circuits/eddsaposeidon.circom";

// Thin wrapper to set component main for EdDSAPoseidonVerifier.
// All inputs are public for testing (the real circuit would have
// private S, R8x, R8y, M and public enabled, Ax, Ay).

template EdDSAPoseidonTest() {
    signal input enabled;
    signal input Ax;
    signal input Ay;
    signal input S;
    signal input R8x;
    signal input R8y;
    signal input M;
    signal output dummy;

    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== enabled;
    verifier.Ax <== Ax;
    verifier.Ay <== Ay;
    verifier.S <== S;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.M <== M;

    // Dummy output to anchor the circuit
    dummy <== enabled;
}

component main = EdDSAPoseidonTest();
