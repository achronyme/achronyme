pragma circom 2.0.0;

include "circuits/eddsaposeidon.circom";

// Library-mode wrapper for EdDSAPoseidonVerifier.
//
// EdDSAPoseidonVerifier itself has seven scalar inputs and no
// output signal — it enforces constraints internally and relies
// on `component main` to anchor them. Library-mode imports need
// at least one output to satisfy the `T(...)(...)` call pattern,
// so this wrapper forwards every input and exposes `dummy` as
// a pass-through of `enabled`.
//
// Separate from `eddsaposeidon_test.circom` because that file
// carries a `component main` declaration which would force the
// library-mode compilation path through the full-circuit frontend.

template EdDSAPoseidonLib() {
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

    dummy <== enabled;
}
