pragma circom 2.0.0;

include "./circuits/poseidon.circom";

// Poseidon hash arity 16: 16-input → 1-output BN254 hash.
// Probes how the proven_boolean cross-template lever scales with
// hash arity, and how the M[t][t] constant-matrix multiplication +
// (16*nRoundsF + nRoundsP)-element round-constant vector compile
// at larger t.
component main {public [inputs]} = Poseidon(16);
