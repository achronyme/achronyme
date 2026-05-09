pragma circom 2.0.0;

include "./circuits/poseidon.circom";

// Poseidon hash arity 3: 3-input → 1-output BN254 hash.
// Probes how the proven_boolean cross-template lever scales with
// hash arity, and how the M[t][t] constant-matrix multiplication +
// (3*nRoundsF + nRoundsP)-element round-constant vector compile
// at larger t.
component main {public [inputs]} = Poseidon(3);
