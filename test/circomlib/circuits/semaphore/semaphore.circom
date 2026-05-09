pragma circom 2.0.0;

include "../babyjub.circom";
include "../poseidon.circom";
include "binary-merkle-root.circom";
include "../comparators.circom";

// Semaphore protocol main circuit — vendored from
// semaphore-protocol/semaphore (packages/circuits/src/semaphore.circom).
// Ported from circom 2.1.5 to 2.0 syntax: split multi-signal
// declarations, replaced anonymous component invocations with
// explicit `component`/`signal` pairs.
//
// Pipeline:
//   1. Validate `secret` is below the BabyJubjub subgroup order.
//   2. Derive the BabyJubjub public key (Ax, Ay) from `secret`.
//   3. Hash the public key into the Semaphore identity commitment.
//   4. Verify the commitment is part of a binary merkle group at
//      `merkleProofIndex` via `merkleProofSiblings`.
//   5. Emit a nullifier from `(scope, secret)` to prevent replay.
//   6. Bind `message` to the proof via a dummy square constraint.
template Semaphore(MAX_DEPTH) {
    signal input secret;
    signal input merkleProofLength;
    signal input merkleProofIndex;
    signal input merkleProofSiblings[MAX_DEPTH];
    signal input message;
    signal input scope;

    signal output merkleRoot;
    signal output nullifier;

    var l = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    component isLessThan = LessThan(251);
    isLessThan.in[0] <== secret;
    isLessThan.in[1] <== l;
    isLessThan.out === 1;

    component pbk = BabyPbk();
    pbk.in <== secret;

    component idcommit = Poseidon(2);
    idcommit.inputs[0] <== pbk.Ax;
    idcommit.inputs[1] <== pbk.Ay;

    component bmr = BinaryMerkleRoot(MAX_DEPTH);
    bmr.leaf <== idcommit.out;
    bmr.depth <== merkleProofLength;
    bmr.index <== merkleProofIndex;
    for (var i = 0; i < MAX_DEPTH; i++) {
        bmr.siblings[i] <== merkleProofSiblings[i];
    }
    merkleRoot <== bmr.out;

    component nullifierH = Poseidon(2);
    nullifierH.inputs[0] <== scope;
    nullifierH.inputs[1] <== secret;
    nullifier <== nullifierH.out;

    signal dummySquare;
    dummySquare <== message * message;
}
