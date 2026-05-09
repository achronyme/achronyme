pragma circom 2.0.0;

include "circuits/semaphore/semaphore.circom";

// Semaphore protocol main circuit (semaphore-protocol/semaphore v4).
//
// Vendored from packages/circuits/src/semaphore.circom upstream.
// MAX_DEPTH = 32 matches the upstream production parameter.
//
// Body:
//   - LessThan(251) checks the secret scalar is in BabyJubjub
//     subgroup order.
//   - BabyPbk derives the public key (Ax, Ay) from the secret.
//   - Poseidon(2) hashes the pubkey into the identity commitment.
//   - BinaryMerkleRoot(32) verifies membership via 32× Poseidon(2)
//     + 32× MultiMux1 + bit decomposition of the path index.
//   - Poseidon(2) computes the nullifier from (scope, secret).
//   - dummySquare binds the message to the proof.
//
// Public outputs: merkleRoot, nullifier. Public inputs: message, scope.
component main {public [message, scope]} = Semaphore(32);
