pragma circom 2.0.0;

include "circuits/tornado/withdraw.circom";

// Tornado Cash Withdraw circuit (mainnet, levels=20).
//
// Vendored from tornadocash/tornado-core (master) and ported to
// circom 2.0 syntax (see circuits/tornado/withdraw.circom and
// merkleTree.circom for porting notes).
//
// Mainnet Tornado Cash uses tree depth 20 (≈1M leaves capacity).
// Body: CommitmentHasher (2× Pedersen + 2× Num2Bits) +
// MerkleTreeChecker (20× MiMCSponge + 20× DualMux) + 4 binding squares.
component main {public [root, nullifierHash, recipient, relayer, fee, refund]} = Withdraw(20);
