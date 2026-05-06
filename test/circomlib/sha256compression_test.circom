pragma circom 2.0.0;

include "circuits/sha256/sha256compression.circom";

// Wrapper: one Sha256compression block.
// Exposes hin[256] + inp[512] inputs and out[256] outputs to the
// `main` component so the constraint system contains exactly one
// Sha256compression instance with no surrounding padding /
// length-encoding / output-unpacking logic.
//
// Used by the per-block constraint differential vs circom --O2:
// `Sha256(64) - Sha256compression(1)` isolates the cost of the
// outer Sha256 wrapper (padding + length encoding) from the cost
// of one round-block.
component main = Sha256compression();
