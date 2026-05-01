pragma circom 2.0.0;

include "circuits/sha256/sha256.circom";

// Thin wrapper: 8-bit message → 256-bit SHA-256 digest.
// Smallest legal SHA-256 input — exercises the round + finalizer with
// minimal frontend wiring overhead. CI-default companion to
// sha256_test.circom (Sha256(64)).
component main = Sha256(8);
