pragma circom 2.0.0;

include "circuits/sha256/sha256.circom";

// Thin wrapper: 16-bit message → 256-bit SHA-256 digest.
// Intermediate frontend-wiring scale; same single 512-bit block as
// the (8) and (32) variants. Companion to sha256_test.circom.
component main = Sha256(16);
