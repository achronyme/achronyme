pragma circom 2.0.0;

include "circuits/sha256/sha256.circom";

// Thin wrapper: 32-bit message → 256-bit SHA-256 digest.
// Mid-size variant: still one 512-bit block but more frontend
// Num2Bits wiring than (8)/(16). Companion to sha256_test.circom.
component main = Sha256(32);
