pragma circom 2.0.0;

include "circuits/sha256/sha256_2.circom";

// 2-input SHA-256 variant: hashes two 216-bit field elements.
// One Sha256compression invocation + 2× Num2Bits(216) + Bits2Num(216).
// Distinct shape from the parametric Sha256(N): hardcoded length
// encoding via raw `inp[i] <== const` assignments instead of a padding
// loop. Useful for surfacing gaps that the parametric path masks.
component main {public [a, b]} = Sha256_2();
