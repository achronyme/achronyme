pragma circom 2.0.0;

include "circuits/sha256/sha256.circom";

// Thin wrapper: 64-bit message → 256-bit SHA-256 digest.
// One block's worth of padding so the circuit exercises the full
// sha256compression round + finalizer without blowing constraint count.
component main = Sha256(64);
