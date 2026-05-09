pragma circom 2.0.2;

include "circuits/ecdsa/ecdsa.circom";

// secp256k1 ECDSA signature verification — vendored from
// 0xPARC/circom-ecdsa (master). Stock test/circuits/test_ecdsa_verify
// configuration (n=64 bits/register, k=4 registers = 256-bit field).
//
// Body: massive bigint emulation chain.
//   - Pubkey-derived check is omitted (NoPubkeyCheck variant) —
//     callers wrap with a preceding `Secp256k1PointOnCurve`.
//   - Body uses bigint mul/mod/sub for u256 arithmetic via 4× u64
//     register decomposition, plus stride-8 windowed scalar mul on
//     secp256k1.
//
// Boss-fight measurement target: this is one of the most expensive
// real-world ZK circuits in production use. The `proven_boolean`
// cross-template lever fires only on Num2Bits → CompConstant chains;
// circom-ecdsa's bigint loop is built from BigSub / BigMod / BigMult
// over register arrays, NOT bit decomposition. Predicting parity
// (or worse) on this circuit is the test of whether the lever
// generalises.
component main {public [r, s, msghash, pubkey]} = ECDSAVerifyNoPubkeyCheck(64, 4);
