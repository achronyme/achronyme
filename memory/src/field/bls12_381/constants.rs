/// The prime modulus p (BLS12-381 Fr)
/// p = 52435875175126190479447740508185965837690552500527637822603658699938581184513
pub(super) const MODULUS: [u64; 4] = [
    0xffffffff00000001,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];

/// R = 2^256 mod p (Montgomery constant)
pub(super) const R: [u64; 4] = [
    0x00000001fffffffe,
    0x5884b7fa00034802,
    0x998c4fefecbc4ff5,
    0x1824b159acc5056f,
];

/// R^2 = (2^256)^2 mod p (for converting to Montgomery form)
pub(super) const R2: [u64; 4] = [
    0xc999e990f3f29c6d,
    0x2b6cedcb87925c23,
    0x05d314967254398f,
    0x0748d9d99f59ff11,
];

/// Montgomery inverse: -p^{-1} mod 2^64
pub(super) const INV: u64 = 0xfffffffeffffffff;

/// p - 2 (for Fermat's little theorem inversion)
pub(super) const P_MINUS_2: [u64; 4] = [
    0xfffffffeffffffff,
    0x53bda402fffe5bfe,
    0x3339d80809a1d805,
    0x73eda753299d7d48,
];
