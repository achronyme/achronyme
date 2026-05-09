pragma circom 2.0.0;

include "circuits/pointbits.circom";

// Edwards curve point → 256-bit packed representation.
// Exercises: 2× Num2Bits(254) + 2× AliasCheck + CompConstant against
// the half-field-order constant + sign-bit packing. Distinct from
// EscalarMul / EdDSA paths covered by the existing benchmark.
component main = Point2Bits_Strict();
