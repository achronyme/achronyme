pragma circom 2.0.0;

include "circuits/pointbits.circom";

// 256-bit packed representation → Edwards curve point.
// Inverse of Point2Bits_Strict. Distinct surface from that test:
//   - Witness hint via `<--` (sqrt computed at witness time, free
//     assignment to the circuit).
//   - Conditional negation in witness logic (`if in[255] == 1, x = -x`).
//   - BabyCheck enforces a·x² + y² === 1 + d·x²·y² as a quadratic
//     constraint.
//   - AliasCheck on both X bits AND the input bit array.
// Mark `in` as public to pin the soundness invariant: a sound R1CS
// optimiser must NOT substitute away constraints that bind public
// inputs. Without this annotation the input bits are private (circom
// 2.x default), and constraints like `in[254] === 0` can be lawfully
// substituted away — making post-O1 forgery of those wires a no-op
// rather than a soundness probe.
component main { public [in] } = Bits2Point_Strict();
