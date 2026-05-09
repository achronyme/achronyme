pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Phase 3 width-stress fixture: lift `prod(64, 4, a, b)` at the
// nominal bigint call-graph config. The `prod_val[i]` accumulator
// can reach ~2^130 (4 products of 64-bit operands), exceeding U128.
// The lift relies on field-level FShr / FAnd to extract bit ranges
// 0-63, 64-127, and 128-191 from the canonical representative
// without losing the high bits to a U64 / U128 demote.
template ProdK4N64() {
    signal input a[4];
    signal input b[4];
    signal output out[8];
    var p[100] = prod(64, 4, a, b);
    out[0] <-- p[0];
    out[1] <-- p[1];
    out[2] <-- p[2];
    out[3] <-- p[3];
    out[4] <-- p[4];
    out[5] <-- p[5];
    out[6] <-- p[6];
    out[7] <-- p[7];
    out[0] === out[0];
    out[1] === out[1];
    out[2] === out[2];
    out[3] === out[3];
    out[4] === out[4];
    out[5] === out[5];
    out[6] === out[6];
    out[7] === out[7];
}

component main = ProdK4N64();
