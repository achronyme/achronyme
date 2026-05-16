pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Regression: `long_sub(64, 8, x, y)` at the `b[i] + borrow == 2^64`
// boundary. With n = 64 and a limb `y[i] = 2^64 - 1` plus an incoming
// borrow of 1, the comparison `x[i] >= y[i] + borrow[i-1]` has a
// right-hand side of exactly 2^64. Lowering that compare at a fixed
// machine width truncates 2^64 to 0 and inverts the borrow branch,
// producing a difference that wraps in the field. These inputs are a
// real partial-remainder / subtrahend pair from `long_div` over
// 256-bit operands, chosen so the 2^64-boundary borrow path is taken.
template LongSubBorrowBoundary() {
    signal input x[8];
    signal input y[8];
    signal output d[8];
    var diff[100] = long_sub(64, 8, x, y);
    for (var i = 0; i < 8; i++) {
        d[i] <-- diff[i];
        d[i] === d[i];
    }
}

component main = LongSubBorrowBoundary();
