pragma circom 2.0.0;

include "circuits/babyjub.circom";

// BabyAdd: Edwards curve point addition (a=168700, d=168696)
// BabyDbl wraps BabyAdd with same point → doubling
// BabyCheck verifies a point is on the curve
//
// Test: add two known BabyJubjub points, verify result is on-curve.
template BabyJubTest() {
    signal input x1;
    signal input y1;
    signal input x2;
    signal input y2;
    signal output xout;
    signal output yout;

    // Add two points
    component add = BabyAdd();
    add.x1 <== x1;
    add.y1 <== y1;
    add.x2 <== x2;
    add.y2 <== y2;

    xout <== add.xout;
    yout <== add.yout;

    // Verify result is on-curve
    component check = BabyCheck();
    check.x <== add.xout;
    check.y <== add.yout;

    // Also test BabyDbl (double the first point)
    component dbl = BabyDbl();
    dbl.x <== x1;
    dbl.y <== y1;
}

component main = BabyJubTest();
