pragma circom 2.0.2;

include "circuits/ecdsa/secp256k1.circom";

// Regression pin for the lysis walker register-frame ceiling.
//
// `Secp256k1AddUnequal(64, 4)` lifts the circomlib bigint helper
// `secp256k1_addunequal_func`, whose `var sum[2][100]` return flattens
// to a single `WitnessCall` with 200 outputs. The lysis walker frame
// is a `u8` ceiling (255 slots): a `WitnessCall` emitted on the
// classic register-output path needs one frame register per output,
// and a single `WitnessCall` is atomic — the split machinery chains
// templates *between* instructions, never *within* one — so a
// 200-output inline call entered from an already-populated frame
// cannot be rescued by a split and overflows.
//
// Nesting the helper inside an outer fixed-bound loop reproduces that
// populated-frame context minimally (a bare standalone instantiation
// does not — its symbolic indices lack the enclosing loop-iter
// constants and fail an earlier, unrelated walker check instead). The
// walker must route a wide-output `WitnessCall` to the heap-output
// path whenever its outputs would not fit the current frame, so this
// circuit must instantiate through lysis without a frame overflow.
template Secp256k1AddUnequalLoopNested() {
    signal input p[2][4];
    signal input q[2][4];
    signal output r[2][4];

    component add[2];
    for (var i = 0; i < 2; i++) {
        add[i] = Secp256k1AddUnequal(64, 4);
        for (var j = 0; j < 4; j++) {
            add[i].a[0][j] <== p[0][j];
            add[i].a[1][j] <== p[1][j];
            add[i].b[0][j] <== q[0][j];
            add[i].b[1][j] <== q[1][j];
        }
    }
    for (var j = 0; j < 4; j++) {
        r[0][j] <== add[1].out[0][j];
        r[1][j] <== add[1].out[1][j];
    }
}

component main = Secp256k1AddUnequalLoopNested();
