pragma circom 2.0.0;

include "circuits/aliascheck.circom";

// AliasCheck: verifies that the 254-bit input is not an alias
// (not >= field modulus). Uses CompConstant(-1).
template AliasCheckTest() {
    signal input in[254];

    component ac = AliasCheck();
    for (var i = 0; i < 254; i++) {
        ac.in[i] <== in[i];
    }
}

component main = AliasCheckTest();
