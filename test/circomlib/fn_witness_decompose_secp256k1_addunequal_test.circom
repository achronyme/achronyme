pragma circom 2.1.5;

include "circuits/ecdsa/bigint_func.circom";
include "circuits/ecdsa/secp256k1_func.circom";

// Compiles `secp256k1_addunequal_func(64, 4, ...)` standalone. The
// function's body has 11 nested helper calls and a 2D return — too
// heavy for a single Artik frame. The decomposition path lifts each
// inner call as its own `CircuitNode::WitnessCall` fragment.
template WitnessDecomposeSecp256k1AddUnequal() {
    signal input x1[4];
    signal input y1[4];
    signal input x2[4];
    signal input y2[4];
    signal output outx[4];
    signal output outy[4];

    var sum[2][100] = secp256k1_addunequal_func(64, 4, x1, y1, x2, y2);

    for (var i = 0; i < 4; i++) {
        outx[i] <-- sum[0][i];
        outx[i] === outx[i];
        outy[i] <-- sum[1][i];
        outy[i] === outy[i];
    }
}

component main = WitnessDecomposeSecp256k1AddUnequal();
