pragma circom 2.0.0;

include "../poseidon.circom";
include "../mux1.circom";
include "../comparators.circom";

// BinaryMerkleRoot — vendored from privacy-scaling-explorations/zk-kit.circom
// (packages/binary-merkle-root). Ported from circom 2.1 to 2.0 by
// expanding multi-signal declarations, replacing anonymous components
// with explicit declarations, and accumulating `root` as a signal chain
// instead of a `var`.
//
// Computes the merkle root of a binary tree from a leaf, a dynamic
// depth, an index, and sibling nodes. Static MAX_DEPTH bounds the
// circuit size; runtime `depth` ≤ MAX_DEPTH selects how much of the
// chain contributes to the final root.
template BinaryMerkleRoot(MAX_DEPTH) {
    signal input leaf;
    signal input depth;
    signal input index;
    signal input siblings[MAX_DEPTH];

    signal output out;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leaf;

    signal roots[MAX_DEPTH];

    component indexBits = Num2Bits(MAX_DEPTH);
    indexBits.in <== index;

    signal rootAcc[MAX_DEPTH + 1];
    rootAcc[0] <== 0;

    component isDepth[MAX_DEPTH];
    component muxes[MAX_DEPTH];
    component hashers[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        isDepth[i] = IsEqual();
        isDepth[i].in[0] <== depth;
        isDepth[i].in[1] <== i;

        roots[i] <== isDepth[i].out * nodes[i];
        rootAcc[i + 1] <== rootAcc[i] + roots[i];

        muxes[i] = MultiMux1(2);
        muxes[i].c[0][0] <== nodes[i];
        muxes[i].c[0][1] <== siblings[i];
        muxes[i].c[1][0] <== siblings[i];
        muxes[i].c[1][1] <== nodes[i];
        muxes[i].s <== indexBits.out[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];
        nodes[i + 1] <== hashers[i].out;
    }

    component finalIsDepth = IsEqual();
    finalIsDepth.in[0] <== depth;
    finalIsDepth.in[1] <== MAX_DEPTH;

    out <== rootAcc[MAX_DEPTH] + finalIsDepth.out * nodes[MAX_DEPTH];
}
