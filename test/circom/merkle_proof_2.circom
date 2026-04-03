pragma circom 2.0.0;

// Simplified Merkle proof verifier (depth 2).
// Uses a toy "hash" (a*b + a + b) instead of Poseidon/MiMC
// to test component composition and selection logic.

template ToyHash() {
    signal input a;
    signal input b;
    signal output out;

    // toy hash: a*b + a + b (non-linear, deterministic)
    out <== a * b + a + b;
}

template MerkleLeaf() {
    signal input leaf;
    signal input sibling;
    signal input side;  // 0 = leaf is left, 1 = leaf is right
    signal output root;

    component hash = ToyHash();

    // If side=0: hash(leaf, sibling). If side=1: hash(sibling, leaf).
    // left = leaf + side * (sibling - leaf) = side==0 ? leaf : sibling
    // right = sibling + side * (leaf - sibling) = side==0 ? sibling : leaf
    signal left;
    signal right;
    left <== leaf + side * (sibling - leaf);
    right <== sibling + side * (leaf - sibling);

    hash.a <== left;
    hash.b <== right;
    hash.out ==> root;
}

template MerkleProof2() {
    signal input leaf;
    signal input sibling0;
    signal input side0;
    signal input sibling1;
    signal input side1;
    signal input root;

    component level0 = MerkleLeaf();
    level0.leaf <== leaf;
    level0.sibling <== sibling0;
    level0.side <== side0;

    component level1 = MerkleLeaf();
    level1.leaf <== level0.root;
    level1.sibling <== sibling1;
    level1.side <== side1;

    // Verify computed root matches expected root
    level1.root === root;
}

component main {public [root]} = MerkleProof2();
