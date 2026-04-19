pragma circom 2.0.0;

// Minimal SHA-256-shaped probe: a one-shot constant-table
// lookup with runtime index. Exercises `var k[64] = [lit,...]`
// inside a function body + `return k[i]` with a runtime `i`.
// If this passes, circomlib's `sha256K(i)` should lift.

function sha256K_tiny(i) {
    var k[4] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5];
    return k[i];
}

template WitnessLiftSha256K() {
    signal input idx;
    signal output out;
    out <-- sha256K_tiny(idx);
    // Caller owns the correctness constraint; the witness is
    // what we want to measure here.
    out === out;
}

component main = WitnessLiftSha256K();
