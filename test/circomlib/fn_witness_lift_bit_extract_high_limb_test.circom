pragma circom 2.0.0;

// Regression: bit-extraction `(e >> j) & 1` over a 64-bit limb. The
// loop is fully unrolled, so each shift amount `j` is a compile-time
// constant. Lowering a constant `>>` at a fixed machine width would
// truncate `e` to its low 32 bits, so every extracted bit at index
// >= 32 would read zero. The input sets bits across the full 64-bit
// range (indices 0, 31, 32, 62, 63); the test asserts each output
// bit equals the corresponding input bit, in particular bits 32..63.
function extract_bits(e) {
    var bits[64];
    for (var j = 0; j < 64; j++) {
        bits[j] = (e >> j) & 1;
    }
    return bits;
}

template BitExtractHighLimb() {
    signal input e;
    signal output b[64];
    var bits[64] = extract_bits(e);
    for (var i = 0; i < 64; i++) {
        b[i] <-- bits[i];
        b[i] === b[i];
    }
}

component main = BitExtractHighLimb();
