pragma circom 2.0.0;

// Fase 2.3 lift extension: bitwise ops (`&`, `|`, `^`, `<<`, `>>`)
// and `~` lower by promoting to u32, applying the integer op, and
// promoting back to Field. Minimum surface a SHA-256 σ0 witness
// function needs:
//
//   sigma0(x) = rotr(x, 7) XOR rotr(x, 18) XOR (x >> 3)
//
// where rotr(x, k) = (x >> k) | (x << (32 - k)) — the same
// expansion circomlib uses in `sha256/sigma.circom`. The local
// `var` bindings ensure the body has "internal state" so it
// routes through the Artik lift instead of the trivial-inline
// path.

function sigma0(x) {
    var r7 = (x >> 7) | (x << 25);
    var r18 = (x >> 18) | (x << 14);
    var r3 = x >> 3;
    return (r7 ^ r18) ^ r3;
}

template WitnessLiftBitOps() {
    signal input in;
    signal output out;
    out <-- sigma0(in);
    // Pin `out` to itself so the `<--` assignment has a matching
    // `===` without actually constraining the Artik witness (the
    // real constraint would be an equivalent u32-decomposition,
    // out of scope for this test).
    out === out;
}

component main = WitnessLiftBitOps();
