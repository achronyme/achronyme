pragma circom 2.0.0;

include "circuits/ecdsa/bigint_func.circom";

// Like ModInvProbe, but the arrays reaching `mod_inv` are intermediate
// signals (linear combinations of the inputs). The R1CS optimizer can
// substitute such wires away while the lifted witness program still
// reads them directly by wire index — the shape that distinguishes a
// replayed witness from the fused one.
template ModInvIntermediateProbe() {
    signal input a[2];
    signal input p[2];
    signal am[2];
    signal pm[2];
    am[0] <== a[0] + a[1];
    am[1] <== a[1] + 1;
    pm[0] <== p[0] + 2;
    pm[1] <== p[1] + 1;
    signal output q[100];
    var r[100] = mod_inv(32, 2, am, pm);
    for (var i = 0; i < 100; i++) {
        q[i] <-- r[i];
        q[i] === q[i];
    }
}

component main = ModInvIntermediateProbe();
