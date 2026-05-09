pragma circom 2.0.0;

// Phase 2 integration: pull `SplitFn` directly from circomlib's bigint
// witness call graph and verify the lift produces a WitnessCall E2E.
// This exercises the full chain (ArrayLit return path + field-level
// FShr / FAnd dispatch + compile-time arg propagation through the
// outer call site) on the actual call-graph function — not a
// hand-rolled lookalike.
//
// `SplitFn(in, n, m)` returns `[in % (1 << n), (in \ (1 << n)) % (1 << m)]`.
// At `n=4, m=4`, the lift should fold the pow-2 divisors at lift time
// and emit FShr / FAnd directly.

include "circuits/ecdsa/bigint_func.circom";

template SplitFnIntegration() {
    signal input in;
    signal output lo;
    signal output hi;
    var s[2] = SplitFn(in, 4, 4);
    lo <-- s[0];
    hi <-- s[1];
    // 8-bit reconstruction.
    lo + hi * 16 === in;
}

component main = SplitFnIntegration();
