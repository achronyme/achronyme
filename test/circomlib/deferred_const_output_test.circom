pragma circom 2.0.0;

// Regression pin for deferred-component constant-output replay.
//
// `Num2Bits` lifts constant outputs during lowering (its per-bit
// `out[i]` decomposition folds constants the parent consumes). A
// repeatedly-instantiated cacheable body is lowered once and emitted
// as a `ComponentCall`; the second instance is a cache hit whose
// constant outputs are NOT re-scanned from inlined nodes — they are
// replayed from the signature captured at the first (eager)
// instantiation, mangled with the hit instance's prefix. If that
// replay dropped or mis-mangled a constant output, this circuit's
// second-instance constraints would be inconsistent with an
// otherwise-correct witness and R1CS verification would fail. Two
// instances with distinct runtime inputs make the body cacheable
// (runtime-signal inputs, no const inputs, no array args) and force
// exactly one eager lowering + one deferred hit.
template Num2BitsLocal(n) {
    signal input inp;
    signal output out[n];
    var lc1 = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (inp >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 += out[i] * (2 ** i);
    }
    lc1 === inp;
}

template DeferredConstOutput() {
    signal input a;
    signal input b;
    signal output sa;
    signal output sb;

    component x = Num2BitsLocal(8);
    x.inp <== a;

    component y = Num2BitsLocal(8);
    y.inp <== b;

    var s1 = 0;
    var s2 = 0;
    for (var i = 0; i < 8; i++) {
        s1 += x.out[i];
        s2 += y.out[i];
    }
    sa <== s1;
    sb <== s2;
}

component main = DeferredConstOutput();
