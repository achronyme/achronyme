pragma circom 2.0.0;

// Repro for Gap E: name collision between a function's local array var
// and the calling template's signal output of the same name.
//
// Function `derive` has `var out[4]` internally. Template `FnLocalShadowing`
// has `signal output out[4]`. When `derive(in)` is called with a runtime
// argument (`in` is a signal), compile-time evaluation fails. The current
// lowering falls through to an inlining path that reuses the CALLER's env
// to lower `return out;` — and `out` resolves to the template's signal
// array instead of the function's local var, producing a bare
// `CircuitExpr::Var("out")` that survives component mangling and blows up
// at instantiate time with "undeclared variable in circuit: `out`".
function derive(x) {
    var out[4];
    for (var i = 0; i < 4; i++) out[i] = x + i;
    return out;
}

template FnLocalShadowing() {
    signal input in;
    signal output out[4];
    var tmp[4] = derive(in);
    for (var i = 0; i < 4; i++) out[i] <-- tmp[i];
    for (var i = 0; i < 4; i++) out[i] === in + i;
}

component main = FnLocalShadowing();
