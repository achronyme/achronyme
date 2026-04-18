pragma circom 2.0.0;

// Regression fixture for the `var X; X = expr;` compile-time tracking gap.
//
// Exercises three patterns that circomlib's SHA256 padding block uses:
//   1. `var nBlocks;` declared without init, later assigned to a const
//      expression built from a template parameter.
//   2. A signal array whose dimension depends on that var
//      (`signal paddedIn[nBlocks*512]`).
//   3. For-loop bodies whose indexing mixes the var and the loop counter
//      (`paddedIn[nBlocks*512 - k - 1]`), which requires the lowerer to
//      fold the var to a `CircuitExpr::Const` inside `Expr::Ident`.
//
// Before the fix, step 1 passed (the var was precomputed) but step 3 hit
// "indexed assignment into `paddedIn` requires a compile-time constant
// index" because the identifier wasn't being injected into
// `env.known_constants`.
template VarPostDeclPadding(nBits) {
    var nBlocks;
    nBlocks = ((nBits + 64) \ 512) + 1;
    signal output paddedIn[nBlocks * 512];

    for (var k = 0; k < nBits; k++) {
        paddedIn[k] <== 1;
    }
    paddedIn[nBits] <== 2;
    for (var k = nBits + 1; k < nBlocks * 512 - 64; k++) {
        paddedIn[k] <== 3;
    }
    for (var k = 0; k < 64; k++) {
        paddedIn[nBlocks * 512 - k - 1] <== (nBits >> k) & 1;
    }
}

component main = VarPostDeclPadding(64);
