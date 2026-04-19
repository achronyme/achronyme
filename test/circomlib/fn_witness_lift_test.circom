pragma circom 2.0.0;

// Fase 2 lift smoke test: a function with a non-trivial body (one
// `var` and a `return` over a binary op on the parameter) is now
// compiled to an Artik witness program, not rejected with E212.
//
// The lift pass in `circom/src/lowering/artik_lift.rs` accepts:
//   - `var name = expr;` / `name = expr;`
//   - `return expr;`
//   - `BinOp` Add / Sub / Mul / Div over parameters and constants.
//
// Anything beyond that surface (loops, arrays, nested calls, if/else)
// still falls back to E212 — see `fn_local_shadowing_test.circom` for
// that regression.

function derive_scalar(x) {
    var y = x * 2;
    return y + 1;
}

template WitnessLiftOk() {
    signal input in;
    signal output out;
    // Witness hint — the Artik program computes the value off-
    // circuit; the `===` below constrains it so soundness holds.
    out <-- derive_scalar(in);
    out === in * 2 + 1;
}

component main = WitnessLiftOk();
