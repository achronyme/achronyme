pragma circom 2.0.0;

// `is_big` is a trivial `return cond ? a : b;` helper with a runtime
// condition. Reached as a *callee subprogram* of the non-trivial
// `compute` (which routes through the witness lift because its body
// has multiple statements and a runtime argument), its return runs
// through the callee-return path → the expression lift's ternary arm.
// That arm must lower the ternary as a branchless select
// (`cond_bool * a + (1 - cond_bool) * b`) — no conditional jump — or
// the callee declines and compilation fails with E212. circomlib's
// `isNegative` (`return x > (p-1)/2 ? 1 : 0;`), called from
// `getProperRepresentation`, is exactly this shape. Both arms are
// exercised by two signal values straddling the threshold.
function is_big(x) {
    return x > 100 ? 7 : 13;
}

function compute(x) {
    var acc = 0;
    acc = acc + is_big(x);
    return acc;
}

template WitnessLiftTernary() {
    signal input in;
    signal output out;
    out <-- compute(in);
    out === out;
}

component main = WitnessLiftTernary();
