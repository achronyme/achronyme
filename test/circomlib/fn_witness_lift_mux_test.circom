pragma circom 2.0.0;

// Fase 2.2: runtime `if / else` on a signal-dependent condition lifts
// to an Artik witness program via a field-arithmetic mux — no Jump /
// JumpIf emitted. The condition is normalized to {0, 1} via
// FEq(cond, 0) + FieldFromInt + FSub so any non-zero field value
// behaves as circom's `true`.
//
//     select(cond, a, b) = cond ? (a + 1) : (b * 2)
//                        = cond_bool * (a + 1) + (1 - cond_bool) * (b * 2)
//
// The template pins the contract by constraining cond to be {0, 1}
// (standard bool gadget) and asserting `out` equals the expanded mux.

function select(cond, a, b) {
    var out;
    if (cond) {
        out = a + 1;
    } else {
        out = b * 2;
    }
    return out;
}

template WitnessLiftMux() {
    signal input cond;
    signal input a;
    signal input b;
    signal output out;
    out <-- select(cond, a, b);
    cond * (cond - 1) === 0;
    out === cond * (a + 1) + (1 - cond) * (b * 2);
}

component main = WitnessLiftMux();
