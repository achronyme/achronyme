pragma circom 2.1.5;

// Minimal repro of the `long_sub_mod_p` shape: a named 1D array local
// rebound by a nested call inside BOTH arms of a runtime if/else, then
// read after the branch. The post-branch read must observe the array
// the runtime-taken arm built — not whichever arm the lift walked last.

function idcopy(a) {
    var r[4];
    for (var i = 0; i < 4; i++) {
        r[i] = a[i];
    }
    return r;
}

function pick(sel, x, y) {
    var t[4];
    if (sel) {
        t = idcopy(x);
    } else {
        t = idcopy(y);
    }
    return t;
}

template ArtikIfElseArrayRebindProbe() {
    signal input sel;
    signal input x[4];
    signal input y[4];
    signal output o[4];

    var got[4] = pick(sel, x, y);
    for (var i = 0; i < 4; i++) {
        o[i] <-- got[i];
        o[i] === o[i];
    }
}

component main = ArtikIfElseArrayRebindProbe();
