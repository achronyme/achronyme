pragma circom 2.0.0;

// Row slice as return value: a function that builds a 2D local array
// and returns one of its rows. The caller binds the result to a 1D
// var array. Exercises `return arr2d[row]` in the artik lift's
// statement-return path — the lift must materialize the row as a
// fresh 1D field array and emit per-cell witness slots (or pass it
// back as a NestedResult::Array for inlined uses).

function build_and_return_row(x) {
    var m[2][3];
    for (var i = 0; i < 2; i++) {
        for (var j = 0; j < 3; j++) {
            m[i][j] = x + 10 * i + j;
        }
    }
    return m[1];
}

template WitnessRowSliceReturn() {
    signal input in;
    signal output out[3];
    var row[3] = build_and_return_row(in);
    out[0] <-- row[0];
    out[1] <-- row[1];
    out[2] <-- row[2];
    out[0] === in + 10;
    out[1] === in + 11;
    out[2] === in + 12;
}

component main = WitnessRowSliceReturn();
