pragma circom 2.0.0;

function countdown_to_zero(start) {
    var i = start;
    while (i > 0) {
        i = i - 1;
    }
    return i;
}

template WitnessLiftWhile() {
    signal input in;
    signal output out;
    out <-- countdown_to_zero(in);
    out === 0;
}

component main = WitnessLiftWhile();
