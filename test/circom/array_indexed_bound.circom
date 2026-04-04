pragma circom 2.0.0;

// Test: indexed array var as loop bound (Poseidon N_ROUNDS_P pattern).
//
// var ROUNDS[4] = [3, 4, 3, 5];
// var nRounds = ROUNDS[t - 2];    ← scalar from array index
// for (var i = 0; i < nRounds; i++) { ... }  ← uses scalar as bound
//
// Also tests: array literal in var → index at compile time → use as bound.

function GET_ROUND_CONSTANTS(t) {
    if (t == 2) {
        return [10, 20, 30];
    } else if (t == 3) {
        return [100, 200, 300, 400];
    } else {
        return [0];
    }
}

template AddConst(t, C, r) {
    signal input in[t];
    signal output out[t];
    for (var i = 0; i < t; i++) {
        out[i] <== in[i] + C[i + r*t];
    }
}

template Main(nInputs) {
    var t = nInputs + 1;
    var nRoundsF = 4;

    // Array literal with indexed access → scalar loop bound
    var N_ROUNDS[4] = [3, 4, 3, 5];
    var nRoundsP = N_ROUNDS[t - 2];

    // Function-returned array for round constants
    var C[3] = GET_ROUND_CONSTANTS(t);

    signal input in[t];
    signal output out[t];

    // Use nRoundsP as a loop bound (must be resolved at compile time)
    signal acc[nRoundsP + 1][t];
    for (var i = 0; i < t; i++) {
        acc[0][i] <== in[i];
    }

    // nRoundsP iterations with constant addition
    for (var r = 0; r < nRoundsP; r++) {
        component ark = AddConst(t, C, 0);
        for (var i = 0; i < t; i++) {
            ark.in[i] <== acc[r][i];
        }
        for (var i = 0; i < t; i++) {
            acc[r + 1][i] <== ark.out[i];
        }
    }

    for (var i = 0; i < t; i++) {
        out[i] <== acc[nRoundsP][i];
    }
}

// nInputs=1 → t=2, N_ROUNDS[0]=3, nRoundsP=3
// C = [10, 20, 30] (t=2 branch)
// 3 rounds of adding [10, 20]:
//   round 0: [in_0+10, in_1+20]
//   round 1: [in_0+20, in_1+40]
//   round 2: [in_0+30, in_1+60]
// out = [in_0+30, in_1+60]
component main {public [in]} = Main(1);
