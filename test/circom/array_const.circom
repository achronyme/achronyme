pragma circom 2.0.0;

// Minimal Poseidon-like pattern: function returns array via if-else,
// var array init, index access, and array passing to sub-template.

function GET_CONSTANTS(t) {
    if (t == 2) {
        return [10, 20, 30];
    } else if (t == 3) {
        return [100, 200, 300, 400];
    } else {
        return [0];
    }
}

function GET_MATRIX(t) {
    if (t == 2) {
        return [[1, 2], [3, 4]];
    } else {
        return [[5, 6], [7, 8]];
    }
}

// Sub-template that receives an array constant as a template parameter
template AddRoundKey(t, C, offset) {
    signal input in[t];
    signal output out[t];

    for (var i = 0; i < t; i++) {
        out[i] <== in[i] + C[i + offset];
    }
}

template Main(t) {
    signal input in[t];
    signal output out[t];

    // Array var from function call (like POSEIDON_C)
    var C[3] = GET_CONSTANTS(t);

    // 2D array var from function call (like POSEIDON_M)
    var M[t][t] = GET_MATRIX(t);

    // Direct use of array constant
    signal mid[t];
    for (var i = 0; i < t; i++) {
        mid[i] <== in[i] + C[i];
    }

    // Pass array to sub-template
    component ark = AddRoundKey(t, C, 0);
    for (var i = 0; i < t; i++) {
        ark.in[i] <== mid[i];
    }

    // Use 2D array constant
    for (var i = 0; i < t; i++) {
        out[i] <== ark.out[i] + M[0][i];
    }
}

component main {public [in]} = Main(2);
