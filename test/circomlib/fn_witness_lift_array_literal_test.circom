pragma circom 2.0.0;

// Fase 5.1 (array-literal init): a function body declares
// `var k[4] = [literal, literal, ...];` and reads `k[i]` in a
// loop. The Artik lift must allocate the backing store at
// declaration time, StoreArr each literal into its slot, and
// then emit `LoadArr` against the same handle when the body
// indexes the array. This is the SHA-256 shape (`sha256K`
// packs 64 round constants into a table and indexes them once
// per round).
//
//     table_sum() = 1 + 2 + 3 + 4 = 10
//     scaled_sum(n) = n * (1 + 2 + 3 + 4) = 10 * n

function table_sum() {
    var k[4] = [1, 2, 3, 4];
    var total = 0;
    for (var i = 0; i < 4; i++) {
        total += k[i];
    }
    return total;
}

template WitnessLiftArrayLiteral() {
    signal input n;
    signal output out;
    out <-- n * table_sum();
    out === 10 * n;
}

component main = WitnessLiftArrayLiteral();
