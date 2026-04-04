pragma circom 2.0.0;

function double(x) {
    return x * 2;
}

function add_one(x) {
    return x + 1;
}

// Simple function calls in constraint expressions.
// double(3) = 6, add_one(double(2)) = 5
template FuncSimple() {
    signal input a;
    signal input b;
    signal output c;

    // c = a * double(3) = a * 6
    c <== a * double(3);

    // Constraint: b === a * add_one(double(2))  →  b === a * 5
    b === a * add_one(double(2));
}

component main {public [a]} = FuncSimple();
