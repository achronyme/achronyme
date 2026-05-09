pragma circom 2.0.0;

// Phase 2 lift extension: `return [a, b]` allocates a fresh 1D field
// array, lifts each element into a register, and stores at index `i`.
// The path mirrors a named-array return — nested calls receive a
// NestedResult::Array handle, outer functions emit per-cell witness
// slots.
//
// This fixture also exercises the field-level FShr / FAnd dispatch:
// `% (1 << n)` and `\ (1 << n)` where `n` is a compile-time-known
// param of the inner function. The lift propagates literal args into
// the callee's `const_locals` so `match_one_shl_const` recognizes the
// shape and emits FShr / FAnd directly on the field cell instead of
// routing through the IntW::U32 demote path.

function split_byte_pow2(x, n) {
    return [x % (1 << n), (x \ (1 << n)) % (1 << n)];
}

template SplitBytePow2() {
    signal input in;
    signal output lo;
    signal output hi;
    var s[2] = split_byte_pow2(in, 4);
    lo <-- s[0];
    hi <-- s[1];
    // 8-bit byte split into two 4-bit nibbles.
    lo + hi * 16 === in;
}

component main = SplitBytePow2();
