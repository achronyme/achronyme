pub struct NativeMeta {
    pub name: &'static str,
    pub arity: isize,
}

// THE SINGLE SOURCE OF TRUTH
// The index in this array IS the global index.
// Compiler keys = these names
// VM slots 0..N = these functions in this order
pub const NATIVE_TABLE: &[NativeMeta] = &[
    NativeMeta {
        name: "print",
        arity: -1,
    }, // Index 0
    NativeMeta {
        name: "len",
        arity: 1,
    }, // Index 1
    NativeMeta {
        name: "typeof",
        arity: 1,
    }, // Index 2
    NativeMeta {
        name: "assert",
        arity: 1,
    }, // Index 3
    NativeMeta {
        name: "time",
        arity: 0,
    }, // Index 4
    // Collections
    NativeMeta {
        name: "push",
        arity: 2,
    }, // Index 5
    NativeMeta {
        name: "pop",
        arity: 1,
    }, // Index 6
    NativeMeta {
        name: "keys",
        arity: 1,
    }, // Index 7
    // Proof inspection
    NativeMeta {
        name: "proof_json",
        arity: 1,
    }, // Index 8
    NativeMeta {
        name: "proof_public",
        arity: 1,
    }, // Index 9
    NativeMeta {
        name: "proof_vkey",
        arity: 1,
    }, // Index 10
    // String utilities
    NativeMeta {
        name: "substring",
        arity: 3,
    }, // Index 11
    NativeMeta {
        name: "index_of",
        arity: 2,
    }, // Index 12
    NativeMeta {
        name: "split",
        arity: 2,
    }, // Index 13
    NativeMeta {
        name: "trim",
        arity: 1,
    }, // Index 14
    NativeMeta {
        name: "replace",
        arity: 3,
    }, // Index 15
    NativeMeta {
        name: "to_upper",
        arity: 1,
    }, // Index 16
    NativeMeta {
        name: "to_lower",
        arity: 1,
    }, // Index 17
    NativeMeta {
        name: "chars",
        arity: 1,
    }, // Index 18
    // Cryptographic
    NativeMeta {
        name: "poseidon",
        arity: 2,
    }, // Index 19
    NativeMeta {
        name: "poseidon_many",
        arity: -1,
    }, // Index 20
    NativeMeta {
        name: "verify_proof",
        arity: 1,
    }, // Index 21
    // BigInt
    NativeMeta {
        name: "bigint256",
        arity: 1,
    }, // Index 22
    NativeMeta {
        name: "bigint512",
        arity: 1,
    }, // Index 23
    NativeMeta {
        name: "to_bits",
        arity: 1,
    }, // Index 24
    NativeMeta {
        name: "from_bits",
        arity: 2,
    }, // Index 25
    NativeMeta {
        name: "bit_and",
        arity: 2,
    }, // Index 26
    NativeMeta {
        name: "bit_or",
        arity: 2,
    }, // Index 27
    NativeMeta {
        name: "bit_xor",
        arity: 2,
    }, // Index 28
    NativeMeta {
        name: "bit_not",
        arity: 1,
    }, // Index 29
    NativeMeta {
        name: "bit_shl",
        arity: 2,
    }, // Index 30
    NativeMeta {
        name: "bit_shr",
        arity: 2,
    }, // Index 31
    // GC introspection
    NativeMeta {
        name: "gc_stats",
        arity: 0,
    }, // Index 32
    // Higher-order collections
    NativeMeta {
        name: "map",
        arity: 2,
    }, // Index 33
    NativeMeta {
        name: "filter",
        arity: 2,
    }, // Index 34
    NativeMeta {
        name: "reduce",
        arity: 3,
    }, // Index 35
    NativeMeta {
        name: "for_each",
        arity: 2,
    }, // Index 36
    NativeMeta {
        name: "find",
        arity: 2,
    }, // Index 37
    NativeMeta {
        name: "any",
        arity: 2,
    }, // Index 38
    NativeMeta {
        name: "all",
        arity: 2,
    }, // Index 39
    NativeMeta {
        name: "sort",
        arity: 2,
    }, // Index 40
    NativeMeta {
        name: "flat_map",
        arity: 2,
    }, // Index 41
    NativeMeta {
        name: "zip",
        arity: 2,
    }, // Index 42
];

// Expected native count — update this when adding/removing natives.
// Compile-time assertion prevents silent index shifts.
pub const NATIVE_COUNT: usize = 43;
const _: () = assert!(
    NATIVE_TABLE.len() == NATIVE_COUNT,
    "NATIVE_TABLE length changed — update NATIVE_COUNT"
);

// Helper to get start index for user globals
pub const USER_GLOBAL_START: u16 = NATIVE_COUNT as u16;

// --- SERIALIZATION CONTRACT ---
// Binary Format Tags (v2 — tagged u64, no floats)
pub const SER_TAG_INT: u8 = 0;
pub const SER_TAG_STRING: u8 = 1;
pub const SER_TAG_FIELD: u8 = 8;
pub const SER_TAG_BIGINT: u8 = 13;
pub const SER_TAG_NIL: u8 = 255;
