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
    NativeMeta {
        name: "field",
        arity: 1,
    }, // Index 8
    // Proof inspection
    NativeMeta {
        name: "proof_json",
        arity: 1,
    }, // Index 9
    NativeMeta {
        name: "proof_public",
        arity: 1,
    }, // Index 10
    NativeMeta {
        name: "proof_vkey",
        arity: 1,
    }, // Index 11
    // String utilities
    NativeMeta {
        name: "substring",
        arity: 3,
    }, // Index 12
    NativeMeta {
        name: "indexOf",
        arity: 2,
    }, // Index 13
    NativeMeta {
        name: "split",
        arity: 2,
    }, // Index 14
    NativeMeta {
        name: "trim",
        arity: 1,
    }, // Index 15
    NativeMeta {
        name: "replace",
        arity: 3,
    }, // Index 16
    NativeMeta {
        name: "toUpper",
        arity: 1,
    }, // Index 17
    NativeMeta {
        name: "toLower",
        arity: 1,
    }, // Index 18
    NativeMeta {
        name: "chars",
        arity: 1,
    }, // Index 19
    // Cryptographic
    NativeMeta {
        name: "poseidon",
        arity: 2,
    }, // Index 20
    NativeMeta {
        name: "poseidon_many",
        arity: -1,
    }, // Index 21
    NativeMeta {
        name: "verify_proof",
        arity: 1,
    }, // Index 22
];

// Expected native count — update this when adding/removing natives.
// Compile-time assertion prevents silent index shifts.
pub const NATIVE_COUNT: usize = 23;
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
pub const SER_TAG_NIL: u8 = 255;
