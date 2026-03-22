pub struct NativeMeta {
    pub name: &'static str,
    pub arity: isize,
}

// THE SINGLE SOURCE OF TRUTH
// The index in this array IS the global index.
// Compiler keys = these names
// VM slots 0..N = these functions in this order
//
// Grouped by NativeModule: core, string, bigint, collections.
// The order within each group MUST match the module's natives() impl.
pub const NATIVE_TABLE: &[NativeMeta] = &[
    // ── core (0..10) ──
    NativeMeta {
        name: "print",
        arity: -1,
    },
    NativeMeta {
        name: "typeof",
        arity: 1,
    },
    NativeMeta {
        name: "assert",
        arity: 1,
    },
    NativeMeta {
        name: "time",
        arity: 0,
    },
    NativeMeta {
        name: "proof_json",
        arity: 1,
    },
    NativeMeta {
        name: "proof_public",
        arity: 1,
    },
    NativeMeta {
        name: "proof_vkey",
        arity: 1,
    },
    NativeMeta {
        name: "poseidon",
        arity: 2,
    },
    NativeMeta {
        name: "poseidon_many",
        arity: -1,
    },
    NativeMeta {
        name: "verify_proof",
        arity: 1,
    },
    NativeMeta {
        name: "gc_stats",
        arity: 0,
    },
    // ── bigint (11..13) ──
    NativeMeta {
        name: "bigint256",
        arity: 1,
    },
    NativeMeta {
        name: "bigint512",
        arity: 1,
    },
    NativeMeta {
        name: "from_bits",
        arity: 2,
    },
];

// Expected native count — update this when adding/removing natives.
// Compile-time assertion prevents silent index shifts.
pub const NATIVE_COUNT: usize = 14;
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
pub const SER_TAG_BYTES: u8 = 14;
pub const SER_TAG_NIL: u8 = 255;
