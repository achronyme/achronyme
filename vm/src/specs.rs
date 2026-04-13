pub struct NativeMeta {
    pub name: &'static str,
    pub arity: isize,
}

// THE SINGLE SOURCE OF TRUTH
// The index in this array IS the global index.
// Compiler keys = these names
// VM slots 0..N = these functions in this order
//
// Grouped by NativeModule: core, bigint.
// The order within each group MUST match the module's natives() impl.
//
// Movimiento 2 note: this table is cross-checked against
// `resolve::BuiltinRegistry::default()` at every compiler init (debug
// builds) and at every CI run (via
// `compiler/tests/builtin_registry_alignment.rs`). Adding or reordering
// entries requires updating the registry's VmFnHandle values to match.
// Phase 6 will delete this table and drive dispatch directly from the
// registry — see `.claude/plans/movimiento-2-unified-dispatch.md` §4
// Phase 6 MANDATORY block.
pub const NATIVE_TABLE: &[NativeMeta] = &[
    // ── core (0..11) ──
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
    // Phase 2C of Movimiento 2 — scalar VM fallback for the ProveIR
    // `mux` builtin. Promotes mux to Availability::Both, closing gap
    // 1.1 where modules that called mux could not be imported by
    // VM-mode programs.
    NativeMeta {
        name: "mux",
        arity: 3,
    },
    // ── bigint (12..14) ──
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
pub const NATIVE_COUNT: usize = 15;
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
