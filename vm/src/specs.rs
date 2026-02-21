
pub struct NativeMeta {
    pub name: &'static str,
    pub arity: isize,
}

// THE SINGLE SOURCE OF TRUTH
// The index in this array IS the global index.
// Compiler keys = these names
// VM slots 0..N = these functions in this order
pub const NATIVE_TABLE: &[NativeMeta] = &[
    NativeMeta { name: "print",  arity: -1 }, // Index 0
    NativeMeta { name: "len",    arity: 1  }, // Index 1
    NativeMeta { name: "typeof", arity: 1  }, // Index 2
    NativeMeta { name: "assert", arity: 1  }, // Index 3
    NativeMeta { name: "time",   arity: 0  }, // Index 4
    // Collections
    NativeMeta { name: "push",   arity: 2  }, // Index 5
    NativeMeta { name: "pop",    arity: 1  }, // Index 6
    NativeMeta { name: "keys",   arity: 1  }, // Index 7
    NativeMeta { name: "field",  arity: 1  }, // Index 8
    // Proof inspection
    NativeMeta { name: "proof_json",   arity: 1 }, // Index 9
    NativeMeta { name: "proof_public", arity: 1 }, // Index 10
    NativeMeta { name: "proof_vkey",   arity: 1 }, // Index 11
];

// Helper to get start index for user globals
pub const USER_GLOBAL_START: u16 = NATIVE_TABLE.len() as u16;

// --- SERIALIZATION CONTRACT ---
// Binary Format Tags (v1)
pub const SER_TAG_NUMBER: u8 = 0;
pub const SER_TAG_STRING: u8 = 1;
pub const SER_TAG_FIELD:  u8 = 8;
pub const SER_TAG_NIL:    u8 = 255;
