
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
];

// Helper to get start index for user globals
pub const USER_GLOBAL_START: u16 = NATIVE_TABLE.len() as u16;
