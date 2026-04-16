pub struct NativeMeta {
    pub name: &'static str,
    pub arity: isize,
}

// --- SERIALIZATION CONTRACT ---
// Binary Format Tags (v2 — tagged u64, no floats)
pub const SER_TAG_INT: u8 = 0;
pub const SER_TAG_STRING: u8 = 1;
pub const SER_TAG_FIELD: u8 = 8;
pub const SER_TAG_BIGINT: u8 = 13;
pub const SER_TAG_BYTES: u8 = 14;
pub const SER_TAG_NIL: u8 = 255;
