use std::fmt;

// --- Tagged u64 Constants ---
// Bits 63..60 = tag  (4 bits, 16 possible types)
// Bits 59..0  = payload (60 bits)

const TAG_SHIFT: u32 = 60;
const PAYLOAD_MASK: u64 = (1u64 << 60) - 1; // 0x0FFF_FFFF_FFFF_FFFF

// Tags (reassigned for clean ordering)
pub const TAG_INT: u64 = 0; // i60 inline (most common -> tag 0 for speed)
pub const TAG_NIL: u64 = 1;
pub const TAG_FALSE: u64 = 2;
pub const TAG_TRUE: u64 = 3;
pub const TAG_STRING: u64 = 4;
pub const TAG_LIST: u64 = 5;
pub const TAG_MAP: u64 = 6;
pub const TAG_FUNCTION: u64 = 7;
pub const TAG_FIELD: u64 = 8;
pub const TAG_PROOF: u64 = 9;
pub const TAG_NATIVE: u64 = 10;
pub const TAG_CLOSURE: u64 = 11;
pub const TAG_ITER: u64 = 12;
pub const TAG_BIGINT: u64 = 13;
// 14-15 reserved

// i60 range constants
pub const I60_MIN: i64 = -(1i64 << 59);
pub const I60_MAX: i64 = (1i64 << 59) - 1;

// Compile-time guards
const _: () = assert!(TAG_INT < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_NIL < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_FALSE < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_TRUE < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_STRING < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_LIST < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_MAP < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_FUNCTION < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_FIELD < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_PROOF < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_NATIVE < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_CLOSURE < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_ITER < 16, "tag must fit in 4 bits");
const _: () = assert!(TAG_BIGINT < 16, "tag must fit in 4 bits");

#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct Value(pub u64);

impl Value {
    // --- Constructors ---

    #[inline]
    pub fn int(val: i64) -> Self {
        Value((TAG_INT << TAG_SHIFT) | ((val as u64) & PAYLOAD_MASK))
    }

    #[inline]
    pub fn nil() -> Self {
        Value(TAG_NIL << TAG_SHIFT)
    }

    #[inline]
    pub fn bool(b: bool) -> Self {
        if b {
            Value(TAG_TRUE << TAG_SHIFT)
        } else {
            Value(TAG_FALSE << TAG_SHIFT)
        }
    }

    #[inline]
    pub fn string(handle: u32) -> Self {
        Value::make_obj(TAG_STRING, handle)
    }

    #[inline]
    pub fn list(handle: u32) -> Self {
        Value::make_obj(TAG_LIST, handle)
    }

    #[inline]
    pub fn map(handle: u32) -> Self {
        Value::make_obj(TAG_MAP, handle)
    }

    #[inline]
    pub fn function(handle: u32) -> Self {
        Value::make_obj(TAG_FUNCTION, handle)
    }

    #[inline]
    pub fn native(handle: u32) -> Self {
        Value::make_obj(TAG_NATIVE, handle)
    }

    #[inline]
    pub fn closure(handle: u32) -> Self {
        Value::make_obj(TAG_CLOSURE, handle)
    }

    #[inline]
    pub fn iterator(handle: u32) -> Self {
        Value::make_obj(TAG_ITER, handle)
    }

    #[inline]
    pub fn field(handle: u32) -> Self {
        Value::make_obj(TAG_FIELD, handle)
    }

    #[inline]
    pub fn proof(handle: u32) -> Self {
        Value::make_obj(TAG_PROOF, handle)
    }

    #[inline]
    pub fn bigint(handle: u32) -> Self {
        Value::make_obj(TAG_BIGINT, handle)
    }

    #[inline]
    fn make_obj(tag: u64, handle: u32) -> Self {
        Value((tag << TAG_SHIFT) | (handle as u64))
    }

    // --- Checkers ---

    #[inline]
    pub fn tag(&self) -> u64 {
        (self.0 >> TAG_SHIFT) & 0xF
    }

    #[inline]
    pub fn is_int(&self) -> bool {
        self.tag() == TAG_INT
    }

    #[inline]
    pub fn is_obj(&self) -> bool {
        self.tag() >= TAG_STRING
    }

    #[inline]
    pub fn is_nil(&self) -> bool {
        self.tag() == TAG_NIL
    }

    #[inline]
    pub fn is_bool(&self) -> bool {
        let t = self.tag();
        t == TAG_FALSE || t == TAG_TRUE
    }

    #[inline]
    pub fn is_string(&self) -> bool {
        self.tag() == TAG_STRING
    }

    #[inline]
    pub fn is_list(&self) -> bool {
        self.tag() == TAG_LIST
    }

    #[inline]
    pub fn is_map(&self) -> bool {
        self.tag() == TAG_MAP
    }

    #[inline]
    pub fn is_function(&self) -> bool {
        self.tag() == TAG_FUNCTION
    }

    #[inline]
    pub fn is_native(&self) -> bool {
        self.tag() == TAG_NATIVE
    }

    #[inline]
    pub fn is_closure(&self) -> bool {
        self.tag() == TAG_CLOSURE
    }

    #[inline]
    pub fn is_iter(&self) -> bool {
        self.tag() == TAG_ITER
    }

    #[inline]
    pub fn is_field(&self) -> bool {
        self.tag() == TAG_FIELD
    }

    #[inline]
    pub fn is_proof(&self) -> bool {
        self.tag() == TAG_PROOF
    }

    #[inline]
    pub fn is_bigint(&self) -> bool {
        self.tag() == TAG_BIGINT
    }

    // --- Accessors ---

    #[inline]
    pub fn as_int(&self) -> Option<i64> {
        if self.tag() != TAG_INT {
            return None;
        }
        let raw = self.0 & PAYLOAD_MASK;
        // Sign-extend from bit 59
        let extended = if raw & (1u64 << 59) != 0 {
            raw | !PAYLOAD_MASK // fill upper bits with 1s
        } else {
            raw
        };
        Some(extended as i64)
    }

    #[inline]
    pub fn as_bool(&self) -> Option<bool> {
        if self.tag() == TAG_TRUE {
            Some(true)
        } else if self.tag() == TAG_FALSE {
            Some(false)
        } else {
            None
        }
    }

    #[inline]
    pub fn true_val() -> Self {
        Value(TAG_TRUE << TAG_SHIFT)
    }

    #[inline]
    pub fn false_val() -> Self {
        Value(TAG_FALSE << TAG_SHIFT)
    }

    #[inline]
    pub fn is_falsey(&self) -> bool {
        self.is_nil() || (self.tag() == TAG_FALSE)
    }

    #[inline]
    pub fn as_handle(&self) -> Option<u32> {
        if self.is_obj() {
            Some((self.0 & 0xFFFFFFFF) as u32)
        } else {
            None
        }
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_int() {
            write!(f, "Int({})", self.as_int().unwrap())
        } else if self.is_nil() {
            write!(f, "Nil")
        } else if self.is_bool() {
            write!(f, "Bool({})", self.as_bool().unwrap())
        } else if self.is_string() {
            write!(f, "String({})", self.as_handle().unwrap())
        } else if self.is_list() {
            write!(f, "List({})", self.as_handle().unwrap())
        } else if self.is_map() {
            write!(f, "Map({})", self.as_handle().unwrap())
        } else if self.is_function() {
            write!(f, "Function({})", self.as_handle().unwrap())
        } else if self.is_native() {
            write!(f, "NativeFn({})", self.as_handle().unwrap())
        } else if self.is_closure() {
            write!(f, "Closure({})", self.as_handle().unwrap())
        } else if self.is_iter() {
            write!(f, "Iterator({})", self.as_handle().unwrap())
        } else if self.is_field() {
            write!(f, "Field({})", self.as_handle().unwrap())
        } else if self.is_proof() {
            write!(f, "Proof({})", self.as_handle().unwrap())
        } else if self.is_bigint() {
            write!(f, "BigInt({})", self.as_handle().unwrap())
        } else {
            write!(f, "Unknown(Bits: {:x})", self.0)
        }
    }
}
