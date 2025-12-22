use std::fmt;

// --- NaN Boxing Constants ---
// S EEEE... Q TTT ... Payload ...
// QNAN = Exponent all 1s + Quiet bit (0x0008000000000000)
// We use a high base to avoid real QNaNs.
pub const QNAN: u64 = 0x7ffc000000000000;

// Tags live in bits 32-35 (4 bits)
// 0 = Double (implicitly, if QNAN bits are not set)
pub const TAG_NUMBER: u64 = 0; // Helper for type_tag()
pub const TAG_NIL: u64 = 1;
pub const TAG_FALSE: u64 = 2;
pub const TAG_TRUE: u64 = 3;
pub const TAG_STRING: u64 = 4;
pub const TAG_LIST: u64 = 5;
pub const TAG_MAP: u64 = 6;
pub const TAG_FUNCTION: u64 = 7;
pub const TAG_TENSOR: u64 = 8;
pub const TAG_COMPLEX: u64 = 9;
pub const TAG_NATIVE: u64 = 10;
pub const TAG_CLOSURE: u64 = 11;
pub const TAG_ITER: u64 = 12;

#[derive(Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct Value(pub u64);

impl Value {
    // --- Constructors ---

    #[inline]
    pub fn number(n: f64) -> Self {
        // Canonización: Si es un NaN real, lo convertimos a nuestro "Number NaN" seguro
        // para que no colisione con Tags. Usamos el QNaN estándar de float.
        if n.is_nan() {
            Value(f64::NAN.to_bits())
        } else {
            Value(n.to_bits())
        }
    }

    #[inline]
    pub fn nil() -> Self {
        Value(QNAN | (TAG_NIL << 32))
    }

    #[inline]
    pub fn bool(b: bool) -> Self {
        if b {
            Value(QNAN | (TAG_TRUE << 32))
        } else {
            Value(QNAN | (TAG_FALSE << 32))
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
    pub fn tensor(handle: u32) -> Self {
        Value::make_obj(TAG_TENSOR, handle)
    }

    #[inline]
    pub fn complex(handle: u32) -> Self {
        Value::make_obj(TAG_COMPLEX, handle)
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
    fn make_obj(tag: u64, handle: u32) -> Self {
        // Shift Tag to bits 32-35 (lowest 4 bits of high 32)
        // Check plan: QNAN | (Tag << 32) | Handle
        Value(QNAN | (tag << 32) | (handle as u64))
    }

    // --- Checkers ---

    #[inline]
    pub fn is_number(&self) -> bool {
        (self.0 & QNAN) != QNAN
    }

    #[inline]
    pub fn is_obj(&self) -> bool {
        self.is_not_number() && (self.tag() >= TAG_STRING)
    }

    #[inline]
    fn is_not_number(&self) -> bool {
        (self.0 & QNAN) == QNAN
    }

    #[inline]
    fn tag(&self) -> u64 {
        (self.0 >> 32) & 0xF
    }

    #[inline]
    pub fn is_nil(&self) -> bool {
        self.0 == (QNAN | (TAG_NIL << 32))
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
    pub fn is_tensor(&self) -> bool {
        self.tag() == TAG_TENSOR
    }

    #[inline]
    pub fn is_complex(&self) -> bool {
        self.tag() == TAG_COMPLEX
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
    pub fn is_numeric(&self) -> bool {
        self.is_number() || self.is_complex()
    }

    /// Returns the type tag for this value.
    /// Returns TAG_NUMBER (0) for numbers, otherwise the specific object/primitive tag.
    /// This allows for O(1) jump tables in match statements.
    #[inline]
    pub fn type_tag(&self) -> u64 {
        if self.is_number() {
            TAG_NUMBER
        } else {
            self.tag()
        }
    }

    // --- Accessors ---

    #[inline]
    pub fn as_number(&self) -> Option<f64> {
        if self.is_number() {
            Some(f64::from_bits(self.0))
        } else {
            None
        }
    }

    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        self.as_number()
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
        Value(QNAN | (TAG_TRUE << 32))
    }

    #[inline]
    pub fn false_val() -> Self {
        Value(QNAN | (TAG_FALSE << 32))
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
        if self.is_number() {
            write!(f, "Number({})", self.as_number().unwrap())
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
        } else if self.is_tensor() {
            write!(f, "Tensor({})", self.as_handle().unwrap())
        } else if self.is_complex() {
            write!(f, "Complex({})", self.as_handle().unwrap())
        } else if self.is_native() {
            write!(f, "NativeFn({})", self.as_handle().unwrap())
        } else if self.is_closure() {
            write!(f, "Closure({})", self.as_handle().unwrap())
        } else if self.is_iter() {
            write!(f, "Iterator({})", self.as_handle().unwrap())
        } else {
            write!(f, "Unknown(Bits: {:x})", self.0)
        }
    }
}
