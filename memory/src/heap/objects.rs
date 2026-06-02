use crate::Value;

#[derive(Debug, Clone, Default)]
pub struct GcStats {
    pub collections: u64,
    pub total_freed_bytes: u64,
    pub peak_heap_bytes: usize,
    pub total_gc_time_ns: u64,
}

/// Where an upvalue's value lives.
#[derive(Debug, Clone, Copy)]
pub enum UpvalueLocation {
    /// Index into the VM stack (open upvalue — variable still on the stack).
    Open(usize),
    /// Captured value (closed upvalue — variable has left the stack).
    Closed(Value),
}

#[derive(Debug, Clone)]
pub struct Upvalue {
    pub location: UpvalueLocation,
    pub next_open: Option<u32>, // Index into upvalues arena
}

#[derive(Debug, Clone)]
pub struct Closure {
    pub function: u32,
    pub upvalues: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub arity: u8,
    pub max_slots: u16, // <--- NEW: Peak register usage
    pub chunk: Vec<u32>,
    pub constants: Vec<Value>,
    // Upvalue rules (static analysis)
    // (is_local, index)
    // stored flat: [is_local_1, index_1, is_local_2, index_2...]
    pub upvalue_info: Vec<u8>,
    // Source line number for each bytecode instruction (1-based, 0 = unknown)
    pub line_info: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct IteratorObj {
    pub source: Value,
    pub index: usize,
}

#[derive(Debug, Clone)]
pub struct ProofObject {
    pub proof_json: String,
    pub public_json: String,
    pub vkey_json: String,
}

/// Compile-time circom template call descriptor, stored in the
/// heap's `circom_handles` arena and referenced from user code via
/// `Value::circom_handle(idx)`.
///
/// The handle is a leaf object — it does not reference any other
/// `Value`, so GC tracing just marks its slot. The real
/// [`circom::CircomLibrary`] is owned by the VM's `circom_handler`
/// (a trait object injected at program-run time), not by the heap,
/// so this struct never holds a direct reference into it. The
/// `library_id` field selects which library the handler should use
/// at dispatch time.
///
/// `template_args` stores the pre-evaluated compile-time template
/// parameters as u64 values — they were required to reduce to
/// `CircuitExpr::Const` at compile time, which for real-world circom
/// use cases (array lengths, iteration counts, etc.) always fits in
/// a u64.
#[derive(Debug, Clone)]
pub struct CircomHandle {
    pub library_id: u32,
    pub template_name: String,
    pub template_args: Vec<u64>,
}

/// Estimated heap cost of a [`CircomHandle`]: struct stack size +
/// the template name's allocated capacity + the args vec capacity.
pub(super) fn circom_handle_cost(h: &CircomHandle) -> usize {
    std::mem::size_of::<CircomHandle>()
        + h.template_name.capacity()
        + h.template_args.capacity() * std::mem::size_of::<u64>()
}
