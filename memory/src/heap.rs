mod alloc;
mod gc;
mod general;
mod objects;

#[cfg(test)]
mod tests;

use crate::arena::Arena;
use crate::bigint::BigInt;
use crate::field::FieldElement;
use crate::Value;
use std::collections::HashMap;

pub use objects::{
    CircomHandle, Closure, Function, GcStats, IteratorObj, ProofObject, Upvalue, UpvalueLocation,
};

pub struct Heap {
    // Typed Arenas — pub(crate) to prevent external bypass of allocation tracking
    pub(crate) strings: Arena<String>,
    pub(crate) lists: Arena<Vec<Value>>,
    pub(crate) maps: Arena<HashMap<String, Value>>,
    pub(crate) functions: Arena<Function>,
    pub(crate) upvalues: Arena<Upvalue>,
    pub(crate) closures: Arena<Closure>,
    pub(crate) iterators: Arena<IteratorObj>,
    pub(crate) fields: Arena<FieldElement>,
    pub(crate) proofs: Arena<ProofObject>,
    pub(crate) bigints: Arena<BigInt>,
    pub(crate) bytes: Arena<Vec<u8>>,
    pub(crate) circom_handles: Arena<CircomHandle>,

    // GC Metrics
    pub bytes_allocated: usize,
    pub next_gc_threshold: usize,
    pub request_gc: bool,
    gc_lock_depth: u32,
    pub max_heap_bytes: usize,
    pub heap_limit_exceeded: bool,
    pub stats: GcStats,
}
