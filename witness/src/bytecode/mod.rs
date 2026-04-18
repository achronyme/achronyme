//! Artik bytecode serialization: `Program` ↔ `Vec<u8>`.
//!
//! `decode` is the only path that produces a `Program` callers can
//! execute — it runs the validator before returning `Ok`, so the
//! executor can rely on structural invariants (bounded jumps, valid
//! register indices, typed registers, field constants within the
//! backend's canonical size).

pub mod decode;
pub mod encode;

pub use decode::decode;
pub use encode::encode;
