//! Bytecode encode / decode for Lysis programs.
//!
//! The entry points are [`encode`] and [`decode`]:
//!
//! ```text
//! encode:  &Program<F>  ->  Vec<u8>
//! decode:  &[u8]        ->  Program<F>          (structural-decode only)
//! ```
//!
//! Decoding is split into two passes, matching what a validator wants:
//!
//! 1. **Structural decode** (this module): read the header, walk the
//!    const pool, and linearly scan the body producing a
//!    `Vec<Instr>` + a parallel `Vec<Template>` harvested from
//!    `DefineTemplate` opcodes. Fails fast on truncated input or
//!    unknown opcodes.
//! 2. **Semantic validation** ([`super::validate`]): the structural
//!    rules. Operates on the decoded `Program` and never looks at
//!    raw bytes.
//!
//! Every operand here is little-endian, matching the encoding already
//! used by Artik.

mod decode;
mod encode;

pub use decode::{decode, decode_body};
pub use encode::{encode, encode_opcode};

#[cfg(test)]
mod tests;
