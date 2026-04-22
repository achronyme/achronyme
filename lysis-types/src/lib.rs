//! `lysis-types` — shared vocabulary for the Lysis template-instantiation VM.
//!
//! This crate exists to be a leaf in the dependency graph: it holds the
//! types that cross the boundary between Lysis and its consumers (for now
//! `ir` via `lysis_bridge`; post-P7 also `ir-forge`). By keeping these
//! types outside of `lysis` proper, consumers can depend on
//! `lysis-types` without pulling in the bytecode encoder, interner, or
//! VM executor.
//!
//! ## Scope
//!
//! What lives here: `NodeId`, `Visibility`, `InstructionKind<F>` — the
//! minimal set of types that producers of interned Lysis nodes and
//! materializers of those nodes both need to speak.
//!
//! What does NOT live here: anything runtime (`Program`, `ProgramBuilder`,
//! executor, register allocator, bytecode codec) stays in `lysis`;
//! anything IR-side (`Instruction<F>`, `SsaVar`, `ExtendedInstruction<F>`)
//! stays in `ir` / `ir-forge`.
