//! Content-addressed memoization of Artik witness programs.
//!
//! A circom big-integer `<--` hint that cannot be circuit-inlined is
//! lifted into a single Artik program that is executed in two separate
//! witness passes: once to produce the named advice values an off-circuit
//! hint walk consumes, and once to fill the constrained R1CS wires. Both
//! passes run the *same* program on the *same* inputs, so the second run
//! reproduces the first bit-for-bit.
//!
//! [`ArtikMemo`] caches `(program, inputs) -> outputs` so the second pass
//! is a lookup instead of a re-execution. It is content-addressed: a hit
//! occurs only when the program bytes and the full ordered input vector
//! are identical, so a cached result is by definition the result a fresh
//! execution would produce. A miss simply executes — the produced witness
//! is identical regardless of hit rate; only the wall-clock changes.

use std::collections::HashMap;

use memory::{FieldBackend, FieldElement, FieldFamily, PrimeId};

use crate::error::ArtikError;
use crate::{bytecode, execute, ArtikContext};

/// The `FieldFamily` that matches the compile-time backend `F`.
///
/// BN254 and BLS12-381 share `BnLike256`; no circom lift targets any
/// other family today.
fn family_for<F: FieldBackend>() -> Option<FieldFamily> {
    match F::PRIME_ID {
        PrimeId::Bn254 | PrimeId::Bls12_381 => Some(FieldFamily::BnLike256),
        _ => None,
    }
}

/// Decode `program_bytes` and execute it over `inputs`, writing one field
/// element per `slots` entry.
///
/// Shared execution core for both witness passes (the off-circuit advice
/// walk and the R1CS witness fill) so the decode + execute path — and the
/// field-family selection — has a single definition.
pub fn execute_into<F: FieldBackend>(
    program_bytes: &[u8],
    inputs: &[FieldElement<F>],
    slots: &mut [FieldElement<F>],
) -> Result<(), ArtikError> {
    let family =
        family_for::<F>().ok_or(ArtikError::BadHeader("unsupported field family for Artik"))?;
    let program = bytecode::decode(program_bytes, Some(family))?;
    let mut ctx = ArtikContext::<F>::new(inputs, slots);
    execute(&program, &mut ctx)
}

/// Cache key: a content-addressed program id paired with the ordered
/// input field-values.
type MemoKey<F> = (u32, Vec<FieldElement<F>>);

/// Content-addressed cache of Artik program executions, shared across the
/// two witness passes of a single proof.
///
/// The cache owns the program-id interning, so the id half of every key
/// is assigned in one place from the program bytes — both passes that key
/// through the same `ArtikMemo` therefore agree on the id by construction,
/// the property the cross-pass hit rate depends on.
pub struct ArtikMemo<F: FieldBackend> {
    /// Content-addressed program ids (a handful of distinct programs per
    /// proof). `Box<[u8]>` keys compare by contents, so equal program
    /// bytes map to the same id regardless of which pass interned them.
    prog_ids: HashMap<Box<[u8]>, u32>,
    /// `(program id, inputs) -> outputs`.
    table: HashMap<MemoKey<F>, Vec<FieldElement<F>>>,
    /// Cache hits — diagnostics only.
    pub hits: u64,
    /// Cache misses (executions) — diagnostics only.
    pub misses: u64,
}

impl<F: FieldBackend> Default for ArtikMemo<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> ArtikMemo<F> {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self {
            prog_ids: HashMap::new(),
            table: HashMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Number of distinct program byte-strings interned — diagnostics.
    pub fn distinct_programs(&self) -> usize {
        self.prog_ids.len()
    }

    /// Number of cached `(program, inputs) -> outputs` entries — diagnostics.
    pub fn entries(&self) -> usize {
        self.table.len()
    }

    /// Content-addressed id for `program_bytes`, assigned on first sight.
    fn prog_id(&mut self, program_bytes: &[u8]) -> u32 {
        if let Some(&id) = self.prog_ids.get(program_bytes) {
            return id;
        }
        let id = self.prog_ids.len() as u32;
        self.prog_ids.insert(program_bytes.into(), id);
        id
    }

    /// Fill `slots` with the outputs of `program_bytes` run over `inputs`,
    /// reusing a cached result when this exact `(program, inputs)` has been
    /// seen before and executing (and caching) otherwise.
    ///
    /// The cache is checked before decoding, so a hit pays neither the
    /// decode nor the execution.
    pub fn run(
        &mut self,
        program_bytes: &[u8],
        inputs: &[FieldElement<F>],
        slots: &mut [FieldElement<F>],
    ) -> Result<(), ArtikError> {
        let key = (self.prog_id(program_bytes), inputs.to_vec());
        if let Some(cached) = self.table.get(&key) {
            if cached.len() == slots.len() {
                slots.copy_from_slice(cached);
                self.hits += 1;
                return Ok(());
            }
        }
        execute_into(program_bytes, inputs, slots)?;
        self.table.insert(key, slots.to_vec());
        self.misses += 1;
        Ok(())
    }
}
