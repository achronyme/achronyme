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
    /// Decoded (and validated) programs by id. `bytecode::decode` is a
    /// pure function of the program bytes, so decoding once per distinct
    /// program and re-executing the cached `Program` is byte-identical
    /// to decoding per execution — only the wall-clock changes. A
    /// program whose decode fails is never cached, so a bad program
    /// re-errors on every attempt exactly as an uncached one would.
    programs: HashMap<u32, crate::program::Program>,
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
            programs: HashMap::new(),
            table: HashMap::new(),
            hits: 0,
            misses: 0,
        }
    }

    /// Number of distinct program byte-strings interned — diagnostics.
    pub fn distinct_programs(&self) -> usize {
        self.prog_ids.len()
    }

    /// Number of programs decoded into the program cache — diagnostics.
    pub fn decoded_programs(&self) -> usize {
        self.programs.len()
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
        let id = self.prog_id(program_bytes);
        let key = (id, inputs.to_vec());
        if let Some(cached) = self.table.get(&key) {
            if cached.len() == slots.len() {
                slots.copy_from_slice(cached);
                self.hits += 1;
                return Ok(());
            }
        }
        let program = match self.programs.entry(id) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(v) => {
                let family = family_for::<F>()
                    .ok_or(ArtikError::BadHeader("unsupported field family for Artik"))?;
                v.insert(bytecode::decode(program_bytes, Some(family))?)
            }
        };
        let mut ctx = ArtikContext::<F>::new(inputs, slots);
        execute(program, &mut ctx)?;
        self.table.insert(key, slots.to_vec());
        self.misses += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::Instr;
    use crate::program::Program;
    use memory::Bn254Fr;

    /// Read signal 0, square it, write witness slot 0.
    fn square_program_bytes() -> Vec<u8> {
        let body = vec![
            Instr::ReadSignal {
                dst: 0,
                signal_id: 0,
            },
            Instr::FMul { dst: 1, a: 0, b: 0 },
            Instr::WriteWitness { slot_id: 0, src: 1 },
            Instr::Return { srcs: Vec::new() },
        ];
        bytecode::encode(&Program::new(FieldFamily::BnLike256, 2, Vec::new(), body))
    }

    #[test]
    fn misses_share_one_decoded_program() {
        type Fe = FieldElement<Bn254Fr>;
        let bytes = square_program_bytes();
        let mut memo = ArtikMemo::<Bn254Fr>::new();

        let mut out = [Fe::zero()];
        memo.run(&bytes, &[Fe::from_u64(3)], &mut out).expect("run");
        assert_eq!(out[0], Fe::from_u64(9));
        memo.run(&bytes, &[Fe::from_u64(5)], &mut out).expect("run");
        assert_eq!(out[0], Fe::from_u64(25));

        // Two distinct-input misses, one decode.
        assert_eq!(memo.misses, 2);
        assert_eq!(memo.hits, 0);
        assert_eq!(memo.distinct_programs(), 1);
        assert_eq!(memo.decoded_programs(), 1);

        // Identical (program, inputs) is a hit and reproduces the value.
        memo.run(&bytes, &[Fe::from_u64(3)], &mut out).expect("run");
        assert_eq!(out[0], Fe::from_u64(9));
        assert_eq!(memo.hits, 1);
        assert_eq!(memo.decoded_programs(), 1);
    }

    #[test]
    fn bad_program_is_never_cached() {
        type Fe = FieldElement<Bn254Fr>;
        let mut memo = ArtikMemo::<Bn254Fr>::new();
        let garbage = [0u8; 4];
        let mut out = [Fe::zero()];
        assert!(memo.run(&garbage, &[], &mut out).is_err());
        assert!(memo.run(&garbage, &[], &mut out).is_err());
        assert_eq!(memo.decoded_programs(), 0);
        assert_eq!(memo.misses, 0);
    }
}
