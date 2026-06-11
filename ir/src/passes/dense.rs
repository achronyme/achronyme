//! Dense, index-addressed state for the optimization passes.
//!
//! Pass-internal lookups are keyed by [`SsaVar`], whose numbering is
//! dense (`0..next_var`) on every production lowering path. Hash-keyed
//! maps over millions of such keys pay hashing, probing, and resize
//! churn for no benefit; the containers here replace them with direct
//! vector indexing. All accessors are out-of-range safe (a query past
//! the tracked range answers "absent") and writes grow on demand, so
//! programs whose `next_var` watermark is stale still work.

use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar};

/// Bit set over SSA variable indices.
#[derive(Clone, Debug, Default)]
pub struct DenseVarSet {
    words: Vec<u64>,
}

impl DenseVarSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-size for variables `0..n_vars`.
    pub fn with_capacity(n_vars: usize) -> Self {
        Self {
            words: vec![0; n_vars.div_ceil(64)],
        }
    }

    pub fn contains(&self, v: SsaVar) -> bool {
        let i = v.0 as usize;
        self.words
            .get(i / 64)
            .is_some_and(|w| w & (1u64 << (i % 64)) != 0)
    }

    /// Insert `v`, growing if needed. Returns `true` iff newly inserted.
    pub fn insert(&mut self, v: SsaVar) -> bool {
        let i = v.0 as usize;
        let word = i / 64;
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        let mask = 1u64 << (i % 64);
        let newly = self.words[word] & mask == 0;
        self.words[word] |= mask;
        newly
    }

    /// Iterate the contained variables in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = SsaVar> + '_ {
        self.words.iter().enumerate().flat_map(|(wi, &w)| {
            let mut bits = w;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let b = bits.trailing_zeros();
                bits &= bits - 1;
                Some(SsaVar(wi as u64 * 64 + b as u64))
            })
        })
    }
}

impl FromIterator<SsaVar> for DenseVarSet {
    fn from_iter<I: IntoIterator<Item = SsaVar>>(iter: I) -> Self {
        let mut set = Self::new();
        for v in iter {
            set.insert(v);
        }
        set
    }
}

const NO_DEF: usize = usize::MAX;

/// Instruction index of the defining instruction per variable.
///
/// Indexes only [`Instruction::result_var`] — secondary results
/// (`Decompose` bits, extra `WitnessCall` outputs) stay absent, and a
/// later definition of the same variable overwrites an earlier one.
/// Both properties mirror the `HashMap` def-map this replaces.
pub(crate) struct DefIndex {
    idx: Vec<usize>,
    built_len: usize,
}

impl DefIndex {
    pub(crate) fn build<F: FieldBackend>(program: &IrProgram<F>) -> Self {
        let mut idx = vec![NO_DEF; program.next_var() as usize];
        for (i, inst) in program.instructions.iter().enumerate() {
            let r = inst.result_var().0 as usize;
            if r >= idx.len() {
                idx.resize(r + 1, NO_DEF);
            }
            idx[r] = i;
        }
        Self {
            idx,
            built_len: program.len(),
        }
    }

    pub(crate) fn get<'p, F: FieldBackend>(
        &self,
        program: &'p IrProgram<F>,
        v: SsaVar,
    ) -> Option<&'p Instruction<F>> {
        debug_assert_eq!(
            program.len(),
            self.built_len,
            "DefIndex used on a mutated program"
        );
        let i = *self.idx.get(v.0 as usize)?;
        program.instructions.get(i)
    }
}

/// Constant value per variable defined by a `Const` instruction
/// (later definitions overwrite, mirroring the `HashMap` it replaces).
pub(crate) struct ConstIndex {
    idx: Vec<usize>,
    built_len: usize,
}

impl ConstIndex {
    pub(crate) fn build<F: FieldBackend>(program: &IrProgram<F>) -> Self {
        let mut idx = vec![NO_DEF; program.next_var() as usize];
        for (i, inst) in program.instructions.iter().enumerate() {
            if let Instruction::Const { result, .. } = inst {
                let r = result.0 as usize;
                if r >= idx.len() {
                    idx.resize(r + 1, NO_DEF);
                }
                idx[r] = i;
            }
        }
        Self {
            idx,
            built_len: program.len(),
        }
    }

    pub(crate) fn get<'p, F: FieldBackend>(
        &self,
        program: &'p IrProgram<F>,
        v: SsaVar,
    ) -> Option<&'p FieldElement<F>> {
        debug_assert_eq!(
            program.len(),
            self.built_len,
            "ConstIndex used on a mutated program"
        );
        let i = *self.idx.get(v.0 as usize)?;
        match program.instructions.get(i) {
            Some(Instruction::Const { value, .. }) => Some(value),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use memory::FieldElement;

    use super::*;
    use crate::types::{Instruction, IrProgram, Visibility};

    #[test]
    fn dense_set_grows_and_iterates_in_order() {
        let mut set = DenseVarSet::new();
        assert!(!set.contains(SsaVar(1000)));
        assert!(set.insert(SsaVar(1000)));
        assert!(!set.insert(SsaVar(1000)));
        assert!(set.insert(SsaVar(3)));
        assert!(set.contains(SsaVar(3)));
        assert!(set.contains(SsaVar(1000)));
        let vars: Vec<_> = set.iter().collect();
        assert_eq!(vars, vec![SsaVar(3), SsaVar(1000)]);
    }

    #[test]
    fn def_index_last_definition_wins() {
        // Degenerate (non-SSA) input: the HashMap def-map this replaces
        // kept the last definition; the dense index must match.
        let mut p: IrProgram = IrProgram::new();
        let v = p.fresh_var();
        p.push(Instruction::Const {
            result: v,
            value: FieldElement::from_u64(1),
        });
        p.push(Instruction::Input {
            result: v,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let def = DefIndex::build(&p);
        assert!(matches!(def.get(&p, v), Some(Instruction::Input { .. })));
        // The Const index still resolves the Const definition.
        let consts = ConstIndex::build(&p);
        assert!(consts.get(&p, v).is_some());
    }

    #[test]
    fn decompose_bits_are_not_definitions() {
        // `decompose_sum` relies on secondary results staying absent
        // from the def index so a bit variable falls through to the
        // boolean-leaf check.
        let mut p: IrProgram = IrProgram::new();
        let operand = p.fresh_var();
        p.push(Instruction::Input {
            result: operand,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let result = p.fresh_var();
        let bit0 = p.fresh_var();
        let bit1 = p.fresh_var();
        p.push(Instruction::Decompose {
            result,
            operand,
            num_bits: 2,
            bit_results: vec![bit0, bit1],
        });
        let def = DefIndex::build(&p);
        assert!(def.get(&p, result).is_some());
        assert!(def.get(&p, bit0).is_none());
        assert!(def.get(&p, bit1).is_none());
        // Out-of-range query is safely absent.
        assert!(def.get(&p, SsaVar(1_000_000)).is_none());
    }
}
