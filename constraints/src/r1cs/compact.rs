//! Wire compaction for proving backends.
//!
//! After linear-constraint elimination the system still allocates every
//! wire it ever emitted: substituted-away wires and witness-only
//! intermediates appear in no constraint, but `num_variables` (and the
//! witness vector) keep their slots. Proving backends pay for that
//! directly — a Groth16 proving key holds O(num_variables) group
//! elements, so every unreferenced wire contributes an identity point
//! and a zero QAP column. [`ConstraintSystem::compact_referenced`]
//! produces an equivalent system over only the wires that some
//! constraint references (plus `ONE` and the public inputs), densely
//! renumbered.

use memory::FieldBackend;

use super::linear_combination::{LinearCombination, Variable};
use super::system::{Constraint, ConstraintSystem};

impl<F: FieldBackend> ConstraintSystem<F> {
    /// Build a copy of this system over only the wires referenced by at
    /// least one constraint, plus `ONE` and the public inputs (kept
    /// unconditionally), densely renumbered in ascending order — `ONE`
    /// and the public inputs therefore keep their indices.
    ///
    /// Returns the compacted system and the gather list: `gather[new]`
    /// is the old index of the wire now at `new`, so a witness for the
    /// compacted system is `gather.iter().map(|&old| witness[old])`.
    ///
    /// Constraint count, order, and coefficients are unchanged; only
    /// the `Variable` indices inside the terms are remapped. Dropped
    /// wires appear in no constraint, so a witness satisfies the
    /// original system iff its gathered projection satisfies the
    /// compacted one.
    pub fn compact_referenced(&self) -> (ConstraintSystem<F>, Vec<usize>) {
        let nv = self.num_variables();
        let mut keep = vec![false; nv];
        for slot in keep.iter_mut().take(self.num_pub_inputs() + 1) {
            *slot = true;
        }
        for c in self.constraints() {
            for lc in [&c.a, &c.b, &c.c] {
                for (var, _) in lc.terms() {
                    keep[var.index()] = true;
                }
            }
        }

        let mut old_to_new = vec![usize::MAX; nv];
        let mut gather = Vec::with_capacity(keep.iter().filter(|k| **k).count());
        for (old, kept) in keep.iter().enumerate() {
            if *kept {
                old_to_new[old] = gather.len();
                gather.push(old);
            }
        }

        let remap_lc = |lc: &LinearCombination<F>| -> LinearCombination<F> {
            LinearCombination {
                terms: lc
                    .terms()
                    .iter()
                    .map(|(var, coeff)| (Variable(old_to_new[var.index()]), *coeff))
                    .collect(),
            }
        };
        let constraints: Vec<Constraint<F>> = self
            .constraints()
            .iter()
            .map(|c| Constraint {
                a: remap_lc(&c.a),
                b: remap_lc(&c.b),
                c: remap_lc(&c.c),
            })
            .collect();

        let compacted = ConstraintSystem::from_compacted_parts(
            gather.len(),
            self.num_pub_inputs(),
            constraints,
        );
        (compacted, gather)
    }
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use crate::r1cs::{ConstraintSystem, LinearCombination};

    type Fe = FieldElement<Bn254Fr>;

    fn lc_var(v: crate::r1cs::Variable) -> LinearCombination<Bn254Fr> {
        LinearCombination::from_variable(v)
    }

    /// One public input, one referenced witness wire, one wire that is
    /// allocated but never referenced: x * x = y with a dead wire in
    /// between.
    fn gappy_system() -> (ConstraintSystem<Bn254Fr>, Vec<Fe>) {
        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let public = cs.alloc_input();
        let x = cs.alloc_witness();
        let _dead = cs.alloc_witness();
        let y = cs.alloc_witness();
        cs.enforce(lc_var(x), lc_var(x), lc_var(y));
        cs.enforce_equal(lc_var(public), lc_var(y));

        // witness = [1, public=9, x=3, dead=42, y=9]
        let witness = vec![
            Fe::from_u64(1),
            Fe::from_u64(9),
            Fe::from_u64(3),
            Fe::from_u64(42),
            Fe::from_u64(9),
        ];
        cs.verify(&witness).expect("original system satisfied");
        (cs, witness)
    }

    #[test]
    fn drops_unreferenced_wires_and_keeps_publics_identity() {
        let (cs, _witness) = gappy_system();
        let (compacted, gather) = cs.compact_referenced();

        assert_eq!(compacted.num_variables(), 4); // ONE, public, x, y
        assert_eq!(compacted.num_pub_inputs(), cs.num_pub_inputs());
        assert_eq!(compacted.num_constraints(), cs.num_constraints());
        // ONE + publics map to themselves; the dead wire is gone.
        assert_eq!(gather[0], 0);
        assert_eq!(gather[1], 1);
        assert!(!gather.contains(&3));
    }

    #[test]
    fn gathered_witness_satisfies_compacted_system() {
        let (cs, witness) = gappy_system();
        let (compacted, gather) = cs.compact_referenced();

        let gathered: Vec<Fe> = gather.iter().map(|&old| witness[old]).collect();
        assert_eq!(gathered.len(), compacted.num_variables());
        compacted
            .verify(&gathered)
            .expect("compacted system satisfied by gathered witness");
    }

    #[test]
    fn coefficients_and_order_survive_renumbering() {
        let (cs, _witness) = gappy_system();
        let (compacted, gather) = cs.compact_referenced();

        for (original, remapped) in cs.constraints().iter().zip(compacted.constraints()) {
            for (lc_o, lc_r) in [
                (&original.a, &remapped.a),
                (&original.b, &remapped.b),
                (&original.c, &remapped.c),
            ] {
                assert_eq!(lc_o.terms().len(), lc_r.terms().len());
                for ((var_o, coeff_o), (var_r, coeff_r)) in lc_o.terms().iter().zip(lc_r.terms()) {
                    assert_eq!(coeff_o, coeff_r);
                    assert_eq!(gather[var_r.index()], var_o.index());
                }
            }
        }
    }

    #[test]
    fn fully_referenced_system_is_unchanged() {
        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let x = cs.alloc_witness();
        let y = cs.alloc_witness();
        cs.enforce(lc_var(x), lc_var(x), lc_var(y));

        let (compacted, gather) = cs.compact_referenced();
        assert_eq!(compacted.num_variables(), cs.num_variables());
        assert_eq!(gather, vec![0, 1, 2]);
    }

    #[test]
    fn unreferenced_public_inputs_are_kept() {
        let mut cs = ConstraintSystem::<Bn254Fr>::new();
        let _unused_public = cs.alloc_input();
        let x = cs.alloc_witness();
        cs.enforce(lc_var(x), lc_var(x), lc_var(x));

        let (compacted, gather) = cs.compact_referenced();
        assert_eq!(compacted.num_pub_inputs(), 1);
        assert_eq!(gather[1], 1);
        assert_eq!(compacted.num_variables(), 3);
    }
}
