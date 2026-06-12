//! Soundness regression for the greedy eliminator's substitution batch.
//!
//! The greedy scan solves every pivot of a round from the original rows,
//! so without canonicalization a value could reference another wire
//! eliminated the same round, leaving a dangling reference the verifier
//! does not enforce (forgeable). The binding criterion these tests pin is
//! "zero eliminated wires referenced in any surviving constraint" (the
//! production census reduced to a unit check); the reconstruction map is
//! additionally required to be acyclic so the witness fixup is well
//! defined.

use std::collections::{HashMap, HashSet};

use memory::{Bn254Fr, FieldElement};

use super::super::flatten::canonicalize_against_constraints;
use super::super::linear::optimize_linear_with_protected;
use super::super::types::SubstitutionMap;
use super::make_lc_var;
use crate::r1cs::{Constraint, ConstraintSystem};

/// The greedy eliminator breaks cycles in its own map, then the driver
/// rewrites every survivor against it (`canonicalize_against_constraints`).
/// This pairing -- greedy as the per-cluster fallback, driver cleaning once
/// at the end -- is exactly what the clustered O1 entry runs, and what
/// every prove path sees.
fn optimize_and_canonicalize(
    constraints: &mut Vec<Constraint<Bn254Fr>>,
    num_pub_inputs: usize,
) -> SubstitutionMap<Bn254Fr> {
    let (mut subs, _stats) =
        optimize_linear_with_protected(constraints, num_pub_inputs, &HashSet::new());
    canonicalize_against_constraints(&mut subs, constraints);
    subs
}

/// The substitution map's key-dependency graph is a DAG: resolving any key
/// terminates at survivors instead of looping. Cycles in the map would make
/// the witness fixup ill-defined, so the canonicalization must break them.
fn map_is_acyclic(subs: &SubstitutionMap<Bn254Fr>) -> bool {
    let keys: HashSet<usize> = subs.keys().copied().collect();
    let mut state: HashMap<usize, u8> = HashMap::new();
    keys.iter()
        .all(|&k| acyclic_from(k, subs, &keys, &mut state))
}

fn acyclic_from(
    k: usize,
    subs: &SubstitutionMap<Bn254Fr>,
    keys: &HashSet<usize>,
    state: &mut HashMap<usize, u8>,
) -> bool {
    match state.get(&k) {
        Some(2) => return true,  // already proven acyclic
        Some(_) => return false, // on the current stack => cycle
        None => {}
    }
    state.insert(k, 1);
    if let Some(lc) = subs.get(&k) {
        for (v, _) in lc.terms() {
            if keys.contains(&v.index()) && !acyclic_from(v.index(), subs, keys, state) {
                return false;
            }
        }
    }
    state.insert(k, 2);
    true
}

/// No surviving constraint references an eliminated wire with a non-zero
/// coefficient.
fn no_dangling_reference(
    constraints: &[Constraint<Bn254Fr>],
    subs: &SubstitutionMap<Bn254Fr>,
) -> bool {
    let zero = FieldElement::<Bn254Fr>::from_u64(0);
    let keys: HashSet<usize> = subs.keys().copied().collect();
    constraints.iter().all(|c| {
        [&c.a, &c.b, &c.c].iter().all(|lc| {
            lc.terms()
                .iter()
                .all(|(v, coeff)| !(keys.contains(&v.index()) && *coeff != zero))
        })
    })
}

#[test]
fn greedy_batched_round_yields_canonical_map() {
    // Row 0: x1 = x2 + a   (pivot x1, value references x2)
    // Row 1: x2 = a        (x2 solved the SAME round => chain x1 -> x2)
    // Row 2: x1 * x1 = a   (quadratic survivor referencing pivot x1)
    let mut cs: ConstraintSystem<Bn254Fr> = ConstraintSystem::new();
    let a = cs.alloc_input();
    let x2 = cs.alloc_witness();
    let x1 = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(x1), make_lc_var(x2) + make_lc_var(a));
    cs.enforce_equal(make_lc_var(x2), make_lc_var(a));
    cs.enforce(make_lc_var(x1), make_lc_var(x1), make_lc_var(a));

    let mut constraints = cs.constraints().to_vec();
    let subs = optimize_and_canonicalize(&mut constraints, cs.num_pub_inputs());

    assert!(subs.contains_key(&x1.index()) && subs.contains_key(&x2.index()));
    assert!(
        no_dangling_reference(&constraints, &subs),
        "no survivor may reference an eliminated wire after the flatten"
    );
    assert!(
        map_is_acyclic(&subs),
        "the map must reconstruct without looping"
    );
}

#[test]
fn cyclic_batch_is_resolved_and_survivors_are_clean() {
    // A 2-cycle: both rows reference x1 and x2. The greedy claims x1 from
    // row 0, then row 1 is forced to claim x2 with a value referencing the
    // now-protected x1 -> subs[x1] references x2 and subs[x2] references
    // x1 before the flatten. The coupled system is full rank, so the
    // flatten eliminates both with survivor-only values.
    let mut cs: ConstraintSystem<Bn254Fr> = ConstraintSystem::new();
    let a = cs.alloc_input();
    let b = cs.alloc_input();
    let x2 = cs.alloc_witness();
    let x1 = cs.alloc_witness();

    // x1 = 2*x2 + a ; x2 = 3*x1 + b  (det 1 - 6 != 0 => unique solution)
    let two = FieldElement::<Bn254Fr>::from_u64(2);
    let three = FieldElement::<Bn254Fr>::from_u64(3);
    let one = FieldElement::<Bn254Fr>::one();
    let mut lc_2x2 = crate::r1cs::LinearCombination::<Bn254Fr>::zero();
    lc_2x2.add_term(x2, two);
    lc_2x2.add_term(a, one);
    let mut lc_3x1 = crate::r1cs::LinearCombination::<Bn254Fr>::zero();
    lc_3x1.add_term(x1, three);
    lc_3x1.add_term(b, one);

    cs.enforce_equal(make_lc_var(x1), lc_2x2);
    cs.enforce_equal(make_lc_var(x2), lc_3x1);
    // A survivor referencing both cycle wires.
    cs.enforce(make_lc_var(x1), make_lc_var(x2), make_lc_var(a));

    let mut constraints = cs.constraints().to_vec();
    let subs = optimize_and_canonicalize(&mut constraints, cs.num_pub_inputs());

    assert!(
        no_dangling_reference(&constraints, &subs),
        "the survivor must not reference either eliminated cycle wire"
    );
    assert!(
        map_is_acyclic(&subs),
        "the resolved cycle must leave an acyclic map"
    );
}

#[test]
fn self_loop_in_map_is_resolved() {
    // One-pass composition can fold a 2-cycle into a self-loop -- a value
    // that references its own key, `s = c*s + survivors`. The resolver must
    // treat that single node as a cycle (`s = survivors / (1 - c)`); before
    // the self-loop fix it was skipped, leaving `s` dangling.
    use super::super::flatten::resolve_cycles;
    use crate::r1cs::{LinearCombination, Variable};

    let s = 7usize;
    let a = 3usize; // a survivor wire
    let half = FieldElement::<Bn254Fr>::from_u64(2)
        .inv()
        .expect("2 invertible");
    let mut value = LinearCombination::<Bn254Fr>::zero();
    value.add_term(Variable(s), half); // (1/2) * s
    value.add_term(Variable(a), FieldElement::one()); // + a
    let mut subs: SubstitutionMap<Bn254Fr> = SubstitutionMap::default();
    subs.insert(s, value);

    let leftovers = resolve_cycles(&mut subs);
    assert!(leftovers.is_empty(), "full-rank self-loop adds no rows");

    // s = (1/2) s + a  =>  s = 2a.
    let resolved = subs.get(&s).expect("s stays eliminated");
    assert!(
        resolved.terms().iter().all(|(v, _)| v.index() != s),
        "the self-reference must be gone"
    );
    let two = FieldElement::<Bn254Fr>::from_u64(2);
    assert_eq!(resolved.terms(), &[(Variable(a), two)], "s resolves to 2a");
}

#[test]
fn rank_deficient_cycle_reverts_and_keeps_the_exposed_constraint() {
    // Two rows over the same pair of wires with DIFFERENT survivor
    // offsets: x1 = x2 + a ; x1 = x2 + b. The greedy claims x1 (row 0)
    // then x2 (row 1, x1 protected) -> a 2-cycle whose coupled system has
    // rank 1. The flatten must: eliminate one wire (x1), revert the other
    // (x2) to a survivor, and re-emit the exposed constraint a == b.
    let mut cs: ConstraintSystem<Bn254Fr> = ConstraintSystem::new();
    let a = cs.alloc_input();
    let b = cs.alloc_input();
    let x2 = cs.alloc_witness();
    let x1 = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(x1), make_lc_var(x2) + make_lc_var(a));
    cs.enforce_equal(make_lc_var(x1), make_lc_var(x2) + make_lc_var(b));
    // A quadratic survivor referencing x1: after the flatten it must
    // reference x2 (the reverted wire), keeping x2 pinned.
    let q = cs.alloc_witness();
    cs.enforce(make_lc_var(x1), make_lc_var(x1), make_lc_var(q));

    let mut constraints = cs.constraints().to_vec();
    let subs = optimize_and_canonicalize(&mut constraints, cs.num_pub_inputs());

    // Exactly one of the coupled wires is eliminated; the other is
    // reverted to a survivor (which one is an arithmetic detail of the
    // pivot order). Either choice is sound.
    let x1_key = subs.contains_key(&x1.index());
    let x2_key = subs.contains_key(&x2.index());
    assert!(x1_key ^ x2_key, "exactly one cycle wire stays eliminated");
    let reverted = if x1_key { x2 } else { x1 };
    assert!(map_is_acyclic(&subs));
    assert!(no_dangling_reference(&constraints, &subs));

    // The reverted wire stays pinned: some surviving constraint references
    // it with a non-zero coefficient.
    let zero = FieldElement::<Bn254Fr>::from_u64(0);
    let reverted_pinned = constraints.iter().any(|c| {
        [&c.a, &c.b, &c.c].iter().any(|lc| {
            lc.terms()
                .iter()
                .any(|(v, coeff)| v.index() == reverted.index() && *coeff != zero)
        })
    });
    assert!(
        reverted_pinned,
        "reverted wire must remain constrained by a survivor"
    );

    // Honest witness (a == b is forced by the exposed constraint):
    // a=b=5, x2=3 => x1=8, q=64.
    let mut witness = vec![FieldElement::<Bn254Fr>::zero(); cs.num_variables()];
    witness[0] = FieldElement::one();
    witness[a.index()] = FieldElement::from_u64(5);
    witness[b.index()] = FieldElement::from_u64(5);
    witness[x2.index()] = FieldElement::from_u64(3);
    witness[x1.index()] = FieldElement::from_u64(8);
    witness[q.index()] = FieldElement::from_u64(64);
    for (idx, lc) in &subs {
        witness[*idx] = lc.evaluate(&witness).expect("survivor-only eval");
    }
    let satisfies = |w: &[FieldElement<Bn254Fr>]| {
        constraints.iter().all(|c| {
            let av = c.a.evaluate(w).expect("a");
            let bv = c.b.evaluate(w).expect("b");
            let cv = c.c.evaluate(w).expect("c");
            av.mul(&bv) == cv
        })
    };
    assert!(
        satisfies(&witness),
        "honest witness must satisfy the fixed R1CS"
    );

    // Forgeability check: flipping the reverted wire without updating the
    // wires that depend on it must be rejected -- it is constrained, not
    // free.
    let mut forged = witness.clone();
    forged[reverted.index()] = FieldElement::from_u64(99);
    assert!(
        !satisfies(&forged),
        "a tampered value for the reverted wire must be rejected"
    );
}

#[test]
fn full_run_satisfies_original_witness() {
    // End-to-end: a chained batch, optimize, then check the optimized
    // system + substitution fixup reproduces a satisfying witness.
    let mut cs: ConstraintSystem<Bn254Fr> = ConstraintSystem::new();
    let a = cs.alloc_input();
    let x2 = cs.alloc_witness();
    let x1 = cs.alloc_witness();
    let q = cs.alloc_witness();

    cs.enforce_equal(make_lc_var(x1), make_lc_var(x2) + make_lc_var(a));
    cs.enforce_equal(make_lc_var(x2), make_lc_var(a));
    cs.enforce(make_lc_var(x1), make_lc_var(x1), make_lc_var(q));

    let mut constraints = cs.constraints().to_vec();
    let subs = optimize_and_canonicalize(&mut constraints, cs.num_pub_inputs());

    // Honest assignment: a=5 => x2=5, x1=10, q=100.
    let mut witness = vec![FieldElement::<Bn254Fr>::zero(); cs.num_variables()];
    witness[0] = FieldElement::one();
    witness[a.index()] = FieldElement::from_u64(5);
    witness[x2.index()] = FieldElement::from_u64(5);
    witness[x1.index()] = FieldElement::from_u64(10);
    witness[q.index()] = FieldElement::from_u64(100);
    // Apply the substitution fixup for eliminated wires.
    for (idx, lc) in &subs {
        witness[*idx] = lc.evaluate(&witness).expect("survivor-only eval");
    }

    for c in &constraints {
        let av = c.a.evaluate(&witness).expect("a");
        let bv = c.b.evaluate(&witness).expect("b");
        let cv = c.c.evaluate(&witness).expect("c");
        assert_eq!(av.mul(&bv), cv, "optimized constraint must hold");
    }
    assert!(map_is_acyclic(&subs));
}

/// A pivot whose flattened form would be copied into many survivors is
/// reverted by the density budget: its defining row is re-emitted once
/// and the wire becomes an ordinary survivor, leaving the map. Sized to
/// cross both the activation mass (uses * size) and the per-key score
/// ((uses - 1) * size); the other tests in this file sit far below the
/// floor and pin the expand-in-place behavior.
#[test]
fn wide_pivot_reverts_to_survivor_row() {
    use crate::r1cs::{LinearCombination, Variable};

    let one = FieldElement::<Bn254Fr>::one();

    // Eliminated wire with a 2,000-term survivor-only value.
    let k = 5usize;
    let mut value = LinearCombination::<Bn254Fr>::zero();
    for i in 0..2_000usize {
        value.add_term(Variable(10_000 + i), one);
    }
    let mut subs: SubstitutionMap<Bn254Fr> = SubstitutionMap::default();
    subs.insert(k, value);

    // 1,000 surviving rows reference the wire: the flatten would copy the
    // 2,000-term form into each of them.
    let mut constraints: Vec<Constraint<Bn254Fr>> = (0..1_000usize)
        .map(|i| Constraint {
            a: LinearCombination::from_constant(one),
            b: make_lc_var(Variable(k)) + make_lc_var(Variable(100_000 + i)),
            c: LinearCombination::zero(),
        })
        .collect();

    canonicalize_against_constraints(&mut subs, &mut constraints);

    assert!(
        subs.is_empty(),
        "wide pivot must leave the substitution map"
    );
    assert_eq!(
        constraints.len(),
        1_001,
        "exactly one re-emitted defining row joins the survivors"
    );
    let wide_rows = constraints
        .iter()
        .filter(|c| c.b.terms().len() == 2_001)
        .count();
    assert_eq!(wide_rows, 1, "the wide form appears once, not per use");
    let keep_term = constraints
        .iter()
        .filter(|c| c.b.terms().iter().any(|(v, _)| v.index() == k))
        .count();
    assert_eq!(
        keep_term, 1_001,
        "every referencing row keeps the wire as a plain survivor term"
    );
    assert!(no_dangling_reference(&constraints, &subs));
}
