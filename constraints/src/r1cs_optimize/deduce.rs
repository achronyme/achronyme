//! O2 pass — DEDUCE linear constraints from quadratic constraints.
//!
//! Algorithm (from "Distilling Constraints in Zero-Knowledge Protocols",
//! CAV 2022):
//!
//! For each R1CS constraint A×B = C, expand A×B into:
//!   - Quadratic monomials: `a_i * b_j * w_i * w_j`  (i>0, j>0)
//!   - Linear part: terms involving `Variable::ONE` from A×B, minus C
//!
//! Build a matrix M where rows = quadratic monomials, columns =
//! constraints. M[mono, k] = coefficient of monomial `mono` in
//! constraint k's expanded A×B.
//!
//! Find the null space of M via Gaussian elimination: vectors v
//! such that M×v=0. For each null vector,
//! `Σ v_k * (linear_part_k) = 0` is a deduced linear constraint.
//!
//! These deduced constraints are added to the system, and O1
//! optimization is re-run. The process repeats until no more
//! linear constraints can be deduced.
//!
//! [`optimize_o2`] is the public entry that composes O1 + decompose +
//! DEDUCE + O1-with-protection + O1-cleanup in a converging outer
//! loop (bounded to 50 iterations with rollback on no improvement).

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use super::linear_cluster::{
    optimize_linear_clustered as optimize_linear,
    optimize_linear_clustered_with_protected as optimize_linear_with_protected,
};
use super::predicates::lc_fingerprint;
use super::substitution::apply_substitution_in_place;
use super::types::{R1CSOptimizeResult, SubstitutionMap};
use crate::r1cs::{Constraint, LinearCombination, Variable};

/// Canonical quadratic monomial: (i, j) with i <= j, both > 0.
pub(super) type Monomial = (usize, usize);

/// Expand constraint A x B into quadratic monomials and a "linear residual".
///
/// The constraint says: quadratic_part + linear_residual = 0.
/// Where linear_residual = (linear terms from A x B) - C.
pub(super) fn expand_constraint_product<F: FieldBackend>(
    constraint: &Constraint<F>,
) -> (HashMap<Monomial, FieldElement<F>>, LinearCombination<F>) {
    let a = constraint.a.simplify();
    let b = constraint.b.simplify();
    let c = constraint.c.simplify();

    let mut quadratic: HashMap<Monomial, FieldElement<F>> = HashMap::new();
    let mut linear = LinearCombination::<F>::zero();

    // Expand A × B
    for &(var_i, coeff_i) in &a.terms {
        for &(var_j, coeff_j) in &b.terms {
            let product = coeff_i.mul(&coeff_j);
            if product.is_zero() {
                continue;
            }

            let i = var_i.index();
            let j = var_j.index();

            if i == 0 || j == 0 {
                // Involves Variable::ONE → linear term
                // w_0 * w_j = w_j, w_i * w_0 = w_i, w_0 * w_0 = w_0
                if i == 0 && j == 0 {
                    linear.add_term(Variable::ONE, product);
                } else if i == 0 {
                    linear.add_term(var_j, product);
                } else {
                    linear.add_term(var_i, product);
                }
            } else {
                // Genuine quadratic: w_i * w_j
                let mono: Monomial = if i <= j { (i, j) } else { (j, i) };
                let entry = quadratic
                    .entry(mono)
                    .or_insert_with(FieldElement::<F>::zero);
                *entry = entry.add(&product);
            }
        }
    }

    // Subtract C from the linear part (constraint is A×B - C = 0)
    for &(var, coeff) in &c.terms {
        linear.add_term(var, coeff.neg());
    }

    // Remove zero entries
    quadratic.retain(|_, v| !v.is_zero());
    let linear = linear.simplify();

    (quadratic, linear)
}

/// Deduce linear constraints implied by quadratic constraints via Gaussian elimination.
///
/// Returns a list of `LinearCombination`s, each representing `lc = 0`.
/// Only returns non-trivial constraints (at least one variable term).
fn deduce_linear_from_quadratic<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> Vec<LinearCombination<F>> {
    if constraints.is_empty() {
        return vec![];
    }

    // 1. Expand all constraints into quadratic monomials + linear residual
    let expanded: Vec<_> = constraints
        .iter()
        .map(|c| expand_constraint_product(c))
        .collect();

    // 2. Collect and index all distinct quadratic monomials
    let mut monomial_list: Vec<Monomial> = Vec::new();
    {
        let mut monomial_set: HashSet<Monomial> = HashSet::new();
        for (quad, _) in &expanded {
            for &mono in quad.keys() {
                if monomial_set.insert(mono) {
                    monomial_list.push(mono);
                }
            }
        }
    }
    // Sort for deterministic processing
    monomial_list.sort();

    let mono_idx: HashMap<Monomial, usize> = monomial_list
        .iter()
        .enumerate()
        .map(|(idx, &mono)| (mono, idx))
        .collect();

    let q = monomial_list.len(); // rows (monomials)
    let k = constraints.len(); // columns (constraints)

    if q == 0 {
        return vec![];
    }

    // 3. Build work rows: each row = one constraint = (quadratic_vector, linear_part)
    //    Gaussian elimination combines rows → combining constraints.
    //    When the quadratic part becomes zero, the linear part is a deduced constraint.
    let mut quad_matrix: Vec<Vec<FieldElement<F>>> = Vec::with_capacity(k);
    let mut linear_parts: Vec<LinearCombination<F>> = Vec::with_capacity(k);

    for (quad, lin) in &expanded {
        let mut row = vec![FieldElement::<F>::zero(); q];
        for (&mono, &coeff) in quad {
            row[mono_idx[&mono]] = coeff;
        }
        quad_matrix.push(row);
        linear_parts.push(lin.clone());
    }

    // 4. Gaussian elimination: row-reduce using quadratic columns as pivots.
    //    We do full elimination (reduced row echelon form) so that
    //    dependent rows become all-zero in the quadratic part.
    let mut pivot_col_for_row: Vec<Option<usize>> = vec![None; k];
    let mut used_as_pivot: Vec<bool> = vec![false; k];

    for col in 0..q {
        // Find pivot: first non-zero entry in this column among non-pivot rows
        let pivot_row = (0..k).find(|&r| !used_as_pivot[r] && !quad_matrix[r][col].is_zero());

        let Some(pr) = pivot_row else {
            continue;
        };
        used_as_pivot[pr] = true;
        pivot_col_for_row[pr] = Some(col);

        // Normalize pivot row so the pivot entry becomes 1
        let pivot_inv = match quad_matrix[pr][col].inv() {
            Some(inv) => inv,
            None => continue,
        };

        for entry in &mut quad_matrix[pr] {
            *entry = entry.mul(&pivot_inv);
        }
        linear_parts[pr] = linear_parts[pr].clone() * pivot_inv;

        // Eliminate this column from all other rows
        for r in 0..k {
            if r == pr {
                continue;
            }
            let factor = quad_matrix[r][col];
            if factor.is_zero() {
                continue;
            }
            let neg_factor = factor.neg();
            // Can't borrow quad_matrix mutably twice, so clone the pivot row
            let pivot_row: Vec<FieldElement<F>> = quad_matrix[pr].clone();
            for (entry, &pivot_val) in quad_matrix[r].iter_mut().zip(pivot_row.iter()) {
                let delta = pivot_val.mul(&neg_factor);
                *entry = entry.add(&delta);
            }
            let scaled = linear_parts[pr].clone() * neg_factor;
            linear_parts[r] = (linear_parts[r].clone() + scaled).simplify();
        }
    }

    // 5. Extract deduced linear constraints: rows where quadratic part is all zero
    let mut deduced: Vec<LinearCombination<F>> = Vec::new();
    for r in 0..k {
        if used_as_pivot[r] {
            continue; // pivot rows have non-zero quadratic part by construction
        }
        let all_zero = quad_matrix[r].iter().all(|v| v.is_zero());
        if all_zero {
            let lin = linear_parts[r].simplify();
            if !lin.terms.is_empty() {
                deduced.push(lin);
            }
        }
    }

    deduced
}

/// Decompose quadratic constraints with multi-term A/B into simple form.
///
/// For each constraint `A × B = C` where A or B has >1 variable term,
/// introduces an auxiliary wire `w` such that `w = multi_term_LC` (as a
/// new linear constraint) and replaces the multi-term operand with `w`.
///
/// This transforms `(a+b+c) × d = e` into `w × d = e` + `1×(a+b+c-w)=0`,
/// reducing the quadratic monomial count from N×M to 1 per constraint.
/// DEDUCE can then find algebraic dependencies between the simplified
/// monomials more effectively.
pub(super) fn decompose_for_deduce_tracked<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    aux_wire_indices: &mut HashSet<usize>,
) {
    // Find max variable index to allocate beyond it
    let mut max_var: usize = 0;
    for c in constraints.iter() {
        for &(var, _) in
            c.a.terms
                .iter()
                .chain(c.b.terms.iter())
                .chain(c.c.terms.iter())
        {
            max_var = max_var.max(var.index());
        }
    }

    // Map from LC fingerprint → shared auxiliary wire.
    // If the same sub-expression appears in multiple constraints,
    // they share the same wire so DEDUCE sees shared monomials.
    let mut lc_cache: HashMap<Vec<u8>, Variable> = HashMap::new();
    let mut new_linear: Vec<Constraint<F>> = Vec::new();

    for constraint in constraints.iter_mut() {
        let a_simplified = constraint.a.simplify();
        let b_simplified = constraint.b.simplify();

        // Skip linear constraints (one side is constant)
        if a_simplified.constant_value().is_some() || b_simplified.constant_value().is_some() {
            continue;
        }

        // Count non-constant variable terms
        let a_var_count = a_simplified
            .terms
            .iter()
            .filter(|(v, _)| v.index() > 0)
            .count();
        let b_var_count = b_simplified
            .terms
            .iter()
            .filter(|(v, _)| v.index() > 0)
            .count();

        // Decompose A if it has >1 variable term
        if a_var_count > 1 {
            let fp = lc_fingerprint(&a_simplified);
            let cache_len = lc_cache.len();
            let w = *lc_cache.entry(fp).or_insert_with(|| {
                max_var += 1;
                let w = Variable(max_var);
                let mut diff = a_simplified.clone();
                diff.add_term(w, FieldElement::<F>::one().neg());
                new_linear.push(Constraint {
                    a: LinearCombination::from_constant(FieldElement::one()),
                    b: diff,
                    c: LinearCombination::zero(),
                });
                w
            });
            if lc_cache.len() > cache_len {
                aux_wire_indices.insert(w.index());
            }
            constraint.a = LinearCombination::from_variable(w);
        }

        // Decompose B if it has >1 variable term
        if b_var_count > 1 {
            let fp = lc_fingerprint(&b_simplified);
            let cache_len = lc_cache.len();
            let w = *lc_cache.entry(fp).or_insert_with(|| {
                max_var += 1;
                let w = Variable(max_var);
                let mut diff = b_simplified.clone();
                diff.add_term(w, FieldElement::<F>::one().neg());
                new_linear.push(Constraint {
                    a: LinearCombination::from_constant(FieldElement::one()),
                    b: diff,
                    c: LinearCombination::zero(),
                });
                w
            });
            if lc_cache.len() > cache_len {
                aux_wire_indices.insert(w.index());
            }
            constraint.b = LinearCombination::from_variable(w);
        }
    }

    constraints.extend(new_linear);
}

/// O2 optimization: O1 fixpoint + decompose + DEDUCE + O1.
///
/// 1. **O1 fixpoint**: Standard linear constraint elimination.
/// 2. **Decompose**: Introduces auxiliary wires to break multi-term A/B in
///    quadratic constraints into single-variable form. This reduces each
///    constraint's monomial count from N×M to 1, making the monomial matrix
///    for DEDUCE small and dense.
/// 3. **DEDUCE**: Gaussian elimination on the monomial matrix finds linear
///    constraints implied by the quadratic constraints.
/// 4. **O1 again**: Processes deduced constraints and eliminates auxiliary
///    wires introduced by the decomposition.
///
/// Repeats steps 2-4 until convergence. Rolls back if no improvement.
pub fn optimize_o2<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    optimize_o2_with_deducer(constraints, num_pub_inputs, deduce_linear_from_quadratic)
}

/// Generic O2 outer loop: parameterised over the linear-deduction routine
/// run on the post-decompose constraint set.
///
/// `optimize_o2` plugs in the dense `deduce_linear_from_quadratic`. The
/// sparse path (sibling `deduce_sparse` module) plugs in a clustered
/// HashMap-row variant. The wrapping O1-fixpoint, decompose, protected
/// O1, cleanup O1, aux-wire bookkeeping, rollback, and stats accumulation
/// are identical across both paths and live here.
pub(super) fn optimize_o2_with_deducer<F, D>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
    deducer: D,
) -> (SubstitutionMap<F>, R1CSOptimizeResult)
where
    F: FieldBackend,
    D: Fn(&[Constraint<F>]) -> Vec<LinearCombination<F>>,
{
    let constraints_before = constraints.len();

    // Phase 1: O1 fixpoint (standard linear elimination)
    let (mut all_subs, o1_stats) = optimize_linear(constraints, num_pub_inputs);

    let mut total_vars_eliminated = o1_stats.variables_eliminated;
    let mut total_trivial_removed = o1_stats.trivial_removed;
    let mut total_duplicates_removed = o1_stats.duplicates_removed;
    let mut total_rounds = o1_stats.rounds;
    let mut all_round_details: Vec<(usize, usize)> = o1_stats.round_details;

    // Phase 2: Decompose + DEDUCE + protected O1 + cleanup O1
    //
    // 1. Decompose multi-term A/B in quadratic constraints into auxiliary wires
    // 2. DEDUCE finds linear constraints from the simplified monomials
    // 3. O1 runs with auxiliary wires PROTECTED (so DEDUCE structure is preserved)
    //    -> this only eliminates variables from deduced + existing constraints
    // 4. Second O1 run WITHOUT protection eliminates auxiliary wires
    // 5. Repeat until no improvement
    for _outer in 0..50 {
        let count_before = constraints.len();
        let saved = constraints.clone();

        // Step 1: Decompose + record aux wire definitions
        let mut aux_wire_indices: HashSet<usize> = HashSet::new();
        let mut aux_definitions: HashMap<usize, LinearCombination<F>> = HashMap::new();
        {
            // Capture definitions before decomposition modifies constraints
            let pre_count = constraints.len();
            decompose_for_deduce_tracked(constraints, &mut aux_wire_indices);
            // Extract definitions from new linear constraints: 1 x (LC - w) = 0 -> w = LC
            for c in &constraints[pre_count..] {
                let b = c.b.simplify();
                // Find the aux wire term (negative coefficient, index in aux_wire_indices)
                for (var, coeff) in &b.terms {
                    if aux_wire_indices.contains(&var.index()) {
                        // w = (remaining terms) / (-coeff)
                        let inv = match coeff.neg().inv() {
                            Some(inv) => inv,
                            None => continue,
                        };
                        let mut def = LinearCombination::zero();
                        for (v2, c2) in &b.terms {
                            if v2 != var {
                                def.add_term(*v2, c2.mul(&inv));
                            }
                        }
                        aux_definitions.insert(var.index(), def.simplify());
                        break;
                    }
                }
            }
        }

        // Step 2: DEDUCE on decomposed system
        let deduced = deducer(constraints);

        if deduced.is_empty() {
            *constraints = saved;
            break;
        }

        // Add deduced constraints
        for lc in &deduced {
            constraints.push(Constraint {
                a: LinearCombination::from_constant(FieldElement::one()),
                b: lc.clone(),
                c: LinearCombination::zero(),
            });
        }

        // Step 3: O1 with auxiliary wires PROTECTED -- processes deductions
        // without destroying the decomposition wire structure
        let (new_subs, stats) =
            optimize_linear_with_protected(constraints, num_pub_inputs, &aux_wire_indices);

        total_vars_eliminated += stats.variables_eliminated;
        total_trivial_removed += stats.trivial_removed;
        total_duplicates_removed += stats.duplicates_removed;
        total_rounds += stats.rounds;
        all_round_details.extend(stats.round_details);

        for expr in all_subs.values_mut() {
            apply_substitution_in_place(expr, &new_subs);
        }
        all_subs.extend(new_subs);

        // Step 4: O1 WITHOUT protection -- eliminates auxiliary wires
        let (cleanup_subs, cleanup_stats) = optimize_linear(constraints, num_pub_inputs);

        total_vars_eliminated += cleanup_stats.variables_eliminated;
        total_trivial_removed += cleanup_stats.trivial_removed;
        total_duplicates_removed += cleanup_stats.duplicates_removed;
        total_rounds += cleanup_stats.rounds;
        all_round_details.extend(cleanup_stats.round_details);

        for expr in all_subs.values_mut() {
            apply_substitution_in_place(expr, &cleanup_subs);
        }
        all_subs.extend(cleanup_subs);

        // Resolve any remaining auxiliary wire references in substitution map.
        // Protected O1 may have used deduced constraints containing aux wires,
        // and cleanup O1 may not have eliminated all of them.
        let aux_subs: SubstitutionMap<F> = aux_definitions.clone();
        for expr in all_subs.values_mut() {
            apply_substitution_in_place(expr, &aux_subs);
        }
        // Remove aux wire entries from the substitution map (they don't exist
        // in the original witness vector)
        all_subs.retain(|k, _| !aux_wire_indices.contains(k));

        if constraints.len() >= count_before {
            // No improvement -- revert
            *constraints = saved;
            break;
        }
    }

    let result = R1CSOptimizeResult {
        constraints_before,
        constraints_after: constraints.len(),
        variables_eliminated: total_vars_eliminated,
        duplicates_removed: total_duplicates_removed,
        trivial_removed: total_trivial_removed,
        rounds: total_rounds,
        round_details: all_round_details,
    };

    (all_subs, result)
}
