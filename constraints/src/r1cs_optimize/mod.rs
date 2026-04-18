//! R1CS Linear Constraint Elimination
//!
//! Identifies constraints of the form `k * LC_a = LC_b` (where k is a nonzero
//! constant) and substitutes one variable away, eliminating the constraint.
//! Runs to fixpoint — each round may expose new linear constraints.
//!
//! This is the R1CS analogue of circom's `--O1` simplification pass.

use std::collections::{HashMap, HashSet};

use memory::{FieldBackend, FieldElement};

use crate::r1cs::{Constraint, LinearCombination, Variable};

/// Statistics from linear constraint elimination.
#[derive(Debug, Clone)]
pub struct R1CSOptimizeResult {
    /// Number of constraints before optimization.
    pub constraints_before: usize,
    /// Number of constraints after optimization.
    pub constraints_after: usize,
    /// Number of variables substituted away.
    pub variables_eliminated: usize,
    /// Number of duplicate non-linear constraints removed.
    pub duplicates_removed: usize,
    /// Number of trivially-satisfied constraints removed (0*B=0, k1*k2=k3).
    pub trivial_removed: usize,
    /// Number of fixpoint rounds executed.
    pub rounds: usize,
    /// Per-round breakdown: (linear_eliminated, newly_linear_from_nonlinear).
    pub round_details: Vec<(usize, usize)>,
}

/// Maps a variable index to the LC that replaces it.
pub type SubstitutionMap<F> = HashMap<usize, LinearCombination<F>>;

/// Apply all substitutions in `subs` to a linear combination.
///
/// For each term `(var, coeff)` in `lc`: if `var` is in `subs`, replace the
/// term with `coeff * subs[var]`. Returns the simplified result.
fn apply_substitution<F: FieldBackend>(
    lc: &LinearCombination<F>,
    subs: &SubstitutionMap<F>,
) -> LinearCombination<F> {
    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in &lc.terms {
        if let Some(replacement) = subs.get(&var.index()) {
            // var -> replacement LC, scaled by coeff
            result = result + replacement.clone() * *coeff;
        } else {
            result.add_term(*var, *coeff);
        }
    }
    result.simplify()
}

/// Apply substitutions to all three LCs in a constraint.
fn apply_substitution_to_constraint<F: FieldBackend>(
    constraint: &Constraint<F>,
    subs: &SubstitutionMap<F>,
) -> Constraint<F> {
    Constraint {
        a: apply_substitution(&constraint.a, subs),
        b: apply_substitution(&constraint.b, subs),
        c: apply_substitution(&constraint.c, subs),
    }
}

/// Check if a constraint is linear (one side is a constant).
///
/// Returns `Some((constant_value, other_lc, c_lc))` where the constraint
/// encodes `constant * other_lc = c_lc`. Returns `None` if both A and B
/// contain variables (genuinely quadratic).
///
/// Also handles the zero-product case: if A=0 or B=0, the constraint
/// reduces to `C = 0`, returned as `(1, zero_lc, c_lc)`.
fn is_linear<F: FieldBackend>(
    constraint: &Constraint<F>,
) -> Option<(FieldElement<F>, LinearCombination<F>, LinearCombination<F>)> {
    let a_simplified = constraint.a.simplify();
    if let Some(k) = a_simplified.constant_value() {
        if !k.is_zero() {
            return Some((k, constraint.b.simplify(), constraint.c.simplify()));
        }
        // A = 0: constraint is 0 * B = C, i.e., C = 0
        // Encode as: 1 * 0 = C (so combined = C - 0 = C, solve for var in C)
        let c_simplified = constraint.c.simplify();
        if !c_simplified.terms.is_empty() {
            return Some((FieldElement::one(), LinearCombination::zero(), c_simplified));
        }
        // C is also zero → trivially satisfied, handled elsewhere
        return None;
    }
    let b_simplified = constraint.b.simplify();
    if let Some(k) = b_simplified.constant_value() {
        if !k.is_zero() {
            return Some((k, constraint.a.simplify(), constraint.c.simplify()));
        }
        // B = 0: constraint is A * 0 = C, i.e., C = 0
        let c_simplified = constraint.c.simplify();
        if !c_simplified.terms.is_empty() {
            return Some((FieldElement::one(), LinearCombination::zero(), c_simplified));
        }
        return None;
    }
    None
}

/// Count how many constraints each variable appears in (across A, B, C).
fn compute_variable_frequency<F: FieldBackend>(
    constraints: &[Constraint<F>],
) -> HashMap<usize, usize> {
    let mut freq: HashMap<usize, usize> = HashMap::new();
    for constraint in constraints {
        let mut vars_in_constraint: HashSet<usize> = HashSet::new();
        for (var, _) in &constraint.a.terms {
            vars_in_constraint.insert(var.index());
        }
        for (var, _) in &constraint.b.terms {
            vars_in_constraint.insert(var.index());
        }
        for (var, _) in &constraint.c.terms {
            vars_in_constraint.insert(var.index());
        }
        for var_idx in vars_in_constraint {
            *freq.entry(var_idx).or_insert(0) += 1;
        }
    }
    freq
}

/// Check if a constraint is trivially satisfied regardless of witness values.
///
/// Catches patterns after substitution:
/// - `0 * B = 0` or `A * 0 = 0` (zero product with zero C)
/// - `k1 * k2 = k3` where k1*k2 == k3 (fully constant, tautological)
/// - `k * LC = C` where C - k*LC simplifies to zero (tautological linear)
fn is_trivially_satisfied<F: FieldBackend>(constraint: &Constraint<F>) -> bool {
    let a = constraint.a.simplify();
    let b = constraint.b.simplify();
    let c = constraint.c.simplify();

    // If A or B simplifies to zero, then A*B = 0, constraint holds iff C = 0
    if (a.terms.is_empty() || b.terms.is_empty()) && c.terms.is_empty() {
        return true;
    }

    // All three are constants: verify k_a * k_b == k_c
    if let (Some(ka), Some(kb), Some(kc)) =
        (a.constant_value(), b.constant_value(), c.constant_value())
    {
        return ka.mul(&kb) == kc;
    }

    // Tautological linear: k * LC = C where C == k*LC
    // This happens when variable substitution makes both sides identical.
    if let Some(ka) = a.constant_value() {
        if !ka.is_zero() {
            let diff = (c.clone() - b.clone() * ka).simplify();
            if diff.terms.is_empty() {
                return true;
            }
        }
    }
    if let Some(kb) = b.constant_value() {
        if !kb.is_zero() {
            let diff = (c - a * kb).simplify();
            if diff.terms.is_empty() {
                return true;
            }
        }
    }

    false
}

/// Given an LC that must equal zero, solve for a non-protected variable.
///
/// E.g., for `3*x + 2*y - z + 5*ONE = 0`, solving for z gives:
/// `z = 3*x + 2*y + 5*ONE`.
///
/// Prefers the variable that appears in the most constraints (maximizes
/// propagation). Breaks ties by highest index (intermediate wires).
fn solve_for_variable<F: FieldBackend>(
    lc: LinearCombination<F>,
    protected: &HashSet<usize>,
    var_freq: &HashMap<usize, usize>,
) -> Option<(Variable, LinearCombination<F>)> {
    let simplified = lc.simplify();

    // Find the best candidate: most-frequent non-protected variable,
    // breaking ties by highest index.
    let mut best: Option<(Variable, FieldElement<F>, usize)> = None;
    for (var, coeff) in &simplified.terms {
        if protected.contains(&var.index()) {
            continue;
        }
        if var.index() == 0 {
            continue; // Never substitute Variable::ONE
        }
        let freq = var_freq.get(&var.index()).copied().unwrap_or(0);
        match &best {
            None => best = Some((*var, *coeff, freq)),
            Some((prev_var, _, prev_freq)) => {
                if freq > *prev_freq || (freq == *prev_freq && var.index() > prev_var.index()) {
                    best = Some((*var, *coeff, freq));
                }
            }
        }
    }

    let (target_var, target_coeff, _) = best?;

    // We need to compute: target_var = (-1/target_coeff) * (all other terms)
    let neg_inv = target_coeff.neg().inv()?;

    let mut result = LinearCombination::<F>::zero();
    for (var, coeff) in &simplified.terms {
        if *var == target_var {
            continue;
        }
        result.add_term(*var, coeff.mul(&neg_inv));
    }

    Some((target_var, result))
}

/// Run linear constraint elimination to fixpoint.
///
/// Protected variables (ONE + public inputs, indices `0..=num_pub_inputs`)
/// are never substituted away.
///
/// Returns the reduced constraint set, a substitution map (for witness
/// fixup), and optimization statistics.
pub fn optimize_linear<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    optimize_linear_with_protected(constraints, num_pub_inputs, &HashSet::new())
}

/// Like `optimize_linear`, but also protects additional variable indices
/// from substitution. Used by O2 to shield decomposition wires during
/// DEDUCE processing so they remain available as simple monomials.
fn optimize_linear_with_protected<F: FieldBackend>(
    constraints: &mut Vec<Constraint<F>>,
    num_pub_inputs: usize,
    extra_protected: &HashSet<usize>,
) -> (SubstitutionMap<F>, R1CSOptimizeResult) {
    let constraints_before = constraints.len();

    // Protected: ONE (0) + public inputs (1..=num_pub_inputs) + extra
    let mut protected: HashSet<usize> = (0..=num_pub_inputs).collect();
    protected.extend(extra_protected);

    let mut all_subs: SubstitutionMap<F> = HashMap::new();
    let mut rounds = 0usize;
    let mut round_details: Vec<(usize, usize)> = Vec::new();
    let mut total_trivial_removed = 0usize;

    loop {
        rounds += 1;

        // Compute variable frequency for this round's heuristic
        let var_freq = compute_variable_frequency(constraints);

        let mut round_subs: SubstitutionMap<F> = HashMap::new();
        let mut to_remove: HashSet<usize> = HashSet::new();

        // Also protect variables already substituted in previous rounds
        let mut round_protected = protected.clone();
        for var_idx in all_subs.keys() {
            round_protected.insert(*var_idx);
        }

        // Count non-linear constraints before this round (for instrumentation)
        let nonlinear_before = constraints
            .iter()
            .filter(|c| is_linear(c).is_none())
            .count();

        for (idx, constraint) in constraints.iter().enumerate() {
            if let Some((k, other_lc, c_lc)) = is_linear(constraint) {
                // Constraint encodes: k * other_lc = c_lc
                // i.e., c_lc - k * other_lc = 0
                let combined = c_lc - (other_lc * k);

                // Don't solve for a variable already claimed this round
                let mut this_round_protected = round_protected.clone();
                for var_idx in round_subs.keys() {
                    this_round_protected.insert(*var_idx);
                }

                if let Some((var, expr)) =
                    solve_for_variable(combined, &this_round_protected, &var_freq)
                {
                    round_subs.insert(var.index(), expr);
                    to_remove.insert(idx);
                }
            }
        }

        if round_subs.is_empty() {
            rounds -= 1; // Don't count empty round
            break;
        }

        let linear_eliminated = to_remove.len();

        // Remove eliminated constraints and apply substitutions to the rest
        *constraints = constraints
            .iter()
            .enumerate()
            .filter(|(idx, _)| !to_remove.contains(idx))
            .map(|(_, c)| apply_substitution_to_constraint(c, &round_subs))
            .collect();

        // Remove trivially-satisfied constraints (0*B=0, k1*k2=k3)
        let before_trivial = constraints.len();
        constraints.retain(|c| !is_trivially_satisfied(c));
        let trivial_this_round = before_trivial - constraints.len();
        total_trivial_removed += trivial_this_round;

        // Count how many non-linear constraints became linear after substitution
        let nonlinear_after = constraints
            .iter()
            .filter(|c| is_linear(c).is_none())
            .count();
        let newly_linear = nonlinear_before.saturating_sub(nonlinear_after + linear_eliminated);

        round_details.push((linear_eliminated, newly_linear));

        // Compose with previous substitutions: apply new subs to old expressions
        for expr in all_subs.values_mut() {
            *expr = apply_substitution(expr, &round_subs);
        }
        all_subs.extend(round_subs);
    }

    // Phase 2: Remove duplicate non-linear constraints.
    // After variable substitution, constraints from different template instances
    // (wired via AssertEq) can become identical. Deduplicate by hashing.
    let before_dedup = constraints.len();
    deduplicate_constraints(constraints);
    let duplicates_removed = before_dedup - constraints.len();

    // Phase 3: Final trivial constraint removal (post-dedup may expose more).
    let before_final_trivial = constraints.len();
    constraints.retain(|c| !is_trivially_satisfied(c));
    total_trivial_removed += before_final_trivial - constraints.len();

    let result = R1CSOptimizeResult {
        constraints_before,
        constraints_after: constraints.len(),
        variables_eliminated: all_subs.len(),
        duplicates_removed,
        trivial_removed: total_trivial_removed,
        rounds,
        round_details,
    };

    (all_subs, result)
}

/// Hash a simplified linear combination into a deterministic byte vector.
fn lc_fingerprint<F: FieldBackend>(lc: &LinearCombination<F>) -> Vec<u8> {
    let simplified = lc.simplify();
    let mut bytes = Vec::with_capacity(simplified.terms.len() * 40);
    for (var, coeff) in &simplified.terms {
        bytes.extend_from_slice(&var.index().to_le_bytes());
        for limb in coeff.to_canonical().iter() {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

/// Remove duplicate constraints (same A, B, C after simplification).
/// Also removes commuted duplicates (A*B=C == B*A=C).
fn deduplicate_constraints<F: FieldBackend>(constraints: &mut Vec<Constraint<F>>) {
    use std::collections::HashSet;

    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(constraints.len());

    constraints.retain(|c| {
        let fa = lc_fingerprint(&c.a);
        let fb = lc_fingerprint(&c.b);
        let fc = lc_fingerprint(&c.c);

        // Canonical key: sort A,B to handle commutativity (A*B=C ≡ B*A=C)
        let (fa, fb) = if fa <= fb { (fa, fb) } else { (fb, fa) };

        let mut key = Vec::with_capacity(fa.len() + fb.len() + fc.len() + 2);
        key.extend_from_slice(&fa);
        key.push(0xFF); // separator
        key.extend_from_slice(&fb);
        key.push(0xFF);
        key.extend_from_slice(&fc);

        seen.insert(key)
    });
}

// ============================================================================
// O2 Optimization: DEDUCE linear constraints from quadratic constraints
// ============================================================================
//
// Algorithm (from "Distilling Constraints in Zero-Knowledge Protocols", CAV 2022):
//
// For each R1CS constraint A×B = C, expand A×B into:
//   - Quadratic monomials: a_i * b_j * w_i * w_j  (i>0, j>0)
//   - Linear part: terms involving Variable::ONE from A×B, minus C
//
// Build a matrix M where rows = quadratic monomials, columns = constraints.
// M[mono, k] = coefficient of monomial `mono` in constraint k's expanded A×B.
//
// Find the null space of M via Gaussian elimination: vectors v such that M×v=0.
// For each null vector, Σ v_k * (linear_part_k) = 0 is a deduced linear constraint.
//
// These deduced constraints are added to the system, and O1 optimization is
// re-run. The process repeats until no more linear constraints can be deduced.

/// Canonical quadratic monomial: (i, j) with i <= j, both > 0.
type Monomial = (usize, usize);

/// Expand constraint A×B into quadratic monomials and a "linear residual".
///
/// The constraint says: quadratic_part + linear_residual = 0.
/// Where linear_residual = (linear terms from A×B) - C.
fn expand_constraint_product<F: FieldBackend>(
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
fn decompose_for_deduce_tracked<F: FieldBackend>(
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
    //    → this only eliminates variables from deduced + existing constraints
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
            // Extract definitions from new linear constraints: 1 × (LC - w) = 0 → w = LC
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
        let deduced = deduce_linear_from_quadratic(constraints);

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

        // Step 3: O1 with auxiliary wires PROTECTED — processes deductions
        // without destroying the decomposition wire structure
        let (new_subs, stats) =
            optimize_linear_with_protected(constraints, num_pub_inputs, &aux_wire_indices);

        total_vars_eliminated += stats.variables_eliminated;
        total_trivial_removed += stats.trivial_removed;
        total_duplicates_removed += stats.duplicates_removed;
        total_rounds += stats.rounds;
        all_round_details.extend(stats.round_details);

        for expr in all_subs.values_mut() {
            *expr = apply_substitution(expr, &new_subs);
        }
        all_subs.extend(new_subs);

        // Step 4: O1 WITHOUT protection — eliminates auxiliary wires
        let (cleanup_subs, cleanup_stats) = optimize_linear(constraints, num_pub_inputs);

        total_vars_eliminated += cleanup_stats.variables_eliminated;
        total_trivial_removed += cleanup_stats.trivial_removed;
        total_duplicates_removed += cleanup_stats.duplicates_removed;
        total_rounds += cleanup_stats.rounds;
        all_round_details.extend(cleanup_stats.round_details);

        for expr in all_subs.values_mut() {
            *expr = apply_substitution(expr, &cleanup_subs);
        }
        all_subs.extend(cleanup_subs);

        // Resolve any remaining auxiliary wire references in substitution map.
        // Protected O1 may have used deduced constraints containing aux wires,
        // and cleanup O1 may not have eliminated all of them.
        let aux_subs: SubstitutionMap<F> = aux_definitions.clone();
        for expr in all_subs.values_mut() {
            *expr = apply_substitution(expr, &aux_subs);
        }
        // Remove aux wire entries from the substitution map (they don't exist
        // in the original witness vector)
        all_subs.retain(|k, _| !aux_wire_indices.contains(k));

        if constraints.len() >= count_before {
            // No improvement — revert
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::ConstraintSystem;
    use memory::FieldElement;

    /// Helper: build a constraint system, optimize it, and verify.
    fn make_lc_var<F: FieldBackend>(var: Variable) -> LinearCombination<F> {
        LinearCombination::from_variable(var)
    }
    fn make_lc_const<F: FieldBackend>(val: u64) -> LinearCombination<F> {
        LinearCombination::from_constant(FieldElement::from_u64(val))
    }

    // ========================================================================
    // Test 1: Single linear constraint elimination
    // ========================================================================
    #[test]
    fn test_single_linear_elimination() {
        // System: x * y = z (quadratic, kept)
        //         1 * w = z (linear: w = z, eliminate)
        let mut cs = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3
        let w = cs.alloc_witness(); // 4

        // x * y = z
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
        // 1 * w = z  (i.e. w = z)
        cs.enforce_equal(make_lc_var(w), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 1);
        // Frequency heuristic: z (idx 3, freq=2) preferred over w (idx 4, freq=1)
        assert!(subs.contains_key(&3) || subs.contains_key(&4));

        // Remaining constraint should still be satisfiable
        // After substitution, w is replaced by z everywhere
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(6),  // x
            FieldElement::from_u64(7),  // y
            FieldElement::from_u64(42), // z = x*y
            FieldElement::from_u64(42), // w = z
        ];
        for c in &constraints {
            let a_val = c.a.evaluate(&witness).unwrap();
            let b_val = c.b.evaluate(&witness).unwrap();
            let c_val = c.c.evaluate(&witness).unwrap();
            assert_eq!(a_val.mul(&b_val), c_val);
        }
    }

    // ========================================================================
    // Test 2: Constant propagation
    // ========================================================================
    #[test]
    fn test_constant_propagation() {
        // System: 1 * x = 5*ONE  (x = 5, constant)
        //         x * y = z      (after sub x=5: 5*ONE * y = z, also linear → z = 5y)
        // Both constraints are fully linear after propagation → 0 remaining.
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let _z = cs.alloc_witness(); // 3

        // x = 5
        cs.enforce_equal(make_lc_var(x), make_lc_const(5));
        // x * y = z
        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(_z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // x=5 makes the second constraint linear (5*y = z), so z is also eliminated
        assert_eq!(stats.constraints_after, 0);
        assert_eq!(stats.variables_eliminated, 2);
        assert!(subs.contains_key(&1)); // x substituted with constant 5
        assert!(subs.contains_key(&3)); // z substituted with 5*y
    }

    // ========================================================================
    // Test 3: Public variable protection
    // ========================================================================
    #[test]
    fn test_public_variable_not_substituted() {
        // System: 1 * pub_out = w  (linear, but pub_out is public — can't sub it)
        //         w * w = z        (quadratic)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let pub_out = cs.alloc_input(); // 1 (public)
        let w = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3

        // pub_out = w  (linear)
        cs.enforce_equal(make_lc_var(pub_out), make_lc_var(w));
        // w * w = z
        cs.enforce(make_lc_var(w), make_lc_var(w), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // w (idx 2) should be substituted, NOT pub_out (idx 1)
        assert_eq!(stats.variables_eliminated, 1);
        assert!(subs.contains_key(&2)); // w substituted
        assert!(!subs.contains_key(&1)); // pub_out protected

        // After optimization: w is replaced by pub_out
        // Remaining constraints: pub_out * pub_out = z
        assert_eq!(constraints.len(), 1);
    }

    // ========================================================================
    // Test 4: Chain substitution (fixpoint)
    // ========================================================================
    #[test]
    fn test_chain_substitution() {
        // System: 1 * a = b   (a = b)
        //         1 * b = c   (b = c)
        //         c * c = d   (quadratic)
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let d = cs.alloc_witness(); // 4

        cs.enforce_equal(make_lc_var(a), make_lc_var(b));
        cs.enforce_equal(make_lc_var(b), make_lc_var(c));
        cs.enforce(make_lc_var(c), make_lc_var(c), make_lc_var(d));

        let mut constraints = cs.constraints().to_vec();
        let (_subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Both linear constraints eliminated
        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 2);

        // a and b should both resolve to c (or chain: a->b->c)
        // Verify the remaining constraint is satisfiable
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(5),  // a
            FieldElement::from_u64(5),  // b
            FieldElement::from_u64(5),  // c
            FieldElement::from_u64(25), // d = c^2
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 5: Mixed linear and nonlinear
    // ========================================================================
    #[test]
    fn test_mixed_linear_nonlinear() {
        // System: a * b = c  (quadratic, kept)
        //         c * d = e  (quadratic, kept)
        //         1 * f = e  (linear, eliminated)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let d = cs.alloc_witness(); // 4
        let e = cs.alloc_witness(); // 5
        let f = cs.alloc_witness(); // 6

        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(c));
        cs.enforce(make_lc_var(c), make_lc_var(d), make_lc_var(e));
        cs.enforce_equal(make_lc_var(f), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 2);
        assert_eq!(stats.variables_eliminated, 1);
    }

    // ========================================================================
    // Test 6: Empty system
    // ========================================================================
    #[test]
    fn test_empty_system() {
        let mut constraints: Vec<Constraint> = vec![];
        let (subs, stats) = optimize_linear(&mut constraints, 0);

        assert_eq!(stats.constraints_before, 0);
        assert_eq!(stats.constraints_after, 0);
        assert_eq!(stats.variables_eliminated, 0);
        assert!(subs.is_empty());
    }

    // ========================================================================
    // Test 7: Already optimal (only multiplications)
    // ========================================================================
    #[test]
    fn test_already_optimal() {
        // System: a * b = c (all quadratic)
        //         c * d = e
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let a = cs.alloc_witness();
        let b = cs.alloc_witness();
        let c = cs.alloc_witness();
        let d = cs.alloc_witness();
        let e = cs.alloc_witness();

        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(c));
        cs.enforce(make_lc_var(c), make_lc_var(d), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 2);
        assert_eq!(stats.variables_eliminated, 0);
        assert!(subs.is_empty());
    }

    // ========================================================================
    // Test 8: Materialization pattern (the main source of bloat)
    // ========================================================================
    #[test]
    fn test_materialize_pattern() {
        // Simulates what auto_materialize generates:
        // 1 * (a + b + c) = m   (materialization: m = a+b+c)
        // m * d = e              (actual multiplication)
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let m = cs.alloc_witness(); // 4 (materialized)
        let d = cs.alloc_witness(); // 5
        let e = cs.alloc_witness(); // 6

        // materialization: (a+b+c) * 1 = m
        let mut sum = LinearCombination::zero();
        sum.add_term(a, FieldElement::ONE);
        sum.add_term(b, FieldElement::ONE);
        sum.add_term(c, FieldElement::ONE);
        cs.enforce_equal(sum, make_lc_var(m));

        // actual mul: m * d = e
        cs.enforce(make_lc_var(m), make_lc_var(d), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Materialization constraint should be eliminated
        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 1);
        assert!(subs.contains_key(&4)); // m substituted with a+b+c

        // Remaining constraint: (a+b+c) * d = e
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(2),  // a
            FieldElement::from_u64(3),  // b
            FieldElement::from_u64(5),  // c
            FieldElement::from_u64(10), // m = a+b+c = 10
            FieldElement::from_u64(4),  // d
            FieldElement::from_u64(40), // e = (a+b+c)*d = 40
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 9: Scaled linear constraint (k != 1)
    // ========================================================================
    #[test]
    fn test_scaled_linear() {
        // System: 3 * x = y  (i.e., y = 3x)
        //         y * y = z
        let mut cs = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3

        // 3*ONE * x = y
        cs.enforce(make_lc_const(3), make_lc_var(x), make_lc_var(y));
        // y * y = z
        cs.enforce(make_lc_var(y), make_lc_var(y), make_lc_var(z));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 2);
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 1);
        assert!(subs.contains_key(&2)); // y substituted with 3*x

        // Verify: x=4, y=12, z=144
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(4),   // x
            FieldElement::from_u64(12),  // y = 3*4
            FieldElement::from_u64(144), // z = 12*12
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 10: Boolean enforcement is NOT eliminated
    // ========================================================================
    #[test]
    fn test_boolean_enforcement_kept() {
        // Boolean: v * (1 - v) = 0
        // This is NOT linear (both A and B contain variable v)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let v = cs.alloc_witness(); // 1

        // v * (1 - v) = 0
        let one_minus_v =
            LinearCombination::from_variable(Variable::ONE) - LinearCombination::from_variable(v);
        cs.enforce(make_lc_var(v), one_minus_v, LinearCombination::zero());

        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Should NOT be eliminated — both A and B have variables
        assert_eq!(stats.constraints_after, 1);
        assert_eq!(stats.variables_eliminated, 0);
    }

    // ========================================================================
    // Test 11: Multiple materializations in chain
    // ========================================================================
    #[test]
    fn test_multiple_materializations() {
        // Simulates a chain of additions that auto_materialize would produce:
        // m1 = a + b        (linear)
        // m2 = m1 + c       (linear)
        // m2 * d = e        (quadratic)
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let m1 = cs.alloc_witness(); // 4
        let m2 = cs.alloc_witness(); // 5
        let d = cs.alloc_witness(); // 6
        let e = cs.alloc_witness(); // 7

        // m1 = a + b
        let ab = make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b);
        cs.enforce_equal(ab, make_lc_var(m1));
        // m2 = m1 + c
        let m1c = make_lc_var::<memory::Bn254Fr>(m1) + make_lc_var(c);
        cs.enforce_equal(m1c, make_lc_var(m2));
        // m2 * d = e
        cs.enforce(make_lc_var(m2), make_lc_var(d), make_lc_var(e));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Both materializations eliminated (may take 2 rounds for chain)
        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 1);
        assert!(subs.contains_key(&4) || subs.contains_key(&5));

        // Final constraint should be: (a+b+c) * d = e
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(1),  // a
            FieldElement::from_u64(2),  // b
            FieldElement::from_u64(3),  // c
            FieldElement::from_u64(3),  // m1 = a+b
            FieldElement::from_u64(6),  // m2 = m1+c
            FieldElement::from_u64(4),  // d
            FieldElement::from_u64(24), // e = 6*4
        ];
        let con = &constraints[0];
        let a_val = con.a.evaluate(&witness).unwrap();
        let b_val = con.b.evaluate(&witness).unwrap();
        let c_val = con.c.evaluate(&witness).unwrap();
        assert_eq!(a_val.mul(&b_val), c_val);
    }

    // ========================================================================
    // Test 12: Verify optimization preserves witness satisfaction
    // ========================================================================
    #[test]
    fn test_optimization_preserves_satisfaction() {
        // Build a realistic mini-circuit:
        //   pub_out = a * b        (quadratic)
        //   m1 = a + b             (materialization)
        //   m2 = m1 * a            (quadratic, uses materialized wire)
        //   assert m2 = c          (linear: m2 = c)
        let mut cs = ConstraintSystem::new();
        let pub_out = cs.alloc_input(); // 1
        let a = cs.alloc_witness(); // 2
        let b = cs.alloc_witness(); // 3
        let m1 = cs.alloc_witness(); // 4
        let m2 = cs.alloc_witness(); // 5 (= m1 * a)
        let c = cs.alloc_witness(); // 6

        // pub_out = a * b
        cs.enforce(make_lc_var(a), make_lc_var(b), make_lc_var(pub_out));
        // m1 = a + b (materialization)
        cs.enforce_equal(
            make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
            make_lc_var(m1),
        );
        // m2 = m1 * a
        cs.enforce(make_lc_var(m1), make_lc_var(a), make_lc_var(m2));
        // m2 = c (assert)
        cs.enforce_equal(make_lc_var(m2), make_lc_var(c));

        // a=3, b=4: pub_out=12, m1=7, m2=21, c=21
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(12), // pub_out
            FieldElement::from_u64(3),  // a
            FieldElement::from_u64(4),  // b
            FieldElement::from_u64(7),  // m1 = a+b
            FieldElement::from_u64(21), // m2 = m1*a
            FieldElement::from_u64(21), // c = m2
        ];

        // Verify before optimization
        assert!(cs.verify(&witness).is_ok());

        // Optimize
        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // Should eliminate the 2 linear constraints (m1 materialization + m2=c assert)
        assert_eq!(stats.constraints_before, 4);
        assert_eq!(stats.constraints_after, 2);

        // Verify after optimization
        for (i, con) in constraints.iter().enumerate() {
            let a_val = con.a.evaluate(&witness).unwrap();
            let b_val = con.b.evaluate(&witness).unwrap();
            let c_val = con.c.evaluate(&witness).unwrap();
            assert_eq!(
                a_val.mul(&b_val),
                c_val,
                "constraint {i} unsatisfied after optimization"
            );
        }
    }

    // ========================================================================
    // Test 13: Tautological linear constraints are removed
    // ========================================================================
    #[test]
    fn test_tautological_linear_removed() {
        // Directly test is_trivially_satisfied on a tautological constraint:
        // 1 * (3x + 5y) = (3x + 5y) → always satisfied
        let x = Variable(1);
        let y = Variable(2);

        let mut lc = LinearCombination::<memory::Bn254Fr>::zero();
        lc.add_term(x, FieldElement::from_u64(3));
        lc.add_term(y, FieldElement::from_u64(5));

        let taut = Constraint {
            a: LinearCombination::from_variable(Variable::ONE),
            b: lc.clone(),
            c: lc,
        };
        assert!(is_trivially_satisfied(&taut));

        // Non-tautological: 1 * (3x + 5y) = (3x + 7y)
        let mut c2 = LinearCombination::<memory::Bn254Fr>::zero();
        c2.add_term(x, FieldElement::from_u64(3));
        c2.add_term(y, FieldElement::from_u64(7));
        let non_taut = Constraint {
            a: LinearCombination::from_variable(Variable::ONE),
            b: {
                let mut b = LinearCombination::zero();
                b.add_term(x, FieldElement::from_u64(3));
                b.add_term(y, FieldElement::from_u64(5));
                b
            },
            c: c2,
        };
        assert!(!is_trivially_satisfied(&non_taut));

        // Tautological after substitution with protected variables:
        // System: 1 * pub = x       (linear: x = pub, sub x → pub)
        //         1 * x = pub       (after sub: 1*pub = pub → tautological!)
        //         x * x = z         (after sub: pub*pub = z, quadratic, kept)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let pub_out = cs.alloc_input(); // 1 (protected)
        let x_var = cs.alloc_witness(); // 2
        let z_var = cs.alloc_witness(); // 3

        cs.enforce_equal(make_lc_var(pub_out), make_lc_var(x_var));
        cs.enforce_equal(make_lc_var(x_var), make_lc_var(pub_out));
        cs.enforce(make_lc_var(x_var), make_lc_var(x_var), make_lc_var(z_var));

        let mut constraints = cs.constraints().to_vec();
        let (_, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // First constraint: x substituted → pub
        // Second: 1*pub = pub → tautological, removed
        // Third: pub*pub = z → quadratic, kept
        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 1, "only pub*pub=z should remain");
        assert!(
            stats.trivial_removed >= 1,
            "tautological constraint detected"
        );
    }

    // ========================================================================
    // Test 14: Zero-product constraint (0 * B = C) handled
    // ========================================================================
    #[test]
    fn test_zero_product_constraint() {
        // System: x * y = z     (quadratic)
        //         0 * w = v     (zero-product: v = 0, eliminable)
        //         v * v = out   (after sub v→0: 0*0=out → trivial if out=0)
        let mut cs: ConstraintSystem = ConstraintSystem::new();
        let x = cs.alloc_witness(); // 1
        let y = cs.alloc_witness(); // 2
        let z = cs.alloc_witness(); // 3
        let w = cs.alloc_witness(); // 4
        let v = cs.alloc_witness(); // 5
        let out = cs.alloc_witness(); // 6

        cs.enforce(make_lc_var(x), make_lc_var(y), make_lc_var(z));
        // 0 * w = v
        cs.enforce(LinearCombination::zero(), make_lc_var(w), make_lc_var(v));
        cs.enforce(make_lc_var(v), make_lc_var(v), make_lc_var(out));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        // v should be substituted to 0 (from zero-product constraint)
        // Then v*v=out becomes 0*0=out, where out gets substituted to 0 too
        assert!(subs.contains_key(&5) || subs.contains_key(&6)); // v or out substituted
        assert!(stats.constraints_after <= 2); // at most x*y=z + maybe one more

        // Verify
        let witness = vec![
            FieldElement::ONE,
            FieldElement::from_u64(6),  // x
            FieldElement::from_u64(7),  // y
            FieldElement::from_u64(42), // z
            FieldElement::from_u64(99), // w (unconstrained after opt)
            FieldElement::from_u64(0),  // v = 0
            FieldElement::from_u64(0),  // out = 0
        ];
        for c in &constraints {
            let a_val = c.a.evaluate(&witness).unwrap();
            let b_val = c.b.evaluate(&witness).unwrap();
            let c_val = c.c.evaluate(&witness).unwrap();
            assert_eq!(a_val.mul(&b_val), c_val);
        }
    }

    // ========================================================================
    // Test 15: Frequency heuristic picks most-connected variable
    // ========================================================================
    #[test]
    fn test_frequency_heuristic() {
        // Frequency heuristic: substitute the variable that appears in the
        // MOST constraints, to maximize propagation.
        //
        // In constraint `c - a - b = 0`:
        //   a (idx 1): freq=3 (in constraints 1,2,3)
        //   b (idx 2): freq=1 (in constraint 1 only)
        //   c (idx 3): freq=1 (in constraint 1 only)
        // Highest-freq = a → substitute a = c - b
        let mut cs = ConstraintSystem::new();
        let a = cs.alloc_witness(); // 1
        let b = cs.alloc_witness(); // 2
        let c = cs.alloc_witness(); // 3
        let d = cs.alloc_witness(); // 4
        let e = cs.alloc_witness(); // 5
        let f = cs.alloc_witness(); // 6
        let g = cs.alloc_witness(); // 7

        cs.enforce_equal(
            make_lc_var::<memory::Bn254Fr>(a) + make_lc_var(b),
            make_lc_var(c),
        );
        cs.enforce(make_lc_var(a), make_lc_var(d), make_lc_var(e));
        cs.enforce(make_lc_var(a), make_lc_var(f), make_lc_var(g));

        let mut constraints = cs.constraints().to_vec();
        let (subs, stats) = optimize_linear(&mut constraints, cs.num_pub_inputs());

        assert_eq!(stats.constraints_before, 3);
        assert_eq!(stats.constraints_after, 2);
        assert_eq!(stats.variables_eliminated, 1);
        // a (idx 1) should be substituted (highest frequency = 3)
        assert!(
            subs.contains_key(&1),
            "expected a (idx 1) to be substituted (highest freq)"
        );
    }
}
