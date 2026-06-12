//! Cycle resolution for the substitution map: induced-subgraph Tarjan
//! over the key-dependency graph plus per-component reduced-row-echelon
//! over the field. Split out of the `flatten` driver; the entry point is
//! [`resolve_cycles`].

use rustc_hash::{FxHashMap, FxHashSet};

use memory::{FieldBackend, FieldElement};

use crate::r1cs::{Constraint, LinearCombination, Variable};
use crate::r1cs_optimize::types::SubstitutionMap;

/// Break every cycle in `subs`'s key-dependency graph, returning the
/// leftover survivor rows that rank-deficient cycles expose. Acyclic keys
/// are left untouched (chained); only strongly connected components of size
/// > 1 are rewritten. After this the key-dependency graph is a DAG.
///
/// Must run on a *fresh* batch (the values as the eliminator solved them),
/// before any one-pass composition rewrites them: the cycle resolver
/// reconstructs each component's coupled system from its members' values,
/// and a partially-composed value is no longer that system.
pub(in crate::r1cs_optimize) fn resolve_cycles<F: FieldBackend>(
    all_subs: &mut SubstitutionMap<F>,
) -> Vec<Constraint<F>> {
    // Only wires that reference another key can sit in a cycle. Build the
    // induced subgraph over those (and their targets) -- a small fraction of
    // the map at scale -- so Tarjan never walks the millions of acyclic
    // singletons. A wire that references itself (`subs[k]` contains `k`,
    // which one-pass composition can manufacture by folding a 2-cycle into
    // `k = c*k + rest`) is a 1-node cycle and must be resolved too, so it is
    // tracked separately (the inter-node graph excludes the self-edge).
    let mut out_edges: FxHashMap<usize, Vec<usize>> = FxHashMap::default();
    let mut active: FxHashSet<usize> = FxHashSet::default();
    let mut self_looped: FxHashSet<usize> = FxHashSet::default();
    for (&k, lc) in all_subs.iter() {
        let mut seen: FxHashSet<usize> = FxHashSet::default();
        let mut targets: Vec<usize> = Vec::new();
        for (var, _) in lc.terms() {
            let j = var.index();
            if j == k {
                self_looped.insert(k);
            } else if all_subs.contains_key(&j) && seen.insert(j) {
                targets.push(j);
            }
        }
        if !targets.is_empty() {
            active.insert(k);
            for &t in &targets {
                active.insert(t);
            }
            out_edges.insert(k, targets);
        }
    }
    for &k in &self_looped {
        active.insert(k);
    }
    if active.is_empty() {
        return Vec::new();
    }

    let idx_to_key: Vec<usize> = active.into_iter().collect();
    let key_to_idx: FxHashMap<usize, usize> = idx_to_key
        .iter()
        .enumerate()
        .map(|(i, &k)| (k, i))
        .collect();
    let adjacency: Vec<Vec<usize>> = idx_to_key
        .iter()
        .map(|k| {
            out_edges
                .get(k)
                .map(|ts| ts.iter().map(|t| key_to_idx[t]).collect())
                .unwrap_or_default()
        })
        .collect();

    let mut leftovers: Vec<Constraint<F>> = Vec::new();
    for component in tarjan_scc(&adjacency) {
        let members: Vec<usize> = component.iter().map(|&i| idx_to_key[i]).collect();
        // Resolve multi-node cycles and single-node self-loops; an acyclic
        // singleton (no self-edge) is left as its chained definition.
        if members.len() > 1 || self_looped.contains(&members[0]) {
            resolve_cycle(&members, all_subs, &mut leftovers);
        }
    }
    leftovers
}

/// Resolve one cyclic component by reduced-row-echelon over the field. The
/// component's wires are the unknowns; every other term (survivors and keys
/// in other components) rides the symbolic right-hand side, so this neither
/// flattens nor inspects the rest of the map.
fn resolve_cycle<F: FieldBackend>(
    members: &[usize],
    all_subs: &mut SubstitutionMap<F>,
    leftovers: &mut Vec<Constraint<F>>,
) {
    let s = members.len();
    let col_of: FxHashMap<usize, usize> =
        members.iter().enumerate().map(|(c, &k)| (k, c)).collect();

    let zero = FieldElement::<F>::zero();
    let one = FieldElement::<F>::one();
    let mut matrix: Vec<Vec<FieldElement<F>>> = vec![vec![zero; s]; s];
    let mut rhs: Vec<LinearCombination<F>> = vec![LinearCombination::zero(); s];
    for (r, &k) in members.iter().enumerate() {
        // Row r encodes `x_k - subs[k] = 0`: the wire on the diagonal, its
        // component siblings as matrix columns, everything else on the rhs.
        matrix[r][r] = one;
        let lc = all_subs.remove(&k).expect("cycle member present");
        for (var, coeff) in lc.into_terms() {
            match col_of.get(&var.index()) {
                Some(&c) => matrix[r][c] = matrix[r][c].sub(&coeff),
                None => rhs[r].add_term(var, coeff),
            }
        }
    }

    let pivots = rref_in_place(&mut matrix, &mut rhs);
    let mut is_pivot_col = vec![false; s];
    for &(_, col) in &pivots {
        is_pivot_col[col] = true;
    }

    // Pivot rows become substitutions; the pivot wire equals its row's
    // right-hand side minus the free-wire terms still on the row.
    for &(row, col) in &pivots {
        let mut value = std::mem::take(&mut rhs[row]);
        for (f, &is_pivot) in is_pivot_col.iter().enumerate() {
            if is_pivot || f == col {
                continue;
            }
            let coeff = matrix[row][f];
            if !coeff.is_zero() {
                value.add_term(Variable(members[f]), coeff.neg());
            }
        }
        value.simplify_in_place();
        all_subs.insert(members[col], value);
    }

    // All-zero rows with a non-zero right-hand side are constraints on the
    // survivors that the rank deficiency exposes; keep them. (A pure
    // non-zero-constant right-hand side means the original system is
    // inconsistent; the unsatisfiable `1 * c = 0` row is correctly retained
    // by the trivial sweep, never dropped.) Free wires (non-pivot columns)
    // are reverted -- left out of the map so they stay survivor wires.
    for (row, matrix_row) in matrix.iter().enumerate() {
        if matrix_row.iter().all(FieldElement::is_zero) {
            let mut lc = std::mem::take(&mut rhs[row]);
            lc.simplify_in_place();
            if !lc.terms().is_empty() {
                leftovers.push(Constraint {
                    a: LinearCombination::from_constant(one),
                    b: lc,
                    c: LinearCombination::zero(),
                });
            }
        }
    }
}

/// Reduced-row-echelon of `matrix` (square, `s x s`) carrying the symbolic
/// `rhs` vector along. Returns the `(row, col)` pivot positions in row
/// order.
fn rref_in_place<F: FieldBackend>(
    matrix: &mut [Vec<FieldElement<F>>],
    rhs: &mut [LinearCombination<F>],
) -> Vec<(usize, usize)> {
    let s = matrix.len();
    let mut pivots: Vec<(usize, usize)> = Vec::new();
    let mut row = 0usize;
    for col in 0..s {
        if row >= s {
            break;
        }
        let Some(sel) = (row..s).find(|&r| !matrix[r][col].is_zero()) else {
            continue;
        };
        matrix.swap(row, sel);
        rhs.swap(row, sel);

        if let Some(inv) = matrix[row][col].inv() {
            for coeff in matrix[row][col..].iter_mut() {
                *coeff = coeff.mul(&inv);
            }
            scale_lc(&mut rhs[row], &inv);
        }

        let pivot_coeffs: Vec<FieldElement<F>> = matrix[row][col..].to_vec();
        let pivot_rhs = rhs[row].clone();
        for r in 0..s {
            if r == row {
                continue;
            }
            let factor = matrix[r][col];
            if factor.is_zero() {
                continue;
            }
            for (dst, pivot) in matrix[r][col..].iter_mut().zip(pivot_coeffs.iter()) {
                *dst = dst.sub(&pivot.mul(&factor));
            }
            sub_scaled_lc(&mut rhs[r], &pivot_rhs, &factor);
        }

        pivots.push((row, col));
        row += 1;
    }
    pivots
}

/// `lc *= factor`.
fn scale_lc<F: FieldBackend>(lc: &mut LinearCombination<F>, factor: &FieldElement<F>) {
    let scaled: Vec<(Variable, FieldElement<F>)> = lc
        .terms()
        .iter()
        .map(|(var, coeff)| (*var, coeff.mul(factor)))
        .collect();
    let mut out = LinearCombination::zero();
    for (var, coeff) in scaled {
        out.add_term(var, coeff);
    }
    out.simplify_in_place();
    *lc = out;
}

/// `dst -= factor * src`.
fn sub_scaled_lc<F: FieldBackend>(
    dst: &mut LinearCombination<F>,
    src: &LinearCombination<F>,
    factor: &FieldElement<F>,
) {
    for (var, coeff) in src.terms() {
        dst.add_term(*var, coeff.mul(factor).neg());
    }
    dst.simplify_in_place();
}

/// Iterative Tarjan strongly-connected-components over `adjacency`
/// (node -> out-neighbors), returned in reverse-topological order.
fn tarjan_scc(adjacency: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adjacency.len();
    const UNVISITED: usize = usize::MAX;
    let mut index = vec![UNVISITED; n];
    let mut lowlink = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut next_index = 0usize;
    let mut components: Vec<Vec<usize>> = Vec::new();

    let mut work: Vec<(usize, usize)> = Vec::new();
    for start in 0..n {
        if index[start] != UNVISITED {
            continue;
        }
        work.push((start, 0));
        while let Some(&(v, cursor)) = work.last() {
            if cursor == 0 {
                index[v] = next_index;
                lowlink[v] = next_index;
                next_index += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if cursor < adjacency[v].len() {
                let w = adjacency[v][cursor];
                work.last_mut().expect("work nonempty").1 += 1;
                if index[w] == UNVISITED {
                    work.push((w, 0));
                } else if on_stack[w] {
                    lowlink[v] = lowlink[v].min(index[w]);
                }
                continue;
            }

            if lowlink[v] == index[v] {
                let mut component = Vec::new();
                loop {
                    let w = stack.pop().expect("scc stack nonempty");
                    on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                components.push(component);
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                lowlink[parent] = lowlink[parent].min(lowlink[v]);
            }
        }
    }

    components
}
