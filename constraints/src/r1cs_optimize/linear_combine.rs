use memory::{FieldBackend, FieldElement};

use crate::r1cs::{Constraint, LinearCombination, Variable};

const SORTED_COMBINE_MIN_TERMS: usize = 8;

pub(super) struct LinearCandidate<F: FieldBackend> {
    pub combined: LinearCombination<F>,
    pub raw_terms: usize,
}

pub(super) fn linear_constraint_combined<F: FieldBackend>(
    constraint: &Constraint<F>,
) -> Option<LinearCombination<F>> {
    if let Some(k) = constraint.a.constant_value() {
        if !k.is_zero() {
            return Some(combine_linear_parts(&constraint.b, &constraint.c, k));
        }

        let mut combined = constraint.c.clone();
        combined.simplify_in_place();
        return if combined.terms().is_empty() {
            None
        } else {
            Some(combined)
        };
    }

    if let Some(k) = constraint.b.constant_value() {
        if !k.is_zero() {
            return Some(combine_linear_parts(&constraint.a, &constraint.c, k));
        }

        let mut combined = constraint.c.clone();
        combined.simplify_in_place();
        return if combined.terms().is_empty() {
            None
        } else {
            Some(combined)
        };
    }

    None
}

pub(super) fn linear_constraint_combined_profiled<F: FieldBackend>(
    constraint: &Constraint<F>,
) -> Option<LinearCandidate<F>> {
    if let Some(k) = constraint.a.constant_value() {
        if !k.is_zero() {
            let raw_terms = constraint.c.terms().len() + constraint.b.terms().len();
            return Some(LinearCandidate {
                combined: combine_linear_parts(&constraint.b, &constraint.c, k),
                raw_terms,
            });
        }

        let raw_terms = constraint.c.terms().len();
        let mut combined = constraint.c.clone();
        combined.simplify_in_place();
        return if combined.terms().is_empty() {
            None
        } else {
            Some(LinearCandidate {
                combined,
                raw_terms,
            })
        };
    }

    if let Some(k) = constraint.b.constant_value() {
        if !k.is_zero() {
            let raw_terms = constraint.c.terms().len() + constraint.a.terms().len();
            return Some(LinearCandidate {
                combined: combine_linear_parts(&constraint.a, &constraint.c, k),
                raw_terms,
            });
        }

        let raw_terms = constraint.c.terms().len();
        let mut combined = constraint.c.clone();
        combined.simplify_in_place();
        return if combined.terms().is_empty() {
            None
        } else {
            Some(LinearCandidate {
                combined,
                raw_terms,
            })
        };
    }

    None
}

fn combine_linear_parts<F: FieldBackend>(
    other: &LinearCombination<F>,
    c: &LinearCombination<F>,
    k: FieldElement<F>,
) -> LinearCombination<F> {
    let raw_terms = c.terms().len() + other.terms().len();
    if raw_terms >= SORTED_COMBINE_MIN_TERMS
        && terms_are_simplified(c.terms())
        && terms_are_simplified(other.terms())
    {
        return combine_sorted_linear_parts(other, c, k);
    }

    combine_linear_parts_slow(other, c, k)
}

fn terms_are_simplified<F: FieldBackend>(terms: &[(Variable, FieldElement<F>)]) -> bool {
    let mut prev = None;
    for (var, coeff) in terms {
        if coeff.is_zero() || prev.is_some_and(|idx| var.index() <= idx) {
            return false;
        }
        prev = Some(var.index());
    }
    true
}

fn combine_sorted_linear_parts<F: FieldBackend>(
    other: &LinearCombination<F>,
    c: &LinearCombination<F>,
    k: FieldElement<F>,
) -> LinearCombination<F> {
    let c_terms = c.terms();
    let other_terms = other.terms();
    let neg_k = k.neg();
    let mut combined = LinearCombination::zero();
    combined.terms.reserve(c_terms.len() + other_terms.len());

    let mut c_idx = 0usize;
    let mut other_idx = 0usize;
    while c_idx < c_terms.len() && other_idx < other_terms.len() {
        let (c_var, c_coeff) = c_terms[c_idx];
        let (other_var, other_coeff) = other_terms[other_idx];
        match c_var.index().cmp(&other_var.index()) {
            std::cmp::Ordering::Less => {
                combined.add_term(c_var, c_coeff);
                c_idx += 1;
            }
            std::cmp::Ordering::Greater => {
                let coeff = other_coeff.mul(&neg_k);
                if !coeff.is_zero() {
                    combined.add_term(other_var, coeff);
                }
                other_idx += 1;
            }
            std::cmp::Ordering::Equal => {
                let coeff = c_coeff.add(&other_coeff.mul(&neg_k));
                if !coeff.is_zero() {
                    combined.add_term(c_var, coeff);
                }
                c_idx += 1;
                other_idx += 1;
            }
        }
    }

    for (var, coeff) in &c_terms[c_idx..] {
        combined.add_term(*var, *coeff);
    }
    for (var, coeff) in &other_terms[other_idx..] {
        let coeff = coeff.mul(&neg_k);
        if !coeff.is_zero() {
            combined.add_term(*var, coeff);
        }
    }
    combined
}

fn combine_linear_parts_slow<F: FieldBackend>(
    other: &LinearCombination<F>,
    c: &LinearCombination<F>,
    k: FieldElement<F>,
) -> LinearCombination<F> {
    let mut combined = LinearCombination::zero();
    combined
        .terms
        .reserve(c.terms().len() + other.terms().len());
    for (var, coeff) in c.terms() {
        combined.add_term(*var, *coeff);
    }
    let neg_k = k.neg();
    for (var, coeff) in other.terms() {
        combined.add_term(*var, coeff.mul(&neg_k));
    }
    combined.simplify_in_place();
    combined
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;

    fn lc(terms: &[(usize, u64)]) -> LinearCombination<Bn254Fr> {
        let mut lc = LinearCombination::zero();
        for (var, coeff) in terms {
            lc.add_term(Variable(*var), FieldElement::from_u64(*coeff));
        }
        lc
    }

    fn simplified_terms(lc: LinearCombination<Bn254Fr>) -> Vec<(usize, FieldElement<Bn254Fr>)> {
        lc.terms()
            .iter()
            .map(|(var, coeff)| (var.index(), *coeff))
            .collect()
    }

    #[test]
    fn sorted_combine_keeps_terms_ordered_without_slow_simplify() {
        let c = lc(&[(1, 3), (4, 7), (6, 11), (8, 13)]);
        let other = lc(&[(2, 5), (5, 9), (7, 17), (9, 19)]);
        let combined = combine_linear_parts(&other, &c, FieldElement::from_u64(2));
        assert_eq!(
            simplified_terms(combined),
            vec![
                (1, FieldElement::from_u64(3)),
                (
                    2,
                    FieldElement::from_u64(5)
                        .neg()
                        .mul(&FieldElement::from_u64(2))
                ),
                (4, FieldElement::from_u64(7)),
                (
                    5,
                    FieldElement::from_u64(9)
                        .neg()
                        .mul(&FieldElement::from_u64(2))
                ),
                (6, FieldElement::from_u64(11)),
                (
                    7,
                    FieldElement::from_u64(17)
                        .neg()
                        .mul(&FieldElement::from_u64(2))
                ),
                (8, FieldElement::from_u64(13)),
                (
                    9,
                    FieldElement::from_u64(19)
                        .neg()
                        .mul(&FieldElement::from_u64(2))
                ),
            ]
        );
    }

    #[test]
    fn sorted_combine_cancels_cross_side_duplicates() {
        let c = lc(&[(1, 6), (3, 4)]);
        let other = lc(&[(1, 3), (2, 5)]);
        let combined = combine_linear_parts(&other, &c, FieldElement::from_u64(2));
        assert_eq!(
            simplified_terms(combined),
            vec![
                (
                    2,
                    FieldElement::from_u64(5)
                        .neg()
                        .mul(&FieldElement::from_u64(2))
                ),
                (3, FieldElement::from_u64(4)),
            ]
        );
    }

    #[test]
    fn unsorted_inputs_use_slow_canonicalization() {
        let c = lc(&[(3, 4), (1, 6)]);
        let other = lc(&[(1, 3), (2, 5)]);
        let combined = combine_linear_parts(&other, &c, FieldElement::from_u64(2));
        assert_eq!(
            simplified_terms(combined),
            vec![
                (
                    2,
                    FieldElement::from_u64(5)
                        .neg()
                        .mul(&FieldElement::from_u64(2))
                ),
                (3, FieldElement::from_u64(4)),
            ]
        );
    }
}
