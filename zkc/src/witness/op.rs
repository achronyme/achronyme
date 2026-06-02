use std::sync::Arc;

use constraints::r1cs::{LinearCombination, Variable};
use constraints::r1cs_optimize::SubstitutionMap;
use memory::{Bn254Fr, FieldBackend};

// ============================================================================
// WitnessOp — records intermediate variable computation
// ============================================================================

/// A single witness computation operation recorded during circuit compilation.
///
/// Each variant corresponds to a point where `R1CSCompiler` allocates an
/// intermediate variable. Replaying these operations with concrete input
/// values produces the full witness vector.
#[derive(Debug, Clone)]
pub enum WitnessOp<F: FieldBackend = Bn254Fr> {
    /// Assign: `target = lc.evaluate(witness)`
    /// Emitted by `materialize_lc` when it allocates a new variable.
    AssignLC {
        target: Variable,
        lc: LinearCombination<F>,
    },
    /// Multiply: `target = a.evaluate(witness) * b.evaluate(witness)`
    /// Emitted by `multiply_lcs` (general case).
    Multiply {
        target: Variable,
        a: LinearCombination<F>,
        b: LinearCombination<F>,
    },
    /// Inverse: `target = 1 / operand.evaluate(witness)`
    /// Emitted by `divide_lcs` (general case).
    Inverse {
        target: Variable,
        operand: LinearCombination<F>,
    },
    /// Bit extraction: target = (source >> bit_index) & 1.
    /// Emitted by RangeCheck boolean decomposition.
    /// Field elements are 256 bits (4 × 64-bit limbs), so max bit_index is 255.
    BitExtract {
        target: Variable,
        source: LinearCombination<F>,
        bit_index: u32,
    },
    /// IsZero gadget: if diff==0 then inv=0,result=1 else inv=1/diff,result=0.
    IsZero {
        diff: LinearCombination<F>,
        target_inv: Variable,
        target_result: Variable,
    },
    /// Integer division and modulo: q = floor(lhs / rhs), r = lhs - rhs * q.
    IntDivMod {
        q: Variable,
        r: Variable,
        lhs: Variable,
        rhs: Variable,
    },
    /// Poseidon hash: compute all ~361 internal wires by replaying the
    /// permutation natively.
    PoseidonHash {
        left: Variable,
        right: Variable,
        output: Variable,
        internal_start: usize,
        internal_count: usize,
    },
    /// Artik witness program: decode + execute the embedded bytecode,
    /// reading `inputs` from the current witness vector and writing
    /// one element per `outputs`. Emitted by the R1CS backend for
    /// every `Instruction::WitnessCall` in the IR.
    ///
    /// `program_bytes` is `Arc<[u8]>` so the R1CS backend can intern
    /// identical bytecode payloads across emitted Artik calls — at
    /// boss-fight scale a handful of unique templates account for
    /// ~99% of the bytecode bytes accumulated in `witness_ops`.
    ArtikCall {
        outputs: Vec<Variable>,
        inputs: Vec<Variable>,
        program_bytes: Arc<[u8]>,
    },
}

impl<F: FieldBackend> WitnessOp<F> {
    /// Return all target variables produced by this operation.
    ///
    /// Used to identify ops whose targets have been substituted away
    /// by the R1CS linear constraint elimination pass.
    pub fn target_variables(&self) -> Vec<Variable> {
        match self {
            WitnessOp::AssignLC { target, .. }
            | WitnessOp::Multiply { target, .. }
            | WitnessOp::Inverse { target, .. }
            | WitnessOp::BitExtract { target, .. } => vec![*target],
            WitnessOp::IsZero {
                target_inv,
                target_result,
                ..
            } => vec![*target_inv, *target_result],
            WitnessOp::IntDivMod { q, r, .. } => vec![*q, *r],
            WitnessOp::PoseidonHash { .. } => {
                // Poseidon fills a range of internal wires — never substituted
                vec![]
            }
            WitnessOp::ArtikCall { outputs, .. } => outputs.clone(),
        }
    }

    /// Apply variable substitutions to all LinearCombination fields in this op.
    ///
    /// Does NOT change target variables — only updates source LCs that reference
    /// substituted wires.
    pub fn apply_substitutions(&mut self, subs: &SubstitutionMap<F>) {
        fn apply_sub<F2: FieldBackend>(lc: &mut LinearCombination<F2>, subs: &SubstitutionMap<F2>) {
            if lc
                .terms()
                .iter()
                .any(|(v, _)| subs.contains_key(&v.index()))
            {
                let mut result = LinearCombination::<F2>::zero();
                for (var, coeff) in lc.terms() {
                    if let Some(replacement) = subs.get(&var.index()) {
                        result = result + replacement.clone() * *coeff;
                    } else {
                        result.add_term(*var, *coeff);
                    }
                }
                *lc = result.simplify();
            }
        }

        match self {
            WitnessOp::AssignLC { lc, .. } => apply_sub(lc, subs),
            WitnessOp::Multiply { a, b, .. } => {
                apply_sub(a, subs);
                apply_sub(b, subs);
            }
            WitnessOp::Inverse { operand, .. } => apply_sub(operand, subs),
            WitnessOp::BitExtract { source, .. } => apply_sub(source, subs),
            WitnessOp::IsZero { diff, .. } => apply_sub(diff, subs),
            WitnessOp::IntDivMod { .. }
            | WitnessOp::PoseidonHash { .. }
            | WitnessOp::ArtikCall { .. } => {
                // These reference Variables directly, not LCs — substitution
                // doesn't apply (and witness-side wires are not eliminated).
            }
        }
    }
}

/// Remove witness ops whose targets have been substituted away, and apply
/// substitutions to LCs in the remaining ops.
pub fn apply_substitutions_to_witness_ops<F: FieldBackend>(
    ops: &mut crate::segmented_vec::SegmentedVec<WitnessOp<F>>,
    subs: &SubstitutionMap<F>,
) {
    // Remove ops that produce only substituted variables
    ops.retain(|op| {
        let targets = op.target_variables();
        // Keep if: no targets (Poseidon), or at least one target is NOT substituted
        targets.is_empty() || targets.iter().any(|t| !subs.contains_key(&t.index()))
    });

    // Apply substitutions to source LCs in remaining ops
    for op in ops.iter_mut() {
        op.apply_substitutions(subs);
    }
}
