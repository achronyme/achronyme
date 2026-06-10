use std::sync::Arc;

use constraints::r1cs::{LinearCombination, Variable};
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
