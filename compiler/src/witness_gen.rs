use std::collections::HashMap;
use std::fmt;

use constraints::poseidon::PoseidonParams;
use constraints::r1cs::{LinearCombination, Variable};
use constraints::r1cs_optimize::SubstitutionMap;
use constraints::PoseidonParamsProvider;
use memory::{Bn254Fr, FieldBackend, FieldElement};

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
    ArtikCall {
        outputs: Vec<Variable>,
        inputs: Vec<Variable>,
        program_bytes: Vec<u8>,
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
            if lc.terms.iter().any(|(v, _)| subs.contains_key(&v.index())) {
                let mut result = LinearCombination::<F2>::zero();
                for (var, coeff) in &lc.terms {
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
    ops: &mut Vec<WitnessOp<F>>,
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

// ============================================================================
// WitnessError
// ============================================================================

/// Errors that can occur during witness generation.
#[derive(Debug)]
pub enum WitnessError {
    /// A required input variable was not provided.
    MissingInput(String),
    /// Division by zero encountered during witness computation.
    DivisionByZero { variable_index: usize },
    /// The embedded Artik witness program failed to decode, validate,
    /// or execute. `reason` is the stringified underlying error.
    ArtikCallFailed {
        /// First output wire, for locating the failure in bug reports.
        primary_output: usize,
        reason: String,
    },
}

impl fmt::Display for WitnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WitnessError::MissingInput(name) => {
                write!(f, "missing input for variable `{name}`")
            }
            WitnessError::DivisionByZero { variable_index } => {
                write!(
                    f,
                    "division by zero computing witness variable {variable_index}"
                )
            }
            WitnessError::ArtikCallFailed {
                primary_output,
                reason,
            } => write!(
                f,
                "Artik witness call failed at wire {primary_output}: {reason}"
            ),
        }
    }
}

impl std::error::Error for WitnessError {}

// ============================================================================
// Artik dispatch
// ============================================================================

/// Pick the Artik field family that matches the compile-time backend
/// `F`. BN254-family primes share `BnLike256` — Goldilocks would need
/// a separate family and no circom lift targets it today.
fn artik_family<F: FieldBackend>() -> Option<witness::FieldFamily> {
    use memory::PrimeId;
    match F::PRIME_ID {
        PrimeId::Bn254 | PrimeId::Bls12_381 => Some(witness::FieldFamily::BnLike256),
        _ => None,
    }
}

/// Decode + execute an Artik program, reading `inputs` from the
/// witness vector and writing one field element per `outputs` slot.
pub(crate) fn dispatch_artik_call<F: FieldBackend>(
    outputs: &[Variable],
    inputs: &[Variable],
    program_bytes: &[u8],
    witness: &mut [FieldElement<F>],
) -> Result<(), WitnessError> {
    let primary = outputs.first().map(|v| v.index()).unwrap_or(0);

    let family = artik_family::<F>().ok_or_else(|| WitnessError::ArtikCallFailed {
        primary_output: primary,
        reason: "no Artik field-family binding for this backend".to_string(),
    })?;

    let signal_vec: Vec<FieldElement<F>> = inputs.iter().map(|v| witness[v.index()]).collect();

    let program = witness::bytecode::decode(program_bytes, Some(family)).map_err(|e| {
        WitnessError::ArtikCallFailed {
            primary_output: primary,
            reason: format!("decode failed: {e:?}"),
        }
    })?;

    let mut slot_vec: Vec<FieldElement<F>> = vec![FieldElement::<F>::zero(); outputs.len()];
    let mut ctx = witness::ArtikContext::<F>::new(&signal_vec, &mut slot_vec);
    witness::execute(&program, &mut ctx).map_err(|e| WitnessError::ArtikCallFailed {
        primary_output: primary,
        reason: format!("execute failed: {e:?}"),
    })?;

    for (v, val) in outputs.iter().zip(slot_vec.iter()) {
        witness[v.index()] = *val;
    }
    Ok(())
}

// ============================================================================
// WitnessGenerator
// ============================================================================

/// Generates the complete witness vector for a compiled R1CS circuit.
///
/// After `R1CSCompiler::compile_ir()`, call `WitnessGenerator::from_compiler()`
/// to capture the compilation trace. Then call `generate()` with concrete input
/// values to produce a witness that satisfies `cs.verify()`.
pub struct WitnessGenerator<F: FieldBackend = Bn254Fr> {
    ops: Vec<WitnessOp<F>>,
    num_variables: usize,
    public_inputs: Vec<(String, Variable)>,
    witnesses: Vec<(String, Variable)>,
    poseidon_params: Option<PoseidonParams<F>>,
    /// Substitution map from R1CS optimization (if optimize_r1cs was called).
    substitution_map: Option<SubstitutionMap<F>>,
}

impl<F: FieldBackend> WitnessGenerator<F> {
    /// Build a `WitnessGenerator` from a compiled `R1CSCompiler`.
    ///
    /// Must be called after `compile_ir()` — captures the ops trace,
    /// variable layout, and (if used) Poseidon parameters.
    pub fn from_compiler(compiler: &crate::r1cs_backend::R1CSCompiler<F>) -> Self {
        let public_inputs: Vec<(String, Variable)> = compiler
            .public_inputs
            .iter()
            .map(|name| (name.clone(), compiler.bindings[name]))
            .collect();

        let witnesses: Vec<(String, Variable)> = compiler
            .witnesses
            .iter()
            .map(|name| (name.clone(), compiler.bindings[name]))
            .collect();

        Self {
            ops: compiler.witness_ops.clone(),
            num_variables: compiler.cs.num_variables(),
            public_inputs,
            witnesses,
            poseidon_params: compiler.poseidon_params.clone(),
            substitution_map: compiler.substitution_map.clone(),
        }
    }

    /// Generate the complete witness vector from input values.
    ///
    /// `inputs` maps variable names (both public and witness) to their
    /// field element values. All declared public inputs and witnesses must
    /// be present.
    pub fn generate(
        &self,
        inputs: &HashMap<String, FieldElement<F>>,
    ) -> Result<Vec<FieldElement<F>>, WitnessError>
    where
        F: PoseidonParamsProvider,
    {
        let mut witness = vec![FieldElement::<F>::zero(); self.num_variables];
        witness[0] = FieldElement::<F>::one();

        // Fill public inputs
        for (name, var) in &self.public_inputs {
            let val = inputs
                .get(name)
                .ok_or_else(|| WitnessError::MissingInput(name.clone()))?;
            witness[var.index()] = *val;
        }

        // Fill declared witnesses
        for (name, var) in &self.witnesses {
            let val = inputs
                .get(name)
                .ok_or_else(|| WitnessError::MissingInput(name.clone()))?;
            witness[var.index()] = *val;
        }

        // Replay ops to compute all intermediate wires
        for op in &self.ops {
            self.execute_op(op, &mut witness)?;
        }

        // Post-fixup: fill substituted-away wires from substitution map
        if let Some(subs) = &self.substitution_map {
            for (var_idx, lc) in subs {
                witness[*var_idx] = lc
                    .evaluate(&witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
            }
        }

        Ok(witness)
    }

    /// Execute a single `WitnessOp`, filling in the target wire(s).
    fn execute_op(
        &self,
        op: &WitnessOp<F>,
        witness: &mut [FieldElement<F>],
    ) -> Result<(), WitnessError>
    where
        F: PoseidonParamsProvider,
    {
        match op {
            WitnessOp::AssignLC { target, lc } => {
                witness[target.index()] = lc
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
            }
            WitnessOp::Multiply { target, a, b } => {
                let a_val = a
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                let b_val = b
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                witness[target.index()] = a_val.mul(&b_val);
            }
            WitnessOp::Inverse { target, operand } => {
                let val = operand
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                let inv = val.inv().ok_or(WitnessError::DivisionByZero {
                    variable_index: target.index(),
                })?;
                witness[target.index()] = inv;
            }
            WitnessOp::BitExtract {
                target,
                source,
                bit_index,
            } => {
                let val = source
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                let limbs = val.to_canonical();
                let limb_idx = (*bit_index / 64) as usize;
                let bit_pos = *bit_index % 64;
                let bit = if limb_idx < 4 {
                    (limbs[limb_idx] >> bit_pos) & 1
                } else {
                    0
                };
                witness[target.index()] = FieldElement::<F>::from_u64(bit);
            }
            WitnessOp::IsZero {
                diff,
                target_inv,
                target_result,
            } => {
                let diff_val = diff
                    .evaluate(witness)
                    .map_err(|e| WitnessError::MissingInput(e.to_string()))?;
                if diff_val.is_zero() {
                    witness[target_inv.index()] = FieldElement::<F>::zero();
                    witness[target_result.index()] = FieldElement::<F>::one();
                } else {
                    // Safe: diff_val is non-zero, so inv() always returns Some
                    let inv = diff_val.inv().ok_or(WitnessError::DivisionByZero {
                        variable_index: target_inv.index(),
                    })?;
                    witness[target_inv.index()] = inv;
                    witness[target_result.index()] = FieldElement::<F>::zero();
                }
            }
            WitnessOp::IntDivMod { q, r, lhs, rhs } => {
                let a = witness[lhs.index()];
                let b = witness[rhs.index()];
                // Integer division on canonical (unsigned) representations
                let a_limbs = a.to_canonical();
                let b_limbs = b.to_canonical();
                // For simplicity, use the first limb if value fits in 64 bits,
                // otherwise fall back to multi-limb division.
                let (q_val, r_val) = int_divmod_field_pub::<F>(&a_limbs, &b_limbs);
                witness[q.index()] = q_val;
                witness[r.index()] = r_val;
            }
            WitnessOp::PoseidonHash {
                left,
                right,
                output: _,
                internal_start,
                internal_count,
            } => {
                self.fill_poseidon(witness, *left, *right, *internal_start, *internal_count)?;
            }
            WitnessOp::ArtikCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                dispatch_artik_call::<F>(outputs, inputs, program_bytes, witness)?;
            }
        }
        Ok(())
    }

    /// Fill the ~361 internal Poseidon wires by replaying the permutation natively.
    fn fill_poseidon(
        &self,
        witness: &mut [FieldElement<F>],
        left: Variable,
        right: Variable,
        internal_start: usize,
        internal_count: usize,
    ) -> Result<(), WitnessError>
    where
        F: PoseidonParamsProvider,
    {
        let params = self.poseidon_params.as_ref().ok_or_else(|| {
            WitnessError::MissingInput("poseidon parameters not initialized".into())
        })?;
        fill_poseidon_witness(witness, params, left, right, internal_start, internal_count)
    }
}

/// Fill the ~361 internal Poseidon wires by replaying the permutation natively.
///
/// This must replicate *exactly* the variable allocation order of
/// `poseidon_hash_circuit` → `poseidon_permutation_circuit` in
/// `constraints/src/poseidon.rs`.
#[allow(clippy::needless_range_loop)]
pub(crate) fn fill_poseidon_witness<F: FieldBackend>(
    witness: &mut [FieldElement<F>],
    params: &PoseidonParams<F>,
    left: Variable,
    right: Variable,
    internal_start: usize,
    internal_count: usize,
) -> Result<(), WitnessError> {
    let total_rounds = params.r_f + params.r_p;
    let half_f = params.r_f / 2;

    let mut var_idx = internal_start;

    // First wire: capacity = 0
    witness[var_idx] = FieldElement::<F>::zero();
    var_idx += 1;

    // Initial state: [capacity=0, left, right]
    let mut state = [
        FieldElement::<F>::zero(),
        witness[left.index()],
        witness[right.index()],
    ];

    for r in 0..total_rounds {
        // 1. Add round constants
        for i in 0..params.t {
            state[i] = state[i].add(&params.round_constants[r * params.t + i]);
        }

        // 2. S-box layer
        if r < half_f || r >= half_f + params.r_p {
            // Full round: S-box on all 3 elements
            for i in 0..params.t {
                let x = state[i];
                let x2 = x.mul(&x);
                witness[var_idx] = x2;
                var_idx += 1;
                let x4 = x2.mul(&x2);
                witness[var_idx] = x4;
                var_idx += 1;
                let x5 = x4.mul(&x);
                witness[var_idx] = x5;
                var_idx += 1;
                state[i] = x5;
            }
        } else {
            // Partial round: S-box on state[0] only
            let x = state[0];
            let x2 = x.mul(&x);
            witness[var_idx] = x2;
            var_idx += 1;
            let x4 = x2.mul(&x2);
            witness[var_idx] = x4;
            var_idx += 1;
            let x5 = x4.mul(&x);
            witness[var_idx] = x5;
            var_idx += 1;
            state[0] = x5;
        }

        // 3. MDS matrix multiplication
        let old = state;
        for i in 0..params.t {
            state[i] = FieldElement::<F>::zero();
            for j in 0..params.t {
                state[i] = state[i].add(&params.mds[i][j].mul(&old[j]));
            }
        }

        // 4. Materialize state[1..] in partial rounds
        if r >= half_f && r < half_f + params.r_p {
            for i in 1..params.t {
                witness[var_idx] = state[i];
                var_idx += 1;
            }
        }
    }

    // Output state materialization (3 variables)
    for i in 0..params.t {
        witness[var_idx] = state[i];
        var_idx += 1;
    }

    // Sanity check: we filled exactly the expected number of wires
    debug_assert_eq!(
        var_idx - internal_start,
        internal_count,
        "Poseidon fill mismatch: filled {} wires but expected {}",
        var_idx - internal_start,
        internal_count
    );

    Ok(())
}

/// Integer division and modulo on field elements interpreted as unsigned integers.
///
/// Returns `(q, r)` where `a = b * q + r` and `0 <= r < b`.
/// Both `a` and `b` are given as 4-limb canonical representations.
pub fn int_divmod_field_pub<F: FieldBackend>(
    a_limbs: &[u64; 4],
    b_limbs: &[u64; 4],
) -> (FieldElement<F>, FieldElement<F>) {
    // Check if both values fit in a single u64 (common case)
    let a_small = a_limbs[1] == 0 && a_limbs[2] == 0 && a_limbs[3] == 0;
    let b_small = b_limbs[1] == 0 && b_limbs[2] == 0 && b_limbs[3] == 0;

    if a_small && b_small {
        let a = a_limbs[0];
        let b = b_limbs[0];
        if b == 0 {
            return (FieldElement::<F>::zero(), FieldElement::<F>::zero());
        }
        let q = a / b;
        let r = a % b;
        return (
            FieldElement::<F>::from_u64(q),
            FieldElement::<F>::from_u64(r),
        );
    }

    // Multi-limb: convert to BigUint-style division
    // For now, use a simple shift-and-subtract algorithm on 256-bit values
    let a_val = limbs_to_u256(a_limbs);
    let b_val = limbs_to_u256(b_limbs);
    if b_val == [0u64; 4] {
        return (FieldElement::<F>::zero(), FieldElement::<F>::zero());
    }
    let (q_val, r_val) = divmod_u256(&a_val, &b_val);
    (u256_to_field::<F>(&q_val), u256_to_field::<F>(&r_val))
}

fn limbs_to_u256(limbs: &[u64; 4]) -> [u64; 4] {
    *limbs
}

fn u256_to_field<F: FieldBackend>(limbs: &[u64; 4]) -> FieldElement<F> {
    // Reconstruct: limbs[0] + limbs[1]*2^64 + limbs[2]*2^128 + limbs[3]*2^192
    let mut result = FieldElement::<F>::from_u64(limbs[0]);
    if limbs[1] != 0 {
        let shift64 =
            FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
        result = result.add(&FieldElement::<F>::from_u64(limbs[1]).mul(&shift64));
    }
    if limbs[2] != 0 {
        let shift64 =
            FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
        let shift128 = shift64.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[2]).mul(&shift128));
    }
    if limbs[3] != 0 {
        let shift64 =
            FieldElement::<F>::from_u64(1u64 << 32).mul(&FieldElement::<F>::from_u64(1u64 << 32));
        let shift128 = shift64.mul(&shift64);
        let shift192 = shift128.mul(&shift64);
        result = result.add(&FieldElement::<F>::from_u64(limbs[3]).mul(&shift192));
    }
    result
}

/// Simple shift-and-subtract 256-bit unsigned division.
fn divmod_u256(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], [u64; 4]) {
    if cmp_u256(a, b) == std::cmp::Ordering::Less {
        return ([0; 4], *a);
    }

    let mut remainder = *a;
    let mut quotient = [0u64; 4];

    // Find highest set bit of b
    let b_bits = 256 - leading_zeros_u256(b);
    let a_bits = 256 - leading_zeros_u256(a);

    if b_bits == 0 {
        return ([0; 4], [0; 4]); // division by zero
    }

    let shift = a_bits - b_bits;
    let mut shifted_b = shl_u256(b, shift);

    for i in (0..=shift).rev() {
        if cmp_u256(&remainder, &shifted_b) != std::cmp::Ordering::Less {
            remainder = sub_u256(&remainder, &shifted_b);
            let word = i / 64;
            let bit = i % 64;
            quotient[word] |= 1u64 << bit;
        }
        shifted_b = shr_u256(&shifted_b, 1);
    }

    (quotient, remainder)
}

fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> std::cmp::Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

fn leading_zeros_u256(a: &[u64; 4]) -> usize {
    for i in (0..4).rev() {
        if a[i] != 0 {
            return (3 - i) * 64 + a[i].leading_zeros() as usize;
        }
    }
    256
}

fn shl_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in word_shift..4 {
        result[i] = a[i - word_shift] << bit_shift;
        if bit_shift > 0 && i > word_shift {
            result[i] |= a[i - word_shift - 1] >> (64 - bit_shift);
        }
    }
    result
}

fn shr_u256(a: &[u64; 4], shift: usize) -> [u64; 4] {
    if shift >= 256 {
        return [0; 4];
    }
    let word_shift = shift / 64;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in 0..(4 - word_shift) {
        result[i] = a[i + word_shift] >> bit_shift;
        if bit_shift > 0 && i + word_shift + 1 < 4 {
            result[i] |= a[i + word_shift + 1] << (64 - bit_shift);
        }
    }
    result
}

fn sub_u256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff2, b2) = diff.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    result
}
