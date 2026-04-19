use constraints::poseidon::PoseidonParams;
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use constraints::r1cs_optimize::{R1CSOptimizeResult, SubstitutionMap};
use constraints::PoseidonParamsProvider;
use memory::field::PrimeId;
use memory::{Bn254Fr, FieldBackend, FieldElement};
use std::collections::HashMap;

use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar, Visibility as IrVisibility};

use crate::r1cs_error::R1CSError;
use crate::r1cs_gadgets::power_of_two_generic;
use crate::witness_gen::WitnessOp;

/// Maps an R1CS constraint back to the IR instruction that generated it.
#[derive(Debug, Clone)]
pub struct ConstraintOrigin {
    /// Index of the IR instruction in `IrProgram::instructions`.
    pub ir_index: usize,
    /// The SSA variable defined by the instruction.
    pub result_var: SsaVar,
}

/// Maximum LC term count before auto-materialization.
///
/// Without this, chains of Add/Sub (e.g. MDS in Poseidon partial rounds)
/// cause exponential LC growth: f(n) = 2·f(n-1)+1 ≈ 2^n terms.
/// Materializing keeps each LC bounded and prevents OOM on large circuits.
const LC_AUTO_MATERIALIZE_THRESHOLD: usize = 8;

/// Compiles an Achronyme SSA IR program into an R1CS constraint system.
///
/// The R1CSCompiler walks IR instructions and emits R1CS constraints.
/// Each expression maps to a `LinearCombination`, and only multiplications /
/// materializations generate actual constraints.
pub struct R1CSCompiler<F: FieldBackend = Bn254Fr> {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem<F>,
    /// Declared variables: maps `public`/`witness` names → allocated R1CS wire.
    /// Only contains explicitly declared circuit inputs (not `let` bindings).
    pub bindings: HashMap<String, Variable>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
    /// Cached Poseidon parameters. Initialized on first `poseidon()` call.
    pub(crate) poseidon_params: Option<PoseidonParams<F>>,
    /// Witness generation trace: records each intermediate variable allocation.
    pub witness_ops: Vec<WitnessOp<F>>,
    /// Prime field for this compilation.
    /// Determines the default bit width for range checks and comparisons.
    pub prime_id: PrimeId,
    /// SSA variables proven to be boolean by bool_prop analysis.
    /// Boolean enforcement constraints are skipped for these.
    proven_boolean: std::collections::HashSet<ir::types::SsaVar>,
    /// SSA variables for which boolean enforcement (v * (1-v) = 0) has already
    /// been emitted. Avoids duplicate constraints when the same condition
    /// is used in multiple Mux/And/Or instructions.
    bool_enforced: std::collections::HashSet<ir::types::SsaVar>,
    /// Maps each R1CS constraint index to the IR instruction that generated it.
    /// Built during `compile_ir`, parallel to `cs.constraints()`.
    pub constraint_origins: Vec<ConstraintOrigin>,
    /// Variable substitution map from R1CS linear constraint elimination.
    /// Set by `optimize_r1cs()`. Used by witness generation to compute
    /// values for substituted-away wires.
    pub substitution_map: Option<SubstitutionMap<F>>,
}

impl<F: FieldBackend> Default for R1CSCompiler<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> R1CSCompiler<F> {
    /// Create an empty R1CS compiler with a fresh constraint system.
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
            bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
            prime_id: PrimeId::Bn254,
            poseidon_params: None,
            witness_ops: Vec::new(),
            proven_boolean: std::collections::HashSet::new(),
            bool_enforced: std::collections::HashSet::new(),
            constraint_origins: Vec::new(),
            substitution_map: None,
        }
    }

    /// Set the proven-boolean set from bool_prop analysis.
    /// Variables in this set skip redundant boolean enforcement constraints.
    pub fn set_proven_boolean(&mut self, set: std::collections::HashSet<ir::types::SsaVar>) {
        self.proven_boolean = set;
    }

    /// Run linear constraint elimination on the compiled R1CS.
    ///
    /// Must be called after `compile_ir()` / `compile_ir_with_witness()`.
    /// Identifies constraints of the form `k * LC = LC` (linear, no real
    /// multiplication) and substitutes one wire with the LC, eliminating
    /// the constraint. Runs to fixpoint.
    ///
    /// Also updates `witness_ops` (removes ops for substituted targets,
    /// applies substitutions to source LCs) and `constraint_origins`.
    ///
    /// The substitution map is stored for witness post-fixup.
    pub fn optimize_r1cs(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_linear();

        if !subs.is_empty() {
            // Update witness ops
            crate::witness_gen::apply_substitutions_to_witness_ops(&mut self.witness_ops, &subs);

            // Filter constraint_origins to match the new constraint list.
            // We need to rebuild it: the optimization removed some constraints
            // and the remaining ones shifted indices. Since optimize_linear
            // operates on the Vec<Constraint> directly, we rebuild origins
            // by keeping only entries whose constraint index survived.
            // However, optimize_linear replaces the constraint vec entirely,
            // so the old indices are gone. We clear origins for now —
            // the inspector can still work without them.
            self.constraint_origins.clear();

            self.substitution_map = Some(subs);
        }

        stats
    }

    /// Run O2 constraint simplification on the compiled R1CS.
    ///
    /// Includes O1 (linear elimination) plus DEDUCE: extracts linear
    /// constraints implied by quadratic constraints via Gaussian elimination
    /// on the monomial matrix. Matches circom `--O2`.
    pub fn optimize_r1cs_o2(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_o2();

        if !subs.is_empty() {
            crate::witness_gen::apply_substitutions_to_witness_ops(&mut self.witness_ops, &subs);
            self.constraint_origins.clear();
            self.substitution_map = Some(subs);
        }

        stats
    }

    /// Declare a public input variable and bind it to `name`.
    ///
    /// Public inputs must be declared before witnesses to maintain the
    /// snarkjs-compatible wire layout.
    pub fn declare_public(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_input();
        self.bindings.insert(name.to_string(), var);
        self.public_inputs.push(name.to_string());
        var
    }

    /// Declare a private witness variable and bind it to `name`.
    pub fn declare_witness(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_witness();
        self.bindings.insert(name.to_string(), var);
        self.witnesses.push(name.to_string());
        var
    }

    /// Materialize an LC if it exceeds the auto-materialization threshold.
    ///
    /// Prevents exponential LC term growth in long chains of Add/Sub
    /// (e.g. MDS matrix multiplication in Poseidon partial rounds).
    /// Adds at most 1 constraint per materialization.
    fn auto_materialize(&mut self, lc: LinearCombination<F>) -> LinearCombination<F> {
        if lc.terms.len() > LC_AUTO_MATERIALIZE_THRESHOLD {
            let var = self.materialize_lc(&lc);
            LinearCombination::from_variable(var)
        } else {
            lc
        }
    }

    /// Look up a previously declared variable by name.
    pub fn lookup(&self, name: &str) -> Result<Variable, R1CSError> {
        self.bindings
            .get(name)
            .copied()
            .ok_or_else(|| R1CSError::UndeclaredVariable(name.to_string(), None))
    }

    /// Compile an SSA IR program into R1CS constraints.
    ///
    /// ```
    /// use compiler::r1cs_backend::R1CSCompiler;
    /// use ir::IrLowering;
    ///
    /// let prog: ir::types::IrProgram = IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
    /// let mut rc = R1CSCompiler::new();
    /// rc.compile_ir(&prog).unwrap();
    /// assert!(rc.cs.num_constraints() > 0);
    /// ```
    pub fn compile_ir(&mut self, program: &IrProgram<F>) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        // Lookup cache: SSA variable → its LinearCombination. Used for O(1)
        // lookups only — never iterated, so HashMap ordering is irrelevant.
        let mut lc_map: HashMap<SsaVar, LinearCombination<F>> = HashMap::new();
        // Track proven bit-width bounds from RangeCheck for IsLt/IsLe optimization
        let mut range_bounds: HashMap<SsaVar, u32> = HashMap::new();
        // Cache divmod gadgets: (lhs, rhs, max_bits) → (q_lc, r_lc).
        // When IntDiv and IntMod use the same operands, the second one reuses
        // the cached result instead of generating duplicate constraints.
        #[allow(clippy::type_complexity)]
        let mut divmod_cache: HashMap<
            (SsaVar, SsaVar, u32),
            (LinearCombination<F>, LinearCombination<F>),
        > = HashMap::new();

        // Helper closure to look up SSA variables with proper error messages
        let lookup = |map: &HashMap<SsaVar, LinearCombination<F>>,
                      var: &SsaVar|
         -> Result<LinearCombination<F>, R1CSError> {
            map.get(var).cloned().ok_or_else(|| {
                R1CSError::UnsupportedOperation(format!("undefined SSA variable {:?}", var), None)
            })
        };

        for (ir_idx, inst) in program.instructions.iter().enumerate() {
            let constraints_before = self.cs.num_constraints();

            match inst {
                IrInstruction::Const { result, value } => {
                    lc_map.insert(*result, LinearCombination::from_constant(*value));
                }
                IrInstruction::Input {
                    result,
                    name,
                    visibility,
                } => {
                    let var = match visibility {
                        IrVisibility::Public => {
                            let v = self.cs.alloc_input();
                            self.bindings.insert(name.clone(), v);
                            self.public_inputs.push(name.clone());
                            v
                        }
                        IrVisibility::Witness => {
                            let v = self.cs.alloc_witness();
                            self.bindings.insert(name.clone(), v);
                            self.witnesses.push(name.clone());
                            v
                        }
                    };
                    lc_map.insert(*result, LinearCombination::from_variable(var));
                }
                IrInstruction::Add { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let out = self.auto_materialize(a + b);
                    lc_map.insert(*result, out);
                }
                IrInstruction::Sub { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let out = self.auto_materialize(a - b);
                    lc_map.insert(*result, out);
                }
                IrInstruction::Neg { result, operand } => {
                    let lc = lookup(&lc_map, operand)?;
                    lc_map.insert(*result, lc * FieldElement::<F>::one().neg());
                }
                IrInstruction::Mul { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let out = self.multiply_lcs(&a, &b);
                    lc_map.insert(*result, out);
                }
                IrInstruction::Div { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let out = self.divide_lcs(&a, &b)?;
                    lc_map.insert(*result, out);
                }
                IrInstruction::Mux {
                    result,
                    cond,
                    if_true,
                    if_false,
                } => {
                    let cond_lc = lookup(&lc_map, cond)?;
                    let then_lc = lookup(&lc_map, if_true)?;
                    let else_lc = lookup(&lc_map, if_false)?;

                    // Skip boolean enforcement if cond is proven boolean or already enforced
                    if !self.proven_boolean.contains(cond) && self.bool_enforced.insert(*cond) {
                        let one = LinearCombination::from_constant(FieldElement::<F>::one());
                        let one_minus_cond = one - cond_lc.clone();
                        self.cs
                            .enforce(cond_lc.clone(), one_minus_cond, LinearCombination::zero());
                    }

                    // MUX: result = cond * (then - else) + else
                    let diff = then_lc - else_lc.clone();
                    let selected = self.multiply_lcs(&cond_lc, &diff);
                    lc_map.insert(*result, selected + else_lc);
                }
                IrInstruction::AssertEq {
                    result, lhs, rhs, ..
                } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    self.cs.enforce_equal(a, b.clone());
                    lc_map.insert(*result, b);
                }
                IrInstruction::RangeCheck {
                    result,
                    operand,
                    bits,
                } => {
                    let lc = lookup(&lc_map, operand)?;
                    // Boolean decomposition: x = sum(b_i * 2^i), each b_i boolean
                    // Cost: bits boolean constraints + 1 sum equality = bits+1 total
                    let mut sum = LinearCombination::zero();
                    for i in 0..*bits {
                        let bit_var = self.cs.alloc_witness();
                        // b_i * (1 - b_i) = 0  (enforces b_i ∈ {0, 1})
                        self.cs.enforce(
                            LinearCombination::from_variable(bit_var),
                            LinearCombination::from_constant(FieldElement::<F>::one())
                                - LinearCombination::from_variable(bit_var),
                            LinearCombination::zero(),
                        );
                        let coeff = power_of_two_generic::<F>(i);
                        sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                        self.witness_ops.push(WitnessOp::BitExtract {
                            target: bit_var,
                            source: lc.clone(),
                            bit_index: i,
                        });
                    }
                    self.cs.enforce_equal(lc.clone(), sum);
                    // Record proven bound for IsLt/IsLe optimization
                    range_bounds.insert(*operand, *bits);
                    lc_map.insert(*result, lc);
                }
                IrInstruction::Not { result, operand } => {
                    let op_lc = lookup(&lc_map, operand)?;
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    // Skip boolean enforcement if proven boolean or already enforced
                    if !self.proven_boolean.contains(operand) && self.bool_enforced.insert(*operand)
                    {
                        self.cs.enforce(
                            op_lc.clone(),
                            one.clone() - op_lc.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    // result = 1 - op
                    lc_map.insert(*result, one - op_lc);
                }
                IrInstruction::And { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    if !self.proven_boolean.contains(lhs) && self.bool_enforced.insert(*lhs) {
                        self.cs.enforce(
                            a.clone(),
                            one.clone() - a.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    if !self.proven_boolean.contains(rhs) && self.bool_enforced.insert(*rhs) {
                        self.cs
                            .enforce(b.clone(), one - b.clone(), LinearCombination::zero());
                    }
                    // result = a * b
                    let out = self.multiply_lcs(&a, &b);
                    lc_map.insert(*result, out);
                }
                IrInstruction::Or { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    if !self.proven_boolean.contains(lhs) && self.bool_enforced.insert(*lhs) {
                        self.cs.enforce(
                            a.clone(),
                            one.clone() - a.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    if !self.proven_boolean.contains(rhs) && self.bool_enforced.insert(*rhs) {
                        self.cs
                            .enforce(b.clone(), one - b.clone(), LinearCombination::zero());
                    }
                    // result = a + b - a*b
                    let product = self.multiply_lcs(&a, &b);
                    lc_map.insert(*result, a + b - product);
                }
                IrInstruction::IsEq { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let diff = a - b;
                    // IsZero gadget: alloc inv + eq_result
                    // enforce: diff * inv = 1 - eq_result
                    // enforce: diff * eq_result = 0
                    let inv_var = self.cs.alloc_witness();
                    let eq_var = self.cs.alloc_witness();
                    self.witness_ops.push(WitnessOp::IsZero {
                        diff: diff.clone(),
                        target_inv: inv_var,
                        target_result: eq_var,
                    });
                    let inv_lc = LinearCombination::from_variable(inv_var);
                    let eq_lc = LinearCombination::from_variable(eq_var);
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    self.cs.enforce(diff.clone(), inv_lc, one - eq_lc.clone());
                    self.cs
                        .enforce(diff, eq_lc.clone(), LinearCombination::zero());
                    lc_map.insert(*result, eq_lc);
                }
                IrInstruction::IsNeq { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let diff = a - b;
                    // IsZero gadget then negate
                    let inv_var = self.cs.alloc_witness();
                    let eq_var = self.cs.alloc_witness();
                    self.witness_ops.push(WitnessOp::IsZero {
                        diff: diff.clone(),
                        target_inv: inv_var,
                        target_result: eq_var,
                    });
                    let inv_lc = LinearCombination::from_variable(inv_var);
                    let eq_lc = LinearCombination::from_variable(eq_var);
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    self.cs
                        .enforce(diff.clone(), inv_lc, one.clone() - eq_lc.clone());
                    self.cs
                        .enforce(diff, eq_lc.clone(), LinearCombination::zero());
                    // neq = 1 - eq
                    lc_map.insert(*result, one - eq_lc);
                }
                IrInstruction::IsLt { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let bound_a = range_bounds.get(lhs).copied();
                    let bound_b = range_bounds.get(rhs).copied();
                    let default_bits = self.default_range_bits();

                    let effective_bits = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => ba.max(bb),
                        _ => {
                            if bound_a.is_none() {
                                self.enforce_default_range(&a);
                            }
                            if bound_b.is_none() {
                                self.enforce_default_range(&b);
                            }
                            default_bits
                        }
                    };

                    let offset =
                        power_of_two_generic::<F>(effective_bits).sub(&FieldElement::<F>::one());
                    let diff = b - a + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                    lc_map.insert(*result, lt_lc);
                }
                IrInstruction::IsLe { result, lhs, rhs } => {
                    // a <= b  ≡  !(b < a)  ≡  1 - IsLt(b, a)
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let bound_a = range_bounds.get(lhs).copied();
                    let bound_b = range_bounds.get(rhs).copied();
                    let default_bits = self.default_range_bits();

                    let effective_bits = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => ba.max(bb),
                        _ => {
                            if bound_a.is_none() {
                                self.enforce_default_range(&a);
                            }
                            if bound_b.is_none() {
                                self.enforce_default_range(&b);
                            }
                            default_bits
                        }
                    };

                    let offset =
                        power_of_two_generic::<F>(effective_bits).sub(&FieldElement::<F>::one());
                    let diff = a - b + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    lc_map.insert(*result, one - lt_lc);
                }
                IrInstruction::IsLtBounded {
                    result,
                    lhs,
                    rhs,
                    bitwidth,
                } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let offset =
                        power_of_two_generic::<F>(*bitwidth).sub(&FieldElement::<F>::one());
                    let diff = b - a + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                    lc_map.insert(*result, lt_lc);
                }
                IrInstruction::IsLeBounded {
                    result,
                    lhs,
                    rhs,
                    bitwidth,
                } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    let offset =
                        power_of_two_generic::<F>(*bitwidth).sub(&FieldElement::<F>::one());
                    let diff = a - b + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    lc_map.insert(*result, one - lt_lc);
                }
                IrInstruction::Assert {
                    result, operand, ..
                } => {
                    let op_lc = lookup(&lc_map, operand)?;
                    let one = LinearCombination::from_constant(FieldElement::<F>::one());
                    // Skip boolean enforcement if proven boolean or already enforced
                    if !self.proven_boolean.contains(operand) && self.bool_enforced.insert(*operand)
                    {
                        self.cs.enforce(
                            op_lc.clone(),
                            one.clone() - op_lc.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    // Enforce op == 1
                    self.cs.enforce_equal(op_lc.clone(), one);
                    lc_map.insert(*result, op_lc);
                }
                IrInstruction::PoseidonHash {
                    result,
                    left,
                    right,
                } => {
                    let left_lc = lookup(&lc_map, left)?;
                    let right_lc = lookup(&lc_map, right)?;

                    let left_var = self.materialize_lc(&left_lc);
                    let right_var = self.materialize_lc(&right_lc);

                    if self.poseidon_params.is_none() {
                        self.poseidon_params = Some(F::default_poseidon_t3());
                    }
                    let params = self.poseidon_params.as_ref().unwrap();

                    let internal_start = self.cs.num_variables();
                    let hash_var = constraints::poseidon::poseidon_hash_circuit(
                        &mut self.cs,
                        params,
                        left_var,
                        right_var,
                    );
                    let internal_count = self.cs.num_variables() - internal_start;

                    self.witness_ops.push(WitnessOp::PoseidonHash {
                        left: left_var,
                        right: right_var,
                        output: hash_var,
                        internal_start,
                        internal_count,
                    });

                    lc_map.insert(*result, LinearCombination::from_variable(hash_var));
                }
                IrInstruction::Decompose {
                    result,
                    bit_results,
                    operand,
                    num_bits,
                } => {
                    let lc = lookup(&lc_map, operand)?;
                    // Materialize source to avoid cloning large LC num_bits times.
                    let src_var = self.materialize_lc(&lc);
                    let src_lc = LinearCombination::from_variable(src_var);

                    // Same as RangeCheck but also registers each bit in lc_map.
                    let mut sum = LinearCombination::zero();
                    for (i, bit_ssa) in bit_results.iter().enumerate() {
                        let bit_var = self.cs.alloc_witness();
                        // b_i * (1 - b_i) = 0
                        self.cs.enforce(
                            LinearCombination::from_variable(bit_var),
                            LinearCombination::from_constant(FieldElement::<F>::one())
                                - LinearCombination::from_variable(bit_var),
                            LinearCombination::zero(),
                        );
                        // Track as bool-enforced so Mux/And/Or won't emit duplicate enforcement
                        self.bool_enforced.insert(*bit_ssa);
                        let coeff = power_of_two_generic::<F>(i as u32);
                        sum = sum + LinearCombination::from_variable(bit_var) * coeff;
                        self.witness_ops.push(WitnessOp::BitExtract {
                            target: bit_var,
                            source: src_lc.clone(),
                            bit_index: i as u32,
                        });
                        // Register each bit in lc_map so subsequent instructions can use it
                        lc_map.insert(*bit_ssa, LinearCombination::from_variable(bit_var));
                    }
                    self.cs.enforce_equal(src_lc, sum);
                    range_bounds.insert(*operand, *num_bits);
                    lc_map.insert(*result, lc);
                }
                IrInstruction::IntDiv {
                    result,
                    lhs,
                    rhs,
                    max_bits,
                } => {
                    let cache_key = (*lhs, *rhs, *max_bits);
                    if let Some((cached_q, _)) = divmod_cache.get(&cache_key) {
                        // Reuse cached quotient from a previous divmod on same operands
                        lc_map.insert(*result, cached_q.clone());
                    } else {
                        let a_lc = lookup(&lc_map, lhs)?;
                        let b_lc = lookup(&lc_map, rhs)?;

                        let q_var = self.cs.alloc_witness();
                        let r_var = self.cs.alloc_witness();

                        let lhs_var = self.materialize_lc(&a_lc);
                        let rhs_var = self.materialize_lc(&b_lc);
                        self.witness_ops.push(WitnessOp::IntDivMod {
                            q: q_var,
                            r: r_var,
                            lhs: lhs_var,
                            rhs: rhs_var,
                        });

                        let q_lc = LinearCombination::from_variable(q_var);
                        let r_lc = LinearCombination::from_variable(r_var);

                        let bq = self.multiply_lcs(&b_lc, &q_lc);
                        self.cs.enforce_equal(bq + r_lc.clone(), a_lc);

                        self.enforce_n_range(&q_lc, *max_bits);
                        self.enforce_n_range(&r_lc, *max_bits);

                        let one = LinearCombination::from_constant(FieldElement::<F>::one());
                        let b_minus_r_minus_1 = b_lc.clone() - r_lc.clone() - one;
                        self.enforce_n_range(&b_minus_r_minus_1, *max_bits);

                        divmod_cache.insert(cache_key, (q_lc.clone(), r_lc));
                        lc_map.insert(*result, q_lc);
                    }
                }
                IrInstruction::IntMod {
                    result,
                    lhs,
                    rhs,
                    max_bits,
                } => {
                    let cache_key = (*lhs, *rhs, *max_bits);
                    if let Some((_, cached_r)) = divmod_cache.get(&cache_key) {
                        // Reuse cached remainder from a previous divmod on same operands
                        lc_map.insert(*result, cached_r.clone());
                    } else {
                        let a_lc = lookup(&lc_map, lhs)?;
                        let b_lc = lookup(&lc_map, rhs)?;

                        let q_var = self.cs.alloc_witness();
                        let r_var = self.cs.alloc_witness();

                        let lhs_var = self.materialize_lc(&a_lc);
                        let rhs_var = self.materialize_lc(&b_lc);
                        self.witness_ops.push(WitnessOp::IntDivMod {
                            q: q_var,
                            r: r_var,
                            lhs: lhs_var,
                            rhs: rhs_var,
                        });

                        let q_lc = LinearCombination::from_variable(q_var);
                        let r_lc = LinearCombination::from_variable(r_var);

                        let bq = self.multiply_lcs(&b_lc, &q_lc);
                        self.cs.enforce_equal(bq + r_lc.clone(), a_lc);

                        self.enforce_n_range(&q_lc, *max_bits);
                        self.enforce_n_range(&r_lc, *max_bits);

                        let one = LinearCombination::from_constant(FieldElement::<F>::one());
                        let b_minus_r_minus_1 = b_lc.clone() - r_lc.clone() - one;
                        self.enforce_n_range(&b_minus_r_minus_1, *max_bits);

                        divmod_cache.insert(cache_key, (q_lc, r_lc.clone()));
                        lc_map.insert(*result, r_lc);
                    }
                }
                IrInstruction::WitnessCall {
                    outputs,
                    inputs,
                    program_bytes,
                } => {
                    // Each output is a fresh witness wire — no
                    // constraints are emitted here. The prover's
                    // witness generator replays the Artik program
                    // against `inputs` at witness-gen time to fill
                    // the wires.
                    let mut input_vars: Vec<Variable> = Vec::with_capacity(inputs.len());
                    for v in inputs {
                        let lc = lookup(&lc_map, v)?;
                        input_vars.push(self.materialize_lc(&lc));
                    }
                    let mut output_vars: Vec<Variable> = Vec::with_capacity(outputs.len());
                    for out_ssa in outputs {
                        let out_var = self.cs.alloc_witness();
                        output_vars.push(out_var);
                        lc_map.insert(*out_ssa, LinearCombination::from_variable(out_var));
                    }
                    self.witness_ops.push(WitnessOp::ArtikCall {
                        outputs: output_vars,
                        inputs: input_vars,
                        program_bytes: program_bytes.clone(),
                    });
                }
            }

            // Record which IR instruction generated each new constraint.
            let constraints_after = self.cs.num_constraints();
            let result_var = inst.result_var();
            for _ in constraints_before..constraints_after {
                self.constraint_origins.push(ConstraintOrigin {
                    ir_index: ir_idx,
                    result_var,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ir::types::{Instruction, IrProgram, SsaVar, Visibility as IrVisibility};

    #[test]
    fn constraint_origins_tracks_mul() {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        // Mul generates exactly 1 constraint
        assert_eq!(compiler.cs.num_constraints(), 1);
        assert_eq!(compiler.constraint_origins.len(), 1);
        assert_eq!(compiler.constraint_origins[0].ir_index, 2); // third instruction
        assert_eq!(compiler.constraint_origins[0].result_var, SsaVar(2));
    }

    #[test]
    fn constraint_origins_tracks_assert_eq() {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Public,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v2,
            lhs: v0,
            rhs: v1,
            message: Some("values must match".into()),
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        assert_eq!(compiler.cs.num_constraints(), 1);
        assert_eq!(compiler.constraint_origins.len(), 1);
        assert_eq!(compiler.constraint_origins[0].ir_index, 2);
        assert_eq!(compiler.constraint_origins[0].result_var, SsaVar(2));
    }

    #[test]
    fn constraint_origins_empty_for_linear_ops() {
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        // Add is free (no constraints)
        let v2 = prog.fresh_var();
        prog.push(Instruction::Add {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        assert_eq!(compiler.cs.num_constraints(), 0);
        assert!(compiler.constraint_origins.is_empty());
    }

    #[test]
    fn constraint_origins_count_matches_constraints() {
        // Mixed circuit: Mul + PoseidonHash + AssertEq
        let mut prog: IrProgram = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: IrVisibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: IrVisibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: v3,
            left: v0,
            right: v1,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v4,
            lhs: v2,
            rhs: v3,
            message: None,
        });

        let mut compiler = R1CSCompiler::new();
        compiler.compile_ir(&prog).unwrap();

        // Origins length must match constraint count exactly
        assert_eq!(
            compiler.constraint_origins.len(),
            compiler.cs.num_constraints()
        );

        // Verify Poseidon constraints map back to the PoseidonHash instruction (index 3)
        let poseidon_origins: Vec<_> = compiler
            .constraint_origins
            .iter()
            .filter(|o| o.ir_index == 3)
            .collect();
        assert_eq!(poseidon_origins.len(), 361); // PoseidonHash = 361 constraints
    }
}
