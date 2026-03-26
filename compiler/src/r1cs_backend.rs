use constraints::poseidon::PoseidonParams;
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use memory::FieldElement;
use std::collections::HashMap;

use ir::types::{Instruction as IrInstruction, IrProgram, SsaVar, Visibility as IrVisibility};

use crate::r1cs_error::R1CSError;
use crate::r1cs_gadgets::compute_power_of_two;
use crate::witness_gen::WitnessOp;

/// Compiles an Achronyme SSA IR program into an R1CS constraint system.
///
/// The R1CSCompiler walks IR instructions and emits R1CS constraints.
/// Each expression maps to a `LinearCombination`, and only multiplications /
/// materializations generate actual constraints.
pub struct R1CSCompiler {
    /// The underlying R1CS constraint system being built.
    pub cs: ConstraintSystem,
    /// Declared variables: maps `public`/`witness` names → allocated R1CS wire.
    /// Only contains explicitly declared circuit inputs (not `let` bindings).
    pub bindings: HashMap<String, Variable>,
    /// Names of variables declared as public inputs (in declaration order).
    pub public_inputs: Vec<String>,
    /// Names of variables declared as private witnesses (in declaration order).
    pub witnesses: Vec<String>,
    /// Cached Poseidon parameters. Initialized on first `poseidon()` call.
    pub(crate) poseidon_params: Option<PoseidonParams>,
    /// Witness generation trace: records each intermediate variable allocation.
    pub witness_ops: Vec<WitnessOp>,
    /// SSA variables proven to be boolean by bool_prop analysis.
    /// Boolean enforcement constraints are skipped for these.
    proven_boolean: std::collections::HashSet<ir::types::SsaVar>,
}

impl Default for R1CSCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl R1CSCompiler {
    /// Create an empty R1CS compiler with a fresh constraint system.
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
            bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
            poseidon_params: None,
            witness_ops: Vec::new(),
            proven_boolean: std::collections::HashSet::new(),
        }
    }

    /// Set the proven-boolean set from bool_prop analysis.
    /// Variables in this set skip redundant boolean enforcement constraints.
    pub fn set_proven_boolean(&mut self, set: std::collections::HashSet<ir::types::SsaVar>) {
        self.proven_boolean = set;
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
    /// let prog = IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
    /// let mut rc = R1CSCompiler::new();
    /// rc.compile_ir(&prog).unwrap();
    /// assert!(rc.cs.num_constraints() > 0);
    /// ```
    pub fn compile_ir(&mut self, program: &IrProgram) -> Result<(), R1CSError> {
        // Lookup cache: SSA variable → its LinearCombination. Used for O(1)
        // lookups only — never iterated, so HashMap ordering is irrelevant.
        let mut lc_map: HashMap<SsaVar, LinearCombination> = HashMap::new();
        // Track proven bit-width bounds from RangeCheck for IsLt/IsLe optimization
        let mut range_bounds: HashMap<SsaVar, u32> = HashMap::new();

        // Helper closure to look up SSA variables with proper error messages
        let lookup = |map: &HashMap<SsaVar, LinearCombination>,
                      var: &SsaVar|
         -> Result<LinearCombination, R1CSError> {
            map.get(var).cloned().ok_or_else(|| {
                R1CSError::UnsupportedOperation(format!("undefined SSA variable {:?}", var), None)
            })
        };

        for inst in &program.instructions {
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
                    lc_map.insert(*result, a + b);
                }
                IrInstruction::Sub { result, lhs, rhs } => {
                    let a = lookup(&lc_map, lhs)?;
                    let b = lookup(&lc_map, rhs)?;
                    lc_map.insert(*result, a - b);
                }
                IrInstruction::Neg { result, operand } => {
                    let lc = lookup(&lc_map, operand)?;
                    lc_map.insert(*result, lc * FieldElement::ONE.neg());
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

                    // Skip boolean enforcement if cond is proven boolean
                    if !self.proven_boolean.contains(cond) {
                        let one = LinearCombination::from_constant(FieldElement::ONE);
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
                            LinearCombination::from_constant(FieldElement::ONE)
                                - LinearCombination::from_variable(bit_var),
                            LinearCombination::zero(),
                        );
                        let coeff = compute_power_of_two(i);
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
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    // Skip boolean enforcement if operand is proven boolean
                    if !self.proven_boolean.contains(operand) {
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
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    if !self.proven_boolean.contains(lhs) {
                        self.cs.enforce(
                            a.clone(),
                            one.clone() - a.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    if !self.proven_boolean.contains(rhs) {
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
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    if !self.proven_boolean.contains(lhs) {
                        self.cs.enforce(
                            a.clone(),
                            one.clone() - a.clone(),
                            LinearCombination::zero(),
                        );
                    }
                    if !self.proven_boolean.contains(rhs) {
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
                    let one = LinearCombination::from_constant(FieldElement::ONE);
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
                    let one = LinearCombination::from_constant(FieldElement::ONE);
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

                    let effective_bits = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => ba.max(bb),
                        _ => {
                            if bound_a.is_none() {
                                self.enforce_252_range(&a);
                            }
                            if bound_b.is_none() {
                                self.enforce_252_range(&b);
                            }
                            252
                        }
                    };

                    let offset = compute_power_of_two(effective_bits).sub(&FieldElement::ONE);
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

                    let effective_bits = match (bound_a, bound_b) {
                        (Some(ba), Some(bb)) => ba.max(bb),
                        _ => {
                            if bound_a.is_none() {
                                self.enforce_252_range(&a);
                            }
                            if bound_b.is_none() {
                                self.enforce_252_range(&b);
                            }
                            252
                        }
                    };

                    let offset = compute_power_of_two(effective_bits).sub(&FieldElement::ONE);
                    let diff = a - b + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, effective_bits + 1);
                    let one = LinearCombination::from_constant(FieldElement::ONE);
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
                    let offset = compute_power_of_two(*bitwidth).sub(&FieldElement::ONE);
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
                    let offset = compute_power_of_two(*bitwidth).sub(&FieldElement::ONE);
                    let diff = a - b + LinearCombination::from_constant(offset);
                    let lt_lc = self.compile_is_lt_via_bits(&diff, *bitwidth + 1);
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    lc_map.insert(*result, one - lt_lc);
                }
                IrInstruction::Assert { result, operand } => {
                    let op_lc = lookup(&lc_map, operand)?;
                    let one = LinearCombination::from_constant(FieldElement::ONE);
                    // Skip boolean enforcement if operand is proven boolean
                    if !self.proven_boolean.contains(operand) {
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
                        self.poseidon_params =
                            Some(constraints::poseidon::PoseidonParams::bn254_t3());
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
            }
        }

        Ok(())
    }
}
