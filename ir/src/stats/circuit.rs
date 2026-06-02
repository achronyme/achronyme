use std::collections::{HashMap, HashSet};

use memory::FieldBackend;

use super::costs::is_lt_cost;
use super::ConstraintCategory;
use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

/// Aggregated cost for one category of instructions.
#[derive(Debug, Clone)]
pub struct CategoryCost {
    pub category: ConstraintCategory,
    /// Number of IR instructions in this category.
    pub count: usize,
    /// Total estimated R1CS constraints.
    pub constraints: usize,
}

/// Profiling stats for a single circuit / prove block.
#[derive(Debug, Clone)]
pub struct CircuitStats {
    /// Name from ProveIR (or `<anonymous>`).
    pub name: String,
    /// Per-category constraint breakdown, sorted by constraints descending.
    pub categories: Vec<CategoryCost>,
    /// Number of public inputs.
    pub n_public: usize,
    /// Number of witness inputs.
    pub n_witness: usize,
    /// Total IR instructions (excluding Const/Input).
    pub n_instructions: usize,
    /// Total estimated R1CS constraints.
    pub total_constraints: usize,
}

impl CircuitStats {
    /// Compute circuit stats from an optimized IR program.
    ///
    /// The `proven_boolean` set should come from `bool_prop::compute_proven_boolean`.
    /// The `name` is typically from `ProveIR.name`.
    pub fn from_program<F: FieldBackend>(
        program: &IrProgram<F>,
        proven_boolean: &HashSet<SsaVar>,
        name: Option<&str>,
    ) -> Self {
        let mut cat_map: HashMap<ConstraintCategory, (usize, usize)> = HashMap::new();
        let mut range_bounds: HashMap<SsaVar, u32> = HashMap::new();
        // Track boolean enforcement dedup (mirrors R1CS backend behavior)
        let mut bool_enforced: HashSet<SsaVar> = HashSet::new();
        // Track variables whose LC is non-trivial (products from Mul/Div/Mux).
        // PoseidonHash materializes these inputs, adding 1 constraint each.
        let mut non_single: HashSet<SsaVar> = HashSet::new();
        let mut n_public = 0usize;
        let mut n_witness = 0usize;
        let mut n_instructions = 0usize;

        for inst in &program.instructions {
            let (category, cost) = match inst {
                Instruction::Const { .. } => continue,
                Instruction::Input { visibility, .. } => {
                    match visibility {
                        Visibility::Public => n_public += 1,
                        Visibility::Witness => n_witness += 1,
                    }
                    continue;
                }
                Instruction::Add { .. } | Instruction::Sub { .. } | Instruction::Neg { .. } => {
                    continue;
                }

                Instruction::Mul { result, .. } => {
                    non_single.insert(*result);
                    (ConstraintCategory::Arithmetic, 1)
                }
                Instruction::Div { result, .. } => {
                    non_single.insert(*result);
                    (ConstraintCategory::Arithmetic, 2)
                }

                Instruction::AssertEq { .. } => (ConstraintCategory::Assertion, 1),
                Instruction::Assert { operand, .. } => {
                    let bool_cost =
                        if proven_boolean.contains(operand) || !bool_enforced.insert(*operand) {
                            0
                        } else {
                            1
                        };
                    (ConstraintCategory::Assertion, 1 + bool_cost)
                }

                Instruction::RangeCheck { operand, bits, .. } => {
                    range_bounds.insert(*operand, *bits);
                    (ConstraintCategory::RangeCheck, (*bits as usize) + 1)
                }

                Instruction::Not { operand, .. } => {
                    let cost =
                        if proven_boolean.contains(operand) || !bool_enforced.insert(*operand) {
                            0
                        } else {
                            1
                        };
                    if cost == 0 {
                        continue;
                    }
                    (ConstraintCategory::Boolean, cost)
                }
                Instruction::And { lhs, rhs, .. } => {
                    let mut cost = 1; // product
                    if !proven_boolean.contains(lhs) && bool_enforced.insert(*lhs) {
                        cost += 1;
                    }
                    if !proven_boolean.contains(rhs) && bool_enforced.insert(*rhs) {
                        cost += 1;
                    }
                    (ConstraintCategory::Boolean, cost)
                }
                Instruction::Or { lhs, rhs, .. } => {
                    let mut cost = 1; // product
                    if !proven_boolean.contains(lhs) && bool_enforced.insert(*lhs) {
                        cost += 1;
                    }
                    if !proven_boolean.contains(rhs) && bool_enforced.insert(*rhs) {
                        cost += 1;
                    }
                    (ConstraintCategory::Boolean, cost)
                }

                Instruction::Mux { result, cond, .. } => {
                    non_single.insert(*result);
                    // 1 materialize(then - else) + 1 multiply for selection
                    let mut cost = 2;
                    if !proven_boolean.contains(cond) && bool_enforced.insert(*cond) {
                        cost += 1;
                    }
                    (ConstraintCategory::Selection, cost)
                }

                Instruction::IsEq { .. } => (ConstraintCategory::Comparison, 2),
                Instruction::IsNeq { .. } => (ConstraintCategory::Comparison, 2),

                Instruction::IsLt { lhs, rhs, .. } => {
                    let cost = is_lt_cost(&range_bounds, lhs, rhs);
                    (ConstraintCategory::Comparison, cost)
                }
                Instruction::IsLe { lhs, rhs, .. } => {
                    let cost = is_lt_cost(&range_bounds, lhs, rhs);
                    (ConstraintCategory::Comparison, cost)
                }
                Instruction::IsLtBounded { bitwidth, .. } => {
                    // 1 materialize + (bitwidth+1) boolean + 1 sum
                    (ConstraintCategory::Comparison, (*bitwidth as usize) + 3)
                }
                Instruction::IsLeBounded { bitwidth, .. } => {
                    (ConstraintCategory::Comparison, (*bitwidth as usize) + 3)
                }

                // S-box: full=8*3*3=72, partial=57*1*3=171, subtotal=243
                // Materializations: partial=57*2=114, final=3
                // Capacity: 1
                // Total: 243 + 114 + 3 + 1 = 361
                // + input materializations (1 each for non-single-variable inputs)
                Instruction::PoseidonHash { left, right, .. } => {
                    let mut cost = 361;
                    if non_single.contains(left) {
                        cost += 1;
                    }
                    if non_single.contains(right) {
                        cost += 1;
                    }
                    (ConstraintCategory::Hash, cost)
                }

                // Decompose: n boolean constraints + 1 reconstruction sum constraint
                Instruction::Decompose { num_bits, .. } => {
                    (ConstraintCategory::RangeCheck, (*num_bits as usize) + 1)
                }

                // IntDiv/IntMod: division constraint + range checks on quotient and remainder
                // Cost: 1 (division relation) + 2*(max_bits+1) (range checks for q and r)
                Instruction::IntDiv { max_bits, .. } | Instruction::IntMod { max_bits, .. } => (
                    ConstraintCategory::Arithmetic,
                    1 + 2 * (*max_bits as usize + 1),
                ),

                // Artik witness call — each output is a raw witness
                // wire, no constraints. Count each output slot toward
                // the witness-input tally so size reports reflect the
                // real witness surface, then skip category accounting.
                Instruction::WitnessCall(call) => {
                    n_witness += call.outputs.len();
                    continue;
                }
            };

            n_instructions += 1;
            let entry = cat_map.entry(category).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += cost;
        }

        let total_constraints: usize = cat_map.values().map(|(_, c)| c).sum();

        let mut categories: Vec<CategoryCost> = cat_map
            .into_iter()
            .map(|(cat, (count, constraints))| CategoryCost {
                category: cat,
                count,
                constraints,
            })
            .collect();
        categories.sort_by(|a, b| b.constraints.cmp(&a.constraints));

        CircuitStats {
            name: name.unwrap_or("<anonymous>").to_string(),
            categories,
            n_public,
            n_witness,
            n_instructions,
            total_constraints,
        }
    }

    /// Returns the category with the highest constraint cost, if any.
    pub fn bottleneck(&self) -> Option<&CategoryCost> {
        self.categories.first()
    }
}
