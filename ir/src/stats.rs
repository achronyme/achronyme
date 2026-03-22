use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

/// Broad category of constraint cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintCategory {
    /// Mul, Div
    Arithmetic,
    /// AssertEq, Assert
    Assertion,
    /// RangeCheck
    RangeCheck,
    /// PoseidonHash
    Hash,
    /// IsEq, IsNeq, IsLt, IsLe, IsLtBounded, IsLeBounded
    Comparison,
    /// And, Or, Not
    Boolean,
    /// Mux
    Selection,
}

impl fmt::Display for ConstraintCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arithmetic => write!(f, "Arithmetic"),
            Self::Assertion => write!(f, "Assertions"),
            Self::RangeCheck => write!(f, "Range checks"),
            Self::Hash => write!(f, "Hashes"),
            Self::Comparison => write!(f, "Comparisons"),
            Self::Boolean => write!(f, "Boolean ops"),
            Self::Selection => write!(f, "Selections"),
        }
    }
}

/// Display order priority (lower = shown first, i.e. highest priority).
impl ConstraintCategory {
    fn display_order(self) -> u8 {
        match self {
            Self::Hash => 0,
            Self::Comparison => 1,
            Self::RangeCheck => 2,
            Self::Arithmetic => 3,
            Self::Assertion => 4,
            Self::Boolean => 5,
            Self::Selection => 6,
        }
    }
}

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
    pub fn from_program(
        program: &IrProgram,
        proven_boolean: &HashSet<SsaVar>,
        name: Option<&str>,
    ) -> Self {
        let mut cat_map: HashMap<ConstraintCategory, (usize, usize)> = HashMap::new();
        let mut range_bounds: HashMap<SsaVar, u32> = HashMap::new();
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

                Instruction::Mul { .. } => (ConstraintCategory::Arithmetic, 1),
                Instruction::Div { .. } => (ConstraintCategory::Arithmetic, 2),

                Instruction::AssertEq { .. } => (ConstraintCategory::Assertion, 1),
                Instruction::Assert { operand, .. } => {
                    let bool_cost = if proven_boolean.contains(operand) {
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
                    let cost = if proven_boolean.contains(operand) {
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
                    if !proven_boolean.contains(lhs) {
                        cost += 1;
                    }
                    if !proven_boolean.contains(rhs) {
                        cost += 1;
                    }
                    (ConstraintCategory::Boolean, cost)
                }
                Instruction::Or { lhs, rhs, .. } => {
                    let mut cost = 1; // product
                    if !proven_boolean.contains(lhs) {
                        cost += 1;
                    }
                    if !proven_boolean.contains(rhs) {
                        cost += 1;
                    }
                    (ConstraintCategory::Boolean, cost)
                }

                Instruction::Mux { cond, .. } => {
                    let mut cost = 1; // multiply for selection
                    if !proven_boolean.contains(cond) {
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
                    // compile_is_lt_via_bits(diff, bitwidth+1) = bitwidth+1 boolean + 1 sum
                    (ConstraintCategory::Comparison, (*bitwidth as usize) + 2)
                }
                Instruction::IsLeBounded { bitwidth, .. } => {
                    (ConstraintCategory::Comparison, (*bitwidth as usize) + 2)
                }

                // S-box: full=8*3*3=72, partial=57*1*3=171, subtotal=243
                // Materializations: partial=57*2=114, final=3
                // Capacity: 1
                // Total: 243 + 114 + 3 + 1 = 361
                Instruction::PoseidonHash { .. } => (ConstraintCategory::Hash, 361),
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

/// Compute R1CS cost for IsLt/IsLe based on range bounds.
///
/// If both operands have prior RangeCheck bounds, uses `max(bound_a, bound_b) + 2`.
/// Otherwise, adds 253 per missing bound + 254 for the decomposition.
fn is_lt_cost(range_bounds: &HashMap<SsaVar, u32>, lhs: &SsaVar, rhs: &SsaVar) -> usize {
    let bound_a = range_bounds.get(lhs).copied();
    let bound_b = range_bounds.get(rhs).copied();

    match (bound_a, bound_b) {
        (Some(ba), Some(bb)) => {
            let effective = ba.max(bb);
            // compile_is_lt_via_bits(diff, effective+1) = (effective+1) boolean + 1 sum
            (effective as usize) + 2
        }
        _ => {
            let mut cost = 0usize;
            // enforce_252_range per missing bound = enforce_n_range(252) = 252+1 = 253
            if bound_a.is_none() {
                cost += 253;
            }
            if bound_b.is_none() {
                cost += 253;
            }
            // compile_is_lt_via_bits(diff, 253) = 253 boolean + 1 sum = 254
            cost += 254;
            cost
        }
    }
}

impl fmt::Display for CircuitStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bar = "─".repeat(55);
        writeln!(f, "── Circuit Stats (R1CS) {}", "─".repeat(31))?;
        writeln!(f, "  Circuit: \"{}\"", self.name)?;
        writeln!(
            f,
            "  Inputs:  {} public, {} witness",
            self.n_public, self.n_witness
        )?;
        writeln!(f, "  {bar}")?;
        writeln!(
            f,
            "  {:<20} {:>6}  {:>11}  {:>5}",
            "Category", "Instrs", "Constraints", "%"
        )?;
        writeln!(f, "  {bar}")?;

        // Sort by constraints desc, then by display order for ties
        let mut sorted = self.categories.clone();
        sorted.sort_by(|a, b| {
            b.constraints
                .cmp(&a.constraints)
                .then(a.category.display_order().cmp(&b.category.display_order()))
        });

        for entry in &sorted {
            let pct = if self.total_constraints > 0 {
                (entry.constraints as f64 / self.total_constraints as f64) * 100.0
            } else {
                0.0
            };
            writeln!(
                f,
                "  {:<20} {:>6}  {:>11}  {:>4.1}%",
                entry.category.to_string(),
                entry.count,
                entry.constraints,
                pct,
            )?;
        }

        writeln!(f, "  {bar}")?;
        writeln!(
            f,
            "  {:<20} {:>6}  {:>11}",
            "TOTAL", self.n_instructions, self.total_constraints
        )?;

        if let Some(top) = self.bottleneck() {
            if self.total_constraints > 0 {
                let pct = (top.constraints as f64 / self.total_constraints as f64) * 100.0;
                writeln!(f, "  Bottleneck: {} ({:.1}%)", top.category, pct)?;
            }
        }

        write!(f, "{}", "─".repeat(55))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Instruction, IrProgram, SsaVar, Visibility};
    use memory::FieldElement;

    fn empty_proven() -> HashSet<SsaVar> {
        HashSet::new()
    }

    #[test]
    fn empty_program() {
        let prog = IrProgram::new();
        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.name, "<anonymous>");
        assert_eq!(stats.total_constraints, 0);
        assert_eq!(stats.n_public, 0);
        assert_eq!(stats.n_witness, 0);
        assert_eq!(stats.n_instructions, 0);
    }

    #[test]
    fn named_circuit() {
        let prog = IrProgram::new();
        let stats = CircuitStats::from_program(&prog, &empty_proven(), Some("my_circuit"));
        assert_eq!(stats.name, "my_circuit");
    }

    #[test]
    fn input_counts() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v2,
            name: "z".into(),
            visibility: Visibility::Public,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.n_public, 2);
        assert_eq!(stats.n_witness, 1);
        assert_eq!(stats.total_constraints, 0);
    }

    #[test]
    fn mul_costs_one() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 1);
        assert_eq!(stats.n_instructions, 1);
        let arith = stats
            .categories
            .iter()
            .find(|c| c.category == ConstraintCategory::Arithmetic)
            .unwrap();
        assert_eq!(arith.constraints, 1);
        assert_eq!(arith.count, 1);
    }

    #[test]
    fn div_costs_two() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Div {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 2);
    }

    #[test]
    fn assert_eq_costs_one() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Public,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 1);
    }

    #[test]
    fn range_check_cost() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::RangeCheck {
            result: v1,
            operand: v0,
            bits: 64,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        // 64 boolean + 1 sum = 65
        assert_eq!(stats.total_constraints, 65);
    }

    #[test]
    fn poseidon_costs_362() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: v2,
            left: v0,
            right: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 361);
        let hash = stats
            .categories
            .iter()
            .find(|c| c.category == ConstraintCategory::Hash)
            .unwrap();
        assert_eq!(hash.constraints, 361);
    }

    #[test]
    fn is_eq_costs_two() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::IsEq {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 2);
    }

    #[test]
    fn is_lt_bounded_cost() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::IsLtBounded {
            result: v2,
            lhs: v0,
            rhs: v1,
            bitwidth: 8,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        // compile_is_lt_via_bits(diff, 9) = 9 boolean + 1 sum = 10
        assert_eq!(stats.total_constraints, 10);
    }

    #[test]
    fn is_lt_unbounded_no_range_check() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::IsLt {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        // Both unbounded: 253 + 253 + 254 = 760
        assert_eq!(stats.total_constraints, 760);
    }

    #[test]
    fn is_lt_with_range_bounds() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        // Range check both to 8 bits
        let v2 = prog.fresh_var();
        prog.push(Instruction::RangeCheck {
            result: v2,
            operand: v0,
            bits: 8,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::RangeCheck {
            result: v3,
            operand: v1,
            bits: 8,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::IsLt {
            result: v4,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        // 2x RangeCheck(8) = 2*(8+1) = 18
        // IsLt with bounds max(8,8) = 8+2 = 10
        // Total = 28
        assert_eq!(stats.total_constraints, 28);
    }

    #[test]
    fn assert_with_proven_boolean() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Assert {
            result: v1,
            operand: v0,
        });

        // Without proven boolean: 1 enforce + 1 boolean = 2
        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 2);

        // With proven boolean: 1 enforce, no boolean enforcement
        let mut proven = HashSet::new();
        proven.insert(v0);
        let stats = CircuitStats::from_program(&prog, &proven, None);
        assert_eq!(stats.total_constraints, 1);
    }

    #[test]
    fn not_with_proven_boolean_is_free() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Not {
            result: v1,
            operand: v0,
        });

        // Proven boolean: Not is free (just 1 - x)
        let mut proven = HashSet::new();
        proven.insert(v0);
        let stats = CircuitStats::from_program(&prog, &proven, None);
        assert_eq!(stats.total_constraints, 0);
        assert_eq!(stats.n_instructions, 0); // skipped entirely
    }

    #[test]
    fn mux_with_proven_cond() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "c".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v2,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::Mux {
            result: v3,
            cond: v0,
            if_true: v1,
            if_false: v2,
        });

        // Without proven: 1 mul + 1 bool = 2
        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 2);

        // With proven cond: 1 mul only
        let mut proven = HashSet::new();
        proven.insert(v0);
        let stats = CircuitStats::from_program(&prog, &proven, None);
        assert_eq!(stats.total_constraints, 1);
    }

    #[test]
    fn mixed_circuit_total() {
        let mut prog = IrProgram::new();
        let x = prog.fresh_var();
        prog.push(Instruction::Input {
            result: x,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let y = prog.fresh_var();
        prog.push(Instruction::Input {
            result: y,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        // x * y
        let mul = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: mul,
            lhs: x,
            rhs: y,
        });
        // poseidon(x, y)
        let hash = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: hash,
            left: x,
            right: y,
        });
        // assert_eq(mul, hash)
        let eq = prog.fresh_var();
        prog.push(Instruction::AssertEq {
            result: eq,
            lhs: mul,
            rhs: hash,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        // Mul=1, PoseidonHash=361, AssertEq=1 → total=363
        assert_eq!(stats.total_constraints, 363);
        assert_eq!(stats.n_public, 1);
        assert_eq!(stats.n_witness, 1);
        assert_eq!(stats.n_instructions, 3);
    }

    #[test]
    fn add_sub_neg_are_free() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Add {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::Sub {
            result: v3,
            lhs: v0,
            rhs: v1,
        });
        let v4 = prog.fresh_var();
        prog.push(Instruction::Neg {
            result: v4,
            operand: v0,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 0);
        assert_eq!(stats.n_instructions, 0);
    }

    #[test]
    fn bottleneck_is_highest_cost() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        // Mul = 1 constraint
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });
        // Poseidon = 362 constraints
        let v3 = prog.fresh_var();
        prog.push(Instruction::PoseidonHash {
            result: v3,
            left: v0,
            right: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        let bottleneck = stats.bottleneck().unwrap();
        assert_eq!(bottleneck.category, ConstraintCategory::Hash);
        assert_eq!(bottleneck.constraints, 361);
    }

    #[test]
    fn display_format() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::Mul {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), Some("test_circuit"));
        let output = format!("{stats}");
        assert!(output.contains("test_circuit"));
        assert!(output.contains("1 public"));
        assert!(output.contains("1 witness"));
        assert!(output.contains("Arithmetic"));
        assert!(output.contains("TOTAL"));
    }

    #[test]
    fn and_or_boolean_enforcement_cost() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "a".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "b".into(),
            visibility: Visibility::Witness,
        });
        let v2 = prog.fresh_var();
        prog.push(Instruction::And {
            result: v2,
            lhs: v0,
            rhs: v1,
        });

        // No proven boolean: 1 mul + 2 bool enforcement = 3
        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        assert_eq!(stats.total_constraints, 3);

        // Both proven: 1 mul only
        let mut proven = HashSet::new();
        proven.insert(v0);
        proven.insert(v1);
        let stats = CircuitStats::from_program(&prog, &proven, None);
        assert_eq!(stats.total_constraints, 1);
    }

    #[test]
    fn is_lt_one_bound_one_unbound() {
        let mut prog = IrProgram::new();
        let v0 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v0,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let v1 = prog.fresh_var();
        prog.push(Instruction::Input {
            result: v1,
            name: "y".into(),
            visibility: Visibility::Witness,
        });
        // Only range check v0
        let v2 = prog.fresh_var();
        prog.push(Instruction::RangeCheck {
            result: v2,
            operand: v0,
            bits: 8,
        });
        let v3 = prog.fresh_var();
        prog.push(Instruction::IsLt {
            result: v3,
            lhs: v0,
            rhs: v1,
        });

        let stats = CircuitStats::from_program(&prog, &empty_proven(), None);
        // RangeCheck(8) = 9
        // IsLt: bound_a=Some(8), bound_b=None → 253 + 254 = 507
        // Total = 9 + 507 = 516
        assert_eq!(stats.total_constraints, 516);
    }
}
