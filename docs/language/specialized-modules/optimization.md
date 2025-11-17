---
title: "Optimization"
description: "Linear programming and optimization algorithms in Achronyme"
section: "specialized-modules"
order: 3
---


Achronyme provides comprehensive linear programming capabilities for solving optimization problems, including multiple simplex variants, sensitivity analysis, and resource allocation algorithms.

## Overview

| Category | Functions |
|----------|-----------|
| **General Solvers** | linprog, simplex |
| **Specialized Solvers** | dual_simplex, two_phase_simplex, revised_simplex |
| **Objective** | objective_value |
| **Sensitivity Analysis** | shadow_price, sensitivity_c, sensitivity_b |

All optimization functions use the high-performance **achronyme-solver** library implementing industry-standard algorithms.

## Linear Programming Problem

### Standard Form

Linear programming solves problems of the form:

```
Maximize/Minimize:  z = c^T × x

Subject to:         A × x ≤ b
                    x ≥ 0
```

**Where**:
- **x**: Decision variables (what we're solving for)
- **c**: Objective coefficients (profits, costs, etc.)
- **A**: Constraint coefficient matrix
- **b**: Constraint bounds (resources, limits)
- **sense**: 1 for maximize, -1 for minimize

### Example Problem

```javascript
// Production problem: maximize profit
// Products: x1 (chairs), x2 (tables)
// Profit: $3 per chair, $5 per table

// Constraints:
// - Wood:  2*x1 + 4*x2 ≤ 100 hours
// - Labor: 1*x1 + 2*x2 ≤ 40 hours
// - Non-negativity: x1, x2 ≥ 0

let c = [3, 5]              // Objective: maximize 3*x1 + 5*x2
let A = [[2, 4],            // Constraint matrix
         [1, 2]]
let b = [100, 40]           // Right-hand side
let sense = 1               // 1 = maximize

let solution = linprog(c, A, b, sense)
// [20, 10] - optimal: 20 chairs, 10 tables
// Profit: 3*20 + 5*10 = 110
```

## General Solvers

### Linear Programming - linprog

Automatically select best solver for the problem:

```javascript
// Diet problem: minimize cost
let costs = [0.5, 0.3, 0.8]  // Cost per unit of foods A, B, C

let nutrients = [
    [10, 5, 8],   // Protein content
    [6, 8, 4],    // Carbs content
    [4, 3, 7]     // Fat content
]

let requirements = [50, 40, 30]  // Minimum daily requirements

let solution = linprog(costs, nutrients, requirements, -1)
// Returns optimal quantities to minimize cost
```

**Signature**: `linprog(c, A, b, sense) -> Vector`

**Parameters**:
- `c`: Objective coefficients (vector)
- `A`: Constraint matrix (rank-2 tensor)
- `b`: Constraint bounds (vector)
- `sense`: 1 (maximize) or -1 (minimize)

**Returns**: Vector of decision variable values

**Algorithm**: Auto-selects based on problem characteristics
- Currently uses standard simplex
- Future: will select dual, revised, or interior point

**Requirements**:
- A must be a matrix (rank-2 tensor)
- Dimensions: A is m×n, c is n×1, b is m×1
- All values must be numeric

### Standard Simplex - simplex

Classic simplex algorithm:

```javascript
// Investment problem
let returns = [0.08, 0.12, 0.10]  // 8%, 12%, 10% returns

let constraints = [
    [1, 1, 1],      // Total investment ≤ 100000
    [1, 0, 0],      // Stock A ≤ 50000
    [0, 1, 0],      // Stock B ≤ 40000
    [0, 0, 1]       // Stock C ≤ 60000
]

let limits = [100000, 50000, 40000, 60000]

let allocation = simplex(returns, constraints, limits, 1)
// Maximize returns subject to investment limits
```

**Signature**: `simplex(c, A, b, sense) -> Vector`

**Algorithm**: Tableau-based simplex method
- Iteratively moves from vertex to vertex
- Guaranteed to find optimal solution (if bounded)
- Complexity: polynomial in practice, exponential worst-case

**Use when**:
- General-purpose LP solving
- Teaching/learning simplex method
- Problems with clear initial basic feasible solution

**Limitations**:
- Requires all constraints in ≤ form
- Requires non-negative RHS (b ≥ 0)
- Needs obvious initial feasible solution

## Specialized Solvers

### Dual Simplex - dual_simplex

Solve when dual is feasible:

```javascript
// Post-optimality: adding a constraint
let c = [3, 2]
let A = [[2, 1],
         [1, 2],
         [1, 0]]  // New constraint added
let b = [10, 8, 3]

let solution = dual_simplex(c, A, b, 1)
```

**Signature**: `dual_simplex(c, A, b, sense) -> Vector`

**Algorithm**: Dual simplex method
- Works from dual-feasible but primal-infeasible solution
- Maintains dual feasibility, achieves primal feasibility

**Use when**:
- Many variables, few constraints
- Sensitivity analysis (adding constraints)
- Branch-and-bound algorithms
- Re-optimization after parameter changes

**Advantages**:
- Efficient for adding constraints
- Good for integer programming branch-and-bound
- Fewer iterations for certain problem types

### Two-Phase Simplex - two_phase_simplex

Find initial solution when not obvious:

```javascript
// Problem with equality or ≥ constraints
let c = [2, 3]
let A = [[1, 1],      // x1 + x2 ≥ 5 (converted: -x1 - x2 ≤ -5)
         [2, -1]]     // 2*x1 - x2 ≤ 4
let b = [-5, 4]       // Note negative RHS

let solution = two_phase_simplex(c, A, b, 1)
```

**Signature**: `two_phase_simplex(c, A, b, sense) -> Vector`

**Algorithm**: Two-phase method
1. **Phase I**: Find initial basic feasible solution using artificial variables
2. **Phase II**: Optimize original objective from Phase I solution

**Use when**:
- Equality constraints (=)
- Greater-than constraints (≥)
- Negative RHS values (b[i] < 0)
- No obvious initial feasible solution

**Process**:
```javascript
// Phase I: Minimize sum of artificial variables
// If minimum = 0, feasible solution found → Phase II
// If minimum > 0, problem is infeasible
```

### Revised Simplex - revised_simplex

Memory-efficient variant:

```javascript
// Large-scale problem
let c = [...Array(1000).fill(1)]  // 1000 variables
let A = [...]  // Sparse matrix
let b = [...]

let solution = revised_simplex(c, A, b, 1)
// More efficient for large n
```

**Signature**: `revised_simplex(c, A, b, sense) -> Vector`

**Algorithm**: Revised simplex method
- Stores only basis inverse B⁻¹ instead of full tableau
- Recomputes only necessary values each iteration
- Same optimality guarantees as standard simplex

**Use when**:
- Large problems (n > 1000 variables)
- Sparse constraint matrices
- Many variables, relatively few constraints
- Memory is a concern

**Advantages**:
- O(m²) storage vs O(mn) for tableau
- Faster for large sparse problems
- Numerical stability improvements

**Complexity**:
- Time: O(m³) per iteration (same as simplex)
- Space: O(m²) vs O(mn)

## Objective Value

### Calculate Objective - objective_value

Compute objective function value:

```javascript
let c = [3, 5]
let x = [20, 10]

let z = objective_value(c, x)
// 3*20 + 5*10 = 110
```

**Signature**: `objective_value(c, x) -> Number`

**Formula**: `z = Σ(c[i] × x[i]) = c^T × x`

**Use cases**:
- Verify solution quality
- Compare different solutions
- Post-processing analysis

## Sensitivity Analysis

Sensitivity analysis determines how changes in parameters affect the optimal solution.

### Shadow Prices - shadow_price

Calculate marginal value of resources:

```javascript
let c = [3, 5]
let A = [[2, 4],
         [1, 2]]
let b = [100, 40]

let prices = shadow_price(c, A, b, 1)
// [y1, y2] - dual variables
// y1: value of one more unit of resource 1 (wood)
// y2: value of one more unit of resource 2 (labor)
```

**Signature**: `shadow_price(c, A, b, sense) -> Vector`

**Returns**: Dual variable values (one per constraint)

**Interpretation**:
- Shadow price = 0: Resource is not fully utilized (slack > 0)
- Shadow price > 0: Resource is binding, value per additional unit
- For minimize: shadow price is cost of additional requirement

**Use cases**:
- Resource valuation
- Determining which constraints to relax
- Investment decisions (buy more resources?)
- Pricing in production planning

**Example interpretation**:
```javascript
let prices = shadow_price(c, A, b, 1)
// [0.5, 2.0]
// - Each additional hour of wood increases profit by $0.50
// - Each additional hour of labor increases profit by $2.00
```

### Sensitivity for c - sensitivity_c

Range of objective coefficients maintaining optimal basis:

```javascript
let c = [3, 5]
let A = [[2, 4],
         [1, 2]]
let b = [100, 40]

let range_c1 = sensitivity_c(c, A, b, 0)
// [c_min, c_max] for c[0]
// e.g., [2.5, 4.0]
// Optimal basis stays same if c[0] ∈ [2.5, 4.0]
```

**Signature**: `sensitivity_c(c, A, b, index) -> Vector`

**Parameters**:
- `c`, `A`, `b`: Problem parameters
- `index`: Which objective coefficient to analyze (0-indexed)

**Returns**: `[c_min, c_max]` - allowable range

**Interpretation**:
- If c[index] stays within range, optimal solution doesn't change
- Outside range: need to re-solve
- Useful for "what-if" analysis

**Use cases**:
- Price flexibility analysis
- Contract negotiations
- Risk assessment

**Example**:
```javascript
let range = sensitivity_c(c, A, b, 0)
// [2.5, 4.0]
// Chair profit can vary between $2.50 and $4.00
// without changing the optimal production mix
```

### Sensitivity for b - sensitivity_b

Range of RHS values maintaining optimal basis:

```javascript
let c = [3, 5]
let A = [[2, 4],
         [1, 2]]
let b = [100, 40]

let range_b1 = sensitivity_b(c, A, b, 0)
// [b_min, b_max] for b[0]
// e.g., [80, 120]
// Optimal basis same if b[0] ∈ [80, 120]
```

**Signature**: `sensitivity_b(c, A, b, index) -> Vector`

**Parameters**:
- `c`, `A`, `b`: Problem parameters
- `index`: Which constraint bound to analyze (0-indexed)

**Returns**: `[b_min, b_max]` - allowable range

**Interpretation**:
- Shadow price valid within this range
- Outside range: basis changes, need re-optimization
- Indicates resource flexibility

**Use cases**:
- Resource planning
- Capacity expansion decisions
- Understanding constraint criticality

**Example**:
```javascript
let range = sensitivity_b(c, A, b, 0)
// [80, 120]
// Wood hours can vary between 80 and 120
// Shadow price remains valid in this range
// Outside: need to re-solve
```

## Practical Examples

### Production Planning

```javascript
// Furniture factory
// Products: chairs (x1), tables (x2), desks (x3)
// Profit: $25, $60, $40

let profits = [25, 60, 40]

// Resources:
// - Wood:   2, 4, 3 units
// - Labor:  1, 3, 2 hours
// - Paint:  1, 2, 2 liters

let resources = [
    [2, 4, 3],  // Wood constraint
    [1, 3, 2],  // Labor constraint
    [1, 2, 2]   // Paint constraint
]

let available = [200, 150, 120]  // Available units

let production = linprog(profits, resources, available, 1)
let max_profit = objective_value(profits, production)

// Sensitivity analysis
let shadow = shadow_price(profits, resources, available, 1)
// Which resource is most valuable?

let wood_range = sensitivity_b(profits, resources, available, 0)
// Can we reduce wood without changing plan?
```

### Diet Problem

```javascript
// Minimize cost while meeting nutritional requirements
let costs = [0.50, 0.30, 0.80, 0.20]  // Foods: A, B, C, D

// Nutritional content per unit
let nutrition = [
    [400, 200, 500, 100],  // Calories
    [20, 10, 30, 5],       // Protein (g)
    [50, 40, 60, 20],      // Carbs (g)
    [10, 5, 15, 3]         // Fat (g)
]

let requirements = [2000, 50, 200, 30]  // Daily minimums

// Convert to standard form (≥ becomes ≤ by negation)
let A_neg = map(row => map(x => -x, row), nutrition)
let b_neg = map(x => -x, requirements)

let diet = linprog(costs, A_neg, b_neg, -1)
let min_cost = objective_value(costs, diet)

// Interpretation
// diet = [x1, x2, x3, x4] units of each food
// min_cost = minimum daily cost
```

### Transportation Problem

```javascript
// Ship products from warehouses to stores
// Minimize shipping cost

// Warehouses: W1, W2, W3
// Stores: S1, S2, S3, S4

// Cost matrix (per unit shipped)
let costs = [
    2, 3, 4, 5,  // W1 -> S1,S2,S3,S4
    3, 2, 5, 4,  // W2 -> S1,S2,S3,S4
    4, 5, 2, 3   // W3 -> S1,S2,S3,S4
]

// Supply constraints (warehouse capacity)
let supply_A = [
    [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],  // W1 total
    [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0],  // W2 total
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1]   // W3 total
]
let supply_b = [100, 150, 120]

// Demand constraints (store requirements)
let demand_A = [
    [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0],  // S1 demand
    [0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],  // S2 demand
    [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0],  // S3 demand
    [0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1]   // S4 demand
]
let demand_b = [80, 90, 70, 60]

// Combine constraints
let A = [...supply_A, ...demand_A]
let b = [...supply_b, ...demand_b]

let shipments = linprog(costs, A, b, -1)
// Optimal shipping plan
```

### Investment Portfolio

```javascript
// Maximize expected return
// Constraints: budget, risk limits, diversification

let returns = [0.08, 0.12, 0.10, 0.15, 0.09]  // Expected returns

let constraints = [
    [1, 1, 1, 1, 1],        // Total ≤ 1000000 (budget)
    [0.1, 0.3, 0.2, 0.5, 0.15],  // Risk ≤ 200000
    [1, 0, 0, 0, 0],        // Stock A ≤ 300000
    [0, 1, 0, 0, 0],        // Stock B ≤ 400000
    [0, 0, 1, 0, 0],        // Stock C ≤ 300000
    [0, 0, 0, 1, 0],        // Stock D ≤ 200000
    [0, 0, 0, 0, 1]         // Stock E ≤ 300000
]

let limits = [1000000, 200000, 300000, 400000, 300000, 200000, 300000]

let portfolio = simplex(returns, constraints, limits, 1)
let expected = objective_value(returns, portfolio)

// Shadow prices: which constraint to relax?
let duals = shadow_price(returns, constraints, limits, 1)
```

### Blending Problem

```javascript
// Gasoline blending: mix crude oils
// Minimize cost, meet octane and sulfur requirements

// Crude types: Light, Medium, Heavy
let costs = [50, 40, 30]  // $ per barrel

// Properties:
// - Octane: 95, 90, 85
// - Sulfur: 0.5%, 1.0%, 1.5%

// Requirements for 10000 barrels:
// - Min octane: 90
// - Max sulfur: 1.0%

let A = [
    [1, 1, 1],                    // Total = 10000 barrels
    [-95, -90, -85],              // Octane ≥ 90*10000
    [0.5, 1.0, 1.5]               // Sulfur ≤ 1.0*10000
]

let b = [10000, -900000, 10000]

let blend = two_phase_simplex(costs, A, b, -1)
let total_cost = objective_value(costs, blend)

// Result: optimal mix of crude oils
```

### Sensitivity Analysis Example

```javascript
// Original problem
let c = [40, 30]  // Profit per unit
let A = [[1, 1],   // Machine time
         [2, 1]]   // Labor time
let b = [100, 150]

let x = linprog(c, A, b, 1)
let profit = objective_value(c, x)

// Question 1: Can we change product 1 price?
let c1_range = sensitivity_c(c, A, b, 0)
// [30, 60]
// Price can vary $30-$60 without changing production plan

// Question 2: Worth buying more machine time?
let shadow = shadow_price(c, A, b, 1)
// [15, 10]
// Machine time shadow price: $15/hour
// Labor shadow price: $10/hour
// → Priority: buy more machine time

// Question 3: Valid range for machine time?
let machine_range = sensitivity_b(c, A, b, 0)
// [80, 120]
// Shadow price valid for 80-120 hours
// Can increase up to 120 hours at $15/hour value
```

## Algorithm Comparison

### When to Use Each Method

| Method | Best For | Advantages | Limitations |
|--------|----------|------------|-------------|
| **linprog** | General problems | Auto-selection, easy to use | May not be optimal choice |
| **simplex** | Standard LP, teaching | Well-understood, reliable | Memory intensive for large n |
| **dual_simplex** | Adding constraints, many variables | Efficient re-optimization | Needs dual feasibility |
| **two_phase_simplex** | Equality/≥ constraints | Handles any constraint type | Two-phase overhead |
| **revised_simplex** | Large sparse problems | Memory efficient | More complex implementation |

### Complexity Comparison

```javascript
// Problem size: m constraints, n variables

// Space complexity:
// - simplex:         O(mn)    (full tableau)
// - revised_simplex: O(m²)    (basis inverse)

// Time per iteration:
// - simplex:         O(mn)
// - revised_simplex: O(m² + mn)

// For large sparse problems (n >> m):
// revised_simplex is better: O(m²) << O(mn)
```

## Error Handling

### Common Errors

```javascript
// Dimension mismatch
let c = [1, 2, 3]
let A = [[1, 2]]  // 1×2, needs 1×3
let b = [10]
linprog(c, A, b, 1)  // Error: dimension mismatch

// Invalid sense
simplex(c, A, b, 0)  // Error: sense must be 1 or -1

// Infeasible problem
let c = [1, 1]
let A = [[1, 1],
         [-1, -1]]
let b = [5, -10]  // Impossible: x1+x2≤5 and x1+x2≥10
linprog(c, A, b, 1)  // Error: infeasible

// Unbounded problem
let c = [1, 1]
let A = [[-1, 0]]  // Only x1 ≥ 0, x2 unconstrained
let b = [10]
linprog(c, A, b, 1)  // Error: unbounded
```

### Validation Checks

```javascript
// ✅ Validate dimensions before solving
let validate_lp = (c, A, b) => {
    let m = length(b)
    let n = length(c)

    if(A.rows != m, error("A rows must match b length"), true)
    if(A.cols != n, error("A cols must match c length"), true)
}
```

## Performance Considerations

### Problem Size Guidelines

```javascript
// Small problems (n < 100, m < 50)
// - Use simplex or linprog
// - Performance difference negligible

// Medium problems (n < 1000, m < 500)
// - Use linprog or simplex
// - Consider revised_simplex if sparse

// Large problems (n > 1000)
// - Use revised_simplex
// - Sparse matrices: significant speedup
// - Dense matrices: comparable performance
```

### Preprocessing Tips

```javascript
// ✅ Remove redundant constraints
// Before solving, check for dominated constraints

// ✅ Scale coefficients
// Large magnitude differences can cause numerical issues
let scale_problem = (c, A, b) => {
    // Scale so coefficients are O(1)
    // Improves numerical stability
}

// ✅ Eliminate fixed variables
// If x[i] is known, substitute it out
```

## Summary

**General solvers**: linprog (auto-select), simplex (standard)

**Specialized**: dual_simplex, two_phase_simplex, revised_simplex

**Analysis**: objective_value, shadow_price, sensitivity_c, sensitivity_b

**Key features**:
- Industry-standard algorithms
- Multiple solver variants
- Sensitivity analysis support
- Efficient for large problems

**Problem format**:
```javascript
// Maximize/minimize: c^T × x
// Subject to: A × x ≤ b, x ≥ 0
```

**Best practices**:
- Use linprog() for general problems
- Use revised_simplex() for large sparse problems
- Use two_phase_simplex() for equality constraints
- Perform sensitivity analysis for decision support
- Validate dimensions before solving
- Check feasibility and boundedness

**Common applications**:
- Production planning
- Resource allocation
- Transportation optimization
- Portfolio management
- Diet/nutrition planning
- Blending problems
- Scheduling

---

**Next**: [String Manipulation](20-strings.md)
