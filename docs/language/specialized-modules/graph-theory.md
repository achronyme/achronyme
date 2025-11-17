---
title: "Graph Theory"
description: "Graph algorithms, BFS, DFS, Dijkstra, and PERT/CPM in Achronyme"
section: "specialized-modules"
order: 2
---


Achronyme provides comprehensive graph theory and network analysis capabilities, including graph construction, traversal algorithms, shortest paths, minimum spanning trees, and project management with PERT/CPM methods.

## Overview

| Category | Functions |
|----------|-----------|
| **Graph Construction** | network, -> (directed edge), <> (undirected edge) |
| **Graph Properties** | nodes, edges, neighbors, degree |
| **Traversal** | bfs, dfs, bfs_path |
| **Shortest Paths** | dijkstra |
| **Cycle Detection** | has_cycle |
| **Minimum Spanning Tree** | kruskal, prim |
| **Connectivity** | connected_components, is_connected |
| **Topological Sorting** | topological_sort |
| **PERT/CPM** | forward_pass, backward_pass, calculate_slack, critical_path, all_critical_paths, project_duration |
| **PERT Probabilistic** | expected_time, task_variance, project_variance, project_std_dev, completion_probability, time_for_probability |
| **Complete Analysis** | pert_analysis |

## Graph Construction

### Network Creation

Create a graph using the `network()` function with edge expressions:

```javascript
// Directed graph
let g = network(
    A -> B,
    B -> C,
    A -> C
)

// Undirected graph
let g = network(
    A <> B,
    B <> C,
    A <> C
)

// Mixed edges
let g = network(
    A -> B,    // Directed: A to B
    B <> C,    // Undirected: B and C
    C -> D     // Directed: C to D
)
```

**Syntax**:
- `A -> B`: Directed edge from A to B
- `A <> B`: Undirected edge between A and B
- Node names: Identifiers without quotes

### Weighted Graphs

Add weights using tuples:

```javascript
// Weighted directed graph
let g = network(
    A -> [B, 5],     // Edge from A to B with weight 5
    B -> [C, 3],
    A -> [C, 10]
)

// Weighted undirected graph
let g = network(
    A <> [B, 4],
    B <> [C, 2],
    A <> [C, 7]
)
```

**Weight format**: `[destination, weight]`

**Default weight**: 1.0 if not specified

## Graph Properties

### Get Nodes

Retrieve all nodes in the graph:

```javascript
let g = network(
    A -> B,
    B -> C,
    C -> D
)

let node_list = nodes(g)
// ["A", "B", "C", "D"]
```

**Signature**: `nodes(graph) -> Vector<String>`

### Get Edges

Retrieve all edges:

```javascript
let g = network(
    A -> [B, 5],
    B -> [C, 3]
)

let edge_list = edges(g)
// Returns vector of edge records
// Each edge: {from: "A", to: "B", weight: 5}
```

**Signature**: `edges(graph) -> Vector<Record>`

**Edge record format**:
```javascript
{
    from: "A",      // Source node
    to: "B",        // Target node
    weight: 5       // Edge weight
}
```

### Get Neighbors

Find adjacent nodes:

```javascript
let g = network(
    A -> B,
    A -> C,
    B -> D
)

neighbors(g, "A")   // ["B", "C"]
neighbors(g, "B")   // ["D"]
neighbors(g, "D")   // []
```

**Signature**: `neighbors(graph, node) -> Vector<String>`

**Note**: For undirected edges, neighbors include both directions

### Node Degree

Get the degree (number of connections):

```javascript
let g = network(
    A -> B,
    A -> C,
    B -> C
)

degree(g, "A")      // 2 (outgoing edges)
degree(g, "B")      // 1
degree(g, "C")      // 0 (no outgoing)
```

**Signature**: `degree(graph, node) -> Number`

**Definition**: Number of outgoing edges for directed graphs, total connections for undirected

## Graph Traversal

### Breadth-First Search (BFS)

Visit nodes level by level:

```javascript
let g = network(
    A -> B,
    A -> C,
    B -> D,
    C -> D
)

let order = bfs(g, "A")
// ["A", "B", "C", "D"]
```

**Signature**: `bfs(graph, start) -> Vector<String>`

**Algorithm**: Queue-based traversal

**Use cases**:
- Level-order traversal
- Finding shortest path (unweighted)
- Testing reachability

### Depth-First Search (DFS)

Visit nodes by exploring paths deeply:

```javascript
let g = network(
    A -> B,
    A -> C,
    B -> D,
    C -> D
)

let order = dfs(g, "A")
// ["A", "B", "D", "C"] or similar
```

**Signature**: `dfs(graph, start) -> Vector<String>`

**Algorithm**: Stack-based (recursive) traversal

**Use cases**:
- Topological sorting
- Cycle detection
- Path finding

### BFS Path Finding

Find shortest path between two nodes:

```javascript
let g = network(
    A -> B,
    A -> C,
    B -> D,
    C -> D
)

let path = bfs_path(g, "A", "D")
// ["A", "B", "D"] - shortest path
```

**Signature**: `bfs_path(graph, start, end) -> Vector<String>`

**Returns**: Shortest path or empty vector if no path exists

**Complexity**: O(V + E)

## Shortest Paths

### Dijkstra's Algorithm

Find shortest paths from a source to all other nodes:

```javascript
let g = network(
    A -> [B, 4],
    A -> [C, 2],
    B -> [C, 1],
    B -> [D, 5],
    C -> [D, 8]
)

let result = dijkstra(g, "A")
// Returns record with distances and paths
```

**Signature**: `dijkstra(graph, source) -> Record`

**Result format**:
```javascript
{
    distances: {
        A: 0,
        B: 4,
        C: 2,
        D: 9
    },
    predecessors: {
        A: null,
        B: "A",
        C: "A",
        D: "B"
    }
}
```

**Algorithm**: Priority queue-based

**Complexity**: O((V + E) log V) with binary heap

**Requirements**: Non-negative edge weights

**Use cases**:
- Shortest path in weighted graphs
- Route planning
- Network optimization

### Extract Path from Dijkstra

```javascript
// Get shortest path from A to D
let result = dijkstra(g, "A")

// Reconstruct path (manual)
let get_path = (predecessors, target) => {
    // Implementation needed
    // Walk backwards from target using predecessors
}
```

## Cycle Detection

### Check for Cycles

Detect if graph contains cycles:

```javascript
// Acyclic graph
let g1 = network(
    A -> B,
    B -> C,
    A -> C
)
has_cycle(g1)       // false

// Cyclic graph
let g2 = network(
    A -> B,
    B -> C,
    C -> A
)
has_cycle(g2)       // true
```

**Signature**: `has_cycle(graph) -> Boolean`

**Algorithm**: DFS with state tracking

**Use cases**:
- Validating DAGs
- Detecting deadlocks
- Dependency checking

## Minimum Spanning Tree

### Kruskal's Algorithm

Find MST by sorting edges:

```javascript
let g = network(
    A <> [B, 4],
    A <> [C, 2],
    B <> [C, 1],
    B <> [D, 5],
    C <> [D, 8]
)

let mst = kruskal(g)
// Returns network with MST edges
// Total weight: 1 + 2 + 5 = 8
```

**Signature**: `kruskal(graph) -> Graph`

**Algorithm**: Union-Find based

**Complexity**: O(E log E)

**Result**: New graph containing only MST edges

### Prim's Algorithm

Find MST by growing from a vertex:

```javascript
let g = network(
    A <> [B, 4],
    A <> [C, 2],
    B <> [C, 1],
    B <> [D, 5],
    C <> [D, 8]
)

let mst = prim(g, "A")
// Returns network with MST edges
// Same total weight: 8
```

**Signature**: `prim(graph, start) -> Graph`

**Algorithm**: Priority queue-based

**Complexity**: O((V + E) log V)

**Comparison with Kruskal**:
- Prim: Better for dense graphs
- Kruskal: Better for sparse graphs
- Both produce optimal MST

## Connectivity

### Connected Components

Find all connected components:

```javascript
let g = network(
    A <> B,
    B <> C,
    D <> E,
    F
)

let components = connected_components(g)
// [["A", "B", "C"], ["D", "E"], ["F"]]
```

**Signature**: `connected_components(graph) -> Vector<Vector<String>>`

**Algorithm**: Multiple BFS/DFS

**Use cases**:
- Network analysis
- Cluster detection
- Identifying isolated nodes

### Check Connectivity

Test if graph is fully connected:

```javascript
let g1 = network(
    A <> B,
    B <> C,
    C <> A
)
is_connected(g1)    // true

let g2 = network(
    A <> B,
    C <> D
)
is_connected(g2)    // false
```

**Signature**: `is_connected(graph) -> Boolean`

**Definition**: All nodes reachable from any starting node

## Topological Sorting

### Topological Sort

Order nodes in a DAG:

```javascript
let g = network(
    A -> B,
    A -> C,
    B -> D,
    C -> D
)

let order = topological_sort(g)
// ["A", "B", "C", "D"] or ["A", "C", "B", "D"]
```

**Signature**: `topological_sort(graph) -> Vector<String>`

**Algorithm**: Kahn's algorithm or DFS-based

**Requirements**: Must be a DAG (no cycles)

**Error**: Returns error if cycle detected

**Use cases**:
- Task scheduling
- Build systems
- Course prerequisites
- **PERT/CPM critical path**

## PERT/CPM - Project Management

PERT (Program Evaluation and Review Technique) and CPM (Critical Path Method) are project management tools for scheduling and analyzing task networks.

### Network Setup for PERT/CPM

Create a task network with dependencies:

```javascript
// Task network: A -> B -> D
//               A -> C -> D
let tasks = network(
    Start -> [A, 3],    // A takes 3 days, depends on Start
    A -> [B, 4],        // B takes 4 days, depends on A
    A -> [C, 2],        // C takes 2 days, depends on A
    B -> [D, 5],        // D depends on B (5 days)
    C -> [D, 0]         // D also depends on C
)
```

**Edge format**: `predecessor -> [successor, duration]`

**Duration**: Time to complete the task (days, weeks, etc.)

### Forward Pass

Calculate earliest start and finish times:

```javascript
let tasks = network(
    Start -> [A, 3],
    A -> [B, 4],
    A -> [C, 2],
    B -> [D, 5],
    C -> [D, 5]
)

let forward = forward_pass(tasks, "Start")
```

**Signature**: `forward_pass(graph, start) -> Record`

**Result format**:
```javascript
{
    A: {es: 0, ef: 3},      // Earliest start: 0, finish: 3
    B: {es: 3, ef: 7},      // Start: 3, finish: 7
    C: {es: 3, ef: 5},      // Start: 3, finish: 5
    D: {es: 7, ef: 12}      // Start: 7, finish: 12
}
```

**Algorithm**:
- ES(task) = max(EF of all predecessors)
- EF(task) = ES(task) + duration

### Backward Pass

Calculate latest start and finish times:

```javascript
let forward = forward_pass(tasks, "Start")
let backward = backward_pass(tasks, forward, "D")
```

**Signature**: `backward_pass(graph, forward_result, end) -> Record`

**Result format**:
```javascript
{
    A: {ls: 0, lf: 3},      // Latest start: 0, finish: 3
    B: {ls: 3, lf: 7},      // Start: 3, finish: 7
    C: {ls: 5, lf: 7},      // Start: 5, finish: 7
    D: {ls: 7, lf: 12}      // Start: 7, finish: 12
}
```

**Algorithm**:
- LF(task) = min(LS of all successors)
- LS(task) = LF(task) - duration

### Calculate Slack (Float)

Determine scheduling flexibility:

```javascript
let forward = forward_pass(tasks, "Start")
let backward = backward_pass(tasks, forward, "D")
let slack = calculate_slack(forward, backward)
```

**Signature**: `calculate_slack(forward_result, backward_result) -> Record`

**Result format**:
```javascript
{
    A: 0,       // No slack - critical
    B: 0,       // No slack - critical
    C: 2,       // 2 days of slack
    D: 0        // No slack - critical
}
```

**Formula**: `Slack = LS - ES = LF - EF`

**Interpretation**:
- Slack = 0: Critical task (no delay allowed)
- Slack > 0: Can be delayed without affecting project

### Critical Path

Find the critical path (zero slack tasks):

```javascript
let tasks = network(
    Start -> [A, 3],
    A -> [B, 4],
    A -> [C, 2],
    B -> [D, 5],
    C -> [D, 5]
)

let cp = critical_path(tasks, "Start", "D")
// ["Start", "A", "B", "D"]
```

**Signature**: `critical_path(graph, start, end) -> Vector<String>`

**Definition**: Longest path through the network

**Properties**:
- Tasks with zero slack
- Determines minimum project duration
- Any delay affects project completion

### All Critical Paths

Find all critical paths (if multiple exist):

```javascript
let tasks = network(
    Start -> [A, 5],
    Start -> [B, 5],
    A -> [End, 3],
    B -> [End, 3]
)

let paths = all_critical_paths(tasks, "Start", "End")
// [["Start", "A", "End"], ["Start", "B", "End"]]
```

**Signature**: `all_critical_paths(graph, start, end) -> Vector<Vector<String>>`

**Use case**: Identify all paths that determine project duration

### Project Duration

Get total project duration:

```javascript
let tasks = network(
    Start -> [A, 3],
    A -> [B, 4],
    B -> [End, 5]
)

let duration = project_duration(tasks, "Start", "End")
// 12 (days/weeks/etc.)
```

**Signature**: `project_duration(graph, start, end) -> Number`

**Calculation**: Length of critical path

## PERT Probabilistic Analysis

PERT extends CPM with probabilistic time estimates using three time estimates per task.

### Expected Time

Calculate expected task duration:

```javascript
// Three-point estimate: optimistic, most likely, pessimistic
let optimistic = 2
let most_likely = 4
let pessimistic = 8

let expected = expected_time(optimistic, most_likely, pessimistic)
// (2 + 4*4 + 8) / 6 = 4.33
```

**Signature**: `expected_time(optimistic, most_likely, pessimistic) -> Number`

**Formula**: `te = (o + 4m + p) / 6`

**Beta distribution**: Weighted average favoring most likely

### Task Variance

Calculate variance for a task:

```javascript
let optimistic = 2
let pessimistic = 8

let variance = task_variance(optimistic, pessimistic)
// ((8 - 2) / 6)^2 = 1.0
```

**Signature**: `task_variance(optimistic, pessimistic) -> Number`

**Formula**: `σ² = ((p - o) / 6)²`

**Interpretation**: Measure of uncertainty

### Project Variance

Calculate total project variance:

```javascript
// Variances of tasks on critical path
let variances = [1.0, 0.44, 2.25]

let proj_var = project_variance(variances)
// 1.0 + 0.44 + 2.25 = 3.69
```

**Signature**: `project_variance(variances) -> Number`

**Formula**: Sum of variances on critical path

**Assumption**: Tasks are independent

### Project Standard Deviation

```javascript
let variances = [1.0, 0.44, 2.25]
let std_dev = project_std_dev(variances)
// sqrt(3.69) = 1.92
```

**Signature**: `project_std_dev(variances) -> Number`

**Formula**: `σ = √(Σ variances)`

### Completion Probability

Probability of completing by a given time:

```javascript
let expected_duration = 20   // Expected project duration
let target_time = 22         // Target completion time
let std_dev = 2.5            // Project standard deviation

let prob = completion_probability(expected_duration, target_time, std_dev)
// Probability of completing within 22 time units
// Uses normal distribution: P(Z ≤ (22-20)/2.5)
```

**Signature**: `completion_probability(expected, target, std_dev) -> Number`

**Formula**: `P(T ≤ target) = Φ((target - expected) / σ)`

**Returns**: Probability between 0 and 1

**Uses**: Normal distribution (Central Limit Theorem)

### Time for Probability

Find required time for desired probability:

```javascript
let expected_duration = 20
let probability = 0.95       // 95% confidence
let std_dev = 2.5

let time = time_for_probability(expected_duration, probability, std_dev)
// Time needed for 95% completion probability
// ≈ 24.1 time units
```

**Signature**: `time_for_probability(expected, probability, std_dev) -> Number`

**Formula**: `T = expected + Z(p) × σ`

**Use case**: Determine project deadline for desired confidence level

## Complete PERT Analysis

### One-Stop PERT Analysis

Perform complete PERT/CPM analysis:

```javascript
// Define tasks with three-point estimates
let tasks = {
    A: {
        predecessors: [],
        optimistic: 2,
        most_likely: 4,
        pessimistic: 8
    },
    B: {
        predecessors: ["A"],
        optimistic: 3,
        most_likely: 5,
        pessimistic: 9
    },
    C: {
        predecessors: ["A"],
        optimistic: 1,
        most_likely: 2,
        pessimistic: 3
    },
    D: {
        predecessors: ["B", "C"],
        optimistic: 4,
        most_likely: 6,
        pessimistic: 10
    }
}

let analysis = pert_analysis(tasks)
```

**Signature**: `pert_analysis(task_definitions) -> Record`

**Result includes**:
```javascript
{
    expected_times: {...},      // Expected duration per task
    variances: {...},           // Variance per task
    forward_pass: {...},        // ES/EF times
    backward_pass: {...},       // LS/LF times
    slack: {...},               // Slack per task
    critical_path: [...],       // Critical path nodes
    project_duration: 16.33,    // Expected project duration
    project_variance: 3.69,     // Project variance
    project_std_dev: 1.92,      // Project std deviation
    probabilities: {            // Completion probabilities
        on_time: 0.50,
        within_1_sigma: 0.84,
        within_2_sigma: 0.98
    }
}
```

## Practical Examples

### Basic Graph Analysis

```javascript
// Create network
let network = network(
    A -> [B, 5],
    A -> [C, 3],
    B -> [D, 2],
    C -> [D, 4],
    D -> [E, 1]
)

// Analyze structure
let all_nodes = nodes(network)
let all_edges = edges(network)

// Find shortest path
let shortest = dijkstra(network, "A")
let distance_to_E = shortest.distances.E

// Traversal
let bfs_order = bfs(network, "A")
let path_to_E = bfs_path(network, "A", "E")
```

### Minimum Spanning Tree Example

```javascript
// City connections with costs
let cities = network(
    NYC <> [Boston, 215],
    NYC <> [Philadelphia, 95],
    Boston <> [Philadelphia, 310],
    Philadelphia <> [DC, 140],
    NYC <> [DC, 225]
)

// Find minimum cost network
let mst = kruskal(cities)

// Calculate total cost (manual)
let total = sum(map(e => e.weight, edges(mst)))
```

### Software Build Dependencies

```javascript
// Build tasks with dependencies
let build = network(
    clean -> compile,
    compile -> test,
    compile -> lint,
    test -> package,
    lint -> package,
    package -> deploy
)

// Check for circular dependencies
if (has_cycle(build)) {
    error("Circular dependency detected!")
}

// Get build order
let build_order = topological_sort(build)
// ["clean", "compile", "test", "lint", "package", "deploy"]
```

### Complete Project Management Example

```javascript
// Software development project
let project = network(
    Start -> [Requirements, 5],
    Requirements -> [Design, 8],
    Requirements -> [Database, 6],
    Design -> [Frontend, 10],
    Design -> [Backend, 12],
    Database -> [Backend, 0],
    Frontend -> [Integration, 4],
    Backend -> [Integration, 0],
    Integration -> [Testing, 6],
    Testing -> [Deployment, 2]
)

// CPM Analysis
let forward = forward_pass(project, "Start")
let backward = backward_pass(project, forward, "Deployment")
let slack = calculate_slack(forward, backward)
let critical = critical_path(project, "Start", "Deployment")
let duration = project_duration(project, "Start", "Deployment")

// Results
// Critical path: [Start, Requirements, Design, Backend, Integration, Testing, Deployment]
// Project duration: 33 days
// Tasks with slack: Frontend (4 days), Database (6 days)
```

### PERT with Uncertainty

```javascript
// Task estimates (optimistic, most likely, pessimistic)
let task_A = {
    o: 3,
    m: 5,
    p: 9
}

let task_B = {
    o: 2,
    m: 4,
    p: 8
}

// Calculate expected times
let te_A = expected_time(task_A.o, task_A.m, task_A.p)  // 5.33
let te_B = expected_time(task_B.o, task_B.m, task_B.p)  // 4.33

// Calculate variances
let var_A = task_variance(task_A.o, task_A.p)  // 1.0
let var_B = task_variance(task_B.o, task_B.p)  // 1.0

// Project statistics (if A and B are on critical path)
let proj_duration = te_A + te_B  // 9.66
let proj_var = project_variance([var_A, var_B])  // 2.0
let proj_std = project_std_dev([var_A, var_B])  // 1.41

// Probability analysis
// What's the probability of finishing in 11 days?
let prob_11 = completion_probability(proj_duration, 11, proj_std)
// ≈ 0.83 (83% chance)

// What time gives 95% confidence?
let time_95 = time_for_probability(proj_duration, 0.95, proj_std)
// ≈ 11.98 days
```

### Network Analysis

```javascript
// Social network
let social = network(
    Alice <> Bob,
    Alice <> Carol,
    Bob <> David,
    Carol <> David,
    Eve <> Frank
)

// Connectivity analysis
let is_fully_connected = is_connected(social)  // false (Eve/Frank isolated)
let components = connected_components(social)
// [["Alice", "Bob", "Carol", "David"], ["Eve", "Frank"]]

// Find most connected person
let degrees = map(
    node => ({name: node, degree: degree(social, node)}),
    nodes(social)
)
// Find max degree (manual max by comparison)
```

### Cycle Detection Example

```javascript
// Course prerequisites
let courses = network(
    Math101 -> Calculus,
    Calculus -> LinearAlgebra,
    LinearAlgebra -> MachineLearning,
    MachineLearning -> AdvancedML
)

if (has_cycle(courses)) {
    error("Invalid prerequisites: circular dependency")
} else {
    let course_order = topological_sort(courses)
    // Valid sequence to take courses
}
```

## Performance Considerations

### Graph Representation

Graphs are stored using adjacency list representation:
- Space complexity: O(V + E)
- Fast neighbor lookup
- Efficient for sparse graphs

### Algorithm Complexity

| Algorithm | Time Complexity | Space |
|-----------|----------------|-------|
| BFS | O(V + E) | O(V) |
| DFS | O(V + E) | O(V) |
| Dijkstra | O((V + E) log V) | O(V) |
| Kruskal | O(E log E) | O(V) |
| Prim | O((V + E) log V) | O(V) |
| Topological Sort | O(V + E) | O(V) |
| PERT Analysis | O(V + E) | O(V) |

### Best Practices

```javascript
// ✅ Reuse graph for multiple queries
let g = network(A -> B, B -> C, C -> D)
let n = nodes(g)
let path1 = dijkstra(g, "A")
let path2 = bfs(g, "A")

// ✅ Choose right algorithm
// Dense graphs: Prim for MST
// Sparse graphs: Kruskal for MST
// Unweighted shortest path: BFS
// Weighted shortest path: Dijkstra

// ✅ Validate before expensive operations
if (has_cycle(g)) {
    error("Cannot topological sort cyclic graph")
}
let order = topological_sort(g)
```

## Summary

**Graph construction**: `network()` with `->` and `<>` operators

**Properties**: nodes, edges, neighbors, degree

**Traversal**: bfs, dfs, bfs_path

**Paths**: dijkstra (shortest weighted path)

**Trees**: kruskal, prim (minimum spanning tree)

**Cycles**: has_cycle

**Connectivity**: connected_components, is_connected

**Ordering**: topological_sort

**PERT/CPM**: forward_pass, backward_pass, calculate_slack, critical_path, project_duration

**PERT Probabilistic**: expected_time, task_variance, completion_probability

**Complete analysis**: pert_analysis

**Key features**:
- Natural edge syntax
- Directed and undirected edges
- Weighted graphs
- Industry-standard algorithms
- Project management support
- Probabilistic analysis

**Best practices**:
- Validate DAG before topological sort
- Use appropriate algorithm for graph density
- Check connectivity for network problems
- Use PERT for uncertain task durations
- Analyze critical path for project scheduling

**Common applications**:
- Route planning and navigation
- Network optimization
- Dependency management
- Project scheduling (PERT/CPM)
- Social network analysis
- Task sequencing
- Resource allocation

---

**Next**: [Optimization and Linear Programming](19-optimization.md)
