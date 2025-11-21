//! PERT/CPM (Program Evaluation and Review Technique / Critical Path Method) built-in functions for VM
//!
//! This module provides project management operations including:
//! - CPM: forward_pass, backward_pass, calculate_slack
//! - Critical Path: critical_path, all_critical_paths, project_duration
//! - PERT Probabilistic: expected_time, task_variance, project_variance, project_std_dev
//! - PERT Analysis: completion_probability, time_for_probability, pert_analysis

use crate::builtins::graph::{vm_has_cycle, vm_topological_sort};
use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate that network is a DAG (required for PERT)
fn validate_dag(vm: &mut VM, network: &HashMap<String, Value>) -> Result<(), VmError> {
    let network_value = Value::Record(Rc::new(RefCell::new(network.clone())));
    match vm_has_cycle(vm, &[network_value])? {
        Value::Boolean(true) => Err(VmError::Runtime(
            "PERT requires a Directed Acyclic Graph (DAG), but the network contains cycles"
                .to_string(),
        )),
        _ => Ok(()),
    }
}

/// Get duration from node with priority:
/// 1. 'duration' (explicit, deterministic)
/// 2. 'te' (explicit, pre-calculated expected time)
/// 3. Calculate from (op, mo, pe) using PERT formula: (op + 4*mo + pe) / 6
fn get_node_duration(node_props: &HashMap<String, Value>) -> Result<f64, VmError> {
    // Priority 1: duration
    if let Some(Value::Number(d)) = node_props.get("duration") {
        return Ok(*d);
    }

    // Priority 2: te (expected time)
    if let Some(Value::Number(t)) = node_props.get("te") {
        return Ok(*t);
    }

    // Priority 3: Calculate from op, mo, pe
    if let (Some(Value::Number(op)), Some(Value::Number(mo)), Some(Value::Number(pe))) = (
        node_props.get("op"),
        node_props.get("mo"),
        node_props.get("pe"),
    ) {
        // Validate op <= mo <= pe
        if !(*op <= *mo && *mo <= *pe) {
            return Err(VmError::Runtime(format!(
                "Invalid PERT estimates: op <= mo <= pe required (got op={}, mo={}, pe={})",
                op, mo, pe
            )));
        }
        // Calculate expected time: te = (op + 4*mo + pe) / 6
        return Ok((op + 4.0 * mo + pe) / 6.0);
    }

    Err(VmError::Runtime(
        "Node must have 'duration', 'te', or ('op', 'mo', 'pe') properties".to_string(),
    ))
}

/// Validate that all nodes have duration, te, or (op, mo, pe) properties
fn validate_node_durations(network: &HashMap<String, Value>) -> Result<(), VmError> {
    let nodes_record = match network.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field with a record".to_string(),
            ))
        }
    };

    for (node_id, node_data) in &nodes_record {
        match node_data {
            Value::Record(props) => {
                let props_borrowed = props.borrow();
                match get_node_duration(&props_borrowed) {
                    Ok(duration) => {
                        // Validate duration is non-negative
                        if duration < 0.0 {
                            return Err(VmError::Runtime(format!(
                                "Node '{}' has negative duration: {}",
                                node_id, duration
                            )));
                        }
                    }
                    Err(e) => {
                        return Err(VmError::Runtime(format!("Node '{}': {}", node_id, e)));
                    }
                }
            }
            _ => {
                return Err(VmError::Runtime(format!(
                    "Node '{}' data must be a record",
                    node_id
                )))
            }
        }
    }

    Ok(())
}

/// Validate that all nodes have op, mo, pe properties for probabilistic PERT
fn validate_probabilistic_properties(network: &HashMap<String, Value>) -> Result<(), VmError> {
    let nodes_record = match network.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field with a record".to_string(),
            ))
        }
    };

    for (node_id, node_data) in &nodes_record {
        match node_data {
            Value::Record(props) => {
                let props_borrowed = props.borrow();
                // Check for op, mo, pe
                let op = props_borrowed.get("op");
                let mo = props_borrowed.get("mo");
                let pe = props_borrowed.get("pe");

                if op.is_none() || mo.is_none() || pe.is_none() {
                    return Err(VmError::Runtime(format!(
                        "Node '{}' must have 'op', 'mo', and 'pe' properties for probabilistic PERT",
                        node_id
                    )));
                }

                // Extract values and validate op <= mo <= pe
                let op_val = match op {
                    Some(Value::Number(n)) => *n,
                    _ => {
                        return Err(VmError::Runtime(format!(
                            "Node '{}' 'op' must be a number",
                            node_id
                        )))
                    }
                };

                let mo_val = match mo {
                    Some(Value::Number(n)) => *n,
                    _ => {
                        return Err(VmError::Runtime(format!(
                            "Node '{}' 'mo' must be a number",
                            node_id
                        )))
                    }
                };

                let pe_val = match pe {
                    Some(Value::Number(n)) => *n,
                    _ => {
                        return Err(VmError::Runtime(format!(
                            "Node '{}' 'pe' must be a number",
                            node_id
                        )))
                    }
                };

                if !(op_val <= mo_val && mo_val <= pe_val) {
                    return Err(VmError::Runtime(format!(
                        "Node '{}' must satisfy: op <= mo <= pe (got op={}, mo={}, pe={})",
                        node_id, op_val, mo_val, pe_val
                    )));
                }

                if op_val < 0.0 || mo_val < 0.0 || pe_val < 0.0 {
                    return Err(VmError::Runtime(format!(
                        "Node '{}' times must be non-negative",
                        node_id
                    )));
                }
            }
            _ => {
                return Err(VmError::Runtime(format!(
                    "Node '{}' data must be a record",
                    node_id
                )))
            }
        }
    }

    Ok(())
}

/// Check if network has ES and EF calculated (from forward_pass)
fn has_es_ef_data(network: &HashMap<String, Value>) -> bool {
    if let Some(Value::Record(nodes)) = network.get("nodes") {
        let nodes_borrowed = nodes.borrow();
        return nodes_borrowed.iter().any(|(_id, node_data)| {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                props_borrowed.contains_key("ES") && props_borrowed.contains_key("EF")
            } else {
                false
            }
        });
    }
    false
}

/// Check if network has LS and LF calculated (from backward_pass)
fn has_ls_lf_data(network: &HashMap<String, Value>) -> bool {
    if let Some(Value::Record(nodes)) = network.get("nodes") {
        let nodes_borrowed = nodes.borrow();
        return nodes_borrowed.iter().any(|(_id, node_data)| {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                props_borrowed.contains_key("LS") && props_borrowed.contains_key("LF")
            } else {
                false
            }
        });
    }
    false
}

/// Check if network has slack calculated (from calculate_slack)
fn has_slack_data(network: &HashMap<String, Value>) -> bool {
    if let Some(Value::Record(nodes)) = network.get("nodes") {
        let nodes_borrowed = nodes.borrow();
        return nodes_borrowed.iter().any(|(_id, node_data)| {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                props_borrowed.contains_key("slack")
            } else {
                false
            }
        });
    }
    false
}

/// Build adjacency list from network edges
fn build_adjacency_list(edges: &[Value]) -> Result<HashMap<String, Vec<String>>, VmError> {
    let mut adj_list: HashMap<String, Vec<String>> = HashMap::new();

    for edge in edges {
        match edge {
            Value::Edge { from, to, .. } => {
                // Only add forward edge (directed graph)
                adj_list
                    .entry(from.clone())
                    .or_insert_with(Vec::new)
                    .push(to.clone());
            }
            _ => return Err(VmError::Runtime("Invalid edge in edges vector".to_string())),
        }
    }

    Ok(adj_list)
}

// ============================================================================
// CPM Functions
// ============================================================================

/// Forward pass: Calculate Early Start (ES) and Early Finish (EF) for all tasks
pub fn vm_forward_pass(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "forward_pass() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "forward_pass() requires a network record".to_string(),
            ))
        }
    };

    // Validate DAG and durations
    validate_dag(vm, &network)?;
    validate_node_durations(&network)?;

    // Get nodes and edges
    let nodes_record = match network.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field".to_string(),
            ))
        }
    };

    let edges_vec = match network.get("edges") {
        Some(Value::Vector(v)) => v.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'edges' field".to_string(),
            ))
        }
    };

    // Build reverse adjacency list (predecessors)
    let mut predecessors: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &edges_vec {
        if let Value::Edge { from, to, .. } = edge {
            predecessors
                .entry(to.clone())
                .or_insert_with(Vec::new)
                .push(from.clone());
        }
    }

    // Get topological order
    let topo_order = match vm_topological_sort(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])? {
        Value::Vector(v) => v.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Failed to get topological order".to_string(),
            ))
        }
    };

    // Calculate ES and EF for each node in topological order
    let mut es_map: HashMap<String, f64> = HashMap::new();
    let mut ef_map: HashMap<String, f64> = HashMap::new();

    for node_val in &topo_order {
        let node_id = match node_val {
            Value::String(s) => s,
            _ => {
                return Err(VmError::Runtime(
                    "Invalid node in topological order".to_string(),
                ))
            }
        };

        let node_props = match nodes_record.get(node_id) {
            Some(Value::Record(p)) => p.borrow().clone(),
            _ => return Err(VmError::Runtime(format!("Node '{}' not found", node_id))),
        };

        let duration = get_node_duration(&node_props)?;

        // ES = max(EF of all predecessors), or 0 if no predecessors
        let es = if let Some(preds) = predecessors.get(node_id) {
            let mut max_ef: f64 = 0.0;
            for pred in preds {
                if let Some(pred_ef) = ef_map.get(pred) {
                    max_ef = max_ef.max(*pred_ef);
                }
            }
            max_ef
        } else {
            0.0 // Start nodes have ES = 0
        };

        let ef = es + duration;

        es_map.insert(node_id.clone(), es);
        ef_map.insert(node_id.clone(), ef);
    }

    // Build new network with ES and EF added to nodes
    let mut new_nodes = HashMap::new();
    for (node_id, node_data) in &nodes_record {
        let mut new_props = match node_data {
            Value::Record(p) => p.borrow().clone(),
            _ => HashMap::new(),
        };

        new_props.insert("ES".to_string(), Value::Number(*es_map.get(node_id.as_str()).unwrap()));
        new_props.insert("EF".to_string(), Value::Number(*ef_map.get(node_id.as_str()).unwrap()));

        new_nodes.insert(node_id.clone(), Value::Record(Rc::new(RefCell::new(new_props))));
    }

    let mut new_network = network.clone();
    new_network.insert(
        "nodes".to_string(),
        Value::Record(Rc::new(RefCell::new(new_nodes))),
    );

    Ok(Value::Record(Rc::new(RefCell::new(new_network))))
}

/// Backward pass: Calculate Late Start (LS) and Late Finish (LF) for all tasks
pub fn vm_backward_pass(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "backward_pass() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "backward_pass() requires a network record".to_string(),
            ))
        }
    };

    // Auto-calculate forward pass if ES/EF data is missing
    let network_with_es_ef = if !has_es_ef_data(&network) {
        match vm_forward_pass(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])? {
            Value::Record(n) => n.borrow().clone(),
            _ => {
                return Err(VmError::Runtime(
                    "Failed to calculate forward pass".to_string(),
                ))
            }
        }
    } else {
        network.clone()
    };

    // Validate that network has ES/EF (from forward_pass)
    let nodes_record = match network_with_es_ef.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field".to_string(),
            ))
        }
    };

    let edges_vec = match network_with_es_ef.get("edges") {
        Some(Value::Vector(v)) => v.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'edges' field".to_string(),
            ))
        }
    };

    // Build adjacency list (successors)
    let adj_list = build_adjacency_list(&edges_vec)?;

    // Get topological order (reversed for backward pass)
    let mut topo_order = match vm_topological_sort(vm, &[Value::Record(Rc::new(RefCell::new(network_with_es_ef.clone())))])? {
        Value::Vector(v) => v.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Failed to get topological order".to_string(),
            ))
        }
    };
    topo_order.reverse();

    // Find project completion time (max EF)
    let mut project_completion: f64 = 0.0;
    for node_data in nodes_record.values() {
        if let Value::Record(props) = node_data {
            let props_borrowed = props.borrow();
            if let Some(Value::Number(ef)) = props_borrowed.get("EF") {
                project_completion = project_completion.max(*ef);
            }
        }
    }

    // Calculate LS and LF for each node in reverse topological order
    let mut ls_map: HashMap<String, f64> = HashMap::new();
    let mut lf_map: HashMap<String, f64> = HashMap::new();

    for node_val in &topo_order {
        let node_id = match node_val {
            Value::String(s) => s,
            _ => {
                return Err(VmError::Runtime(
                    "Invalid node in topological order".to_string(),
                ))
            }
        };

        let node_props = match nodes_record.get(node_id) {
            Some(Value::Record(p)) => p.borrow().clone(),
            _ => return Err(VmError::Runtime(format!("Node '{}' not found", node_id))),
        };

        let duration = get_node_duration(&node_props)?;

        // LF = min(LS of all successors), or project_completion if no successors
        let lf = if let Some(succs) = adj_list.get(node_id) {
            let mut min_ls = f64::INFINITY;
            for succ in succs {
                if let Some(succ_ls) = ls_map.get(succ) {
                    min_ls = min_ls.min(*succ_ls);
                }
            }
            if min_ls == f64::INFINITY {
                project_completion
            } else {
                min_ls
            }
        } else {
            project_completion // End nodes have LF = project completion
        };

        let ls = lf - duration;

        ls_map.insert(node_id.clone(), ls);
        lf_map.insert(node_id.clone(), lf);
    }

    // Build new network with LS and LF added to nodes
    let mut new_nodes = HashMap::new();
    for (node_id, node_data) in &nodes_record {
        let mut new_props = match node_data {
            Value::Record(p) => p.borrow().clone(),
            _ => HashMap::new(),
        };

        new_props.insert("LS".to_string(), Value::Number(*ls_map.get(node_id.as_str()).unwrap()));
        new_props.insert("LF".to_string(), Value::Number(*lf_map.get(node_id.as_str()).unwrap()));

        new_nodes.insert(node_id.clone(), Value::Record(Rc::new(RefCell::new(new_props))));
    }

    let mut new_network = network_with_es_ef.clone();
    new_network.insert(
        "nodes".to_string(),
        Value::Record(Rc::new(RefCell::new(new_nodes))),
    );

    Ok(Value::Record(Rc::new(RefCell::new(new_network))))
}

/// Calculate slack (float) for all tasks
pub fn vm_calculate_slack(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "calculate_slack() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "calculate_slack() requires a network record".to_string(),
            ))
        }
    };

    // Auto-calculate backward pass if LS/LF data is missing
    let network_with_all_data = if !has_ls_lf_data(&network) {
        match vm_backward_pass(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])? {
            Value::Record(n) => n.borrow().clone(),
            _ => {
                return Err(VmError::Runtime(
                    "Failed to calculate backward pass".to_string(),
                ))
            }
        }
    } else {
        network.clone()
    };

    let nodes_record = match network_with_all_data.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field".to_string(),
            ))
        }
    };

    // Calculate slack for each node
    let mut new_nodes = HashMap::new();
    for (node_id, node_data) in &nodes_record {
        let mut new_props = match node_data {
            Value::Record(p) => p.borrow().clone(),
            _ => HashMap::new(),
        };

        let es = match new_props.get("ES") {
            Some(Value::Number(n)) => *n,
            _ => return Err(VmError::Runtime(format!("Node '{}' missing ES", node_id))),
        };

        let ls = match new_props.get("LS") {
            Some(Value::Number(n)) => *n,
            _ => return Err(VmError::Runtime(format!("Node '{}' missing LS", node_id))),
        };

        let slack = ls - es;
        new_props.insert("slack".to_string(), Value::Number(slack));

        new_nodes.insert(node_id.clone(), Value::Record(Rc::new(RefCell::new(new_props))));
    }

    let mut new_network = network_with_all_data.clone();
    new_network.insert(
        "nodes".to_string(),
        Value::Record(Rc::new(RefCell::new(new_nodes))),
    );

    Ok(Value::Record(Rc::new(RefCell::new(new_network))))
}

// ============================================================================
// Critical Path Functions
// ============================================================================

/// Find one complete critical path from start to finish
pub fn vm_critical_path(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "critical_path() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "critical_path() requires a network record".to_string(),
            ))
        }
    };

    // Auto-calculate slack if missing
    let network_with_slack = if !has_slack_data(&network) {
        match vm_calculate_slack(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])? {
            Value::Record(n) => n.borrow().clone(),
            _ => {
                return Err(VmError::Runtime(
                    "Failed to calculate slack".to_string(),
                ))
            }
        }
    } else {
        network.clone()
    };

    let nodes_record = match network_with_slack.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field".to_string(),
            ))
        }
    };

    let edges_vec = match network_with_slack.get("edges") {
        Some(Value::Vector(v)) => v.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'edges' field".to_string(),
            ))
        }
    };

    // Find nodes with slack ~= 0 (critical nodes)
    let epsilon = 1e-6;
    let mut critical_nodes_set: HashSet<String> = HashSet::new();

    for (node_id, node_data) in &nodes_record {
        if let Value::Record(props) = node_data {
            let props_borrowed = props.borrow();
            if let Some(Value::Number(slack)) = props_borrowed.get("slack") {
                if slack.abs() < epsilon {
                    critical_nodes_set.insert(node_id.clone());
                }
            }
        }
    }

    // Build adjacency list for critical nodes only
    let mut critical_adj: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &edges_vec {
        if let Value::Edge { from, to, .. } = edge {
            if critical_nodes_set.contains(from) && critical_nodes_set.contains(to) {
                critical_adj
                    .entry(from.clone())
                    .or_insert_with(Vec::new)
                    .push(to.clone());
            }
        }
    }

    // Find start node (ES = 0 and is critical)
    let mut start_node: Option<String> = None;
    for (node_id, node_data) in &nodes_record {
        if critical_nodes_set.contains(node_id.as_str()) {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                if let Some(Value::Number(es)) = props_borrowed.get("ES") {
                    if es.abs() < epsilon {
                        start_node = Some(node_id.clone());
                        break;
                    }
                }
            }
        }
    }

    let start = start_node.ok_or_else(|| {
        VmError::Runtime("No critical start node found (ES=0)".to_string())
    })?;

    // Find project duration to identify end nodes
    let mut project_duration: f64 = 0.0;
    for node_data in nodes_record.values() {
        if let Value::Record(props) = node_data {
            let props_borrowed = props.borrow();
            if let Some(Value::Number(ef)) = props_borrowed.get("EF") {
                project_duration = project_duration.max(*ef);
            }
        }
    }

    // Find end nodes (EF = project_duration and is critical)
    let mut end_nodes: Vec<String> = Vec::new();
    for (node_id, node_data) in &nodes_record {
        if critical_nodes_set.contains(node_id.as_str()) {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                if let Some(Value::Number(ef)) = props_borrowed.get("EF") {
                    if (ef - project_duration).abs() < epsilon {
                        end_nodes.push(node_id.clone());
                    }
                }
            }
        }
    }

    if end_nodes.is_empty() {
        return Err(VmError::Runtime(
            "No critical end node found".to_string(),
        ));
    }

    // DFS to find one complete path from start to any end node
    fn dfs_find_path(
        current: &str,
        end_nodes: &[String],
        adj: &HashMap<String, Vec<String>>,
        path: &mut Vec<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        path.push(current.to_string());
        visited.insert(current.to_string());

        // Check if we reached an end node
        if end_nodes.contains(&current.to_string()) {
            return true;
        }

        // Explore neighbors
        if let Some(neighbors) = adj.get(current) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    if dfs_find_path(neighbor, end_nodes, adj, path, visited) {
                        return true;
                    }
                }
            }
        }

        // Backtrack
        path.pop();
        visited.remove(current);
        false
    }

    let mut path = Vec::new();
    let mut visited = HashSet::new();

    if !dfs_find_path(&start, &end_nodes, &critical_adj, &mut path, &mut visited) {
        return Err(VmError::Runtime(
            "Could not find complete critical path from start to end".to_string(),
        ));
    }

    // Convert to Value::Vector
    let path_values: Vec<Value> = path.into_iter().map(Value::String).collect();
    Ok(Value::Vector(Rc::new(RefCell::new(path_values))))
}

/// Find all complete critical paths from start to finish
pub fn vm_all_critical_paths(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "all_critical_paths() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "all_critical_paths() requires a network record".to_string(),
            ))
        }
    };

    // Auto-calculate slack if missing
    let network_with_slack = if !has_slack_data(&network) {
        match vm_calculate_slack(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])? {
            Value::Record(n) => n.borrow().clone(),
            _ => {
                return Err(VmError::Runtime(
                    "Failed to calculate slack".to_string(),
                ))
            }
        }
    } else {
        network.clone()
    };

    let nodes_record = match network_with_slack.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field".to_string(),
            ))
        }
    };

    let edges_vec = match network_with_slack.get("edges") {
        Some(Value::Vector(v)) => v.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'edges' field".to_string(),
            ))
        }
    };

    // Find nodes with slack ~= 0 (critical nodes)
    let epsilon = 1e-6;
    let mut critical_nodes_set: HashSet<String> = HashSet::new();

    for (node_id, node_data) in &nodes_record {
        if let Value::Record(props) = node_data {
            let props_borrowed = props.borrow();
            if let Some(Value::Number(slack)) = props_borrowed.get("slack") {
                if slack.abs() < epsilon {
                    critical_nodes_set.insert(node_id.clone());
                }
            }
        }
    }

    // Build adjacency list for critical nodes only
    let mut critical_adj: HashMap<String, Vec<String>> = HashMap::new();
    for edge in &edges_vec {
        if let Value::Edge { from, to, .. } = edge {
            if critical_nodes_set.contains(from) && critical_nodes_set.contains(to) {
                critical_adj
                    .entry(from.clone())
                    .or_insert_with(Vec::new)
                    .push(to.clone());
            }
        }
    }

    // Find start node (ES = 0 and is critical)
    let mut start_node: Option<String> = None;
    for (node_id, node_data) in &nodes_record {
        if critical_nodes_set.contains(node_id.as_str()) {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                if let Some(Value::Number(es)) = props_borrowed.get("ES") {
                    if es.abs() < epsilon {
                        start_node = Some(node_id.clone());
                        break;
                    }
                }
            }
        }
    }

    let start = start_node.ok_or_else(|| {
        VmError::Runtime("No critical start node found (ES=0)".to_string())
    })?;

    // Find project duration to identify end nodes
    let mut project_duration: f64 = 0.0;
    for node_data in nodes_record.values() {
        if let Value::Record(props) = node_data {
            let props_borrowed = props.borrow();
            if let Some(Value::Number(ef)) = props_borrowed.get("EF") {
                project_duration = project_duration.max(*ef);
            }
        }
    }

    // Find end nodes (EF = project_duration and is critical)
    let mut end_nodes: Vec<String> = Vec::new();
    for (node_id, node_data) in &nodes_record {
        if critical_nodes_set.contains(node_id.as_str()) {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                if let Some(Value::Number(ef)) = props_borrowed.get("EF") {
                    if (ef - project_duration).abs() < epsilon {
                        end_nodes.push(node_id.clone());
                    }
                }
            }
        }
    }

    if end_nodes.is_empty() {
        return Err(VmError::Runtime(
            "No critical end node found".to_string(),
        ));
    }

    // DFS to find ALL complete paths from start to any end node
    fn dfs_find_all_paths(
        current: &str,
        end_nodes: &[String],
        adj: &HashMap<String, Vec<String>>,
        path: &mut Vec<String>,
        visited: &mut HashSet<String>,
        all_paths: &mut Vec<Vec<String>>,
    ) {
        path.push(current.to_string());
        visited.insert(current.to_string());

        // Check if we reached an end node
        if end_nodes.contains(&current.to_string()) {
            all_paths.push(path.clone());
        } else {
            // Explore neighbors
            if let Some(neighbors) = adj.get(current) {
                for neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        dfs_find_all_paths(neighbor, end_nodes, adj, path, visited, all_paths);
                    }
                }
            }
        }

        // Backtrack
        path.pop();
        visited.remove(current);
    }

    let mut all_paths = Vec::new();
    let mut path = Vec::new();
    let mut visited = HashSet::new();

    dfs_find_all_paths(
        &start,
        &end_nodes,
        &critical_adj,
        &mut path,
        &mut visited,
        &mut all_paths,
    );

    if all_paths.is_empty() {
        return Err(VmError::Runtime(
            "Could not find any critical path from start to end".to_string(),
        ));
    }

    // Convert to Value::Vector of Value::Vector
    let paths_values: Vec<Value> = all_paths
        .into_iter()
        .map(|p| {
            Value::Vector(Rc::new(RefCell::new(
                p.into_iter().map(Value::String).collect(),
            )))
        })
        .collect();

    Ok(Value::Vector(Rc::new(RefCell::new(paths_values))))
}

/// Calculate total project duration (max EF across all nodes)
pub fn vm_project_duration(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "project_duration() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "project_duration() requires a network record".to_string(),
            ))
        }
    };

    // Validate and calculate
    validate_dag(vm, &network)?;
    validate_node_durations(&network)?;

    // Run forward pass to get EF values
    let network_with_times = vm_forward_pass(vm, &[Value::Record(Rc::new(RefCell::new(network)))])?;

    let nodes_record = match network_with_times {
        Value::Record(ref map) => match map.borrow().get("nodes") {
            Some(Value::Record(r)) => r.borrow().clone(),
            _ => {
                return Err(VmError::Runtime(
                    "Invalid network structure".to_string(),
                ))
            }
        },
        _ => {
            return Err(VmError::Runtime(
                "Invalid network structure".to_string(),
            ))
        }
    };

    // Find max EF
    let mut max_ef: f64 = 0.0;
    for node_data in nodes_record.values() {
        if let Value::Record(props) = node_data {
            let props_borrowed = props.borrow();
            if let Some(Value::Number(ef)) = props_borrowed.get("EF") {
                max_ef = max_ef.max(*ef);
            }
        }
    }

    Ok(Value::Number(max_ef))
}

// ============================================================================
// PERT Probabilistic Functions
// ============================================================================

/// Calculate expected time using PERT formula: te = (op + 4*mo + pe) / 6
pub fn vm_expected_time(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(
            "expected_time() requires three numbers (op, mo, pe)".to_string(),
        ));
    }

    let op = match &args[0] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "expected_time() requires three numbers (op, mo, pe)".to_string(),
            ))
        }
    };

    let mo = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "expected_time() requires three numbers (op, mo, pe)".to_string(),
            ))
        }
    };

    let pe = match &args[2] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "expected_time() requires three numbers (op, mo, pe)".to_string(),
            ))
        }
    };

    // Validate op <= mo <= pe
    if !(op <= mo && mo <= pe) {
        return Err(VmError::Runtime(format!(
            "expected_time() requires op <= mo <= pe (got op={}, mo={}, pe={})",
            op, mo, pe
        )));
    }

    let te = (op + 4.0 * mo + pe) / 6.0;
    Ok(Value::Number(te))
}

/// Calculate task variance: variance = ((pe - op) / 6)^2
pub fn vm_task_variance(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(
            "task_variance() requires three numbers (op, mo, pe)".to_string(),
        ));
    }

    let op = match &args[0] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "task_variance() requires three numbers (op, mo, pe)".to_string(),
            ))
        }
    };

    // mo is not used in variance calculation, but we validate it's a number
    if !matches!(&args[1], Value::Number(_)) {
        return Err(VmError::Runtime(
            "task_variance() requires three numbers (op, mo, pe)".to_string(),
        ));
    }

    let pe = match &args[2] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "task_variance() requires three numbers (op, mo, pe)".to_string(),
            ))
        }
    };

    if pe < op {
        return Err(VmError::Runtime(
            "task_variance() requires pe >= op".to_string(),
        ));
    }

    let variance = ((pe - op) / 6.0).powi(2);
    Ok(Value::Number(variance))
}

/// Calculate project variance (sum of variances on critical path)
pub fn vm_project_variance(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "project_variance() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "project_variance() requires a network record".to_string(),
            ))
        }
    };

    // Validate probabilistic properties
    validate_dag(vm, &network)?;
    validate_probabilistic_properties(&network)?;

    // Get critical path (auto-calculates all prerequisites if needed)
    let critical_nodes = vm_critical_path(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])?;

    let nodes_record = match network.get("nodes") {
        Some(Value::Record(r)) => r.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Network must have 'nodes' field".to_string(),
            ))
        }
    };

    // Sum variances of critical path tasks
    let mut total_variance = 0.0;

    if let Value::Vector(critical) = critical_nodes {
        let critical_borrowed = critical.borrow();
        for node_val in critical_borrowed.iter() {
            let node_id = match node_val {
                Value::String(s) => s,
                _ => continue,
            };

            if let Some(Value::Record(props)) = nodes_record.get(node_id) {
                let props_borrowed = props.borrow();
                let op = match props_borrowed.get("op") {
                    Some(Value::Number(n)) => *n,
                    _ => continue,
                };
                let pe = match props_borrowed.get("pe") {
                    Some(Value::Number(n)) => *n,
                    _ => continue,
                };

                let variance = ((pe - op) / 6.0).powi(2);
                total_variance += variance;
            }
        }
    }

    Ok(Value::Number(total_variance))
}

/// Calculate project standard deviation
pub fn vm_project_std_dev(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    let variance = match vm_project_variance(vm, args)? {
        Value::Number(v) => v,
        _ => {
            return Err(VmError::Runtime(
                "Failed to calculate project variance".to_string(),
            ))
        }
    };

    Ok(Value::Number(variance.sqrt()))
}

/// Cumulative Distribution Function for standard normal distribution
fn normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf(x / std::f64::consts::SQRT_2))
}

/// Error function approximation
fn erf(x: f64) -> f64 {
    // Abramowitz and Stegun approximation
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();

    let t = 1.0 / (1.0 + p * x);
    let y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp();

    sign * y
}

/// Inverse CDF for standard normal distribution
fn inverse_normal_cdf(p: f64) -> f64 {
    // Beasley-Springer-Moro algorithm approximation
    let a = [
        -3.969683028665376e+01,
        2.209460984245205e+02,
        -2.759285104469687e+02,
        1.383577518672690e+02,
        -3.066479806614716e+01,
        2.506628277459239e+00,
    ];

    let b = [
        -5.447609879822406e+01,
        1.615858368580409e+02,
        -1.556989798598866e+02,
        6.680131188771972e+01,
        -1.328068155288572e+01,
    ];

    let c = [
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e+00,
        -2.549732539343734e+00,
        4.374664141464968e+00,
        2.938163982698783e+00,
    ];

    let d = [
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e+00,
        3.754408661907416e+00,
    ];

    let p_low = 0.02425;
    let p_high = 1.0 - p_low;

    if p < p_low {
        // Rational approximation for lower region
        let q = (-2.0 * p.ln()).sqrt();
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0);
    }

    if p > p_high {
        // Rational approximation for upper region
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5])
            / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0);
    }

    // Rational approximation for central region
    let q = p - 0.5;
    let r = q * q;
    (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
        / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
}

/// Calculate probability of completing project by target time
pub fn vm_completion_probability(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(
            "completion_probability() requires a network record and target time".to_string(),
        ));
    }

    let network = match &args[0] {
        Value::Record(map) => map.clone(),
        _ => {
            return Err(VmError::Runtime(
                "completion_probability() requires a network record and target time".to_string(),
            ))
        }
    };

    let target_time = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "completion_probability() requires a target time (number)".to_string(),
            ))
        }
    };

    // Calculate project duration (te) and standard deviation
    let te = match vm_project_duration(vm, &[Value::Record(network.clone())])? {
        Value::Number(n) => n,
        _ => {
            return Err(VmError::Runtime(
                "Failed to calculate project duration".to_string(),
            ))
        }
    };

    let std_dev = match vm_project_std_dev(vm, &[Value::Record(network)])? {
        Value::Number(n) => n,
        _ => {
            return Err(VmError::Runtime(
                "Failed to calculate project standard deviation".to_string(),
            ))
        }
    };

    if std_dev == 0.0 {
        // Deterministic: probability is 0 if target < te, 1 if target >= te
        return Ok(Value::Number(if target_time >= te { 1.0 } else { 0.0 }));
    }

    // Calculate z-score
    let z = (target_time - te) / std_dev;

    // Calculate probability using normal CDF approximation
    let prob = normal_cdf(z);

    Ok(Value::Number(prob))
}

/// Calculate time needed for desired completion probability
pub fn vm_time_for_probability(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(
            "time_for_probability() requires a network record and probability".to_string(),
        ));
    }

    let network = match &args[0] {
        Value::Record(map) => map.clone(),
        _ => {
            return Err(VmError::Runtime(
                "time_for_probability() requires a network record and probability".to_string(),
            ))
        }
    };

    let probability = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::Runtime(
                "time_for_probability() requires a probability (0-1)".to_string(),
            ))
        }
    };

    if !(0.0..=1.0).contains(&probability) {
        return Err(VmError::Runtime(
            "Probability must be between 0 and 1".to_string(),
        ));
    }

    // Calculate project duration (te) and standard deviation
    let te = match vm_project_duration(vm, &[Value::Record(network.clone())])? {
        Value::Number(n) => n,
        _ => {
            return Err(VmError::Runtime(
                "Failed to calculate project duration".to_string(),
            ))
        }
    };

    let std_dev = match vm_project_std_dev(vm, &[Value::Record(network)])? {
        Value::Number(n) => n,
        _ => {
            return Err(VmError::Runtime(
                "Failed to calculate project standard deviation".to_string(),
            ))
        }
    };

    if std_dev == 0.0 {
        // Deterministic: return te
        return Ok(Value::Number(te));
    }

    // Find z-score for probability using inverse normal CDF
    let z = inverse_normal_cdf(probability);

    // Calculate time: time = te + z * σ
    let time = te + z * std_dev;

    Ok(Value::Number(time))
}

/// Complete PERT analysis - one-stop function for all PERT calculations
pub fn vm_pert_analysis(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "pert_analysis() expects 1 argument, got {}",
            args.len()
        )));
    }

    let network = match &args[0] {
        Value::Record(map) => map.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "pert_analysis() requires a network record".to_string(),
            ))
        }
    };

    // Calculate network with all properties (auto-calculates prerequisites)
    let network_with_slack = match vm_calculate_slack(vm, &[Value::Record(Rc::new(RefCell::new(network.clone())))])? {
        Value::Record(n) => n.borrow().clone(),
        _ => {
            return Err(VmError::Runtime(
                "Failed to calculate slack".to_string(),
            ))
        }
    };

    // Get critical path
    let critical_path_nodes = vm_critical_path(vm, &[Value::Record(Rc::new(RefCell::new(network_with_slack.clone())))])?;

    // Calculate project duration
    let duration = vm_project_duration(vm, &[Value::Record(Rc::new(RefCell::new(network_with_slack.clone())))])?;

    // Check if network has probabilistic properties (op, mo, pe)
    let has_probabilistic = if let Some(Value::Record(nodes)) = network.get("nodes") {
        let nodes_borrowed = nodes.borrow();
        nodes_borrowed.iter().any(|(_id, node_data)| {
            if let Value::Record(props) = node_data {
                let props_borrowed = props.borrow();
                props_borrowed.contains_key("op")
                    && props_borrowed.contains_key("mo")
                    && props_borrowed.contains_key("pe")
            } else {
                false
            }
        })
    } else {
        false
    };

    // Build result record
    let mut result = HashMap::new();
    result.insert(
        "network".to_string(),
        Value::Record(Rc::new(RefCell::new(network_with_slack.clone()))),
    );
    result.insert("critical_path".to_string(), critical_path_nodes);
    result.insert("duration".to_string(), duration);

    // Add probabilistic analysis if applicable
    if has_probabilistic {
        let variance = vm_project_variance(vm, &[Value::Record(Rc::new(RefCell::new(network)))])?;
        let std_dev = vm_project_std_dev(vm, &[Value::Record(Rc::new(RefCell::new(network_with_slack)))])?;
        result.insert("variance".to_string(), variance);
        result.insert("std_dev".to_string(), std_dev);
    }

    Ok(Value::Record(Rc::new(RefCell::new(result))))
}
