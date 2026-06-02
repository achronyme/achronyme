use std::collections::{HashMap, HashSet};

use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::config::LysisConfig;
use crate::error::LysisError;
use crate::program::Program;

use super::dataflow::hosting_template;

// ---------------------------------------------------------------------
// Rule 11 — acyclic call graph + longest-path ≤ max_call_depth.
// ---------------------------------------------------------------------

pub(super) fn check_call_graph<F: FieldBackend>(
    program: &Program<F>,
    config: &LysisConfig,
) -> Result<(), LysisError> {
    // Nodes: `None` (root/top-level) + each template id.
    //
    // Edges: for every InstantiateTemplate at offset `off`, add an
    // edge `hosting_template(off) -> target_template`. The same rule
    // applies to LoopRolled / LoopRange, which dispatch to a template
    // body per iteration.
    // Edge = (target, is_tail). A tail edge is a plain
    // `InstantiateTemplate` whose very next body instruction is
    // `Return` with no outputs to forward — the executor
    // tail-eliminates it (replaces the caller frame instead of
    // pushing), so it adds 0 to runtime call depth. Counting it as a
    // depth edge here would reject (in debug builds, the only place
    // this validator runs) the linear split-chains the executor runs
    // fine in release — a debug/release divergence. `LoopRolled` /
    // `LoopRange` dispatch a body per iteration and are never
    // tail-eliminated.
    let mut graph: HashMap<Option<u16>, Vec<(u16, bool)>> = HashMap::new();
    graph.entry(None).or_default();
    for t in &program.templates {
        graph.entry(Some(t.id)).or_default();
    }
    for (i, instr) in program.body.iter().enumerate() {
        let host = hosting_template(program, instr.offset);
        let (target, is_tail) = match &instr.opcode {
            Opcode::InstantiateTemplate {
                template_id,
                output_regs,
                ..
            } => {
                let tail = output_regs.is_empty()
                    && matches!(
                        program.body.get(i + 1).map(|n| &n.opcode),
                        Some(Opcode::Return)
                    );
                (Some(*template_id), tail)
            }
            Opcode::LoopRolled {
                body_template_id: template_id,
                ..
            }
            | Opcode::LoopRange {
                body_template_id: template_id,
                ..
            } => (Some(*template_id), false),
            _ => (None, false),
        };
        if let Some(t) = target {
            graph.entry(host).or_default().push((t, is_tail));
        }
    }

    // DFS with in-progress set to catch cycles, depth tracking to
    // reject chains above the limit. Only one start node (the root),
    // but inaccessible template bodies must still be checked for
    // self-loops, so iterate over every node.
    for start in graph.keys() {
        let mut stack: HashSet<Option<u16>> = HashSet::new();
        let longest = dfs_longest(*start, &graph, &mut stack, config.max_call_depth)?;
        if longest > config.max_call_depth {
            return Err(LysisError::MaxCallDepthExceeded {
                longest,
                max: config.max_call_depth,
            });
        }
    }

    Ok(())
}

fn dfs_longest(
    node: Option<u16>,
    graph: &HashMap<Option<u16>, Vec<(u16, bool)>>,
    stack: &mut HashSet<Option<u16>>,
    max_depth: u32,
) -> Result<u32, LysisError> {
    if stack.contains(&node) {
        return Err(LysisError::CircularTemplateCall {
            template_id: node.unwrap_or(0),
        });
    }
    stack.insert(node);
    let mut best = 0u32;
    if let Some(edges) = graph.get(&node) {
        for &(child, is_tail) in edges {
            // Recurse for cycle detection + deeper-subtree depth, but a
            // tail-eliminated edge does not add a stack frame.
            let sub = dfs_longest(Some(child), graph, stack, max_depth)?;
            let depth = if is_tail { sub } else { sub.saturating_add(1) };
            if depth > best {
                best = depth;
            }
            if best > max_depth {
                // Early bail — we already know we're over the limit.
                stack.remove(&node);
                return Ok(best);
            }
        }
    }
    stack.remove(&node);
    Ok(best)
}
