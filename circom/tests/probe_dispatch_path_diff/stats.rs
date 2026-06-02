use ir_forge::types::{CircuitNode, ForRange};
use ir_forge::ExtendedInstruction;
use memory::Bn254Fr;

// ---------------------------------------------------------------------------
// CircuitNode stats helper
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct CircuitNodeStats {
    pub(super) total: usize,
    pub(super) n_let: usize,
    pub(super) n_let_array: usize,
    pub(super) n_let_indexed: usize,
    pub(super) n_assert_eq: usize,
    pub(super) n_assert: usize,
    pub(super) n_for: usize,
    pub(super) n_if: usize,
    pub(super) n_expr: usize,
    pub(super) n_decompose: usize,
    pub(super) n_witness_hint: usize,
    pub(super) n_witness_hint_indexed: usize,
    pub(super) n_witness_array_decl: usize,
    pub(super) n_witness_call: usize,
    pub(super) n_component_call: usize,
    /// (name, num_bits) for any Decompose >= 100 bits.
    pub(super) wide_decomposes: Vec<(String, u32)>,
    /// (label, body_len, range_repr) for top-level For nodes.
    pub(super) for_summary: Vec<(String, usize, String)>,
}

impl CircuitNodeStats {
    pub(super) fn print(&self, label: &str) {
        eprintln!("  [{label}] CircuitNode total: {}", self.total);
        eprintln!("    Let               : {}", self.n_let);
        eprintln!("    LetArray          : {}", self.n_let_array);
        eprintln!("    LetIndexed        : {}", self.n_let_indexed);
        eprintln!("    AssertEq          : {}", self.n_assert_eq);
        eprintln!("    Assert            : {}", self.n_assert);
        eprintln!("    For               : {}", self.n_for);
        eprintln!("    If                : {}", self.n_if);
        eprintln!("    Expr              : {}", self.n_expr);
        eprintln!("    Decompose         : {}", self.n_decompose);
        eprintln!("    WitnessHint       : {}", self.n_witness_hint);
        eprintln!("    WitnessHintIndexed: {}", self.n_witness_hint_indexed);
        eprintln!("    WitnessArrayDecl  : {}", self.n_witness_array_decl);
        eprintln!("    WitnessCall       : {}", self.n_witness_call);
        eprintln!("    ComponentCall     : {}", self.n_component_call);
        if !self.wide_decomposes.is_empty() {
            eprintln!("    Wide Decompose (>= 100 bits):");
            for (name, n) in &self.wide_decomposes {
                eprintln!("      {name} num_bits={n}");
            }
        }
        if !self.for_summary.is_empty() {
            eprintln!("    For nodes (top-level body):");
            for (label, body_len, range) in &self.for_summary {
                eprintln!("      {label}: body.len={body_len} range={range}");
            }
        }
    }
}

pub(super) fn collect_circuit_node_stats(body: &[CircuitNode]) -> CircuitNodeStats {
    let mut s = CircuitNodeStats::default();
    walk_nodes(body, "", &mut s);
    s
}

fn walk_nodes(body: &[CircuitNode], path: &str, s: &mut CircuitNodeStats) {
    for (i, node) in body.iter().enumerate() {
        s.total += 1;
        match node {
            CircuitNode::Let { .. } => s.n_let += 1,
            CircuitNode::LetArray { .. } => s.n_let_array += 1,
            CircuitNode::LetIndexed { .. } => s.n_let_indexed += 1,
            CircuitNode::AssertEq { .. } => s.n_assert_eq += 1,
            CircuitNode::Assert { .. } => s.n_assert += 1,
            CircuitNode::For {
                var,
                range,
                body: inner,
                ..
            } => {
                s.n_for += 1;
                let label = if path.is_empty() {
                    format!("[{i}] var={var}")
                } else {
                    format!("{path}.[{i}] var={var}")
                };
                s.for_summary
                    .push((label.clone(), inner.len(), format_range(range)));
                walk_nodes(inner, &label, s);
            }
            CircuitNode::If {
                then_body,
                else_body,
                ..
            } => {
                s.n_if += 1;
                let then_path = if path.is_empty() {
                    format!("[{i}].then")
                } else {
                    format!("{path}.[{i}].then")
                };
                let else_path = if path.is_empty() {
                    format!("[{i}].else")
                } else {
                    format!("{path}.[{i}].else")
                };
                walk_nodes(then_body, &then_path, s);
                walk_nodes(else_body, &else_path, s);
            }
            CircuitNode::Expr { .. } => s.n_expr += 1,
            CircuitNode::Decompose { name, num_bits, .. } => {
                s.n_decompose += 1;
                if *num_bits >= 100 {
                    s.wide_decomposes.push((name.clone(), *num_bits));
                }
            }
            CircuitNode::WitnessHint { .. } => s.n_witness_hint += 1,
            CircuitNode::WitnessHintIndexed { .. } => s.n_witness_hint_indexed += 1,
            CircuitNode::WitnessArrayDecl { .. } => s.n_witness_array_decl += 1,
            CircuitNode::WitnessCall { .. } => s.n_witness_call += 1,
            CircuitNode::ComponentCall { .. } => s.n_component_call += 1,
        }
    }
}

fn format_range(r: &ForRange) -> String {
    match r {
        ForRange::Literal { start, end } => format!("{start}..{end}"),
        ForRange::WithCapture { start, end_capture } => format!("{start}..{end_capture}"),
        ForRange::WithExpr { start, .. } => format!("{start}..<expr>"),
        ForRange::Array(name) => format!("over Array({name})"),
    }
}

// ---------------------------------------------------------------------------
// ExtendedInstruction stats helper
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct ExtendedStats {
    pub(super) total: usize,
    pub(super) n_plain: usize,
    pub(super) n_template_body: usize,
    pub(super) n_template_call: usize,
    pub(super) n_loop_unroll: usize,
    pub(super) n_sym_indexed_effect: usize,
    pub(super) n_sym_array_read: usize,
    pub(super) n_sym_shift: usize,
    /// Largest `body.len()` seen across any `LoopUnroll` (top + nested).
    pub(super) max_loop_body_len: usize,
    /// Longest run of consecutive `Plain` ops at the top level.
    pub(super) max_plain_run_top: usize,
    /// Per-LoopUnroll summary at the top level: (start..end, body_len).
    pub(super) top_loops: Vec<(i64, i64, usize)>,
}

impl ExtendedStats {
    pub(super) fn print(&self, label: &str) {
        eprintln!("  [{label}] ExtendedInstruction total: {}", self.total);
        eprintln!("    Plain                 : {}", self.n_plain);
        eprintln!("    TemplateBody          : {}", self.n_template_body);
        eprintln!("    TemplateCall          : {}", self.n_template_call);
        eprintln!("    LoopUnroll            : {}", self.n_loop_unroll);
        eprintln!("    SymbolicIndexedEffect : {}", self.n_sym_indexed_effect);
        eprintln!("    SymbolicArrayRead     : {}", self.n_sym_array_read);
        eprintln!("    SymbolicShift         : {}", self.n_sym_shift);
        eprintln!("    Max LoopUnroll body   : {}", self.max_loop_body_len);
        eprintln!("    Max top-level Plain run: {}", self.max_plain_run_top);
        if !self.top_loops.is_empty() {
            eprintln!("    Top-level LoopUnroll summary:");
            for (start, end, len) in &self.top_loops {
                eprintln!("      {start}..{end} body.len={len}");
            }
        }
    }
}

pub(super) fn collect_extended_stats(body: &[ExtendedInstruction<Bn254Fr>]) -> ExtendedStats {
    let mut s = ExtendedStats::default();
    walk_extended(body, true, &mut s);
    s
}

fn walk_extended(body: &[ExtendedInstruction<Bn254Fr>], top_level: bool, s: &mut ExtendedStats) {
    let mut current_plain_run: usize = 0;
    for inst in body {
        s.total += 1;
        match inst {
            ExtendedInstruction::Plain(_) => {
                s.n_plain += 1;
                if top_level {
                    current_plain_run += 1;
                    if current_plain_run > s.max_plain_run_top {
                        s.max_plain_run_top = current_plain_run;
                    }
                }
            }
            other => {
                if top_level {
                    current_plain_run = 0;
                }
                match other {
                    ExtendedInstruction::TemplateBody { body, .. } => {
                        s.n_template_body += 1;
                        walk_extended(body, false, s);
                    }
                    ExtendedInstruction::TemplateCall { .. } => s.n_template_call += 1,
                    ExtendedInstruction::LoopUnroll {
                        start, end, body, ..
                    } => {
                        s.n_loop_unroll += 1;
                        if body.len() > s.max_loop_body_len {
                            s.max_loop_body_len = body.len();
                        }
                        if top_level {
                            s.top_loops.push((*start, *end, body.len()));
                        }
                        walk_extended(body, false, s);
                    }
                    ExtendedInstruction::SymbolicIndexedEffect { .. } => {
                        s.n_sym_indexed_effect += 1;
                    }
                    ExtendedInstruction::SymbolicArrayRead { .. } => s.n_sym_array_read += 1,
                    ExtendedInstruction::SymbolicShift { .. } => s.n_sym_shift += 1,
                    ExtendedInstruction::Plain(_) => unreachable!(),
                }
            }
        }
    }
}
