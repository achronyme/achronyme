//! Compiled form of a ProveIR body for the witness-hints walk.
//!
//! The walk's reference interpreter expands every `ComponentCall` by
//! cloning and name-mangling the shared body (`mangle_nodes`), then
//! re-resolves every name through a `String`-keyed env. At circuit
//! scale that re-materializes the same few dozen shared bodies tens of
//! thousands of times. A [`HintTemplate`] is compiled ONCE per distinct
//! body: every static name becomes a [`NameId`] into a per-template
//! name table, every expression an [`ExprId`] into an arena, and the
//! replay (see [`super::replay`]) resolves each name to a value slot
//! once per instance instead of once per access.
//!
//! Compilation is a pure structural pass — no evaluation, no env. The
//! matches over `CircuitNode` / `CircuitExpr` are exhaustive on
//! purpose: a new variant must be classified here (and in the
//! reference interpreter) before the crate compiles again.

use std::collections::HashMap;

use ir_forge::types::{
    CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitNode, CircuitUnaryOp,
    FieldConst, ForRange,
};

/// Index into [`HintTemplate::names`] — a body-local, unmangled name.
pub(super) type NameId = u32;

/// Index into [`HintTemplate::exprs`].
pub(super) type ExprId = u32;

/// One compiled body: shared, instance-independent.
pub(super) struct HintTemplate {
    /// Body-local names (signal/var/array/capture identifiers) exactly
    /// as they appear in the nodes, deduplicated.
    pub names: Vec<String>,
    /// Expression arena. Children always precede parents.
    pub exprs: Vec<TExpr>,
    /// Statement ops in body order.
    pub ops: Vec<TOp>,
}

/// Compiled statement. Mirrors the hint-relevant `CircuitNode` arms;
/// the four walk no-ops (`AssertEq`, `Expr`, `Decompose`,
/// `WitnessArrayDecl`) compile to nothing.
pub(super) enum TOp {
    Let {
        name: NameId,
        value: ExprId,
    },
    LetArray {
        name: NameId,
        elements: Vec<ExprId>,
    },
    Assert {
        expr: ExprId,
        message: Option<String>,
    },
    For {
        var: NameId,
        range: TRange,
        body: Vec<TOp>,
    },
    If {
        cond: ExprId,
        then_body: Vec<TOp>,
        else_body: Vec<TOp>,
    },
    WitnessHint {
        name: NameId,
        hint: ExprId,
    },
    LetIndexed {
        array: NameId,
        index: ExprId,
        value: ExprId,
    },
    WitnessHintIndexed {
        array: NameId,
        index: ExprId,
        hint: ExprId,
    },
    WitnessCall {
        output_bindings: Vec<NameId>,
        input_signals: Vec<ExprId>,
        program_bytes: Vec<u8>,
    },
    ComponentCall {
        body_key: String,
        comp_name: NameId,
        param_subs: Vec<(String, ExprId)>,
    },
}

/// Compiled for-loop range. The reference walk sees ranges AFTER
/// `mangle_range` substituted the instance's params; here the range
/// stays symbolic and the replay performs the same substitution
/// branch per instance.
pub(super) enum TRange {
    Literal { start: u64, end: u64 },
    WithCapture { start: u64, cap: NameId },
    WithExpr { start: u64, expr: ExprId },
    Array,
}

/// Compiled expression. Mirrors `eval_hint`'s arms; the five
/// off-circuit-unevaluable constructs (`PoseidonHash`, `PoseidonMany`,
/// `RangeCheck`, `MerkleVerify`, `ArrayLen`) and the `LoopVar`
/// placeholder fold to [`TExpr::Unevaluable`].
pub(super) enum TExpr {
    Const(FieldConst),
    /// `Input` / `Var` leaf — resolves to the instance-qualified slot.
    Name(NameId),
    /// `Capture` leaf — resolves through the instance's param
    /// substitutions first, then like a qualified name.
    Capture(NameId),
    BinOp {
        op: CircuitBinOp,
        lhs: ExprId,
        rhs: ExprId,
    },
    UnaryOp {
        op: CircuitUnaryOp,
        operand: ExprId,
    },
    Comparison {
        op: CircuitCmpOp,
        lhs: ExprId,
        rhs: ExprId,
    },
    BoolOp {
        op: CircuitBoolOp,
        lhs: ExprId,
        rhs: ExprId,
    },
    Mux {
        cond: ExprId,
        if_true: ExprId,
        if_false: ExprId,
    },
    Pow {
        base: ExprId,
        exp: u64,
    },
    IntDiv {
        lhs: ExprId,
        rhs: ExprId,
    },
    IntMod {
        lhs: ExprId,
        rhs: ExprId,
    },
    BitAnd {
        lhs: ExprId,
        rhs: ExprId,
    },
    BitOr {
        lhs: ExprId,
        rhs: ExprId,
    },
    BitXor {
        lhs: ExprId,
        rhs: ExprId,
    },
    BitNot {
        operand: ExprId,
        num_bits: u32,
    },
    ShiftR {
        operand: ExprId,
        shift: ExprId,
    },
    ShiftL {
        operand: ExprId,
        shift: ExprId,
    },
    ArrayIndex {
        array: NameId,
        index: ExprId,
    },
    Unevaluable,
}

/// Compile one body into a [`HintTemplate`].
pub(super) fn compile_body(nodes: &[CircuitNode]) -> HintTemplate {
    let mut c = Compiler {
        names: Vec::new(),
        name_ids: HashMap::new(),
        exprs: Vec::new(),
    };
    let ops = c.compile_nodes(nodes);
    HintTemplate {
        names: c.names,
        exprs: c.exprs,
        ops,
    }
}

struct Compiler {
    names: Vec<String>,
    name_ids: HashMap<String, NameId>,
    exprs: Vec<TExpr>,
}

impl Compiler {
    fn name(&mut self, name: &str) -> NameId {
        if let Some(&id) = self.name_ids.get(name) {
            return id;
        }
        let id = self.names.len() as NameId;
        self.names.push(name.to_string());
        self.name_ids.insert(name.to_string(), id);
        id
    }

    fn push(&mut self, e: TExpr) -> ExprId {
        let id = self.exprs.len() as ExprId;
        self.exprs.push(e);
        id
    }

    fn compile_nodes(&mut self, nodes: &[CircuitNode]) -> Vec<TOp> {
        let mut ops = Vec::new();
        for node in nodes {
            match node {
                CircuitNode::Let { name, value, .. } => {
                    let op = TOp::Let {
                        name: self.name(name),
                        value: self.expr(value),
                    };
                    ops.push(op);
                }
                CircuitNode::LetArray { name, elements, .. } => {
                    let op = TOp::LetArray {
                        name: self.name(name),
                        elements: elements.iter().map(|e| self.expr(e)).collect(),
                    };
                    ops.push(op);
                }
                CircuitNode::Assert { expr, message, .. } => {
                    let op = TOp::Assert {
                        expr: self.expr(expr),
                        message: message.clone(),
                    };
                    ops.push(op);
                }
                CircuitNode::For {
                    var, range, body, ..
                } => {
                    let op = TOp::For {
                        var: self.name(var),
                        range: self.range(range),
                        body: self.compile_nodes(body),
                    };
                    ops.push(op);
                }
                CircuitNode::If {
                    cond,
                    then_body,
                    else_body,
                    ..
                } => {
                    let op = TOp::If {
                        cond: self.expr(cond),
                        then_body: self.compile_nodes(then_body),
                        else_body: self.compile_nodes(else_body),
                    };
                    ops.push(op);
                }
                CircuitNode::WitnessHint { name, hint, .. } => {
                    let op = TOp::WitnessHint {
                        name: self.name(name),
                        hint: self.expr(hint),
                    };
                    ops.push(op);
                }
                CircuitNode::LetIndexed {
                    array,
                    index,
                    value,
                    ..
                } => {
                    let op = TOp::LetIndexed {
                        array: self.name(array),
                        index: self.expr(index),
                        value: self.expr(value),
                    };
                    ops.push(op);
                }
                CircuitNode::WitnessHintIndexed {
                    array, index, hint, ..
                } => {
                    let op = TOp::WitnessHintIndexed {
                        array: self.name(array),
                        index: self.expr(index),
                        hint: self.expr(hint),
                    };
                    ops.push(op);
                }
                CircuitNode::WitnessCall {
                    output_bindings,
                    input_signals,
                    program_bytes,
                    ..
                } => {
                    let op = TOp::WitnessCall {
                        output_bindings: output_bindings.iter().map(|n| self.name(n)).collect(),
                        input_signals: input_signals.iter().map(|e| self.expr(e)).collect(),
                        program_bytes: program_bytes.clone(),
                    };
                    ops.push(op);
                }
                CircuitNode::ComponentCall {
                    body_key,
                    comp_name,
                    param_subs,
                    ..
                } => {
                    let op = TOp::ComponentCall {
                        body_key: body_key.clone(),
                        comp_name: self.name(comp_name),
                        param_subs: param_subs
                            .iter()
                            .map(|(k, v)| (k.clone(), self.expr(v)))
                            .collect(),
                    };
                    ops.push(op);
                }
                // Constraint-only / declaration nodes: the walk reads
                // no hint values from them.
                CircuitNode::AssertEq { .. }
                | CircuitNode::Expr { .. }
                | CircuitNode::Decompose { .. }
                | CircuitNode::WitnessArrayDecl { .. } => {}
            }
        }
        ops
    }

    fn range(&mut self, range: &ForRange) -> TRange {
        match range {
            ForRange::Literal { start, end } => TRange::Literal {
                start: *start,
                end: *end,
            },
            ForRange::WithCapture { start, end_capture } => TRange::WithCapture {
                start: *start,
                cap: self.name(end_capture),
            },
            ForRange::WithExpr { start, end_expr } => TRange::WithExpr {
                start: *start,
                expr: self.expr(end_expr),
            },
            ForRange::Array(_) => TRange::Array,
        }
    }

    fn expr(&mut self, expr: &CircuitExpr) -> ExprId {
        let compiled = match expr {
            CircuitExpr::Const(fc) => TExpr::Const(*fc),
            // The R1'' loop placeholder must not survive lowering; the
            // evaluator treats a stray one as unevaluable, same as the
            // reference interpreter.
            CircuitExpr::LoopVar(_) => TExpr::Unevaluable,
            CircuitExpr::Input(name) | CircuitExpr::Var(name) => {
                let id = self.name(name);
                TExpr::Name(id)
            }
            CircuitExpr::Capture(name) => {
                let id = self.name(name);
                TExpr::Capture(id)
            }
            CircuitExpr::BinOp { op, lhs, rhs } => TExpr::BinOp {
                op: *op,
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::UnaryOp { op, operand } => TExpr::UnaryOp {
                op: *op,
                operand: self.expr(operand),
            },
            CircuitExpr::Comparison { op, lhs, rhs } => TExpr::Comparison {
                op: *op,
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::BoolOp { op, lhs, rhs } => TExpr::BoolOp {
                op: *op,
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => TExpr::Mux {
                cond: self.expr(cond),
                if_true: self.expr(if_true),
                if_false: self.expr(if_false),
            },
            CircuitExpr::Pow { base, exp } => TExpr::Pow {
                base: self.expr(base),
                exp: *exp,
            },
            CircuitExpr::IntDiv { lhs, rhs, .. } => TExpr::IntDiv {
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::IntMod { lhs, rhs, .. } => TExpr::IntMod {
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::BitAnd { lhs, rhs, .. } => TExpr::BitAnd {
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::BitOr { lhs, rhs, .. } => TExpr::BitOr {
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::BitXor { lhs, rhs, .. } => TExpr::BitXor {
                lhs: self.expr(lhs),
                rhs: self.expr(rhs),
            },
            CircuitExpr::BitNot { operand, num_bits } => TExpr::BitNot {
                operand: self.expr(operand),
                num_bits: *num_bits,
            },
            CircuitExpr::ShiftR { operand, shift, .. } => TExpr::ShiftR {
                operand: self.expr(operand),
                shift: self.expr(shift),
            },
            CircuitExpr::ShiftL { operand, shift, .. } => TExpr::ShiftL {
                operand: self.expr(operand),
                shift: self.expr(shift),
            },
            CircuitExpr::ArrayIndex { array, index } => TExpr::ArrayIndex {
                array: self.name(array),
                index: self.expr(index),
            },
            // Off-circuit-unevaluable constructs: the reference
            // interpreter returns None for these.
            CircuitExpr::PoseidonHash { .. }
            | CircuitExpr::PoseidonMany(_)
            | CircuitExpr::RangeCheck { .. }
            | CircuitExpr::MerkleVerify { .. }
            | CircuitExpr::ArrayLen(_) => TExpr::Unevaluable,
        };
        self.push(compiled)
    }
}
