//! `Display` impls for ProveIR types — human-readable dump of a template.
//!
//! Separated from the data-type definitions so the structs and enums stay
//! declarative. The entry point is `Display for ProveIR`, which delegates
//! body rendering to the private `write_node` helper.

use std::fmt;

use super::{
    ArraySize, CaptureUsage, CircuitBinOp, CircuitBoolOp, CircuitCmpOp, CircuitExpr, CircuitNode,
    CircuitUnaryOp, ForRange, ProveIR,
};

impl fmt::Display for ProveIR {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Captures
        if !self.captures.is_empty() {
            writeln!(f, "  Captures:")?;
            for cap in &self.captures {
                let usage = match cap.usage {
                    CaptureUsage::StructureOnly => "structure",
                    CaptureUsage::CircuitInput => "witness",
                    CaptureUsage::Both => "witness+structure",
                };
                writeln!(f, "    {:<20} ({})", cap.name, usage)?;
            }
        }
        if !self.capture_arrays.is_empty() {
            for arr in &self.capture_arrays {
                writeln!(f, "    {:<20} (array, len={})", arr.name, arr.size)?;
            }
        }

        // Inputs
        if !self.public_inputs.is_empty() {
            writeln!(f, "  Public inputs:")?;
            for inp in &self.public_inputs {
                write!(f, "    {}: {}", inp.name, inp.ir_type)?;
                if let Some(ref sz) = inp.array_size {
                    write!(f, "[{}]", sz)?;
                }
                writeln!(f)?;
            }
        }
        if !self.witness_inputs.is_empty() {
            writeln!(f, "  Witness inputs:")?;
            for inp in &self.witness_inputs {
                write!(f, "    {}: {}", inp.name, inp.ir_type)?;
                if let Some(ref sz) = inp.array_size {
                    write!(f, "[{}]", sz)?;
                }
                writeln!(f)?;
            }
        }

        // Body
        if !self.body.is_empty() {
            writeln!(f, "  Body:")?;
            for node in &self.body {
                write_node(f, node, 2)?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for ArraySize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArraySize::Literal(n) => write!(f, "{n}"),
            ArraySize::Capture(name) => write!(f, "{name}"),
        }
    }
}

fn write_node(f: &mut fmt::Formatter<'_>, node: &CircuitNode, indent: usize) -> fmt::Result {
    let pad = "    ".repeat(indent);
    match node {
        CircuitNode::Let { name, value, .. } => {
            writeln!(f, "{pad}let {name} = {value}")
        }
        CircuitNode::LetArray { name, elements, .. } => {
            write!(f, "{pad}let {name} = [")?;
            for (i, e) in elements.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{e}")?;
            }
            writeln!(f, "]")
        }
        CircuitNode::AssertEq {
            lhs, rhs, message, ..
        } => {
            write!(f, "{pad}assert_eq({lhs}, {rhs}")?;
            if let Some(msg) = message {
                write!(f, ", \"{msg}\"")?;
            }
            writeln!(f, ")")
        }
        CircuitNode::Assert { expr, message, .. } => {
            write!(f, "{pad}assert({expr}")?;
            if let Some(msg) = message {
                write!(f, ", \"{msg}\"")?;
            }
            writeln!(f, ")")
        }
        CircuitNode::For {
            var, range, body, ..
        } => {
            write!(f, "{pad}for {var} in ")?;
            match range {
                ForRange::Literal { start, end } => writeln!(f, "{start}..{end} {{")?,
                ForRange::WithCapture { start, end_capture } => {
                    writeln!(f, "{start}..{end_capture} {{")?
                }
                ForRange::WithExpr { start, end_expr } => {
                    writeln!(f, "{start}..({end_expr:?}) {{")?
                }
                ForRange::Array(name) => writeln!(f, "{name} {{")?,
            }
            for n in body {
                write_node(f, n, indent + 1)?;
            }
            writeln!(f, "{pad}}}")
        }
        CircuitNode::If {
            cond,
            then_body,
            else_body,
            ..
        } => {
            writeln!(f, "{pad}if {cond} {{")?;
            for n in then_body {
                write_node(f, n, indent + 1)?;
            }
            if !else_body.is_empty() {
                writeln!(f, "{pad}}} else {{")?;
                for n in else_body {
                    write_node(f, n, indent + 1)?;
                }
            }
            writeln!(f, "{pad}}}")
        }
        CircuitNode::Expr { expr, .. } => {
            writeln!(f, "{pad}{expr}")
        }
        CircuitNode::Decompose {
            name,
            value,
            num_bits,
            ..
        } => {
            writeln!(f, "{pad}let {name} = decompose({value}, {num_bits})")
        }
        CircuitNode::WitnessHint { name, hint, .. } => {
            writeln!(f, "{pad}{name} <-- {hint}")
        }
        CircuitNode::WitnessArrayDecl { name, size, .. } => {
            writeln!(f, "{pad}signal {name}[{size}]")
        }
        CircuitNode::LetIndexed {
            array,
            index,
            value,
            ..
        } => {
            writeln!(f, "{pad}let {array}[{index}] = {value}")
        }
        CircuitNode::WitnessHintIndexed {
            array, index, hint, ..
        } => {
            writeln!(f, "{pad}{array}[{index}] <-- {hint}")
        }
        CircuitNode::WitnessCall {
            output_bindings,
            input_signals,
            program_bytes,
            ..
        } => {
            // Disassembly is intentionally opaque — the payload is
            // Artik bytecode and is expected to be meaningful only to
            // the witness executor. Show a one-liner summary instead.
            write!(f, "{pad}(")?;
            for (i, name) in output_bindings.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{name}")?;
            }
            write!(f, ") <-- artik_call(")?;
            for (i, sig) in input_signals.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{sig}")?;
            }
            writeln!(f, ") [{} bytes]", program_bytes.len())
        }
    }
}

impl fmt::Display for CircuitExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitExpr::Const(fe) => write!(f, "{fe:?}"),
            CircuitExpr::Input(name) => write!(f, "{name}"),
            CircuitExpr::Capture(name) => write!(f, "${name}"),
            CircuitExpr::Var(name) => write!(f, "{name}"),
            CircuitExpr::LoopVar(token) => write!(f, "%loop_var_{token}"),
            CircuitExpr::BinOp { op, lhs, rhs } => {
                write!(f, "({lhs} {op} {rhs})")
            }
            CircuitExpr::UnaryOp { op, operand } => {
                write!(f, "{op}{operand}")
            }
            CircuitExpr::Comparison { op, lhs, rhs } => {
                write!(f, "({lhs} {op} {rhs})")
            }
            CircuitExpr::BoolOp { op, lhs, rhs } => {
                write!(f, "({lhs} {op} {rhs})")
            }
            CircuitExpr::Mux {
                cond,
                if_true,
                if_false,
            } => write!(f, "mux({cond}, {if_true}, {if_false})"),
            CircuitExpr::PoseidonHash { left, right } => {
                write!(f, "poseidon({left}, {right})")
            }
            CircuitExpr::PoseidonMany(args) => {
                write!(f, "poseidon(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            CircuitExpr::RangeCheck { value, bits } => {
                write!(f, "range_check({value}, {bits})")
            }
            CircuitExpr::MerkleVerify {
                root,
                leaf,
                path,
                indices,
            } => write!(f, "merkle_verify({root}, {leaf}, {path}, {indices})"),
            CircuitExpr::ArrayIndex { array, index } => write!(f, "{array}[{index}]"),
            CircuitExpr::ArrayLen(name) => write!(f, "{name}.len()"),
            CircuitExpr::Pow { base, exp } => write!(f, "({base} ^ {exp})"),
            CircuitExpr::IntDiv { lhs, rhs, max_bits } => {
                write!(f, "int_div({lhs}, {rhs}, {max_bits})")
            }
            CircuitExpr::IntMod { lhs, rhs, max_bits } => {
                write!(f, "int_mod({lhs}, {rhs}, {max_bits})")
            }
            CircuitExpr::BitAnd { lhs, rhs, .. } => write!(f, "({lhs} & {rhs})"),
            CircuitExpr::BitOr { lhs, rhs, .. } => write!(f, "({lhs} | {rhs})"),
            CircuitExpr::BitXor { lhs, rhs, .. } => write!(f, "({lhs} ^ {rhs})"),
            CircuitExpr::BitNot { operand, .. } => write!(f, "~{operand}"),
            CircuitExpr::ShiftR { operand, shift, .. } => write!(f, "({operand} >> {shift})"),
            CircuitExpr::ShiftL { operand, shift, .. } => write!(f, "({operand} << {shift})"),
        }
    }
}

impl fmt::Display for CircuitBinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBinOp::Add => write!(f, "+"),
            CircuitBinOp::Sub => write!(f, "-"),
            CircuitBinOp::Mul => write!(f, "*"),
            CircuitBinOp::Div => write!(f, "/"),
        }
    }
}

impl fmt::Display for CircuitUnaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitUnaryOp::Neg => write!(f, "-"),
            CircuitUnaryOp::Not => write!(f, "!"),
        }
    }
}

impl fmt::Display for CircuitCmpOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitCmpOp::Eq => write!(f, "=="),
            CircuitCmpOp::Neq => write!(f, "!="),
            CircuitCmpOp::Lt => write!(f, "<"),
            CircuitCmpOp::Le => write!(f, "<="),
            CircuitCmpOp::Gt => write!(f, ">"),
            CircuitCmpOp::Ge => write!(f, ">="),
        }
    }
}

impl fmt::Display for CircuitBoolOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitBoolOp::And => write!(f, "&&"),
            CircuitBoolOp::Or => write!(f, "||"),
        }
    }
}
