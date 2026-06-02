use std::sync::Arc;

use achronyme_parser::ast::Expr;
use akron::opcode::OpCode;
use ir_forge::CircomLibraryHandle;
use memory::{CircomHandle, Value};

use crate::codegen::Compiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;

/// Extension trait adding circom-call support to the bytecode
/// compiler. Kept in this module (rather than in `expressions/`)
/// so every circom-related state mutation on the compiler lives in
/// one place.
pub trait CircomVmCallEmitter {
    /// Resolve the inner callee of a `T(...)(...)` / `P.T(...)(...)`
    /// shape to a `(library, template_name)` pair if one of the
    /// compiler's circom import tables contains it. Returns `None`
    /// for any other shape so the normal call dispatch takes over.
    fn try_resolve_circom_vm_call(
        &self,
        inner_callee: &Expr,
    ) -> Option<(Arc<circom::CircomLibrary>, String)>;

    /// Emit a `CallCircomTemplate` opcode sequence for a VM-mode
    /// template call. Handles template-arg const evaluation, signal
    /// input compilation into contiguous registers, handle
    /// interning, and register cleanup.
    fn compile_circom_vm_call(
        &mut self,
        library: Arc<circom::CircomLibrary>,
        template_name: String,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
    ) -> Result<u8, CompilerError>;
}

impl CircomVmCallEmitter for Compiler {
    fn try_resolve_circom_vm_call(
        &self,
        inner_callee: &Expr,
    ) -> Option<(Arc<circom::CircomLibrary>, String)> {
        match inner_callee {
            Expr::Ident { name, .. } => self
                .circom_template_aliases
                .get(name)
                .map(|lib| (lib.clone(), name.clone())),
            // `P::Poseidon(...)` — the compile-time `::` namespace
            // form mirrored here so VM-mode calls match the ProveIR
            // compiler's dispatch. Same fast-path as Ident: look up
            // `type_name` in `circom_namespaces`, check the template
            // actually exists in the library.
            Expr::StaticAccess {
                type_name, member, ..
            } => {
                let lib = self.circom_namespaces.get(type_name)?.clone();
                if lib.template(member).is_some() {
                    Some((lib, member.clone()))
                } else {
                    None
                }
            }
            Expr::DotAccess { object, field, .. } => {
                let Expr::Ident { name: alias, .. } = object.as_ref() else {
                    return None;
                };
                let lib = self.circom_namespaces.get(alias)?.clone();
                // Validate the template actually exists in the
                // library; otherwise let the normal call path
                // produce a proper error.
                if lib.template(field).is_some() {
                    Some((lib, field.clone()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn compile_circom_vm_call(
        &mut self,
        library: Arc<circom::CircomLibrary>,
        template_name: String,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
    ) -> Result<u8, CompilerError> {
        // Look up the template signature to validate arity and
        // discover the declared input-signal count.
        let entry = library.template(&template_name).ok_or_else(|| {
            CompilerError::CompileError(
                format!(
                    "circom library `{}` has no template `{template_name}`",
                    library.source_path.display()
                ),
                self.cur_span(),
            )
        })?;
        let expected_params = entry.params.len();
        let expected_inputs = entry.inputs.len();

        // --- Template args: must be compile-time integer constants ---
        if template_args.len() != expected_params {
            return Err(CompilerError::CompileError(
                format!(
                    "circom template `{template_name}` expects {expected_params} \
                     template parameter(s), got {}",
                    template_args.len()
                ),
                self.cur_span(),
            ));
        }
        let mut template_u64_args: Vec<u64> = Vec::with_capacity(expected_params);
        for (i, arg) in template_args.iter().enumerate() {
            // Accept any ConstExpr, not just Expr::Number. First try
            // the literal path (cheapest), then check the resolver's
            // const_values annotation map.
            let const_val = match arg {
                Expr::Number { value, .. } => value.parse::<i64>().ok(),
                _ => self.resolved_program.as_ref().and_then(|rp| {
                    let module = self.resolver_root_module?;
                    rp.const_values.get(&(module, arg.id())).copied()
                }),
            };
            match const_val {
                Some(v) if v >= 0 => {
                    template_u64_args.push(v as u64);
                }
                _ => {
                    return Err(CompilerError::CompileError(
                        format!(
                            "circom template `{template_name}`: template argument at \
                             position {i} must be a compile-time constant \
                             (e.g. `let n = 8; {template_name}(n)(...)`)"
                        ),
                        self.cur_span(),
                    ));
                }
            }
        }

        // --- Validate signal input count ---
        if signal_inputs.len() != expected_inputs {
            return Err(CompilerError::CompileError(
                format!(
                    "circom template `{template_name}` expects {expected_inputs} \
                     signal input(s), got {}",
                    signal_inputs.len()
                ),
                self.cur_span(),
            ));
        }

        // Expand array signal inputs: for every declared array input
        // the caller must pass an `Expr::Array` literal whose total
        // element count matches the resolved array size. Each element
        // lands in its own register — the runtime handler maps them
        // back to `signal_name_i` keys via the same layout.
        //
        // Resolve the layout here (rather than relying on the raw
        // library entry) so parametric sizes like `inputs[nInputs]`
        // collapse to the concrete value the user passed as template arg.
        let template_const_args: Vec<ir_forge::types::FieldConst> = template_u64_args
            .iter()
            .map(|n| ir_forge::types::FieldConst::from_u64(*n))
            .collect();
        let layouts = <circom::CircomLibrary as CircomLibraryHandle>::resolve_input_layout(
            library.as_ref(),
            &template_name,
            &template_const_args,
        )
        .ok_or_else(|| {
            CompilerError::CompileError(
                format!(
                    "circom template `{template_name}`: could not resolve input signal \
                     dimensions for the given template arguments"
                ),
                self.cur_span(),
            )
        })?;

        // Build a flat list of (expression, owned optional allocation)
        // that compile_expr should evaluate in order. Scalar inputs
        // map 1:1 to the user's expression; array inputs are
        // replaced by their ArrayLit elements in row-major order.
        let mut flat_exprs: Vec<&Expr> = Vec::with_capacity(expected_inputs);
        for (layout, input_expr) in layouts.iter().zip(signal_inputs.iter()) {
            if layout.dims.is_empty() {
                flat_exprs.push(*input_expr);
                continue;
            }
            let expected_len: usize = layout.dims.iter().product::<u64>() as usize;
            let Expr::Array { elements, .. } = *input_expr else {
                return Err(CompilerError::CompileError(
                    format!(
                        "circom template `{template_name}`: signal input `{}` is declared \
                         as an array of size {} but the caller passed a non-array \
                         expression; wrap the inputs in `[...]`",
                        layout.name, expected_len
                    ),
                    self.cur_span(),
                ));
            };
            if elements.len() != expected_len {
                return Err(CompilerError::CompileError(
                    format!(
                        "circom template `{template_name}`: signal input `{}` expects an \
                         array of {} element(s) but the caller passed {}",
                        layout.name,
                        expected_len,
                        elements.len()
                    ),
                    self.cur_span(),
                ));
            }
            for elem in elements {
                flat_exprs.push(elem);
            }
        }

        if flat_exprs.len() > 254 {
            return Err(CompilerError::CompileError(
                format!(
                    "circom template `{template_name}` expands to {} signal input \
                     element(s); VM-mode calls are limited to 254 (register budget)",
                    flat_exprs.len()
                ),
                self.cur_span(),
            ));
        }

        // --- Register the library and build the handle descriptor ---
        let library_id = self.register_circom_library(library);
        let handle = CircomHandle {
            library_id,
            template_name: template_name.clone(),
            template_args: template_u64_args,
        };
        let handle_idx = self.intern_circom_handle(handle);
        let handle_const_val = Value::circom_handle(handle_idx);
        let const_idx = self.add_constant(handle_const_val)?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }

        // --- Emit the register sequence ---
        //
        // Layout (same convention MethodCall uses for its name slot):
        //   handle_reg = R[top]       ← LoadConst handle_const
        //   R[handle_reg + 1 .. + N]  ← each signal input expression
        //   CallCircomTemplate A=handle_reg, B=handle_reg+1, C=N
        //
        // Reusing `handle_reg` as the destination A matches the rest
        // of the compiler's "first allocated register becomes the
        // result register" convention (see compile_method_call).
        let handle_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadConst, handle_reg, const_idx as u16)?;

        // Compile every signal input in sequence. compile_expr
        // allocates at `reg_top`, which has already advanced past
        // `handle_reg`, so the first input lands at handle_reg + 1,
        // second at handle_reg + 2, etc. `flat_exprs` already expanded
        // any array-valued inputs into their individual elements.
        let first_input_reg = handle_reg + 1;
        for (i, input) in flat_exprs.iter().enumerate() {
            let landed = self.compile_expr(input)?;
            debug_assert_eq!(
                landed as usize,
                first_input_reg as usize + i,
                "circom input {i} landed in r{landed}, expected r{}",
                first_input_reg as usize + i
            );
        }

        let input_count = flat_exprs.len() as u8;
        self.emit_abc(
            OpCode::CallCircomTemplate,
            handle_reg,
            first_input_reg,
            input_count,
        )?;

        // Free the input registers; the dest is handle_reg which
        // becomes the result register returned to the caller.
        for _ in 0..input_count {
            let top = self.current()?.reg_top - 1;
            self.free_reg(top)?;
        }

        Ok(handle_reg)
    }
}
