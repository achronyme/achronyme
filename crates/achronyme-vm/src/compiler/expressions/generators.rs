//! Generator compilation

use crate::bytecode::FunctionPrototype;
use crate::compiler::registers::{RegResult, RegisterAllocator};
use crate::compiler::symbols::SymbolTable;
use crate::compiler::Compiler;
use crate::error::CompileError;
use crate::opcode::{instruction::*, OpCode};
use achronyme_parser::ast::AstNode;

impl Compiler {
    /// Compile a generate block
    ///
    /// Generates bytecode that creates a generator object:
    /// ```
    /// let gen = generate {
    ///     yield 1
    ///     yield 2
    /// }
    /// ```
    ///
    /// Compiles to:
    /// ```
    /// CREATE_GEN R[dst], proto_idx
    /// ```
    pub(crate) fn compile_generate_block(
        &mut self,
        statements: &[AstNode],
    ) -> Result<RegResult, CompileError> {
        // Create a nested function prototype for the generator
        let gen_name = format!("<generator@{}>", self.current_position());
        let mut child_compiler = Compiler {
            module_name: self.module_name.clone(), // Inherit module name from parent
            function: FunctionPrototype::new(gen_name, self.function.constants.clone()),
            registers: RegisterAllocator::new(),
            symbols: SymbolTable::new(),
            loops: Vec::new(),
            parent: None,
            builtins: self.builtins.clone(),
            type_registry: self.type_registry.clone(), // Share the type registry
            exported_values: std::collections::HashMap::new(),
            exported_types: std::collections::HashMap::new(),
            exports_reg: None, // Generators don't have exports
        };

        // Mark the function as a generator
        child_compiler.function.is_generator = true;

        // Analyze upvalues by finding variables used but not defined in generator
        let mut used_vars = std::collections::HashSet::new();
        for stmt in statements {
            self.collect_variable_refs(stmt, &mut used_vars)?;
        }

        let mut upvalues = Vec::new();
        for var in used_vars {
            if !child_compiler.symbols.has(&var) {
                // This variable is captured from parent scope
                if let Ok(parent_reg) = self.symbols.get(&var) {
                    let upvalue_idx = upvalues.len();
                    if upvalue_idx >= 256 {
                        return Err(CompileError::TooManyUpvalues);
                    }

                    upvalues.push(crate::bytecode::UpvalueDescriptor {
                        depth: 0, // Immediate parent
                        register: parent_reg,
                        is_mutable: true, // Assume mutable for now
                    });

                    // Map variable to upvalue in child's symbol table
                    child_compiler
                        .symbols
                        .define_upvalue(var.clone(), upvalue_idx as u8)?;
                }
            }
        }

        child_compiler.function.upvalues = upvalues;

        // Compile generator body
        for stmt in statements {
            child_compiler.compile_statement(stmt)?;
        }

        // If the generator doesn't end with an explicit return, add ReturnNull
        child_compiler.emit(encode_abc(OpCode::ReturnNull.as_u8(), 0, 0, 0));

        // Set register count
        child_compiler.function.register_count = child_compiler.registers.max_used();

        // Add to current function's nested functions list
        let func_idx = self.function.functions.len();
        self.function.functions.push(child_compiler.function);

        // Emit CREATE_GEN instruction
        let dst = self.registers.allocate()?;
        self.emit(encode_abx(OpCode::CreateGen.as_u8(), dst, func_idx as u16));

        Ok(RegResult::temp(dst))
    }

    /// Compile a yield statement
    ///
    /// ```
    /// yield value
    /// ```
    ///
    /// Compiles to:
    /// ```
    /// R[temp] = value
    /// YIELD R[temp]
    /// ```
    pub(crate) fn compile_yield(&mut self, value: &AstNode) -> Result<(), CompileError> {
        // Compile the value to yield
        let value_res = self.compile_expression(value)?;

        // Emit YIELD instruction
        self.emit(encode_abc(OpCode::Yield.as_u8(), value_res.reg(), 0, 0));

        // Free the value register if temporary
        if value_res.is_temp() {
            self.registers.free(value_res.reg());
        }

        Ok(())
    }

    /// Compile a yield expression (returns the yielded value)
    ///
    /// When yield is used as an expression, it yields the value and returns it.
    /// This allows patterns like: `let x = yield value`
    pub(crate) fn compile_yield_expr(
        &mut self,
        value: &AstNode,
    ) -> Result<RegResult, CompileError> {
        // Compile the value to yield
        let value_res = self.compile_expression(value)?;

        // Allocate a register for the result (same as yielded value)
        let result_reg = if value_res.is_temp() {
            // Reuse the temporary register
            value_res.reg()
        } else {
            // Allocate new register and copy
            let reg = self.registers.allocate()?;
            self.emit_move(reg, value_res.reg());
            reg
        };

        // Emit YIELD instruction
        self.emit(encode_abc(OpCode::Yield.as_u8(), result_reg, 0, 0));

        // Return the result (yield returns null in most implementations)
        // But we return the yielded value for consistency
        Ok(RegResult::temp(result_reg))
    }
}
