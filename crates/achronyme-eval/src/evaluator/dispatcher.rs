use achronyme_parser::ast::AstNode;
use achronyme_types::value::Value;
use crate::handlers;

use super::Evaluator;

/// Main evaluation dispatcher
impl Evaluator {
    /// Evaluate a SOC expression string using the Pest parser
    ///
    /// This is the recommended way to evaluate SOC expressions.
    /// It uses the Pest parser which is more robust and maintainable.
    ///
    /// Example:
    /// ```rust
    /// use achronyme_eval::Evaluator;
    ///
    /// let mut evaluator = Evaluator::new();
    /// let result = evaluator.eval_str("2 + 3 * 4").unwrap();
    /// ```
    pub fn eval_str(&mut self, source: &str) -> Result<Value, String> {
        use achronyme_parser::parse;

        let statements = parse(source)?;

        if statements.is_empty() {
            return Err("No statements to evaluate".to_string());
        }

        // Evaluate all statements, return the last one
        let mut result = Value::Number(0.0);
        for stmt in &statements {
            result = self.evaluate(stmt)?;
        }

        Ok(result)
    }

    /// Evaluate an AST node and return the result
    ///
    /// This is the main dispatch method that routes AST nodes to their
    /// appropriate handler functions.
    pub fn evaluate(&mut self, node: &AstNode) -> Result<Value, String> {
        match node {
            // Literals
            AstNode::Number(n) => handlers::literals::evaluate_number(*n),
            AstNode::Boolean(b) => handlers::literals::evaluate_boolean(*b),
            AstNode::StringLiteral(s) => handlers::literals::evaluate_string(s),
            AstNode::ComplexLiteral { re, im } => handlers::literals::evaluate_complex(*re, *im),
            AstNode::ArrayLiteral(elements) => handlers::literals::evaluate_array(self, elements),
            AstNode::RecordLiteral(fields) => handlers::literals::evaluate_record(self, fields),
            AstNode::Null => Ok(Value::Null),

            // Variables
            AstNode::VariableDecl { name, type_annotation, initializer } => {
                handlers::variables::evaluate_declaration(self, name, type_annotation, initializer)
            }
            AstNode::VariableRef(name) => handlers::variables::evaluate_reference(self, name),
            AstNode::MutableDecl { name, type_annotation, initializer } => {
                handlers::variables::evaluate_mutable_declaration(self, name, type_annotation, initializer)
            }
            AstNode::LetDestructuring { pattern, type_annotation, initializer } => {
                handlers::variables::evaluate_let_destructuring(self, pattern, type_annotation, initializer)
            }
            AstNode::MutableDestructuring { pattern, type_annotation, initializer } => {
                handlers::variables::evaluate_mutable_destructuring(self, pattern, type_annotation, initializer)
            }
            AstNode::Assignment { target, value } => {
                handlers::assignment::evaluate_assignment(self, target, value)
            }
            AstNode::Return { value } => {
                // Evaluate the return value and wrap it in EarlyReturn
                let return_value = self.evaluate(value)?;
                Ok(Value::EarlyReturn(Box::new(return_value)))
            }
            AstNode::SelfReference => {
                // Look up 'self' in the environment
                self.env.get("self").map_err(|_| {
                    "'self' can only be used inside record methods".to_string()
                })
            }
            AstNode::RecReference => {
                // Look up 'rec' in the environment
                self.env.get("rec").map_err(|_| {
                    "'rec' can only be used inside functions".to_string()
                })
            }

            // Field access
            AstNode::FieldAccess { record, field } => {
                self.evaluate_field_access(record, field)
            }

            // Control flow
            AstNode::If {
                condition,
                then_expr,
                else_expr,
            } => handlers::control_flow::evaluate_if(self, condition, then_expr, else_expr),
            AstNode::WhileLoop { condition, body } => {
                handlers::control_flow::evaluate_while(self, condition, body)
            }
            AstNode::Piecewise { cases, default } => {
                handlers::control_flow::evaluate_piecewise(self, cases, default)
            }
            AstNode::ForInLoop { variable, iterable, body } => {
                handlers::control_flow::evaluate_for_in(self, variable, iterable, body)
            }

            // Generators
            AstNode::GenerateBlock { statements } => {
                handlers::control_flow::evaluate_generate_block(self, statements)
            }
            AstNode::Yield { value } => {
                // Check if we're in generator context
                if !self.in_generator {
                    return Err("yield can only be used inside a generator (generate { ... })".to_string());
                }

                // We're in generator context - evaluate and return yield marker
                let yield_value = self.evaluate(value)?;
                Ok(Value::GeneratorYield(Box::new(yield_value)))
            }

            // Operations
            AstNode::BinaryOp { op, left, right } => {
                let left_val = self.evaluate(left)?;
                let right_val = self.evaluate(right)?;
                handlers::binary_ops::apply(op, left_val, right_val)
            }
            AstNode::UnaryOp { op, operand } => {
                let operand_val = self.evaluate(operand)?;
                handlers::unary_ops::apply(op, operand_val)
            }

            // Functions and lambdas
            AstNode::FunctionCall { name, args } => {
                handlers::function_call::dispatch(self, name, args)
            }
            AstNode::CallExpression { callee, args } => {
                self.evaluate_call_expression(callee, args)
            }
            AstNode::Lambda { params, body, return_type } => {
                handlers::functions::evaluate_lambda_with_return_type(self, params, return_type.clone(), body)
            }

            // Edges (graph/network support)
            AstNode::Edge { from, to, directed, metadata } => {
                handlers::literals::evaluate_edge(self, from, to, *directed, metadata)
            }

            // Indexing and slicing
            AstNode::IndexAccess { object, indices } => {
                handlers::indexing::evaluate_index_access(self, object, indices)
            }

            // Sequence: multiple statements separated by semicolons
            AstNode::Sequence { statements } => {
                self.evaluate_sequence(statements)
            }

            // DoBlock: do { statements }
            AstNode::DoBlock { statements } => {
                self.evaluate_do_block(statements)
            }

            // Module system
            AstNode::Import { items, module_path } => {
                self.evaluate_import(items, module_path)
            }
            AstNode::Export { items } => {
                self.evaluate_export(items)
            }

            // Type system
            AstNode::TypeAlias { name, type_definition } => {
                // Register the type alias in the type registry
                self.register_type_alias(name.clone(), type_definition.clone());
                // Type alias statements don't produce a value, return unit (true)
                Ok(Value::Boolean(true))
            }

            // Error handling
            AstNode::Throw { value } => {
                handlers::control_flow::evaluate_throw(self, value)
            }
            AstNode::TryCatch { try_block, error_param, catch_block } => {
                handlers::control_flow::evaluate_try_catch(self, try_block, error_param, catch_block)
            }

            // Pattern matching
            AstNode::Match { value, arms } => {
                handlers::pattern_matching::evaluate_match(self, value, arms)
            }
        }
    }

    /// Evaluate field access on records and edges
    fn evaluate_field_access(&mut self, record: &AstNode, field: &str) -> Result<Value, String> {
        let record_value = self.evaluate(record)?;
        match record_value {
            Value::Record(ref map) => {
                let field_value = map.get(field)
                    .cloned()
                    .ok_or_else(|| format!("Field '{}' not found in record", field))?;
                // Auto-deref MutableRef when accessing fields
                field_value.deref()
            }
            Value::Edge { from, to, directed, properties } => {
                // Handle special fields
                match field {
                    "from" => Ok(Value::String(from.clone())),
                    "to" => Ok(Value::String(to.clone())),
                    "directed" => Ok(Value::Boolean(directed)),
                    // Otherwise, look in properties
                    _ => properties.get(field)
                        .cloned()
                        .ok_or_else(|| format!("Field '{}' not found in edge", field))
                }
            }
            Value::Generator(_) => {
                // Generator field access - only 'next' is supported as a method call
                // Field access alone (without call) is not meaningful for generators
                match field {
                    "next" => {
                        // This shouldn't be reached because generator.next() is handled
                        // in evaluate_call_expression. If we get here, user is accessing
                        // .next without calling it.
                        Err("Generator.next is a method - use generator.next() to call it".to_string())
                    }
                    _ => Err(format!("Generators only have a 'next' method, not '{}'", field)),
                }
            }
            Value::Error { message, kind, source } => {
                // Error field access
                match field {
                    "message" => Ok(Value::String(message)),
                    "kind" => match kind {
                        Some(k) => Ok(Value::String(k)),
                        None => Ok(Value::Null),
                    },
                    "source" => match source {
                        Some(src) => Ok(*src),
                        None => Ok(Value::Null),
                    },
                    _ => Err(format!("Error has no field '{}'. Available fields: message, kind, source", field)),
                }
            }
            _ => Err(format!("Cannot access field '{}' on non-record/edge value", field)),
        }
    }

    /// Evaluate call expressions (function application)
    fn evaluate_call_expression(&mut self, callee: &AstNode, args: &[AstNode]) -> Result<Value, String> {
        // Special case: if callee is a field access (record.method), we need to inject 'self'
        if let AstNode::FieldAccess { record, field } = callee {
            let record_value = self.evaluate(record)?;

            match &record_value {
                Value::Record(ref map) => {
                    let func_value = map.get(field)
                        .cloned()
                        .ok_or_else(|| format!("Field '{}' not found in record", field))?;

                    if let Value::Function(ref func) = func_value {
                        // Evaluate arguments
                        let mut arg_values = Vec::new();
                        for arg in args {
                            arg_values.push(self.evaluate(arg)?);
                        }

                        // Inject 'self' for method calls
                        self.environment_mut().push_scope();
                        self.environment_mut().define("self".to_string(), record_value)?;

                        let func_clone = func.clone();
                        let result = self.apply_lambda(&func_clone, arg_values);

                        self.environment_mut().pop_scope();
                        return result;
                    } else {
                        return Err(format!("Field '{}' is not a function", field));
                    }
                }
                Value::Generator(ref gen_rc) => {
                    // Generator method calls
                    match field.as_str() {
                        "next" => {
                            if !args.is_empty() {
                                return Err("Generator.next() takes no arguments".to_string());
                            }
                            // Resume the generator
                            return handlers::control_flow::resume_generator(self, gen_rc);
                        }
                        _ => return Err(format!("Generators only have a 'next' method, not '{}'", field)),
                    }
                }
                _ => return Err(format!("Cannot access field '{}' on non-record value", field)),
            }
        }

        // TCO OPTIMIZATION: Check if this is a tail call to 'rec' in TCO mode
        if self.is_tco_mode() && matches!(callee, AstNode::RecReference) {
            // This is a tail call to rec - return TailCall marker instead of calling
            let mut arg_values = Vec::new();
            for arg in args {
                arg_values.push(self.evaluate(arg)?);
            }
            return Ok(Value::TailCall(arg_values));
        }

        // If callee is a VariableRef, it might be a built-in function
        // Dispatch to function_call handler which checks module registry
        if let AstNode::VariableRef(name) = callee {
            return handlers::function_call::dispatch(self, name, args);
        }

        // Regular call expression - evaluate callee to get the function
        let func_value = self.evaluate(callee)?;

        // Must be a function
        match func_value {
            Value::Function(ref func) => {
                match func {
                    achronyme_types::function::Function::UserDefined { .. } => {
                        // User-defined lambda - evaluate args and apply
                        let mut arg_values = Vec::new();
                        for arg in args {
                            arg_values.push(self.evaluate(arg)?);
                        }
                        let func_clone = func.clone();
                        self.apply_lambda(&func_clone, arg_values)
                    }
                    achronyme_types::function::Function::Builtin(name) => {
                        // Built-in function - dispatch without evaluating args (let handler do it)
                        handlers::function_call::dispatch(self, name, args)
                    }
                }
            }
            _ => Err("CallExpression requires a function, got non-function value".to_string()),
        }
    }

    /// Evaluate sequence of statements
    fn evaluate_sequence(&mut self, statements: &[AstNode]) -> Result<Value, String> {
        if statements.is_empty() {
            return Err("Empty sequence".to_string());
        }

        // Create a new scope for the sequence
        self.env.push_scope();

        // Evaluate all statements, keeping the last result
        let mut result = None;
        for stmt in statements {
            let value = self.evaluate(stmt)?;

            // Check for early return - propagate it up immediately
            if matches!(value, Value::EarlyReturn(_)) {
                self.env.pop_scope();
                return Ok(value);
            }

            result = Some(value);
        }

        // Pop the scope
        self.env.pop_scope();

        // Return the last evaluated expression
        result.ok_or_else(|| "Empty sequence (no statements)".to_string())
    }

    /// Evaluate do block
    fn evaluate_do_block(&mut self, statements: &[AstNode]) -> Result<Value, String> {
        if statements.is_empty() {
            return Err("Empty do block".to_string());
        }

        // Create a new scope for the do block
        self.env.push_scope();

        // Evaluate all statements, keeping the last result
        let mut result = None;
        for stmt in statements {
            let value = self.evaluate(stmt)?;

            // Check for early return - propagate it immediately
            if matches!(value, Value::EarlyReturn(_)) {
                self.env.pop_scope();
                return Ok(value);
            }

            result = Some(value);
        }

        // Pop the scope
        self.env.pop_scope();

        // Return the last evaluated expression
        result.ok_or_else(|| "Empty do block (no statements)".to_string())
    }

    /// Evaluate import statement
    fn evaluate_import(&mut self, items: &[achronyme_parser::ast::ImportItem], module_path: &str) -> Result<Value, String> {
        // Check if this is a built-in module or a file-based user module
        if self.module_registry.has_module(module_path) {
            // Built-in module: add to imported_modules map
            for item in items {
                let local_name = item.local_name();
                let original_name = &item.name;

                // Check if the function exists in the module
                let module = self.module_registry.get_module(module_path).unwrap();
                if !module.has(original_name) {
                    return Err(format!(
                        "Function '{}' not found in module '{}'",
                        original_name, module_path
                    ));
                }

                self.imported_modules.insert(
                    local_name.to_string(),
                    (module_path.to_string(), original_name.clone())
                );
            }
        } else {
            // User-defined module: load from file and import exported values
            let exports = self.load_user_module(module_path)?;

            for item in items {
                let local_name = item.local_name();
                let original_name = &item.name;

                // Check if the value is exported from the module
                let value = exports.get(original_name).ok_or_else(|| {
                    format!(
                        "'{}' is not exported from module '{}'",
                        original_name, module_path
                    )
                })?;

                // Add the imported value to the environment
                self.env.define(local_name.to_string(), value.clone())?;
            }
        }

        // Import statements don't produce a value, return unit (true)
        Ok(Value::Boolean(true))
    }

    /// Evaluate export statement
    fn evaluate_export(&mut self, items: &[achronyme_parser::ast::ImportItem]) -> Result<Value, String> {
        // Export statement: marks variables/functions for external use
        for item in items {
            let name = &item.name;
            let export_name = item.local_name(); // Use alias if provided

            // Check if the value exists in the environment
            if !self.env.has(name) {
                return Err(format!(
                    "Cannot export '{}': not found in current scope",
                    name
                ));
            }

            // Get the value from environment
            let value = self.env.get(name)?;

            // Add to exported values
            self.exported_values.insert(export_name.to_string(), value);
        }

        // Export statements don't produce a value, return unit (true)
        Ok(Value::Boolean(true))
    }
}
