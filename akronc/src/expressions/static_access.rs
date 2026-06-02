use crate::codegen::Compiler;
use crate::error::CompilerError;
use akron::opcode::OpCode;
use memory::Value;

impl Compiler {
    pub(super) fn compile_static_access(
        &mut self,
        type_name: &str,
        member: &str,
    ) -> Result<u8, CompilerError> {
        let reg = self.alloc_reg()?;
        match (type_name, member) {
            // Int::MAX, Int::MIN
            ("Int", "MAX") => {
                let val = Value::int(memory::I60_MAX);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            ("Int", "MIN") => {
                let val = Value::int(memory::I60_MIN);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            // Field::ZERO, Field::ONE
            ("Field", "ZERO") => {
                let handle = self.intern_field(memory::FieldElement::ZERO);
                let val = Value::field(handle);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            ("Field", "ONE") => {
                let fe = memory::FieldElement::from_u64(1);
                let handle = self.intern_field(fe);
                let val = Value::field(handle);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            // Field::ORDER — the BN254 Fr modulus as a string
            ("Field", "ORDER") => {
                let order_str =
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
                let handle = self.intern_string(order_str);
                let val = Value::string(handle);
                let const_idx = self.add_constant(val)?;
                if const_idx > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(self.cur_span()));
                }
                self.emit_abx(OpCode::LoadConst, reg, const_idx as u16)?;
            }
            // BigInt::from_bits — resolve to a global (native function)
            ("BigInt", "from_bits") => {
                // Look up the global for from_bits (still a native global at this point)
                let idx = self
                    .global_symbols
                    .get("from_bits")
                    .map(|e| e.index)
                    .ok_or_else(|| {
                        CompilerError::CompileError(
                            "BigInt::from_bits is not available (from_bits native not found)"
                                .into(),
                            self.cur_span(),
                        )
                    })?;
                self.emit_abx(OpCode::GetGlobal, reg, idx)?;
            }
            _ => {
                // Namespace alias lookup: `alias::name` where `alias` came
                // from an `import "./foo.ach" as alias` resolves to the
                // mangled global `alias::name` at compile time — no runtime
                // map dispatch, no HashMap lookup per call. Same strategy
                // `Int::MAX` already uses for built-in static constants,
                // extended to user-imported modules.
                if self.imported_aliases.contains_key(type_name) {
                    let mangled = format!("{type_name}::{member}");
                    let entry = self.global_symbols.get(&mangled).ok_or_else(|| {
                        CompilerError::CompileError(
                            format!("module `{type_name}` does not export `{member}`"),
                            self.cur_span(),
                        )
                    })?;
                    // Mark the imported name as used so W005 doesn't flag it.
                    if self.imported_names.contains_key(&mangled) {
                        self.used_imported_names.insert(mangled.clone());
                    }
                    let idx = entry.index;
                    self.emit_abx(OpCode::GetGlobal, reg, idx)?;
                    return Ok(reg);
                }
                // Check if type is known but member isn't
                let known_types = ["Int", "Field", "BigInt"];
                if known_types.contains(&type_name) {
                    return Err(CompilerError::CompileError(
                        format!("unknown static member: '{type_name}::{member}'"),
                        self.cur_span(),
                    ));
                }
                return Err(CompilerError::CompileError(
                    format!("unknown type: '{type_name}'"),
                    self.cur_span(),
                ));
            }
        }
        Ok(reg)
    }
}
