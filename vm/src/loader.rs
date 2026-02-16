use std::io::Read;
use byteorder::{LittleEndian, ReadBytesExt};
use crate::specs::{SER_TAG_FIELD, SER_TAG_NUMBER, SER_TAG_STRING, SER_TAG_NIL};
use crate::{VM, CallFrame};
use memory::{Function, Closure, Value};


#[derive(Debug)]
pub enum LoaderError {
    Io(std::io::Error),
    Format(String),
    Security(String),
}

impl From<std::io::Error> for LoaderError {
    fn from(e: std::io::Error) -> Self {
        LoaderError::Io(e)
    }
}

impl VM {
    /// Load an executable binary (.achb) into the VM.
    /// 
    /// # Security
    /// This method includes checks against "Allocation Bomb" attacks.
    pub fn load_executable<R: Read>(&mut self, reader: &mut R) -> Result<(), LoaderError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"ACH\x08" {
            return Err(LoaderError::Format("Invalid binary magic or version".to_string()));
        }

        let max_slots = reader.read_u16::<LittleEndian>()?;

        // --- String Table ---
        let str_count = reader.read_u32::<LittleEndian>()?;
        // Protection: Limit string count to avoid massive pre-allocation if malformed
        if str_count > 1_000_000 {
             return Err(LoaderError::Security(format!("String count too large: {}", str_count)));
        }
        let mut strings = Vec::with_capacity(str_count as usize);

        for _ in 0..str_count {
            let len = reader.read_u32::<LittleEndian>()?;
            
            // SECURITY: Allocation Bomb Protection
            if len > 1024 {
                return Err(LoaderError::Security(format!("String length exceeds limit of 1024: {}", len)));
            }

            let mut bytes = vec![0u8; len as usize];
            reader.read_exact(&mut bytes)?;
            
            let s = String::from_utf8(bytes)
                .map_err(|_| LoaderError::Format("Invalid UTF-8 in binary".to_string()))?;
            strings.push(s);
        }

        // Sync Strings to Heap
        self.heap.import_strings(strings);

        // --- Constants ---
        let const_count = reader.read_u32::<LittleEndian>()?;
         if const_count > 1_000_000 {
             return Err(LoaderError::Security(format!("Constant count too large: {}", const_count)));
        }
        let mut constants = Vec::with_capacity(const_count as usize);
        for _ in 0..const_count {
            let tag = reader.read_u8()?;
            match tag {
                SER_TAG_NUMBER => {
                    let n = reader.read_f64::<LittleEndian>()?;
                    constants.push(Value::number(n));
                }
                SER_TAG_STRING => {
                    // Read Handle -> Create Value
                    let handle = reader.read_u32::<LittleEndian>()?;
                    constants.push(Value::string(handle));
                }
                SER_TAG_FIELD => {
                    let l0 = reader.read_u64::<LittleEndian>()?;
                    let l1 = reader.read_u64::<LittleEndian>()?;
                    let l2 = reader.read_u64::<LittleEndian>()?;
                    let l3 = reader.read_u64::<LittleEndian>()?;
                    let fe = memory::FieldElement::from_canonical([l0, l1, l2, l3]);
                    let handle = self.heap.alloc_field(fe);
                    constants.push(Value::field(handle));
                }
                SER_TAG_NIL => {
                    constants.push(Value::nil());
                }
                _ => return Err(LoaderError::Format(format!("Unknown constant tag: {}", tag))),
            }
        }

        // --- Prototypes (Function Table) ---
        let proto_count = reader.read_u32::<LittleEndian>()?;
         if proto_count > 100_000 {
             return Err(LoaderError::Security(format!("Prototype count too large: {}", proto_count)));
        }
        
        let mut proto_funcs = Vec::with_capacity(proto_count as usize);
        for _ in 0..proto_count {
            // Name
            let name_len = reader.read_u32::<LittleEndian>()? as usize;
            
            // SECURITY: Allocation Bomb Protection
            if name_len > 1024 {
                return Err(LoaderError::Security(format!("Function name length exceeds limit of 1024: {}", name_len)));
            }

            let mut name_bytes = vec![0u8; name_len];
            reader.read_exact(&mut name_bytes)?;
            let name = String::from_utf8(name_bytes)
                .map_err(|_| LoaderError::Format("Invalid UTF-8 in function name".to_string()))?;
            
            // Arity and max_slots
            let arity = reader.read_u8()?;
            let proto_max_slots = reader.read_u16::<LittleEndian>()?;
            
            // Proto constants
            let proto_const_count = reader.read_u32::<LittleEndian>()?;
            let mut proto_constants = Vec::with_capacity(proto_const_count as usize);
            for _ in 0..proto_const_count {
                let tag = reader.read_u8()?;
                match tag {
                    SER_TAG_NUMBER => {
                        let n = reader.read_f64::<LittleEndian>()?;
                        proto_constants.push(Value::number(n));
                    }
                    SER_TAG_STRING => {
                        let handle = reader.read_u32::<LittleEndian>()?;
                        proto_constants.push(Value::string(handle));
                    }
                    SER_TAG_FIELD => {
                        let l0 = reader.read_u64::<LittleEndian>()?;
                        let l1 = reader.read_u64::<LittleEndian>()?;
                        let l2 = reader.read_u64::<LittleEndian>()?;
                        let l3 = reader.read_u64::<LittleEndian>()?;
                        let fe = memory::FieldElement::from_canonical([l0, l1, l2, l3]);
                        let handle = self.heap.alloc_field(fe);
                        proto_constants.push(Value::field(handle));
                    }
                    SER_TAG_NIL => {
                        proto_constants.push(Value::nil());
                    }
                    _ => return Err(LoaderError::Format(format!("Unknown proto constant tag: {}", tag))),
                }
            }
            
            // Upvalue Info
            let upvalue_count = reader.read_u32::<LittleEndian>()?;
            if upvalue_count > 1024 {
                return Err(LoaderError::Security(format!("Too many upvalues: {}", upvalue_count)));
            }
            let info_len = (upvalue_count * 2) as usize;
            let mut upvalue_info = vec![0u8; info_len];
            reader.read_exact(&mut upvalue_info)?;

            // Proto bytecode
            let proto_code_len = reader.read_u32::<LittleEndian>()?;
             // Limit bytecode size per function? 1MB?
             if proto_code_len > 1_000_000 {
                 return Err(LoaderError::Security(format!("Bytecode length too large: {}", proto_code_len)));
             }

            let mut proto_bytecode = Vec::with_capacity(proto_code_len as usize);
            for _ in 0..proto_code_len {
                proto_bytecode.push(reader.read_u32::<LittleEndian>()?);
            }
            
            proto_funcs.push(Function {
                name,
                arity,
                max_slots: proto_max_slots,
                chunk: proto_bytecode,
                constants: proto_constants,
                upvalue_info,
            });
        }

        // Load prototypes into VM
        for proto in proto_funcs {
            let handle = self.heap.alloc_function(proto);
            self.prototypes.push(handle);
        }

        // --- Main Bytecode ---
        let code_len = reader.read_u32::<LittleEndian>()?;
        let mut bytecode = Vec::with_capacity(code_len as usize);
        for _ in 0..code_len {
            bytecode.push(reader.read_u32::<LittleEndian>()?);
        }

        // Try load debug symbols (Sidecar) - Optional
        // Reading remaining bytes? Or check if EOF?
        // run.rs logic: "if file.read_to_end...".
        // Here we just read what we can. 
        let mut debug_bytes = Vec::new();
        if reader.read_to_end(&mut debug_bytes).is_ok() && !debug_bytes.is_empty() {
             self.load_debug_section(&debug_bytes);
        }

        // Construct Main Function
        let func = Function {
            name: "main".to_string(),
            arity: 0,
            max_slots,
            chunk: bytecode,
            constants,
            upvalue_info: vec![],
        };
        let func_idx = self.heap.alloc_function(func);
        let closure_idx = self.heap.alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        });
        
        self.frames.push(CallFrame {
            closure: closure_idx,
            ip: 0,
            base: 0,
            dest_reg: 0, 
        });

        Ok(())
    }
}
