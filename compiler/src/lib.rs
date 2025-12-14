use memory::Value;
// use achronyme_parser::...; // Will use later

pub struct Local {
    pub name: String,       // Nombre de la variable (solo usado al compilar)
    pub depth: u32,         // Profundidad del scope donde se declaró
    pub is_captured: bool,  // Si es capturada por una closure anidada
}

pub struct Compiler {
    // Simulación del stack en tiempo de compilación para rastrear registros
    pub locals: Vec<Local>, 
    pub scope_depth: u32,
    
    // Bytecode output buffer (placeholder)
    pub bytecode: Vec<u8>,
}

impl Compiler {
    pub fn new() -> Self {
        Self {
            locals: Vec::new(),
            scope_depth: 0,
            bytecode: Vec::new(),
        }
    }
    
    pub fn compile(&mut self, _source: &str) -> Result<Vec<u8>, String> {
        // Parsing and code gen logic here
        Ok(self.bytecode.clone())
    }
}
