#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    // --- Primitivos (Viven en el stack/registros) ---
    Nil,
    Bool(bool),
    Number(f64),
    
    // --- Handles (Índices a las Arenas del Heap) ---
    String(u32),   
    List(u32),     
    Map(u32),      
    Function(u32), 
    Tensor(u32),
    Complex(u32),  // Handle to Complex64 in Heap
}

impl Value {
    /// Check if this value is a numeric type (Number or Complex)
    #[inline]
    pub fn is_numeric(&self) -> bool {
        matches!(self, Value::Number(_) | Value::Complex(_))
    }
    
    /// Try to extract as f64 (only works for Number)
    #[inline]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }
}
