#[derive(Clone, Copy, Debug)]
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
}
