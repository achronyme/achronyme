use crate::complex::Complex;
use crate::tensor::core::{ComplexTensor, RealTensor};

// ============================================================================
// Type Conversion
// ============================================================================

impl RealTensor {
    /// Convert real tensor to complex tensor
    pub fn to_complex(&self) -> ComplexTensor {
        let data: Vec<Complex> = self.data.iter().map(|&x| Complex::new(x, 0.0)).collect();
        ComplexTensor::new(data, self.shape.clone()).unwrap()
    }
}
