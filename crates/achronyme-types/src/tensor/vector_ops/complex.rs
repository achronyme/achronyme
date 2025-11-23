use crate::complex::Complex;
use crate::tensor::core::{ComplexTensor, TensorError};

impl ComplexTensor {
    /// Dot product of two complex vectors
    pub fn dot(&self, other: &ComplexTensor) -> Result<Complex, TensorError> {
        if !self.is_vector() || !other.is_vector() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![self.size()],
                got: other.shape.clone(),
            });
        }

        if self.size() != other.size() {
            return Err(TensorError::DimensionMismatch {
                expected: self.shape.clone(),
                got: other.shape.clone(),
            });
        }

        Ok(self
            .data
            .iter()
            .zip(other.data.iter())
            .map(|(a, b)| a.conjugate() * *b) // Hermitian inner product
            .fold(Complex::new(0.0, 0.0), |acc, x| acc + x))
    }

    /// Norm of complex vector
    pub fn norm(&self) -> f64 {
        self.data
            .iter()
            .map(|c| c.magnitude() * c.magnitude())
            .sum::<f64>()
            .sqrt()
    }

    /// Normalize complex vector
    pub fn normalize(&self) -> Result<ComplexTensor, TensorError> {
        let n = self.norm();
        if n < 1e-10 {
            return Err(TensorError::EmptyTensor);
        }
        Ok(self.mul_scalar(Complex::new(1.0 / n, 0.0)))
    }

    /// Sum of all complex elements
    pub fn sum(&self) -> Complex {
        self.data
            .iter()
            .fold(Complex::new(0.0, 0.0), |acc, &x| acc + x)
    }

    /// Mean of all complex elements
    pub fn mean(&self) -> Result<Complex, TensorError> {
        if self.is_empty() {
            return Err(TensorError::EmptyTensor);
        }
        let sum = self.sum();
        let n = self.size() as f64;
        Ok(Complex::new(sum.re / n, sum.im / n))
    }

    /// Standard deviation of complex tensor (magnitude-based)
    pub fn std_dev(&self) -> Result<f64, TensorError> {
        if self.size() < 2 {
            return Err(TensorError::EmptyTensor);
        }
        let mean = self.mean()?;
        let sum_squared_diff: f64 = self
            .data
            .iter()
            .map(|x| (*x - mean).magnitude().powi(2))
            .sum();
        Ok((sum_squared_diff / (self.size() - 1) as f64).sqrt())
    }
}
