use crate::tensor::core::{RealTensor, TensorError};

// ============================================================================
// Vector Operations (rank 1 tensors)
// ============================================================================

impl RealTensor {
    /// Dot product (inner product) of two vectors
    pub fn dot(&self, other: &RealTensor) -> Result<f64, TensorError> {
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
            .map(|(a, b)| a * b)
            .sum())
    }

    /// Cross product of two 3D vectors
    pub fn cross(&self, other: &RealTensor) -> Result<RealTensor, TensorError> {
        if !self.is_vector() || !other.is_vector() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![3],
                got: vec![],
            });
        }

        if self.size() != 3 || other.size() != 3 {
            return Err(TensorError::DimensionMismatch {
                expected: vec![3],
                got: self.shape.clone(),
            });
        }

        let a = &self.data;
        let b = &other.data;

        let data = vec![
            a[1] * b[2] - a[2] * b[1],
            a[2] * b[0] - a[0] * b[2],
            a[0] * b[1] - a[1] * b[0],
        ];

        Ok(RealTensor::vector(data))
    }

    /// Euclidean norm (L2 norm)
    pub fn norm(&self) -> f64 {
        self.data.iter().map(|x| x * x).sum::<f64>().sqrt()
    }

    /// L1 norm (Manhattan distance)
    pub fn norm_l1(&self) -> f64 {
        self.data.iter().map(|x| x.abs()).sum()
    }

    /// Normalize vector to unit length
    pub fn normalize(&self) -> Result<RealTensor, TensorError> {
        let n = self.norm();
        if n < 1e-10 {
            return Err(TensorError::EmptyTensor);
        }
        Ok(self.mul_scalar(1.0 / n))
    }

    /// Sum of all elements
    pub fn sum(&self) -> f64 {
        self.data.iter().sum()
    }

    /// Mean of all elements
    pub fn mean(&self) -> Result<f64, TensorError> {
        if self.is_empty() {
            return Err(TensorError::EmptyTensor);
        }
        Ok(self.sum() / self.size() as f64)
    }

    /// Maximum element
    pub fn max(&self) -> Result<f64, TensorError> {
        self.data
            .iter()
            .copied()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .ok_or(TensorError::EmptyTensor)
    }

    /// Minimum element
    pub fn min(&self) -> Result<f64, TensorError> {
        self.data
            .iter()
            .copied()
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .ok_or(TensorError::EmptyTensor)
    }

    /// Variance of all elements (sample variance with Bessel's correction)
    pub fn variance(&self) -> Result<f64, TensorError> {
        if self.size() < 2 {
            return Err(TensorError::EmptyTensor);
        }
        let mean = self.mean()?;
        let sum_squared_diff: f64 = self.data.iter().map(|x| (x - mean).powi(2)).sum();
        Ok(sum_squared_diff / (self.size() - 1) as f64)
    }

    /// Standard deviation of all elements (sample std dev with Bessel's correction)
    pub fn std_dev(&self) -> Result<f64, TensorError> {
        Ok(self.variance()?.sqrt())
    }
}
