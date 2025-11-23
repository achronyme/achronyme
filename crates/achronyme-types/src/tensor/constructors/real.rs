use crate::tensor::core::{RealTensor, TensorError};

// Specialized constructors for RealTensor
impl RealTensor {
    /// Create a tensor filled with zeros
    pub fn zeros(shape: Vec<usize>) -> Self {
        let size: usize = shape.iter().product();
        let data = vec![0.0; size];
        Self::new(data, shape).expect("zeros: invalid shape")
    }

    /// Create a tensor filled with ones
    pub fn ones(shape: Vec<usize>) -> Self {
        let size: usize = shape.iter().product();
        let data = vec![1.0; size];
        Self::new(data, shape).expect("ones: invalid shape")
    }

    /// Create a tensor filled with a specific value
    pub fn filled(shape: Vec<usize>, value: f64) -> Self {
        let size: usize = shape.iter().product();
        let data = vec![value; size];
        Self::new(data, shape).expect("filled: invalid shape")
    }

    /// Create an identity matrix (rank 2 tensor)
    pub fn eye(n: usize) -> Self {
        let mut data = vec![0.0; n * n];
        for i in 0..n {
            data[i * n + i] = 1.0;
        }
        Self::new(data, vec![n, n]).expect("eye: invalid shape")
    }

    /// Create a scalar tensor
    pub fn scalar(value: f64) -> Self {
        Self::new(vec![value], vec![]).expect("scalar: invalid shape")
    }

    /// Create a vector tensor from a Vec<f64>
    pub fn vector(data: Vec<f64>) -> Self {
        let len = data.len();
        Self::new(data, vec![len]).expect("vector: invalid shape")
    }

    /// Create a matrix tensor from data and dimensions
    pub fn matrix(rows: usize, cols: usize, data: Vec<f64>) -> Result<Self, TensorError> {
        Self::new(data, vec![rows, cols])
    }

    /// Get the number of rows (for rank-2 tensors)
    pub fn rows(&self) -> usize {
        if self.is_matrix() {
            self.shape[0]
        } else {
            0
        }
    }

    /// Get the number of columns (for rank-2 tensors)
    pub fn cols(&self) -> usize {
        if self.is_matrix() {
            self.shape[1]
        } else {
            0
        }
    }

    /// Check if matrix is square (for rank-2 tensors)
    pub fn is_square(&self) -> bool {
        self.is_matrix() && self.shape[0] == self.shape[1]
    }

    /// Get matrix element at (row, col) - convenience method for rank-2 tensors
    pub fn get_matrix(&self, row: usize, col: usize) -> Result<f64, TensorError> {
        if !self.is_matrix() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![0, 0],
                got: self.shape.clone(),
            });
        }
        self.get(&[row, col]).copied()
    }

    /// Set matrix element at (row, col) - convenience method for rank-2 tensors
    pub fn set_matrix(&mut self, row: usize, col: usize, value: f64) -> Result<(), TensorError> {
        if !self.is_matrix() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![0, 0],
                got: self.shape.clone(),
            });
        }
        self.set(&[row, col], value)
    }

    /// Get a row from a matrix as a vector
    pub fn row(&self, index: usize) -> Result<Vec<f64>, TensorError> {
        if !self.is_matrix() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![0, 0],
                got: self.shape.clone(),
            });
        }
        if index >= self.shape[0] {
            return Err(TensorError::IndexOutOfBounds {
                index: vec![index],
                shape: self.shape.clone(),
            });
        }
        let cols = self.shape[1];
        let start = index * cols;
        Ok(self.data[start..start + cols].to_vec())
    }

    /// Get a column from a matrix as a vector
    pub fn col(&self, index: usize) -> Result<Vec<f64>, TensorError> {
        if !self.is_matrix() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![0, 0],
                got: self.shape.clone(),
            });
        }
        if index >= self.shape[1] {
            return Err(TensorError::IndexOutOfBounds {
                index: vec![index],
                shape: self.shape.clone(),
            });
        }
        let rows = self.shape[0];
        let cols = self.shape[1];
        let mut column = Vec::with_capacity(rows);
        for row in 0..rows {
            column.push(self.data[row * cols + index]);
        }
        Ok(column)
    }

    /// Scalar multiplication (convenience method, same as mul_scalar)
    pub fn scale(&self, scalar: f64) -> RealTensor {
        self.mul_scalar(scalar)
    }

    /// Hadamard product (element-wise multiplication, same as mul)
    pub fn hadamard(&self, other: &RealTensor) -> Result<RealTensor, TensorError> {
        self.mul(other)
    }

    /// Matrix determinant (only for square rank-2 tensors)
    pub fn determinant(&self) -> Result<f64, TensorError> {
        if !self.is_square() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![0, 0],
                got: self.shape.clone(),
            });
        }

        let n = self.shape[0];

        // Base cases
        if n == 1 {
            return Ok(self.data[0]);
        }
        if n == 2 {
            return Ok(self.data[0] * self.data[3] - self.data[1] * self.data[2]);
        }

        // For larger matrices, use LU decomposition or cofactor expansion
        // Simple cofactor expansion for now (can be optimized later)
        let mut det = 0.0;
        for j in 0..n {
            let minor = self.minor(0, j)?;
            let sign = if j % 2 == 0 { 1.0 } else { -1.0 };
            det += sign * self.data[j] * minor.determinant()?;
        }
        Ok(det)
    }

    /// Get minor matrix by removing row and column
    fn minor(&self, row: usize, col: usize) -> Result<RealTensor, TensorError> {
        if !self.is_matrix() {
            return Err(TensorError::DimensionMismatch {
                expected: vec![0, 0],
                got: self.shape.clone(),
            });
        }

        let n = self.shape[0];
        let mut data = Vec::with_capacity((n - 1) * (n - 1));

        for i in 0..n {
            if i == row {
                continue;
            }
            for j in 0..n {
                if j == col {
                    continue;
                }
                data.push(self.data[i * n + j]);
            }
        }

        RealTensor::matrix(n - 1, n - 1, data)
    }
}
