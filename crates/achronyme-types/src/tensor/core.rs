use crate::complex::Complex;

/// Generic N-dimensional tensor with efficient storage and operations
#[derive(Debug, Clone, PartialEq)]
pub struct Tensor<T> {
    pub data: Vec<T>,        // Flat storage in row-major order
    pub shape: Vec<usize>,   // Dimensions [d0, d1, d2, ...]
    pub strides: Vec<usize>, // Strides for efficient indexing
}

// Type aliases for common cases
pub type RealTensor = Tensor<f64>;
pub type ComplexTensor = Tensor<Complex>;

#[derive(Debug, Clone, PartialEq)]
pub enum TensorError {
    DimensionMismatch {
        expected: Vec<usize>,
        got: Vec<usize>,
    },
    InvalidShape {
        shape: Vec<usize>,
        data_len: usize,
    },
    IndexOutOfBounds {
        index: Vec<usize>,
        shape: Vec<usize>,
    },
    EmptyTensor,
    InvalidReshape {
        old_shape: Vec<usize>,
        new_shape: Vec<usize>,
    },
    BroadcastError {
        shape1: Vec<usize>,
        shape2: Vec<usize>,
    },
}

impl std::fmt::Display for TensorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TensorError::DimensionMismatch { expected, got } => {
                write!(
                    f,
                    "Dimension mismatch: expected {:?}, got {:?}",
                    expected, got
                )
            }
            TensorError::InvalidShape { shape, data_len } => {
                write!(f, "Invalid shape {:?} for data length {}", shape, data_len)
            }
            TensorError::IndexOutOfBounds { index, shape } => {
                write!(f, "Index {:?} out of bounds for shape {:?}", index, shape)
            }
            TensorError::EmptyTensor => write!(f, "Operation on empty tensor"),
            TensorError::InvalidReshape {
                old_shape,
                new_shape,
            } => {
                write!(
                    f,
                    "Cannot reshape tensor from {:?} to {:?}",
                    old_shape, new_shape
                )
            }
            TensorError::BroadcastError { shape1, shape2 } => {
                write!(f, "Cannot broadcast shapes {:?} and {:?}", shape1, shape2)
            }
        }
    }
}

impl std::error::Error for TensorError {}

impl<T: Clone> Tensor<T> {
    /// Create a new tensor from data and shape
    /// Data is stored in row-major order
    pub fn new(data: Vec<T>, shape: Vec<usize>) -> Result<Self, TensorError> {
        let expected_len: usize = shape.iter().product();

        if data.len() != expected_len {
            return Err(TensorError::InvalidShape {
                shape: shape.clone(),
                data_len: data.len(),
            });
        }

        let strides = Self::compute_strides(&shape);

        Ok(Self {
            data,
            shape,
            strides,
        })
    }

    /// Compute strides from shape (row-major order)
    pub(crate) fn compute_strides(shape: &[usize]) -> Vec<usize> {
        let mut strides = vec![1; shape.len()];
        for i in (0..shape.len().saturating_sub(1)).rev() {
            strides[i] = strides[i + 1] * shape[i + 1];
        }
        strides
    }

    /// Get the rank (number of dimensions) of the tensor
    /// 0 = scalar, 1 = vector, 2 = matrix, 3+ = higher-order tensor
    pub fn rank(&self) -> usize {
        self.shape.len()
    }

    /// Get total number of elements
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Check if tensor is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Check if tensor is a scalar (rank 0)
    pub fn is_scalar(&self) -> bool {
        self.rank() == 0
    }

    /// Check if tensor is a vector (rank 1)
    pub fn is_vector(&self) -> bool {
        self.rank() == 1
    }

    /// Check if tensor is a matrix (rank 2)
    pub fn is_matrix(&self) -> bool {
        self.rank() == 2
    }

    /// Convert multi-dimensional index to flat index
    fn ravel_index(&self, index: &[usize]) -> Result<usize, TensorError> {
        if index.len() != self.shape.len() {
            return Err(TensorError::IndexOutOfBounds {
                index: index.to_vec(),
                shape: self.shape.clone(),
            });
        }

        for (i, &idx) in index.iter().enumerate() {
            if idx >= self.shape[i] {
                return Err(TensorError::IndexOutOfBounds {
                    index: index.to_vec(),
                    shape: self.shape.clone(),
                });
            }
        }

        let flat_idx = index
            .iter()
            .zip(self.strides.iter())
            .map(|(i, s)| i * s)
            .sum();

        Ok(flat_idx)
    }

    /// Get element at given index
    pub fn get(&self, index: &[usize]) -> Result<&T, TensorError> {
        let flat_idx = self.ravel_index(index)?;
        Ok(&self.data[flat_idx])
    }

    /// Set element at given index
    pub fn set(&mut self, index: &[usize], value: T) -> Result<(), TensorError> {
        let flat_idx = self.ravel_index(index)?;
        self.data[flat_idx] = value;
        Ok(())
    }

    /// Reshape tensor to new shape (must preserve total size)
    pub fn reshape(&self, new_shape: Vec<usize>) -> Result<Self, TensorError> {
        let old_size: usize = self.shape.iter().product();
        let new_size: usize = new_shape.iter().product();

        if old_size != new_size {
            return Err(TensorError::InvalidReshape {
                old_shape: self.shape.clone(),
                new_shape,
            });
        }

        Self::new(self.data.clone(), new_shape)
    }

    /// Get a reference to the underlying data
    pub fn data(&self) -> &[T] {
        &self.data
    }

    /// Get shape
    pub fn shape(&self) -> &[usize] {
        &self.shape
    }

    /// Get strides
    pub fn strides(&self) -> &[usize] {
        &self.strides
    }
}
