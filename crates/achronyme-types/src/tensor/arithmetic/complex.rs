use crate::complex::Complex;
use crate::tensor::core::{ComplexTensor, RealTensor, Tensor, TensorError};

// ============================================================================
// Arithmetic Operations for ComplexTensor
// ============================================================================

impl ComplexTensor {
    /// Element-wise addition with broadcasting
    pub fn add(&self, other: &ComplexTensor) -> Result<ComplexTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<Complex> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| *a + *b)
                .collect();
            return ComplexTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<Complex>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<Complex>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<Complex>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(*a + *b);
        }

        ComplexTensor::new(data, result_shape)
    }

    /// Element-wise subtraction with broadcasting
    pub fn sub(&self, other: &ComplexTensor) -> Result<ComplexTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<Complex> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| *a - *b)
                .collect();
            return ComplexTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<Complex>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<Complex>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<Complex>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(*a - *b);
        }

        ComplexTensor::new(data, result_shape)
    }

    /// Element-wise multiplication with broadcasting
    pub fn mul(&self, other: &ComplexTensor) -> Result<ComplexTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<Complex> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| *a * *b)
                .collect();
            return ComplexTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<Complex>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<Complex>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<Complex>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(*a * *b);
        }

        ComplexTensor::new(data, result_shape)
    }

    /// Element-wise division with broadcasting
    pub fn div(&self, other: &ComplexTensor) -> Result<ComplexTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<Complex> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| *a / *b)
                .collect();
            return ComplexTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<Complex>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<Complex>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<Complex>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<Complex>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(*a / *b);
        }

        ComplexTensor::new(data, result_shape)
    }

    /// Scalar addition
    pub fn add_scalar(&self, scalar: Complex) -> ComplexTensor {
        let data: Vec<Complex> = self.data.iter().map(|x| *x + scalar).collect();
        ComplexTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Scalar subtraction (tensor - scalar)
    pub fn sub_scalar(&self, scalar: Complex) -> ComplexTensor {
        let data: Vec<Complex> = self.data.iter().map(|x| *x - scalar).collect();
        ComplexTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Scalar multiplication
    pub fn mul_scalar(&self, scalar: Complex) -> ComplexTensor {
        let data: Vec<Complex> = self.data.iter().map(|x| *x * scalar).collect();
        ComplexTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Scalar division (tensor / scalar)
    pub fn div_scalar(&self, scalar: Complex) -> Result<ComplexTensor, String> {
        if scalar.re == 0.0 && scalar.im == 0.0 {
            return Err("Division by zero".to_string());
        }
        let data: Vec<Complex> = self.data.iter().map(|x| *x / scalar).collect();
        Ok(ComplexTensor::new(data, self.shape.clone()).unwrap())
    }

    /// Negate all elements
    pub fn negate(&self) -> ComplexTensor {
        let data: Vec<Complex> = self.data.iter().map(|x| -*x).collect();
        ComplexTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Convert to RealTensor (magnitude)
    pub fn abs(&self) -> RealTensor {
        let data: Vec<f64> = self.data.iter().map(|c| c.magnitude()).collect();
        RealTensor::new(data, self.shape.clone()).unwrap()
    }
}
