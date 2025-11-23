use crate::tensor::core::{RealTensor, Tensor, TensorError};

// ============================================================================
// Arithmetic Operations for RealTensor
// ============================================================================

impl RealTensor {
    /// Element-wise addition with broadcasting
    pub fn add(&self, other: &RealTensor) -> Result<RealTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<f64> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| a + b)
                .collect();
            return RealTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<f64>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<f64>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<f64>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(a + b);
        }

        RealTensor::new(data, result_shape)
    }

    /// Element-wise subtraction with broadcasting
    pub fn sub(&self, other: &RealTensor) -> Result<RealTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<f64> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| a - b)
                .collect();
            return RealTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<f64>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<f64>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<f64>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(a - b);
        }

        RealTensor::new(data, result_shape)
    }

    /// Element-wise multiplication (Hadamard product) with broadcasting
    pub fn mul(&self, other: &RealTensor) -> Result<RealTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<f64> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| a * b)
                .collect();
            return RealTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<f64>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<f64>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<f64>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(a * b);
        }

        RealTensor::new(data, result_shape)
    }

    /// Element-wise division with broadcasting
    pub fn div(&self, other: &RealTensor) -> Result<RealTensor, TensorError> {
        // Fast path: if shapes are identical, use direct element-wise operation
        if self.shape == other.shape {
            let data: Vec<f64> = self
                .data
                .iter()
                .zip(other.data.iter())
                .map(|(a, b)| a / b)
                .collect();
            return RealTensor::new(data, self.shape.clone());
        }

        // Broadcasting path
        let result_shape = Tensor::<f64>::broadcast_shape(&self.shape, &other.shape)?;
        let result_strides = Tensor::<f64>::compute_strides(&result_shape);
        let result_size: usize = result_shape.iter().product();

        let mut data = Vec::with_capacity(result_size);

        for flat_idx in 0..result_size {
            let result_indices =
                Tensor::<f64>::unravel_index(flat_idx, &result_shape, &result_strides);
            let self_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &self.shape, &result_shape);
            let other_indices =
                Tensor::<f64>::broadcast_index(&result_indices, &other.shape, &result_shape);

            let a = self.get(&self_indices)?;
            let b = other.get(&other_indices)?;
            data.push(a / b);
        }

        RealTensor::new(data, result_shape)
    }

    /// Scalar addition
    pub fn add_scalar(&self, scalar: f64) -> RealTensor {
        let data: Vec<f64> = self.data.iter().map(|x| x + scalar).collect();
        RealTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Scalar subtraction (tensor - scalar)
    pub fn sub_scalar(&self, scalar: f64) -> RealTensor {
        let data: Vec<f64> = self.data.iter().map(|x| x - scalar).collect();
        RealTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Scalar multiplication
    pub fn mul_scalar(&self, scalar: f64) -> RealTensor {
        let data: Vec<f64> = self.data.iter().map(|x| x * scalar).collect();
        RealTensor::new(data, self.shape.clone()).unwrap()
    }

    /// Scalar division (tensor / scalar)
    pub fn div_scalar(&self, scalar: f64) -> Result<RealTensor, String> {
        if scalar == 0.0 {
            return Err("Division by zero".to_string());
        }
        let data: Vec<f64> = self.data.iter().map(|x| x / scalar).collect();
        Ok(RealTensor::new(data, self.shape.clone()).unwrap())
    }

    /// Negate all elements
    pub fn negate(&self) -> RealTensor {
        let data: Vec<f64> = self.data.iter().map(|x| -x).collect();
        RealTensor::new(data, self.shape.clone()).unwrap()
    }
}
