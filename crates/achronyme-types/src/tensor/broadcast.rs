use super::core::{Tensor, TensorError};

// ============================================================================
// Broadcasting Support
// ============================================================================

impl<T: Clone> Tensor<T> {
    /// Check if two shapes are broadcast-compatible
    /// Following NumPy broadcasting rules: dimensions are compatible when:
    /// 1. They are equal, or
    /// 2. One of them is 1
    pub fn can_broadcast(shape1: &[usize], shape2: &[usize]) -> bool {
        let max_len = shape1.len().max(shape2.len());

        for i in 0..max_len {
            let dim1 = if i < shape1.len() {
                shape1[shape1.len() - 1 - i]
            } else {
                1
            };

            let dim2 = if i < shape2.len() {
                shape2[shape2.len() - 1 - i]
            } else {
                1
            };

            if dim1 != dim2 && dim1 != 1 && dim2 != 1 {
                return false;
            }
        }

        true
    }

    /// Compute the broadcasted shape of two tensors
    pub fn broadcast_shape(shape1: &[usize], shape2: &[usize]) -> Result<Vec<usize>, TensorError> {
        if !Self::can_broadcast(shape1, shape2) {
            return Err(TensorError::BroadcastError {
                shape1: shape1.to_vec(),
                shape2: shape2.to_vec(),
            });
        }

        let max_len = shape1.len().max(shape2.len());
        let mut result = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let dim1 = if i < shape1.len() {
                shape1[shape1.len() - 1 - i]
            } else {
                1
            };

            let dim2 = if i < shape2.len() {
                shape2[shape2.len() - 1 - i]
            } else {
                1
            };

            result.push(dim1.max(dim2));
        }

        result.reverse();
        Ok(result)
    }

    /// Convert a flat index to multi-dimensional indices given a shape
    pub(crate) fn unravel_index(flat_idx: usize, shape: &[usize], strides: &[usize]) -> Vec<usize> {
        let mut indices = Vec::with_capacity(shape.len());
        let mut remaining = flat_idx;

        for &stride in strides.iter() {
            indices.push(remaining / stride);
            remaining %= stride;
        }

        indices
    }

    /// Adjust multi-dimensional indices for broadcasting
    /// Maps indices from result shape to indices in original shape
    pub(crate) fn broadcast_index(
        result_indices: &[usize],
        original_shape: &[usize],
        result_shape: &[usize],
    ) -> Vec<usize> {
        let rank_diff = result_shape.len() - original_shape.len();
        let mut adjusted = Vec::with_capacity(original_shape.len());

        for i in 0..original_shape.len() {
            let result_idx = result_indices[i + rank_diff];
            // If the original dimension is 1, always use index 0 (broadcasting)
            adjusted.push(if original_shape[i] == 1 {
                0
            } else {
                result_idx
            });
        }

        adjusted
    }
}
