use super::*;
use crate::complex::Complex;

#[test]
fn test_tensor_creation() {
    let t = RealTensor::new(vec![1.0, 2.0, 3.0, 4.0], vec![2, 2]).unwrap();
    assert_eq!(t.rank(), 2);
    assert_eq!(t.size(), 4);
    assert_eq!(t.shape(), &[2, 2]);
}

#[test]
fn test_scalar() {
    let s = RealTensor::scalar(5.0);
    assert_eq!(s.rank(), 0);
    assert_eq!(s.size(), 1);
    assert!(s.is_scalar());
}

#[test]
fn test_vector() {
    let v = RealTensor::vector(vec![1.0, 2.0, 3.0]);
    assert_eq!(v.rank(), 1);
    assert_eq!(v.size(), 3);
    assert!(v.is_vector());
}

#[test]
fn test_matrix() {
    let m = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
    assert_eq!(m.rank(), 2);
    assert_eq!(m.shape(), &[2, 3]);
    assert!(m.is_matrix());
}

#[test]
fn test_get_set() {
    let mut t = RealTensor::matrix(2, 2, vec![1.0, 2.0, 3.0, 4.0]).unwrap();
    assert_eq!(*t.get(&[0, 0]).unwrap(), 1.0);
    assert_eq!(*t.get(&[1, 1]).unwrap(), 4.0);

    t.set(&[0, 1], 10.0).unwrap();
    assert_eq!(*t.get(&[0, 1]).unwrap(), 10.0);
}

#[test]
fn test_reshape() {
    let t = RealTensor::vector(vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
    let reshaped = t.reshape(vec![2, 3]).unwrap();
    assert_eq!(reshaped.shape(), &[2, 3]);
    assert_eq!(reshaped.rank(), 2);
}

#[test]
fn test_zeros_ones() {
    let z = RealTensor::zeros(vec![2, 3]);
    assert_eq!(z.size(), 6);
    assert!(z.data.iter().all(|&x| x == 0.0));

    let o = RealTensor::ones(vec![2, 3]);
    assert!(o.data.iter().all(|&x| x == 1.0));
}

#[test]
fn test_eye() {
    let eye = RealTensor::eye(3);
    assert_eq!(eye.shape(), &[3, 3]);
    assert_eq!(*eye.get(&[0, 0]).unwrap(), 1.0);
    assert_eq!(*eye.get(&[1, 1]).unwrap(), 1.0);
    assert_eq!(*eye.get(&[0, 1]).unwrap(), 0.0);
}

#[test]
fn test_complex_tensor() {
    let data = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    let ct = ComplexTensor::vector(data);
    assert_eq!(ct.rank(), 1);
    assert_eq!(ct.size(), 2);
}

// ========================================================================
// Broadcasting Tests
// ========================================================================

#[test]
fn test_broadcast_compatibility() {
    assert!(RealTensor::can_broadcast(&[3, 4], &[3, 4])); // Same shape
    assert!(RealTensor::can_broadcast(&[3, 1], &[3, 4])); // One dimension is 1
    assert!(RealTensor::can_broadcast(&[3, 4], &[1, 4])); // One dimension is 1
    assert!(RealTensor::can_broadcast(&[5, 3, 4], &[3, 4])); // Different ranks
    assert!(!RealTensor::can_broadcast(&[3, 4], &[2, 4])); // Incompatible
}

#[test]
fn test_broadcast_shape() {
    assert_eq!(
        RealTensor::broadcast_shape(&[3, 4], &[3, 4]).unwrap(),
        vec![3, 4]
    );
    assert_eq!(
        RealTensor::broadcast_shape(&[3, 1], &[3, 4]).unwrap(),
        vec![3, 4]
    );
    assert_eq!(
        RealTensor::broadcast_shape(&[5, 3, 4], &[3, 4]).unwrap(),
        vec![5, 3, 4]
    );
}

// ========================================================================
// Arithmetic Tests
// ========================================================================

#[test]
fn test_tensor_addition() {
    let a = RealTensor::vector(vec![1.0, 2.0, 3.0]);
    let b = RealTensor::vector(vec![4.0, 5.0, 6.0]);
    let c = a.add(&b).unwrap();

    assert_eq!(c.data(), &[5.0, 7.0, 9.0]);
}

#[test]
fn test_tensor_subtraction() {
    let a = RealTensor::vector(vec![5.0, 7.0, 9.0]);
    let b = RealTensor::vector(vec![1.0, 2.0, 3.0]);
    let c = a.sub(&b).unwrap();

    assert_eq!(c.data(), &[4.0, 5.0, 6.0]);
}

#[test]
fn test_tensor_multiplication() {
    let a = RealTensor::vector(vec![2.0, 3.0, 4.0]);
    let b = RealTensor::vector(vec![5.0, 6.0, 7.0]);
    let c = a.mul(&b).unwrap();

    assert_eq!(c.data(), &[10.0, 18.0, 28.0]);
}

#[test]
fn test_tensor_division() {
    let a = RealTensor::vector(vec![10.0, 20.0, 30.0]);
    let b = RealTensor::vector(vec![2.0, 4.0, 5.0]);
    let c = a.div(&b).unwrap();

    assert_eq!(c.data(), &[5.0, 5.0, 6.0]);
}

#[test]
fn test_scalar_operations() {
    let t = RealTensor::vector(vec![1.0, 2.0, 3.0]);

    let add_result = t.add_scalar(10.0);
    assert_eq!(add_result.data(), &[11.0, 12.0, 13.0]);

    let mul_result = t.mul_scalar(2.0);
    assert_eq!(mul_result.data(), &[2.0, 4.0, 6.0]);

    let neg_result = t.negate();
    assert_eq!(neg_result.data(), &[-1.0, -2.0, -3.0]);
}

#[test]
fn test_complex_arithmetic() {
    let a = ComplexTensor::vector(vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)]);
    let b = ComplexTensor::vector(vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)]);

    let c = a.add(&b).unwrap();
    assert_eq!(c.data[0], Complex::new(6.0, 8.0));
    assert_eq!(c.data[1], Complex::new(10.0, 12.0));
}

// ========================================================================
// Vector Operation Tests
// ========================================================================

#[test]
fn test_dot_product() {
    let a = RealTensor::vector(vec![1.0, 2.0, 3.0]);
    let b = RealTensor::vector(vec![4.0, 5.0, 6.0]);

    let result = a.dot(&b).unwrap();
    assert_eq!(result, 32.0); // 1*4 + 2*5 + 3*6 = 32
}

#[test]
fn test_cross_product() {
    let a = RealTensor::vector(vec![1.0, 0.0, 0.0]);
    let b = RealTensor::vector(vec![0.0, 1.0, 0.0]);

    let c = a.cross(&b).unwrap();
    assert_eq!(c.data(), &[0.0, 0.0, 1.0]);
}

#[test]
fn test_norm() {
    let v = RealTensor::vector(vec![3.0, 4.0]);
    assert_eq!(v.norm(), 5.0); // 3-4-5 triangle

    let v2 = RealTensor::vector(vec![1.0, 2.0, 2.0]);
    assert_eq!(v2.norm(), 3.0);
}

#[test]
fn test_normalize() {
    let v = RealTensor::vector(vec![3.0, 4.0]);
    let normalized = v.normalize().unwrap();

    assert!((normalized.data()[0] - 0.6).abs() < 1e-10);
    assert!((normalized.data()[1] - 0.8).abs() < 1e-10);
    assert!((normalized.norm() - 1.0).abs() < 1e-10);
}

#[test]
fn test_statistics() {
    let t = RealTensor::vector(vec![1.0, 2.0, 3.0, 4.0, 5.0]);

    assert_eq!(t.sum(), 15.0);
    assert_eq!(t.mean().unwrap(), 3.0);
    assert_eq!(t.max().unwrap(), 5.0);
    assert_eq!(t.min().unwrap(), 1.0);
}

#[test]
fn test_complex_dot() {
    let a = ComplexTensor::vector(vec![Complex::new(1.0, 0.0), Complex::new(0.0, 1.0)]);
    let b = ComplexTensor::vector(vec![Complex::new(1.0, 0.0), Complex::new(0.0, 1.0)]);

    let result = a.dot(&b).unwrap();
    // Hermitian: conj(a[0])*b[0] + conj(a[1])*b[1]
    // = (1+0i)*conj * (1+0i) + (0+1i)*conj * (0+1i)
    // = 1 + (0-1i)*(0+1i) = 1 + 1 = 2
    assert_eq!(result, Complex::new(2.0, 0.0));
}

#[test]
fn test_complex_norm() {
    let v = ComplexTensor::vector(vec![Complex::new(3.0, 0.0), Complex::new(0.0, 4.0)]);
    assert_eq!(v.norm(), 5.0);
}

// ========================================================================
// Matrix Operation Tests
// ========================================================================

#[test]
fn test_transpose() {
    let m = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();

    let mt = m.transpose().unwrap();
    assert_eq!(mt.shape(), &[3, 2]);
    assert_eq!(*mt.get(&[0, 0]).unwrap(), 1.0);
    assert_eq!(*mt.get(&[0, 1]).unwrap(), 4.0);
    assert_eq!(*mt.get(&[1, 0]).unwrap(), 2.0);
    assert_eq!(*mt.get(&[1, 1]).unwrap(), 5.0);
}

#[test]
fn test_trace() {
    let m = RealTensor::matrix(3, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0]).unwrap();

    let tr = m.trace().unwrap();
    assert_eq!(tr, 15.0); // 1 + 5 + 9
}

#[test]
fn test_matrix_multiplication() {
    let a = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();

    let b = RealTensor::matrix(3, 2, vec![7.0, 8.0, 9.0, 10.0, 11.0, 12.0]).unwrap();

    let c = a.matmul(&b).unwrap();
    assert_eq!(c.shape(), &[2, 2]);

    // Result should be:
    // [1*7 + 2*9 + 3*11,  1*8 + 2*10 + 3*12]   = [58, 64]
    // [4*7 + 5*9 + 6*11,  4*8 + 5*10 + 6*12]   = [139, 154]
    assert_eq!(*c.get(&[0, 0]).unwrap(), 58.0);
    assert_eq!(*c.get(&[0, 1]).unwrap(), 64.0);
    assert_eq!(*c.get(&[1, 0]).unwrap(), 139.0);
    assert_eq!(*c.get(&[1, 1]).unwrap(), 154.0);
}

#[test]
fn test_complex_hermitian() {
    let m = ComplexTensor::zeros(vec![2, 2]);
    let h = m.hermitian().unwrap();
    assert_eq!(h.shape(), &[2, 2]);
}

#[test]
fn test_complex_trace() {
    let m = ComplexTensor::eye(3);
    let tr = m.trace().unwrap();
    assert_eq!(tr, Complex::new(3.0, 0.0));
}

// ========================================================================
// Type Conversion Tests
// ========================================================================

#[test]
fn test_real_to_complex() {
    let r = RealTensor::vector(vec![1.0, 2.0, 3.0]);
    let c = r.to_complex();

    assert_eq!(c.size(), 3);
    assert_eq!(c.data[0], Complex::new(1.0, 0.0));
    assert_eq!(c.data[1], Complex::new(2.0, 0.0));
}

#[test]
fn test_complex_abs() {
    let c = ComplexTensor::vector(vec![Complex::new(3.0, 4.0), Complex::new(5.0, 12.0)]);

    let abs_tensor = c.abs();
    assert_eq!(abs_tensor.data()[0], 5.0); // sqrt(3^2 + 4^2)
    assert_eq!(abs_tensor.data()[1], 13.0); // sqrt(5^2 + 12^2)
}

// ========================================================================
// N-Dimensional Broadcasting Tests
// ========================================================================

#[test]
fn test_broadcast_vector_to_matrix() {
    // Matrix [2, 3] + Vector [3] → broadcast to [2, 3]
    let m = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();

    let v = RealTensor::vector(vec![10.0, 20.0, 30.0]);

    let result = m.add(&v).unwrap();

    assert_eq!(result.shape(), &[2, 3]);
    // First row: [1+10, 2+20, 3+30] = [11, 22, 33]
    assert_eq!(*result.get(&[0, 0]).unwrap(), 11.0);
    assert_eq!(*result.get(&[0, 1]).unwrap(), 22.0);
    assert_eq!(*result.get(&[0, 2]).unwrap(), 33.0);
    // Second row: [4+10, 5+20, 6+30] = [14, 25, 36]
    assert_eq!(*result.get(&[1, 0]).unwrap(), 14.0);
    assert_eq!(*result.get(&[1, 1]).unwrap(), 25.0);
    assert_eq!(*result.get(&[1, 2]).unwrap(), 36.0);
}

#[test]
fn test_broadcast_column_to_matrix() {
    // Matrix [2, 3] + Column [2, 1] → broadcast to [2, 3]
    let m = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();

    let col = RealTensor::matrix(2, 1, vec![100.0, 200.0]).unwrap();

    let result = m.add(&col).unwrap();

    assert_eq!(result.shape(), &[2, 3]);
    // First row: [1+100, 2+100, 3+100] = [101, 102, 103]
    assert_eq!(*result.get(&[0, 0]).unwrap(), 101.0);
    assert_eq!(*result.get(&[0, 1]).unwrap(), 102.0);
    assert_eq!(*result.get(&[0, 2]).unwrap(), 103.0);
    // Second row: [4+200, 5+200, 6+200] = [204, 205, 206]
    assert_eq!(*result.get(&[1, 0]).unwrap(), 204.0);
    assert_eq!(*result.get(&[1, 1]).unwrap(), 205.0);
    assert_eq!(*result.get(&[1, 2]).unwrap(), 206.0);
}

#[test]
fn test_broadcast_3d_tensor() {
    // Tensor [2, 2, 1] + Tensor [2, 1, 3] → broadcast to [2, 2, 3]
    let t1 = RealTensor::new(vec![1.0, 2.0, 3.0, 4.0], vec![2, 2, 1]).unwrap();
    let t2 = RealTensor::new(vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0], vec![2, 1, 3]).unwrap();

    let result = t1.add(&t2).unwrap();

    assert_eq!(result.shape(), &[2, 2, 3]);
    assert_eq!(result.size(), 12);

    // Check a few key elements
    assert_eq!(*result.get(&[0, 0, 0]).unwrap(), 11.0); // 1 + 10
    assert_eq!(*result.get(&[0, 0, 1]).unwrap(), 21.0); // 1 + 20
    assert_eq!(*result.get(&[0, 0, 2]).unwrap(), 31.0); // 1 + 30
}

#[test]
fn test_broadcast_subtraction() {
    // Test broadcasting with subtraction
    let m = RealTensor::matrix(3, 2, vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0]).unwrap();

    let v = RealTensor::vector(vec![1.0, 2.0]);

    let result = m.sub(&v).unwrap();

    assert_eq!(result.shape(), &[3, 2]);
    assert_eq!(*result.get(&[0, 0]).unwrap(), 9.0); // 10 - 1
    assert_eq!(*result.get(&[0, 1]).unwrap(), 18.0); // 20 - 2
    assert_eq!(*result.get(&[1, 0]).unwrap(), 29.0); // 30 - 1
    assert_eq!(*result.get(&[1, 1]).unwrap(), 38.0); // 40 - 2
}

#[test]
fn test_broadcast_multiplication() {
    // Test broadcasting with multiplication
    let m = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();

    let v = RealTensor::vector(vec![10.0, 100.0, 1000.0]);

    let result = m.mul(&v).unwrap();

    assert_eq!(result.shape(), &[2, 3]);
    assert_eq!(*result.get(&[0, 0]).unwrap(), 10.0); // 1 * 10
    assert_eq!(*result.get(&[0, 1]).unwrap(), 200.0); // 2 * 100
    assert_eq!(*result.get(&[0, 2]).unwrap(), 3000.0); // 3 * 1000
    assert_eq!(*result.get(&[1, 0]).unwrap(), 40.0); // 4 * 10
    assert_eq!(*result.get(&[1, 1]).unwrap(), 500.0); // 5 * 100
    assert_eq!(*result.get(&[1, 2]).unwrap(), 6000.0); // 6 * 1000
}

#[test]
fn test_broadcast_division() {
    // Test broadcasting with division
    let m = RealTensor::matrix(2, 2, vec![100.0, 200.0, 300.0, 400.0]).unwrap();

    let v = RealTensor::vector(vec![10.0, 20.0]);

    let result = m.div(&v).unwrap();

    assert_eq!(result.shape(), &[2, 2]);
    assert_eq!(*result.get(&[0, 0]).unwrap(), 10.0); // 100 / 10
    assert_eq!(*result.get(&[0, 1]).unwrap(), 10.0); // 200 / 20
    assert_eq!(*result.get(&[1, 0]).unwrap(), 30.0); // 300 / 10
    assert_eq!(*result.get(&[1, 1]).unwrap(), 20.0); // 400 / 20
}

#[test]
fn test_broadcast_complex_tensors() {
    // Test broadcasting with complex tensors
    let m = ComplexTensor::new(
        vec![
            Complex::new(1.0, 1.0),
            Complex::new(2.0, 2.0),
            Complex::new(3.0, 3.0),
            Complex::new(4.0, 4.0),
        ],
        vec![2, 2],
    )
    .unwrap();

    let v = ComplexTensor::vector(vec![Complex::new(10.0, 0.0), Complex::new(20.0, 0.0)]);

    let result = m.add(&v).unwrap();

    assert_eq!(result.shape(), &[2, 2]);
    assert_eq!(*result.get(&[0, 0]).unwrap(), Complex::new(11.0, 1.0)); // (1+1i) + 10
    assert_eq!(*result.get(&[0, 1]).unwrap(), Complex::new(22.0, 2.0)); // (2+2i) + 20
}

#[test]
fn test_broadcast_incompatible_shapes() {
    // Test that incompatible shapes fail properly
    let m1 = RealTensor::matrix(2, 3, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
    let m2 = RealTensor::matrix(2, 4, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]).unwrap();

    let result = m1.add(&m2);
    assert!(result.is_err());
}

#[test]
fn test_broadcast_higher_rank() {
    // Test broadcasting from lower to higher rank
    // [3, 4, 5] + [5] → should broadcast to [3, 4, 5]
    let t1 = RealTensor::ones(vec![3, 4, 5]);
    let t2 = RealTensor::vector(vec![1.0, 2.0, 3.0, 4.0, 5.0]);

    let result = t1.add(&t2).unwrap();

    assert_eq!(result.shape(), &[3, 4, 5]);

    // Every element in the last dimension should be offset by the vector
    assert_eq!(*result.get(&[0, 0, 0]).unwrap(), 2.0); // 1 + 1
    assert_eq!(*result.get(&[0, 0, 1]).unwrap(), 3.0); // 1 + 2
    assert_eq!(*result.get(&[0, 0, 2]).unwrap(), 4.0); // 1 + 3
    assert_eq!(*result.get(&[0, 0, 3]).unwrap(), 5.0); // 1 + 4
    assert_eq!(*result.get(&[0, 0, 4]).unwrap(), 6.0); // 1 + 5
}
