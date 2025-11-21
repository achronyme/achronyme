//! Digital Signal Processing (DSP) functions
//!
//! This module provides DSP operations for the VM:
//! - FFT: Fast Fourier Transform (forward and inverse)
//! - FFT utilities: Magnitude and phase extraction
//! - Convolution: Time-domain and frequency-domain
//! - Windows: Hanning, Hamming, Blackman, Rectangular
//! - Utilities: Linear space generation

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::complex::Complex;
use achronyme_types::tensor::{ComplexTensor, RealTensor};
use std::cell::RefCell;
use std::rc::Rc;

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a VM Vector to a Vec<f64>
fn vector_to_f64_vec(vec_rc: &Rc<RefCell<Vec<Value>>>) -> Result<Vec<f64>, VmError> {
    let vec = vec_rc.borrow();
    let mut result = Vec::with_capacity(vec.len());

    for (i, val) in vec.iter().enumerate() {
        match val {
            Value::Number(n) => result.push(*n),
            _ => {
                return Err(VmError::TypeError {
                    operation: "DSP".to_string(),
                    expected: "numeric vector".to_string(),
                    got: format!("element {} is {:?}", i, val),
                })
            }
        }
    }

    Ok(result)
}

/// Convert a VM Vector to a Vec<Complex>
fn vector_to_complex_vec(vec_rc: &Rc<RefCell<Vec<Value>>>) -> Result<Vec<Complex>, VmError> {
    let vec = vec_rc.borrow();
    let mut result = Vec::with_capacity(vec.len());

    for (i, val) in vec.iter().enumerate() {
        match val {
            Value::Number(n) => result.push(Complex::new(*n, 0.0)),
            Value::Complex(c) => result.push(*c),
            _ => {
                return Err(VmError::TypeError {
                    operation: "DSP".to_string(),
                    expected: "numeric or complex vector".to_string(),
                    got: format!("element {} is {:?}", i, val),
                })
            }
        }
    }

    Ok(result)
}

/// Convert a ComplexTensor to a VM Vector of Complex values
fn complex_tensor_to_vector(tensor: ComplexTensor) -> Value {
    let values: Vec<Value> = tensor
        .data
        .into_iter()
        .map(Value::Complex)
        .collect();

    Value::Vector(Rc::new(RefCell::new(values)))
}

/// Convert a RealTensor to a VM Vector of Number values
fn real_tensor_to_vector(tensor: RealTensor) -> Value {
    let values: Vec<Value> = tensor
        .data
        .into_iter()
        .map(Value::Number)
        .collect();

    Value::Vector(Rc::new(RefCell::new(values)))
}

// ============================================================================
// FFT Functions
// ============================================================================

/// Forward Fast Fourier Transform
///
/// Computes the FFT of a signal (real or complex).
///
/// # Arguments
/// * `signal` - Input signal (Vector of numbers or complex values)
///
/// # Returns
/// Complex spectrum as a ComplexTensor wrapped in a Vector
///
/// # Example
/// ```achronyme
/// let signal = [1.0, 0.0, -1.0, 0.0];
/// let spectrum = fft(signal);
/// ```
pub fn vm_fft(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "fft() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec_rc) => {
            // Try to parse as complex vector first
            let complex_input = vector_to_complex_vec(vec_rc)?;

            // Compute FFT using achronyme-dsp
            let spectrum = achronyme_dsp::fft_transform(&complex_input);

            // Convert result to ComplexTensor
            let tensor = ComplexTensor::new(spectrum, vec![complex_input.len()])
                .map_err(|e| VmError::Runtime(format!("FFT tensor creation failed: {}", e)))?;

            Ok(Value::ComplexTensor(tensor))
        }
        Value::Tensor(tensor) => {
            // Convert RealTensor to complex
            let complex_input: Vec<Complex> = tensor
                .data
                .iter()
                .map(|&x| Complex::new(x, 0.0))
                .collect();

            // Compute FFT
            let spectrum = achronyme_dsp::fft_transform(&complex_input);

            // Convert to ComplexTensor
            let result = ComplexTensor::new(spectrum, tensor.shape.clone())
                .map_err(|e| VmError::Runtime(format!("FFT tensor creation failed: {}", e)))?;

            Ok(Value::ComplexTensor(result))
        }
        _ => Err(VmError::TypeError {
            operation: "fft".to_string(),
            expected: "Vector or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Inverse Fast Fourier Transform
///
/// Computes the inverse FFT of a spectrum.
///
/// # Arguments
/// * `spectrum` - Input spectrum (ComplexTensor or Vector of complex values)
///
/// # Returns
/// Real signal as a Tensor
///
/// # Example
/// ```achronyme
/// let spectrum = fft(signal);
/// let reconstructed = ifft(spectrum);
/// ```
pub fn vm_ifft(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "ifft() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::ComplexTensor(tensor) => {
            // Compute IFFT using achronyme-dsp
            let signal = achronyme_dsp::ifft_transform(&tensor.data);

            // Extract real parts
            let real_signal: Vec<f64> = signal.iter().map(|c| c.re).collect();

            // Convert to RealTensor
            let result = RealTensor::new(real_signal, tensor.shape.clone())
                .map_err(|e| VmError::Runtime(format!("IFFT tensor creation failed: {}", e)))?;

            Ok(Value::Tensor(result))
        }
        Value::Vector(vec_rc) => {
            let complex_input = vector_to_complex_vec(vec_rc)?;

            // Compute IFFT
            let signal = achronyme_dsp::ifft_transform(&complex_input);

            // Extract real parts
            let real_signal: Vec<f64> = signal.iter().map(|c| c.re).collect();

            // Convert to Tensor
            let result = RealTensor::new(real_signal, vec![complex_input.len()])
                .map_err(|e| VmError::Runtime(format!("IFFT tensor creation failed: {}", e)))?;

            Ok(Value::Tensor(result))
        }
        _ => Err(VmError::TypeError {
            operation: "ifft".to_string(),
            expected: "ComplexTensor or Vector".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// FFT Magnitude
///
/// Computes the magnitude (absolute value) of the FFT.
///
/// # Arguments
/// * `signal` - Input signal (Vector of numbers)
///
/// # Returns
/// Magnitude spectrum as a Tensor
///
/// # Example
/// ```achronyme
/// let signal = [1.0, 0.0, -1.0, 0.0];
/// let magnitude = fft_mag(signal);
/// ```
pub fn vm_fft_mag(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "fft_mag() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec_rc) => {
            let real_input = vector_to_f64_vec(vec_rc)?;

            // Compute FFT
            let spectrum = achronyme_dsp::fft_real(&real_input);

            // Compute magnitudes
            let magnitudes: Vec<f64> = spectrum.iter().map(|c| c.magnitude()).collect();

            // Convert to Tensor
            let result = RealTensor::new(magnitudes, vec![real_input.len()])
                .map_err(|e| VmError::Runtime(format!("FFT magnitude tensor creation failed: {}", e)))?;

            Ok(Value::Tensor(result))
        }
        Value::Tensor(tensor) => {
            // Compute FFT
            let spectrum = achronyme_dsp::fft_real(&tensor.data);

            // Compute magnitudes
            let magnitudes: Vec<f64> = spectrum.iter().map(|c| c.magnitude()).collect();

            // Convert to Tensor with same shape
            let result = RealTensor::new(magnitudes, tensor.shape.clone())
                .map_err(|e| VmError::Runtime(format!("FFT magnitude tensor creation failed: {}", e)))?;

            Ok(Value::Tensor(result))
        }
        _ => Err(VmError::TypeError {
            operation: "fft_mag".to_string(),
            expected: "Vector or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// FFT Phase
///
/// Computes the phase (argument) of the FFT.
///
/// # Arguments
/// * `signal` - Input signal (Vector of numbers)
///
/// # Returns
/// Phase spectrum as a Tensor (in radians)
///
/// # Example
/// ```achronyme
/// let signal = [1.0, 0.0, -1.0, 0.0];
/// let phase = fft_phase(signal);
/// ```
pub fn vm_fft_phase(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "fft_phase() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Vector(vec_rc) => {
            let real_input = vector_to_f64_vec(vec_rc)?;

            // Compute FFT
            let spectrum = achronyme_dsp::fft_real(&real_input);

            // Compute phases
            let phases: Vec<f64> = spectrum.iter().map(|c| c.arg()).collect();

            // Convert to Tensor
            let result = RealTensor::new(phases, vec![real_input.len()])
                .map_err(|e| VmError::Runtime(format!("FFT phase tensor creation failed: {}", e)))?;

            Ok(Value::Tensor(result))
        }
        Value::Tensor(tensor) => {
            // Compute FFT
            let spectrum = achronyme_dsp::fft_real(&tensor.data);

            // Compute phases
            let phases: Vec<f64> = spectrum.iter().map(|c| c.arg()).collect();

            // Convert to Tensor with same shape
            let result = RealTensor::new(phases, tensor.shape.clone())
                .map_err(|e| VmError::Runtime(format!("FFT phase tensor creation failed: {}", e)))?;

            Ok(Value::Tensor(result))
        }
        _ => Err(VmError::TypeError {
            operation: "fft_phase".to_string(),
            expected: "Vector or Tensor".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

// ============================================================================
// Convolution Functions
// ============================================================================

/// Time-domain Convolution
///
/// Computes the discrete convolution of two signals using direct method.
///
/// # Arguments
/// * `signal` - Input signal (Vector)
/// * `kernel` - Convolution kernel (Vector)
///
/// # Returns
/// Convolved signal as a Tensor (length = signal.len() + kernel.len() - 1)
///
/// # Example
/// ```achronyme
/// let signal = [1.0, 2.0, 3.0];
/// let kernel = [0.5, 0.5];
/// let result = conv(signal, kernel);
/// ```
pub fn vm_conv(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "conv() expects 2 arguments, got {}",
            args.len()
        )));
    }

    let signal = match &args[0] {
        Value::Vector(vec_rc) => vector_to_f64_vec(vec_rc)?,
        Value::Tensor(tensor) => tensor.data.clone(),
        _ => {
            return Err(VmError::TypeError {
                operation: "conv".to_string(),
                expected: "Vector or Tensor for signal".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let kernel = match &args[1] {
        Value::Vector(vec_rc) => vector_to_f64_vec(vec_rc)?,
        Value::Tensor(tensor) => tensor.data.clone(),
        _ => {
            return Err(VmError::TypeError {
                operation: "conv".to_string(),
                expected: "Vector or Tensor for kernel".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    // Compute convolution using achronyme-dsp
    let result = achronyme_dsp::convolve(&signal, &kernel);

    // Convert to Tensor
    let output_len = result.len();
    let tensor = RealTensor::new(result, vec![output_len])
        .map_err(|e| VmError::Runtime(format!("Convolution tensor creation failed: {}", e)))?;

    Ok(Value::Tensor(tensor))
}

/// Frequency-domain Convolution (FFT-based)
///
/// Computes convolution using FFT (faster for large signals).
///
/// # Arguments
/// * `signal` - Input signal (Vector)
/// * `kernel` - Convolution kernel (Vector)
///
/// # Returns
/// Convolved signal as a Tensor
///
/// # Example
/// ```achronyme
/// let signal = [1.0, 2.0, 3.0, 4.0];
/// let kernel = [0.25, 0.5, 0.25];
/// let result = conv_fft(signal, kernel);
/// ```
pub fn vm_conv_fft(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 2 {
        return Err(VmError::Runtime(format!(
            "conv_fft() expects 2 arguments, got {}",
            args.len()
        )));
    }

    let signal = match &args[0] {
        Value::Vector(vec_rc) => vector_to_f64_vec(vec_rc)?,
        Value::Tensor(tensor) => tensor.data.clone(),
        _ => {
            return Err(VmError::TypeError {
                operation: "conv_fft".to_string(),
                expected: "Vector or Tensor for signal".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let kernel = match &args[1] {
        Value::Vector(vec_rc) => vector_to_f64_vec(vec_rc)?,
        Value::Tensor(tensor) => tensor.data.clone(),
        _ => {
            return Err(VmError::TypeError {
                operation: "conv_fft".to_string(),
                expected: "Vector or Tensor for kernel".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    // Compute FFT-based convolution using achronyme-dsp
    let result = achronyme_dsp::convolve_fft(&signal, &kernel);

    // Convert to Tensor
    let output_len = result.len();
    let tensor = RealTensor::new(result, vec![output_len])
        .map_err(|e| VmError::Runtime(format!("FFT convolution tensor creation failed: {}", e)))?;

    Ok(Value::Tensor(tensor))
}

// ============================================================================
// Window Functions
// ============================================================================

/// Hanning Window
///
/// Generates a Hanning (Hann) window of specified length.
///
/// # Arguments
/// * `n` - Window length (Number)
///
/// # Returns
/// Hanning window as a Vector
///
/// # Example
/// ```achronyme
/// let window = hanning(128);
/// ```
pub fn vm_hanning(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "hanning() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            let size = *n as usize;

            if *n < 0.0 {
                return Err(VmError::Runtime(
                    "hanning() requires non-negative window size".to_string(),
                ));
            }

            // Generate Hanning window using achronyme-dsp
            let window = achronyme_dsp::hanning_window(size);

            // Convert to VM Vector
            let values: Vec<Value> = window.into_iter().map(Value::Number).collect();
            Ok(Value::Vector(Rc::new(RefCell::new(values))))
        }
        _ => Err(VmError::TypeError {
            operation: "hanning".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Hamming Window
///
/// Generates a Hamming window of specified length.
///
/// # Arguments
/// * `n` - Window length (Number)
///
/// # Returns
/// Hamming window as a Vector
///
/// # Example
/// ```achronyme
/// let window = hamming(256);
/// ```
pub fn vm_hamming(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "hamming() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            let size = *n as usize;

            if *n < 0.0 {
                return Err(VmError::Runtime(
                    "hamming() requires non-negative window size".to_string(),
                ));
            }

            // Generate Hamming window using achronyme-dsp
            let window = achronyme_dsp::hamming_window(size);

            // Convert to VM Vector
            let values: Vec<Value> = window.into_iter().map(Value::Number).collect();
            Ok(Value::Vector(Rc::new(RefCell::new(values))))
        }
        _ => Err(VmError::TypeError {
            operation: "hamming".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Blackman Window
///
/// Generates a Blackman window of specified length.
///
/// # Arguments
/// * `n` - Window length (Number)
///
/// # Returns
/// Blackman window as a Vector
///
/// # Example
/// ```achronyme
/// let window = blackman(512);
/// ```
pub fn vm_blackman(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "blackman() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            let size = *n as usize;

            if *n < 0.0 {
                return Err(VmError::Runtime(
                    "blackman() requires non-negative window size".to_string(),
                ));
            }

            // Generate Blackman window using achronyme-dsp
            let window = achronyme_dsp::blackman_window(size);

            // Convert to VM Vector
            let values: Vec<Value> = window.into_iter().map(Value::Number).collect();
            Ok(Value::Vector(Rc::new(RefCell::new(values))))
        }
        _ => Err(VmError::TypeError {
            operation: "blackman".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

/// Rectangular Window
///
/// Generates a rectangular (boxcar) window of specified length (all ones).
///
/// # Arguments
/// * `n` - Window length (Number)
///
/// # Returns
/// Rectangular window as a Vector
///
/// # Example
/// ```achronyme
/// let window = rectangular(64);
/// ```
pub fn vm_rectangular(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "rectangular() expects 1 argument, got {}",
            args.len()
        )));
    }

    match &args[0] {
        Value::Number(n) => {
            let size = *n as usize;

            if *n < 0.0 {
                return Err(VmError::Runtime(
                    "rectangular() requires non-negative window size".to_string(),
                ));
            }

            // Generate rectangular window using achronyme-dsp
            let window = achronyme_dsp::rectangular_window(size);

            // Convert to VM Vector
            let values: Vec<Value> = window.into_iter().map(Value::Number).collect();
            Ok(Value::Vector(Rc::new(RefCell::new(values))))
        }
        _ => Err(VmError::TypeError {
            operation: "rectangular".to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", args[0]),
        }),
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Linear Space
///
/// Generates n evenly spaced numbers between start and end (inclusive).
///
/// # Arguments
/// * `start` - Start value (Number)
/// * `end` - End value (Number)
/// * `n` - Number of points (Number)
///
/// # Returns
/// Vector of evenly spaced numbers
///
/// # Example
/// ```achronyme
/// let x = linspace(0.0, 10.0, 11);  // [0.0, 1.0, 2.0, ..., 10.0]
/// ```
pub fn vm_linspace(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 3 {
        return Err(VmError::Runtime(format!(
            "linspace() expects 3 arguments, got {}",
            args.len()
        )));
    }

    let start = match &args[0] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "linspace".to_string(),
                expected: "Number for start".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let end = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "linspace".to_string(),
                expected: "Number for end".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let n = match &args[2] {
        Value::Number(num) => {
            if *num < 0.0 {
                return Err(VmError::Runtime(
                    "linspace() requires non-negative number of points".to_string(),
                ));
            }
            *num as usize
        }
        _ => {
            return Err(VmError::TypeError {
                operation: "linspace".to_string(),
                expected: "Number for n".to_string(),
                got: format!("{:?}", args[2]),
            })
        }
    };

    if n == 0 {
        return Ok(Value::Vector(Rc::new(RefCell::new(Vec::new()))));
    }

    if n == 1 {
        return Ok(Value::Vector(Rc::new(RefCell::new(vec![Value::Number(start)]))));
    }

    // Generate linearly spaced values
    let mut values = Vec::with_capacity(n);
    let step = (end - start) / ((n - 1) as f64);

    for i in 0..n {
        let value = start + (i as f64) * step;
        values.push(Value::Number(value));
    }

    Ok(Value::Vector(Rc::new(RefCell::new(values))))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linspace() {
        let mut vm = VM::new();

        // Test basic linspace
        let args = vec![Value::Number(0.0), Value::Number(10.0), Value::Number(11.0)];
        let result = vm_linspace(&mut vm, &args).unwrap();

        if let Value::Vector(vec_rc) = result {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 11);

            // Check first and last values
            if let Value::Number(first) = vec[0] {
                assert!((first - 0.0).abs() < 1e-10);
            }
            if let Value::Number(last) = vec[10] {
                assert!((last - 10.0).abs() < 1e-10);
            }
        } else {
            panic!("Expected Vector");
        }
    }

    #[test]
    fn test_hanning_window() {
        let mut vm = VM::new();

        let args = vec![Value::Number(5.0)];
        let result = vm_hanning(&mut vm, &args).unwrap();

        if let Value::Vector(vec_rc) = result {
            let vec = vec_rc.borrow();
            assert_eq!(vec.len(), 5);
        } else {
            panic!("Expected Vector");
        }
    }

    #[test]
    fn test_fft_roundtrip() {
        let mut vm = VM::new();

        // Create a test signal
        let signal = vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
            Value::Number(4.0),
        ];
        let signal_vec = Value::Vector(Rc::new(RefCell::new(signal)));

        // FFT
        let spectrum = vm_fft(&mut vm, &[signal_vec.clone()]).unwrap();

        // IFFT
        let reconstructed = vm_ifft(&mut vm, &[spectrum]).unwrap();

        // Check it's a tensor
        assert!(matches!(reconstructed, Value::Tensor(_)));
    }

    #[test]
    fn test_convolution() {
        let mut vm = VM::new();

        let signal = Value::Vector(Rc::new(RefCell::new(vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
        ])));

        let kernel = Value::Vector(Rc::new(RefCell::new(vec![
            Value::Number(1.0),
            Value::Number(1.0),
        ])));

        let result = vm_conv(&mut vm, &[signal, kernel]).unwrap();

        if let Value::Tensor(tensor) = result {
            assert_eq!(tensor.data.len(), 4); // 3 + 2 - 1 = 4
        } else {
            panic!("Expected Tensor");
        }
    }
}
