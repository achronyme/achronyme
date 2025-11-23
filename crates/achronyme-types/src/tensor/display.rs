use super::core::{ComplexTensor, RealTensor};
use crate::complex::Complex;
use std::fmt;

// Display formatting for RealTensor
impl fmt::Display for RealTensor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rank() {
            0 => {
                // Scalar
                write!(f, "{}", self.data[0])
            }
            1 => {
                // Vector
                write!(f, "[")?;
                for (i, val) in self.data.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, "]")
            }
            2 => {
                // Matrix
                let rows = self.shape[0];
                let cols = self.shape[1];
                write!(f, "[")?;
                for i in 0..rows {
                    if i > 0 {
                        write!(f, "\n ")?;
                    }
                    write!(f, "[")?;
                    for j in 0..cols {
                        if j > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", self.data[i * cols + j])?;
                    }
                    write!(f, "]")?;
                }
                write!(f, "]")
            }
            _ => {
                // Higher-order tensor (3D+)
                format_nd_tensor(f, &self.data, &self.shape, 0, 0)
            }
        }
    }
}

/// Recursively format N-dimensional tensors
fn format_nd_tensor(
    f: &mut fmt::Formatter<'_>,
    data: &[f64],
    shape: &[usize],
    depth: usize,
    offset: usize,
) -> fmt::Result {
    if shape.is_empty() {
        return write!(f, "{}", data[offset]);
    }

    if shape.len() == 1 {
        // Last dimension - print as vector
        write!(f, "[")?;
        for i in 0..shape[0] {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", data[offset + i])?;
        }
        write!(f, "]")
    } else {
        // Multiple dimensions remaining
        let current_dim = shape[0];
        let stride: usize = shape[1..].iter().product();

        write!(f, "[")?;
        for i in 0..current_dim {
            if i > 0 {
                write!(f, ",")?;
                // Add newline and indentation for readability
                write!(f, "\n")?;
                for _ in 0..=depth {
                    write!(f, " ")?;
                }
            }
            format_nd_tensor(f, data, &shape[1..], depth + 1, offset + i * stride)?;
        }
        write!(f, "]")
    }
}

// Display formatting for ComplexTensor
impl fmt::Display for ComplexTensor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rank() {
            0 => {
                // Scalar
                write!(f, "{}", self.data[0])
            }
            1 => {
                // Vector
                write!(f, "[")?;
                for (i, val) in self.data.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", val)?;
                }
                write!(f, "]")
            }
            2 => {
                // Matrix
                let rows = self.shape[0];
                let cols = self.shape[1];
                write!(f, "[")?;
                for i in 0..rows {
                    if i > 0 {
                        write!(f, "\n ")?;
                    }
                    write!(f, "[")?;
                    for j in 0..cols {
                        if j > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", self.data[i * cols + j])?;
                    }
                    write!(f, "]")?;
                }
                write!(f, "]")
            }
            _ => {
                // Higher-order tensor (3D+)
                format_nd_complex_tensor(f, &self.data, &self.shape, 0, 0)
            }
        }
    }
}

/// Recursively format N-dimensional complex tensors
fn format_nd_complex_tensor(
    f: &mut fmt::Formatter<'_>,
    data: &[Complex],
    shape: &[usize],
    depth: usize,
    offset: usize,
) -> fmt::Result {
    if shape.is_empty() {
        return write!(f, "{}", data[offset]);
    }

    if shape.len() == 1 {
        // Last dimension - print as vector
        write!(f, "[")?;
        for i in 0..shape[0] {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", data[offset + i])?;
        }
        write!(f, "]")
    } else {
        // Multiple dimensions remaining
        let current_dim = shape[0];
        let stride: usize = shape[1..].iter().product();

        write!(f, "[")?;
        for i in 0..current_dim {
            if i > 0 {
                write!(f, ",")?;
                // Add newline and indentation for readability
                write!(f, "\n")?;
                for _ in 0..=depth {
                    write!(f, " ")?;
                }
            }
            format_nd_complex_tensor(f, data, &shape[1..], depth + 1, offset + i * stride)?;
        }
        write!(f, "]")
    }
}
