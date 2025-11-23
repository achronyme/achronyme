use std::fmt;
use std::ops::{Add, Div, Mul, Neg, Sub};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

impl Complex {
    pub fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    /// Create a complex number from a real number
    pub fn from_real(re: f64) -> Self {
        Self { re, im: 0.0 }
    }

    /// Create a pure imaginary number
    pub fn from_imag(im: f64) -> Self {
        Self { re: 0.0, im }
    }

    /// Calculate the magnitude (absolute value)
    pub fn magnitude(&self) -> f64 {
        (self.re * self.re + self.im * self.im).sqrt()
    }

    /// Calculate the phase (argument) in radians
    pub fn phase(&self) -> f64 {
        self.im.atan2(self.re)
    }

    /// Calculate the magnitude (absolute value)
    pub fn norm(&self) -> f64 {
        self.magnitude()
    }

    /// Calculate the phase (argument) in radians
    pub fn arg(&self) -> f64 {
        self.phase()
    }

    /// Complex conjugate
    pub fn conjugate(&self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    /// Power of a complex number with real exponent
    pub fn pow(&self, exponent: f64) -> Self {
        let r = self.magnitude();
        let theta = self.phase();
        let new_r = r.powf(exponent);
        let new_theta = theta * exponent;
        Self {
            re: new_r * new_theta.cos(),
            im: new_r * new_theta.sin(),
        }
    }

    /// Power of a complex number with complex exponent
    /// Formula: a^b = e^(b * ln(a))
    pub fn pow_complex(&self, exponent: &Complex) -> Self {
        let ln_self = self.ln();
        let product = *exponent * ln_self;
        product.exp()
    }

    /// Square root of a complex number
    pub fn sqrt(&self) -> Self {
        self.pow(0.5)
    }

    /// Exponential function
    pub fn exp(&self) -> Self {
        let exp_re = self.re.exp();
        Self {
            re: exp_re * self.im.cos(),
            im: exp_re * self.im.sin(),
        }
    }

    /// Natural logarithm
    pub fn ln(&self) -> Self {
        Self {
            re: self.magnitude().ln(),
            im: self.phase(),
        }
    }

    /// Sine function
    pub fn sin(&self) -> Self {
        Self {
            re: self.re.sin() * self.im.cosh(),
            im: self.re.cos() * self.im.sinh(),
        }
    }

    /// Cosine function
    pub fn cos(&self) -> Self {
        Self {
            re: self.re.cos() * self.im.cosh(),
            im: -self.re.sin() * self.im.sinh(),
        }
    }

    /// Tangent function
    pub fn tan(&self) -> Self {
        self.sin() / self.cos()
    }
}

// Addition
impl Add for Complex {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            re: self.re + rhs.re,
            im: self.im + rhs.im,
        }
    }
}

// Subtraction
impl Sub for Complex {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            re: self.re - rhs.re,
            im: self.im - rhs.im,
        }
    }
}

// Multiplication
impl Mul for Complex {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            re: self.re * rhs.re - self.im * rhs.im,
            im: self.re * rhs.im + self.im * rhs.re,
        }
    }
}

// Division
impl Div for Complex {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let denominator = rhs.re * rhs.re + rhs.im * rhs.im;
        Self {
            re: (self.re * rhs.re + self.im * rhs.im) / denominator,
            im: (self.im * rhs.re - self.re * rhs.im) / denominator,
        }
    }
}

// Negation
impl Neg for Complex {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            re: -self.re,
            im: -self.im,
        }
    }
}

// Display formatting
impl fmt::Display for Complex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.im >= 0.0 {
            write!(f, "{}+{}i", self.re, self.im)
        } else {
            write!(f, "{}{}i", self.re, self.im)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        let a = Complex::new(3.0, 4.0);
        let b = Complex::new(1.0, 2.0);
        let c = a + b;
        assert_eq!(c, Complex::new(4.0, 6.0));
    }

    #[test]
    fn test_multiply() {
        let a = Complex::new(3.0, 4.0);
        let b = Complex::new(1.0, 2.0);
        let c = a * b;
        assert_eq!(c, Complex::new(-5.0, 10.0));
    }

    #[test]
    fn test_magnitude() {
        let a = Complex::new(3.0, 4.0);
        assert_eq!(a.magnitude(), 5.0);
    }

    #[test]
    fn test_conjugate() {
        let a = Complex::new(3.0, 4.0);
        let b = a.conjugate();
        assert_eq!(b, Complex::new(3.0, -4.0));
    }
}
