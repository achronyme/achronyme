use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::{Assignments, Column, PlonkishError};

// ============================================================================
// Expression (recursive symbolic polynomials)
// ============================================================================

#[derive(Debug, Clone)]
pub enum Expression<F: FieldBackend = Bn254Fr> {
    Constant(FieldElement<F>),
    Cell(Column, i32), // column, rotation offset (0 = current row)
    Neg(Box<Expression<F>>),
    Sum(Box<Expression<F>>, Box<Expression<F>>),
    Product(Box<Expression<F>>, Box<Expression<F>>),
}

impl<F: FieldBackend> Expression<F> {
    pub fn constant(val: FieldElement<F>) -> Self {
        Expression::Constant(val)
    }

    pub fn cell(col: Column, rotation: i32) -> Self {
        Expression::Cell(col, rotation)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Self {
        Expression::Sum(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: Self) -> Self {
        Expression::Product(Box::new(self), Box::new(other))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Self {
        Expression::Sum(Box::new(self), Box::new(Expression::Neg(Box::new(other))))
    }

    #[allow(clippy::should_implement_trait)]
    pub fn neg(self) -> Self {
        Expression::Neg(Box::new(self))
    }

    /// Evaluate this expression at a given row using the assignments table.
    pub fn evaluate(
        &self,
        assignments: &Assignments<F>,
        row: usize,
    ) -> Result<FieldElement<F>, PlonkishError> {
        match self {
            Expression::Constant(val) => Ok(*val),
            Expression::Cell(col, rotation) => {
                let actual = row as i64 + *rotation as i64;
                if actual < 0 || actual as usize >= assignments.num_rows {
                    Err(PlonkishError::RotationOutOfBounds {
                        column: *col,
                        row,
                        rotation: *rotation,
                        num_rows: assignments.num_rows,
                    })
                } else {
                    Ok(assignments.get(*col, actual as usize))
                }
            }
            Expression::Neg(inner) => Ok(inner.evaluate(assignments, row)?.neg()),
            Expression::Sum(a, b) => {
                let av = a.evaluate(assignments, row)?;
                let bv = b.evaluate(assignments, row)?;
                Ok(av.add(&bv))
            }
            Expression::Product(a, b) => {
                let av = a.evaluate(assignments, row)?;
                let bv = b.evaluate(assignments, row)?;
                Ok(av.mul(&bv))
            }
        }
    }
}
