use memory::{FieldBackend, FieldElement};

use super::super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use ir_core::{Instruction, SsaVar};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    /// Resolve a name to a scalar SsaVar from the environment.
    pub(in super::super) fn resolve_scalar(&self, name: &str) -> Result<SsaVar, ProveIrError> {
        match self.env.get(name) {
            Some(InstEnvValue::Scalar(v)) => Ok(*v),
            Some(InstEnvValue::Array(_)) => Err(ProveIrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: None,
            }),
            None => Err(ProveIrError::UndeclaredVariable {
                name: name.into(),
                span: None,
                suggestion: None,
            }),
        }
    }

    /// Emit a power chain: base^exp as repeated multiplication.
    pub(in super::super) fn emit_pow(
        &mut self,
        base: SsaVar,
        exp: u64,
    ) -> Result<SsaVar, ProveIrError> {
        if exp == 0 {
            return Ok(self.emit_const(FieldElement::<F>::one()));
        }

        // Square-and-multiply for efficiency
        let mut result = None;
        let mut current = base;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = Some(match result {
                    None => current,
                    Some(acc) => {
                        let v = self.fresh_var();
                        self.push_inst(Instruction::Mul {
                            result: v,
                            lhs: acc,
                            rhs: current,
                        });
                        v
                    }
                });
            }
            e >>= 1;
            if e > 0 {
                let v = self.fresh_var();
                self.push_inst(Instruction::Mul {
                    result: v,
                    lhs: current,
                    rhs: current,
                });
                current = v;
            }
        }

        Ok(result.unwrap_or(base))
    }
}
