//! `Type::MEMBER` static-access compilation.
//!
//! Resolves a small set of constrainable namespaces (`Field::ZERO`,
//! `Field::ONE`, `Int::MAX`, `Int::MIN`) directly to a `FieldConst`,
//! rejects un-constrainable namespaces (`BigInt::*`, `Field::ORDER`)
//! with a typed diagnostic, and falls back to a compile-time
//! `alias::const` namespace lookup against the outer-scope env for
//! module-imported constants.

use achronyme_parser::ast::*;
use memory::{FieldBackend, FieldElement};

use super::super::helpers::to_span;
use super::super::{CompEnvValue, ProveIrCompiler};
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
    pub(in crate::ast_lower) fn compile_static_access(
        &self,
        type_name: &str,
        member: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match (type_name, member) {
            ("Field", "ZERO") => Ok(CircuitExpr::Const(FieldConst::zero())),
            ("Field", "ONE") => Ok(CircuitExpr::Const(FieldConst::one())),
            ("Field", "ORDER") => Err(ProveIrError::StaticAccessNotConstrainable {
                type_name: "Field".into(),
                member: "ORDER".into(),
                reason: "Field::ORDER is a string (the BN254 modulus) \
                         and strings cannot be used in circuits"
                    .into(),
                span: to_span(span),
            }),
            ("Int", "MAX") => Ok(CircuitExpr::Const(FieldConst::from_field(
                FieldElement::<F>::from_i64(memory::I60_MAX),
            ))),
            ("Int", "MIN") => Ok(CircuitExpr::Const(FieldConst::from_field(
                FieldElement::<F>::from_i64(memory::I60_MIN),
            ))),
            ("BigInt", _) => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            _ => {
                // Namespace lookup for `alias::const` where `alias` is an
                // `import "./foo.ach" as alias`-style module alias. The
                // fn_table already carries entries keyed `alias::name` for
                // every exported function, and the outer scope's
                // `CompEnvValue` map carries the same for exported
                // constants. Resolving here at compile time is the prove-
                // block sibling of the VM compiler's static-access fast
                // path: no HashMap lookup at proof time, no runtime map
                // object, just a direct value reference.
                let qualified = format!("{type_name}::{member}");
                if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&qualified) {
                    return Ok(CircuitExpr::Var(resolved.clone()));
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!("unknown static access `{type_name}::{member}`"),
                    span: to_span(span),
                })
            }
        }
    }
}
