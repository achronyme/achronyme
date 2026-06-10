//! Recognition of vendored big-integer helper functions for native
//! intrinsic annotation.
//!
//! The Artik executor can run certain well-known circom big-integer
//! helpers natively (see `artik::intrinsics`). The lift may only
//! annotate a callee subprogram when the function the user compiled is
//! *the* reference implementation — same algorithm, same truncation
//! corners — so recognition matches the function source structurally
//! against an embedded copy of the circom-ecdsa `bigint_func` family,
//! including every transitively-called helper. A user-defined function
//! that shares a name but differs anywhere (or calls a modified
//! helper) simply stays interpreted.
//!
//! Recognition is value-conservative by construction: the annotation
//! only redirects execution to a native routine whose results are
//! bit-identical on guarded inputs, and the executor falls back to the
//! interpreted body whenever its runtime guards decline.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::ast::{Block, ElseBranch, Expr, FunctionDef, Stmt};

use super::driver::ParamSig;

/// The reference sources, embedded verbatim from the vendored
/// circom-ecdsa `bigint_func.circom` (0xPARC, MIT-licensed). The
/// registry parses them once per process.
const REFERENCE_SOURCE: &str = include_str!("bigint_reference.circom");

struct RefEntry {
    fingerprint: u64,
    /// Transitively-called helpers that must also match their
    /// reference fingerprints for the annotation to be sound.
    deps: &'static [&'static str],
}

const MOD_INV_DEPS: &[&str] = &[
    "mod_exp",
    "long_sub",
    "prod",
    "long_div",
    "SplitFn",
    "SplitThreeFn",
    "short_div",
    "short_div_norm",
    "long_scalar_mult",
    "long_gt",
];
const MOD_EXP_DEPS: &[&str] = &[
    "prod",
    "long_div",
    "SplitFn",
    "SplitThreeFn",
    "short_div",
    "short_div_norm",
    "long_scalar_mult",
    "long_sub",
    "long_gt",
];
const PROD_DEPS: &[&str] = &["SplitFn", "SplitThreeFn"];
const LONG_DIV_DEPS: &[&str] = &[
    "short_div",
    "short_div_norm",
    "long_scalar_mult",
    "long_sub",
    "long_gt",
];

fn registry() -> Option<&'static HashMap<&'static str, RefEntry>> {
    static REGISTRY: OnceLock<Option<HashMap<&'static str, RefEntry>>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let (program, diagnostics) = crate::parser::parse_circom(REFERENCE_SOURCE).ok()?;
            if !diagnostics.is_empty() {
                return None;
            }
            let mut by_name: HashMap<String, u64> = HashMap::new();
            for def in &program.definitions {
                if let crate::ast::Definition::Function(f) = def {
                    by_name.insert(f.name.clone(), fingerprint(f));
                }
            }
            let entry = |name: &str, deps: &'static [&'static str]| -> Option<RefEntry> {
                Some(RefEntry {
                    fingerprint: *by_name.get(name)?,
                    deps,
                })
            };
            let mut map = HashMap::new();
            map.insert("mod_inv", entry("mod_inv", MOD_INV_DEPS)?);
            map.insert("mod_exp", entry("mod_exp", MOD_EXP_DEPS)?);
            map.insert("prod", entry("prod", PROD_DEPS)?);
            map.insert("long_div", entry("long_div", LONG_DIV_DEPS)?);
            for dep in MOD_INV_DEPS {
                map.insert(dep, entry(dep, &[])?);
            }
            Some(map)
        })
        .as_ref()
}

/// Recognize `callee` (registered under `name` with `param_sig`) as a
/// native intrinsic. Returns `None` unless the function body and every
/// transitively-called helper match the embedded reference and the
/// call-site signature has the expected compile-time shape.
pub(super) fn recognize_intrinsic(
    name: &str,
    callee: &FunctionDef,
    param_sig: &[ParamSig],
    functions: &HashMap<String, &FunctionDef>,
) -> Option<artik::Intrinsic> {
    if !matches!(name, "mod_inv" | "mod_exp" | "prod" | "long_div") {
        return None;
    }
    let registry = registry()?;
    let entry = registry.get(name)?;
    if fingerprint(callee) != entry.fingerprint {
        return None;
    }
    for dep in entry.deps {
        let def = functions.get(*dep)?;
        if fingerprint(def) != registry.get(dep)?.fingerprint {
            return None;
        }
    }

    let scalar = |i: usize| -> Option<u32> {
        match param_sig.get(i)? {
            ParamSig::ScalarConst(v) if (0..=i64::from(u32::MAX)).contains(v) => Some(*v as u32),
            _ => None,
        }
    };
    let is_arr = |i: usize| matches!(param_sig.get(i), Some(ParamSig::Array1D(_)));
    let n = scalar(0)?;
    let k = scalar(1)?;
    // Mirror the executor-side bounds so an emitted annotation always
    // decodes: digits must fit a word, and the prod-based intrinsics
    // need k >= 2 (the reference single-register product truncates).
    if !(1..=64).contains(&n) || !(1..=16).contains(&k) {
        return None;
    }
    match name {
        "mod_inv" if param_sig.len() == 4 && is_arr(2) && is_arr(3) && k >= 2 => {
            Some(artik::Intrinsic::ModInv { n, k, ret_len: 100 })
        }
        "mod_exp" if param_sig.len() == 5 && is_arr(2) && is_arr(3) && is_arr(4) && k >= 2 => {
            Some(artik::Intrinsic::ModExp { n, k, ret_len: 100 })
        }
        "prod" if param_sig.len() == 4 && is_arr(2) && is_arr(3) && k >= 2 => {
            Some(artik::Intrinsic::Prod { n, k, ret_len: 100 })
        }
        "long_div" if param_sig.len() == 5 && is_arr(3) && is_arr(4) => {
            let m = scalar(2)?;
            if !(1..=16).contains(&m) {
                return None;
            }
            Some(artik::Intrinsic::LongDiv {
                n,
                k,
                m,
                ret_len: 200,
            })
        }
        _ => None,
    }
}

// ── Structural fingerprint ──────────────────────────────────────
//
// FNV-1a over a canonical, span-insensitive serialization of the
// function AST: variant tags, identifier names, and literal values.
// Whitespace and comments cannot affect it; any structural edit does.

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn mix(h: &mut u64, bytes: &[u8]) {
    for &b in bytes {
        *h ^= u64::from(b);
        *h = h.wrapping_mul(FNV_PRIME);
    }
}

fn tag(h: &mut u64, t: u8) {
    mix(h, &[t, 0xA5]);
}

pub(super) fn fingerprint(def: &FunctionDef) -> u64 {
    let mut h = FNV_OFFSET;
    mix(&mut h, def.name.as_bytes());
    for p in &def.params {
        tag(&mut h, 1);
        mix(&mut h, p.as_bytes());
    }
    hash_block(&mut h, &def.body);
    h
}

fn hash_block(h: &mut u64, block: &Block) {
    tag(h, 2);
    for stmt in &block.stmts {
        hash_stmt(h, stmt);
    }
    tag(h, 3);
}

fn hash_stmt(h: &mut u64, stmt: &Stmt) {
    match stmt {
        Stmt::VarDecl {
            names,
            dimensions,
            init,
            ..
        } => {
            tag(h, 10);
            for n in names {
                mix(h, n.as_bytes());
                tag(h, 1);
            }
            for d in dimensions {
                hash_expr(h, d);
            }
            tag(h, 4);
            if let Some(e) = init {
                hash_expr(h, e);
            }
        }
        Stmt::Substitution {
            target, op, value, ..
        } => {
            tag(h, 11);
            hash_expr(h, target);
            mix(h, format!("{op:?}").as_bytes());
            hash_expr(h, value);
        }
        Stmt::CompoundAssign {
            target, op, value, ..
        } => {
            tag(h, 12);
            hash_expr(h, target);
            mix(h, format!("{op:?}").as_bytes());
            hash_expr(h, value);
        }
        Stmt::IfElse {
            condition,
            then_body,
            else_body,
            ..
        } => {
            tag(h, 13);
            hash_expr(h, condition);
            hash_block(h, then_body);
            match else_body {
                Some(ElseBranch::Block(b)) => hash_block(h, b),
                Some(ElseBranch::IfElse(s)) => hash_stmt(h, s),
                None => tag(h, 5),
            }
        }
        Stmt::For {
            init,
            condition,
            step,
            body,
            ..
        } => {
            tag(h, 14);
            hash_stmt(h, init);
            hash_expr(h, condition);
            hash_stmt(h, step);
            hash_block(h, body);
        }
        Stmt::While {
            condition, body, ..
        } => {
            tag(h, 15);
            hash_expr(h, condition);
            hash_block(h, body);
        }
        Stmt::Return { value, .. } => {
            tag(h, 16);
            hash_expr(h, value);
        }
        Stmt::Assert { arg, .. } => {
            tag(h, 17);
            hash_expr(h, arg);
        }
        Stmt::Block(b) => {
            tag(h, 18);
            hash_block(h, b);
        }
        Stmt::Expr { expr, .. } => {
            tag(h, 19);
            hash_expr(h, expr);
        }
        // Variants the reference bodies never contain. They still get
        // a stable tag (without descending into substructure) so a
        // candidate using one can never replay a reference stream —
        // the reference streams contain no 0xEE tags at all.
        _ => tag(h, 0xEE),
    }
}

fn hash_expr(h: &mut u64, expr: &Expr) {
    match expr {
        Expr::Number { value, .. } => {
            tag(h, 30);
            mix(h, value.as_bytes());
        }
        Expr::HexNumber { value, .. } => {
            tag(h, 31);
            mix(h, value.as_bytes());
        }
        Expr::Ident { name, .. } => {
            tag(h, 32);
            mix(h, name.as_bytes());
        }
        Expr::BinOp { op, lhs, rhs, .. } => {
            tag(h, 33);
            mix(h, format!("{op:?}").as_bytes());
            hash_expr(h, lhs);
            hash_expr(h, rhs);
        }
        Expr::UnaryOp { op, operand, .. } => {
            tag(h, 34);
            mix(h, format!("{op:?}").as_bytes());
            hash_expr(h, operand);
        }
        Expr::PostfixOp { op, operand, .. } => {
            tag(h, 35);
            mix(h, format!("{op:?}").as_bytes());
            hash_expr(h, operand);
        }
        Expr::PrefixOp { op, operand, .. } => {
            tag(h, 36);
            mix(h, format!("{op:?}").as_bytes());
            hash_expr(h, operand);
        }
        Expr::Ternary {
            condition,
            if_true,
            if_false,
            ..
        } => {
            tag(h, 37);
            hash_expr(h, condition);
            hash_expr(h, if_true);
            hash_expr(h, if_false);
        }
        Expr::Call { callee, args, .. } => {
            tag(h, 38);
            hash_expr(h, callee);
            for a in args {
                hash_expr(h, a);
            }
            tag(h, 6);
        }
        Expr::Index { object, index, .. } => {
            tag(h, 39);
            hash_expr(h, object);
            hash_expr(h, index);
        }
        Expr::ArrayLit { elements, .. } => {
            tag(h, 40);
            for e in elements {
                hash_expr(h, e);
            }
            tag(h, 7);
        }
        Expr::Tuple { elements, .. } => {
            tag(h, 41);
            for e in elements {
                hash_expr(h, e);
            }
            tag(h, 8);
        }
        // See the statement catch-all: stable tag, no substructure.
        _ => tag(h, 0xEF),
    }
}

#[cfg(test)]
mod tests;
