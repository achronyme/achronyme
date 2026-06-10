use std::collections::HashMap;
use std::path::Path;

use super::*;
use crate::ast::Definition;

/// Parse the vendored `bigint_func.circom` fixture and return its
/// functions keyed by name.
fn vendored_functions() -> (crate::ast::CircomProgram, Vec<String>) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let path = manifest.join("test/circomlib/circuits/ecdsa/bigint_func.circom");
    let source = std::fs::read_to_string(&path).expect("vendored bigint_func.circom");
    let (program, diagnostics) = crate::parser::parse_circom(&source).expect("parse");
    assert!(diagnostics.is_empty(), "vendored source parses clean");
    let names = program
        .definitions
        .iter()
        .filter_map(|d| match d {
            Definition::Function(f) => Some(f.name.clone()),
            _ => None,
        })
        .collect();
    (program, names)
}

fn function_map(program: &crate::ast::CircomProgram) -> HashMap<String, &crate::ast::FunctionDef> {
    program
        .definitions
        .iter()
        .filter_map(|d| match d {
            Definition::Function(f) => Some((f.name.clone(), f)),
            _ => None,
        })
        .collect()
}

/// The production pin: every function the registry models must be
/// recognized when compiled from the vendored fixture with the ECDSA
/// production shape (n = 64, k = 4). If the lift's fingerprint hasher
/// or the vendored source drift apart, this fails loudly instead of
/// silently losing the native path.
#[test]
fn vendored_bigint_family_is_recognized() {
    let (program, _) = vendored_functions();
    let functions = function_map(&program);

    let arr = |len: u32| ParamSig::Array1D(len);
    let modinv_sig = vec![
        ParamSig::ScalarConst(64),
        ParamSig::ScalarConst(4),
        arr(100),
        arr(100),
    ];
    let got = recognize_intrinsic("mod_inv", functions["mod_inv"], &modinv_sig, &functions);
    assert_eq!(
        got,
        Some(artik::Intrinsic::ModInv {
            n: 64,
            k: 4,
            ret_len: 100
        })
    );

    let modexp_sig = vec![
        ParamSig::ScalarConst(64),
        ParamSig::ScalarConst(4),
        arr(100),
        arr(100),
        arr(100),
    ];
    let got = recognize_intrinsic("mod_exp", functions["mod_exp"], &modexp_sig, &functions);
    assert_eq!(
        got,
        Some(artik::Intrinsic::ModExp {
            n: 64,
            k: 4,
            ret_len: 100
        })
    );

    let prod_sig = vec![
        ParamSig::ScalarConst(64),
        ParamSig::ScalarConst(4),
        arr(4),
        arr(4),
    ];
    let got = recognize_intrinsic("prod", functions["prod"], &prod_sig, &functions);
    assert_eq!(
        got,
        Some(artik::Intrinsic::Prod {
            n: 64,
            k: 4,
            ret_len: 100
        })
    );

    let longdiv_sig = vec![
        ParamSig::ScalarConst(64),
        ParamSig::ScalarConst(4),
        ParamSig::ScalarConst(4),
        arr(200),
        arr(100),
    ];
    let got = recognize_intrinsic("long_div", functions["long_div"], &longdiv_sig, &functions);
    assert_eq!(
        got,
        Some(artik::Intrinsic::LongDiv {
            n: 64,
            k: 4,
            m: 4,
            ret_len: 200
        })
    );
}

#[test]
fn runtime_or_missing_consts_decline() {
    let (program, _) = vendored_functions();
    let functions = function_map(&program);
    // Runtime n: no annotation.
    let sig = vec![
        ParamSig::ScalarRuntime,
        ParamSig::ScalarConst(4),
        ParamSig::Array1D(100),
        ParamSig::Array1D(100),
    ];
    assert_eq!(
        recognize_intrinsic("mod_inv", functions["mod_inv"], &sig, &functions),
        None
    );
    // Single-register shape declines (reference prod truncates there).
    let sig = vec![
        ParamSig::ScalarConst(64),
        ParamSig::ScalarConst(1),
        ParamSig::Array1D(100),
        ParamSig::Array1D(100),
    ];
    assert_eq!(
        recognize_intrinsic("mod_inv", functions["mod_inv"], &sig, &functions),
        None
    );
}

/// A body that differs from the reference anywhere — here `mod_inv`
/// with one literal changed — must not be recognized, and a matching
/// `mod_inv` whose *helper* was modified must not be recognized
/// either (the dependency closure check).
#[test]
fn modified_body_or_helper_declines() {
    let (program, _) = vendored_functions();
    let functions = function_map(&program);

    let tweaked_src = r#"
function mod_inv(n, k, a, p) {
    var isZero = 1;
    for (var i = 0; i < k; i++) {
        if (a[i] != 0) {
            isZero = 0;
        }
    }
    if (isZero == 1) {
        var ret[100];
        for (var i = 0; i < k; i++) {
            ret[i] = 1;
        }
        return ret;
    }
    var ret[100];
    return ret;
}
"#;
    let (tweaked, diags) = crate::parser::parse_circom(tweaked_src).expect("parse");
    assert!(diags.is_empty());
    let tweaked_fns = function_map(&tweaked);
    let sig = vec![
        ParamSig::ScalarConst(64),
        ParamSig::ScalarConst(4),
        ParamSig::Array1D(100),
        ParamSig::Array1D(100),
    ];
    assert_eq!(
        recognize_intrinsic("mod_inv", tweaked_fns["mod_inv"], &sig, &functions),
        None,
        "a structurally different body must not be recognized"
    );

    // Genuine mod_inv, but the helper map carries a tweaked mod_exp:
    // the closure check must decline.
    let tweaked_helper_src = r#"
function mod_exp(n, k, a, p, e) {
    var out[100];
    out[0] = 2;
    return out;
}
"#;
    let (tweaked_helper, diags) = crate::parser::parse_circom(tweaked_helper_src).expect("parse");
    assert!(diags.is_empty());
    let tweaked_helper_fns = function_map(&tweaked_helper);
    let mut mixed: HashMap<String, &crate::ast::FunctionDef> = functions.clone();
    mixed.insert("mod_exp".to_string(), tweaked_helper_fns["mod_exp"]);
    assert_eq!(
        recognize_intrinsic("mod_inv", functions["mod_inv"], &sig, &mixed),
        None,
        "a modified transitive helper must decline recognition"
    );
}

/// Fingerprints are span-insensitive: reformatting the same function
/// (extra whitespace, comments) hashes identically.
#[test]
fn fingerprint_ignores_formatting() {
    let a = r#"
function f(x, y) {
    var t = x * y + 1;
    return t;
}
"#;
    let b = r#"
// a comment
function f(x, y) {

    var t = x   *   y    + 1;   // trailing
    return t;
}
"#;
    let parse = |s: &str| {
        let (p, d) = crate::parser::parse_circom(s).expect("parse");
        assert!(d.is_empty());
        p
    };
    let pa = parse(a);
    let pb = parse(b);
    let fa = function_map(&pa);
    let fb = function_map(&pb);
    assert_eq!(fingerprint(fa["f"]), fingerprint(fb["f"]));
}
