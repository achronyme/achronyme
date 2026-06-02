use super::*;

/// Guard owning a `tempfile::TempDir` + the path of a `.circom`
/// file inside it. On drop the directory and its contents are
/// deleted -- even if the test panics -- so stray temp files
/// don't accumulate across failing runs.
struct TempCircom {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

fn write_temp_circom(src: &str) -> TempCircom {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("module.circom");
    std::fs::write(&path, src).expect("write temp circom");
    TempCircom { _dir: dir, path }
}

#[test]
fn compile_template_library_single_file_no_main() {
    let src = r#"
            pragma circom 2.0.0;

            template Pair() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b;
            }

            template Num2Bits(n) {
                signal input in;
                signal output out[n];
                var lc = 0;
                var e = 1;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    out[i] * (out[i] - 1) === 0;
                    lc += out[i] * e;
                    e = e + e;
                }
                lc === in;
            }
        "#;
    let tc = write_temp_circom(src);
    let lib = compile_template_library(&tc.path, &[]).expect("library should compile");

    assert!(lib.template("Pair").is_some());
    assert!(lib.template("Num2Bits").is_some());

    let pair = lib.template("Pair").unwrap();
    assert!(pair.params.is_empty());
    assert_eq!(pair.inputs.len(), 2);
    assert_eq!(pair.outputs.len(), 1);

    let n2b = lib.template("Num2Bits").unwrap();
    assert_eq!(n2b.params, vec!["n".to_string()]);
    assert!(matches!(
        n2b.outputs[0].dimensions[0],
        library::DimensionExpr::Param(ref p) if p == "n"
    ));
}

#[test]
fn compile_template_library_with_function() {
    let src = r#"
            pragma circom 2.0.0;

            function nbits(a) {
                var n = 1; var r = 0;
                while (n - 1 < a) { r++; n *= 2; }
                return r;
            }

            template T(maxval) {
                var nb = nbits(maxval);
                signal input in;
                signal output out[nb];
            }
        "#;
    let tc = write_temp_circom(src);
    let lib = compile_template_library(&tc.path, &[]).expect("library should compile");

    assert!(lib.function("nbits").is_some());
    assert!(lib.template("T").is_some());
}

#[test]
fn compile_template_library_ignores_main_component() {
    // Even if the file declares component main, library mode should
    // still extract templates as reusable metadata without failing.
    let src = r#"
            pragma circom 2.0.0;

            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }

            component main = Square();
        "#;
    let tc = write_temp_circom(src);
    let lib = compile_template_library(&tc.path, &[]).expect("library should compile");

    assert!(lib.template("Square").is_some());
    // Main component is preserved in the AST but not required.
    // main_component is pub(crate) after R9 encapsulation -- we only
    // care that library loading succeeds regardless of its presence.
}

#[test]
fn compile_template_library_parse_error() {
    let src = "this is not circom at all @#$%";
    let tc = write_temp_circom(src);
    let result = compile_template_library(&tc.path, &[]);
    // Lexer-level errors are surfaced through the include resolver as
    // IncludeError::Parse, while recovered-parser errors go through
    // ParseError. Either shape is acceptable here -- the important
    // part is that compilation is rejected.
    assert!(
        matches!(
            result,
            Err(CircomError::ParseError(_)) | Err(CircomError::IncludeError(_))
        ),
        "expected ParseError or IncludeError, got {result:?}"
    );
}
