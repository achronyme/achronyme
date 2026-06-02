use crate::ast;

/// Check if the declared pragma version is consistent with features used.
pub(crate) fn validate_version_pragma(program: &ast::CircomProgram) {
    let version = match &program.version {
        Some(v) => v,
        None => return, // No pragma — skip validation
    };

    let (major, minor) = (version.major, version.minor);

    // Check for features that require specific versions
    let has_buses = program
        .definitions
        .iter()
        .any(|d| matches!(d, ast::Definition::Bus(_)));
    if has_buses && (major < 2 || (major == 2 && minor < 2)) {
        eprintln!(
            "warning: `bus` declarations require Circom ≥ 2.2.0, \
             but pragma declares {major}.{minor}.{}",
            version.patch
        );
    }

    if program.custom_templates {
        // custom_templates requires Circom 2.0.6+, but we only track major.minor
        // so just check >= 2.0
        if major < 2 {
            eprintln!(
                "warning: `pragma custom_templates` requires Circom ≥ 2.0.6, \
                 but pragma declares {major}.{minor}.{}",
                version.patch
            );
        }
    }

    // Warn if declared version is newer than what we support
    if major > 2 || (major == 2 && minor > 2) {
        eprintln!(
            "warning: Achronyme's Circom frontend targets Circom 2.0–2.2.x; \
             pragma declares {major}.{minor}.{} which may use unsupported features",
            version.patch
        );
    }
}
