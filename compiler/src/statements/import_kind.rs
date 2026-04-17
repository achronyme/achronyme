use std::path::Path;

/// File kind routed by an `import` / `import circuit` directive, determined
/// from the path's extension. Used to dispatch between the native `.ach`
/// module loader and the `.circom` frontend (library-mode compilation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportFileKind {
    /// Native Achronyme module — `.ach` suffix or no suffix at all.
    Ach,
    /// Circom source file — `.circom` suffix.
    Circom,
}

/// Classify an import path by its file extension.
///
/// Paths ending in `.circom` (case-insensitive) resolve to [`ImportFileKind::Circom`];
/// anything else — including extensionless paths — resolves to
/// [`ImportFileKind::Ach`]. The path is **not** validated here: that stays
/// in the caller so the resulting error message can include the import span.
pub(crate) fn detect_import_kind(path: &str) -> ImportFileKind {
    match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("circom") => ImportFileKind::Circom,
        _ => ImportFileKind::Ach,
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_import_kind, ImportFileKind};

    #[test]
    fn plain_ach_file_is_ach() {
        assert_eq!(detect_import_kind("./lib.ach"), ImportFileKind::Ach);
    }

    #[test]
    fn no_extension_is_ach() {
        assert_eq!(detect_import_kind("lib"), ImportFileKind::Ach);
    }

    #[test]
    fn circom_extension_is_circom() {
        assert_eq!(
            detect_import_kind("./poseidon.circom"),
            ImportFileKind::Circom
        );
    }

    #[test]
    fn circom_extension_case_insensitive() {
        assert_eq!(
            detect_import_kind("./POSEIDON.CIRCOM"),
            ImportFileKind::Circom
        );
    }

    #[test]
    fn circom_in_directory_name_not_in_suffix_is_ach() {
        // Only the final extension matters — a `circom/` directory in the
        // middle of the path should still dispatch as `.ach`.
        assert_eq!(detect_import_kind("circom/lib.ach"), ImportFileKind::Ach);
    }
}
