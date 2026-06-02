use std::path::{Path, PathBuf};

use diagnostics::Span;

pub(super) fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

pub(super) fn lib_dirs() -> Vec<PathBuf> {
    vec![workspace_root().join("test/circomlib")]
}

pub(super) fn dummy_span() -> Span {
    Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 0,
        col_start: 0,
        line_end: 0,
        col_end: 0,
    }
}
