/// Source location for error reporting.
///
/// Tracks byte-range and line/column start and end positions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub byte_start: usize,
    pub byte_end: usize,
    pub line_start: usize,
    pub col_start: usize,
    pub line_end: usize,
    pub col_end: usize,
}

impl Span {
    /// Create a span covering from `start` to `end`.
    pub fn from_to(start: &Span, end: &Span) -> Self {
        Self {
            byte_start: start.byte_start,
            byte_end: end.byte_end,
            line_start: start.line_start,
            col_start: start.col_start,
            line_end: end.line_end,
            col_end: end.col_end,
        }
    }
}
