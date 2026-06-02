/// Maximum legal frame size — matches
/// [`lysis::lower::MAX_FRAME_SIZE`]. Restated here to keep this
/// module reasoning directly about the bound without importing
/// `lysis` just for one constant.
pub const MAX_FRAME_SIZE: u32 = 255;

/// Errors raised during template extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractError {
    /// The proposed template needs more registers than `u8` can
    /// address.
    FrameOverflow { requested: u32 },
    /// The template id space is exhausted (more than `u16::MAX`
    /// distinct templates in one program). Unreachable in practice.
    TemplateSpaceExhausted,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameOverflow { requested } => write!(
                f,
                "template needs {requested} registers, max {MAX_FRAME_SIZE}"
            ),
            Self::TemplateSpaceExhausted => {
                f.write_str("template id space exhausted (> 65535 distinct templates)")
            }
        }
    }
}

impl std::error::Error for ExtractError {}
