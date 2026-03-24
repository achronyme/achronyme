use super::commands::ErrorFormat;

/// ANSI escape codes for terminal styling.
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const GREEN: &str = "\x1b[32m";
    pub const CYAN: &str = "\x1b[36m";
}

use achronyme_parser::atty_stderr;

/// Controls styled output for CLI pipeline messages.
///
/// Respects `NO_COLOR` env var and TTY detection on stderr.
pub struct Styler {
    color: bool,
}

impl Styler {
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    /// Create a Styler from the current error format.
    ///
    /// Only enables color in Human mode, when stderr is a TTY,
    /// and `NO_COLOR` is not set.
    pub fn from_env(fmt: &ErrorFormat) -> Self {
        let color =
            *fmt == ErrorFormat::Human && std::env::var_os("NO_COLOR").is_none() && atty_stderr();
        Self { color }
    }

    /// Whether verbose pipeline output should be emitted.
    pub fn is_verbose(&self, fmt: &ErrorFormat) -> bool {
        *fmt == ErrorFormat::Human
    }

    pub fn green(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}", ansi::GREEN, text, ansi::RESET)
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}", ansi::BOLD, text, ansi::RESET)
        } else {
            text.to_string()
        }
    }

    pub fn dim(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}", ansi::DIM, text, ansi::RESET)
        } else {
            text.to_string()
        }
    }

    pub fn success(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}{}", ansi::BOLD, ansi::GREEN, text, ansi::RESET)
        } else {
            text.to_string()
        }
    }

    pub fn warning(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}{}", ansi::BOLD, ansi::YELLOW, text, ansi::RESET)
        } else {
            text.to_string()
        }
    }

    pub fn cyan(&self, text: &str) -> String {
        if self.color {
            format!("{}{}{}", ansi::CYAN, text, ansi::RESET)
        } else {
            text.to_string()
        }
    }
}

/// Format a number with thousands separators: 2179 → "2,179".
pub fn format_number(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + len / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(b as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_number_small() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(42), "42");
        assert_eq!(format_number(999), "999");
    }

    #[test]
    fn format_number_thousands() {
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(2179), "2,179");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn styler_no_color() {
        let s = Styler::new(false);
        assert_eq!(s.green("ok"), "ok");
        assert_eq!(s.bold("ok"), "ok");
        assert_eq!(s.dim("ok"), "ok");
        assert_eq!(s.success("ok"), "ok");
        assert_eq!(s.cyan("ok"), "ok");
    }

    #[test]
    fn styler_with_color() {
        let s = Styler::new(true);
        assert!(s.green("ok").contains("\x1b[32m"));
        assert!(s.bold("ok").contains("\x1b[1m"));
        assert!(s.dim("ok").contains("\x1b[2m"));
        assert!(s.success("ok").contains("\x1b[1m"));
        assert!(s.success("ok").contains("\x1b[32m"));
        assert!(s.cyan("ok").contains("\x1b[36m"));
    }
}
