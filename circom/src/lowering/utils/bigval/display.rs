use super::BigVal;

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl std::fmt::Debug for BigVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_negative() {
            write!(f, "BigVal(-{})", self.neg().fmt_unsigned())
        } else {
            write!(f, "BigVal({})", self.fmt_unsigned())
        }
    }
}

impl BigVal {
    fn fmt_unsigned(&self) -> String {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            format!("{}", self.0[0])
        } else {
            format!(
                "0x{:016x}{:016x}{:016x}{:016x}",
                self.0[3], self.0[2], self.0[1], self.0[0]
            )
        }
    }
}
