use std::fmt;

use super::CircuitStats;

impl fmt::Display for CircuitStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bar = "─".repeat(55);
        writeln!(f, "── Circuit Stats (R1CS) {}", "─".repeat(31))?;
        writeln!(f, "  Circuit: \"{}\"", self.name)?;
        writeln!(
            f,
            "  Inputs:  {} public, {} witness",
            self.n_public, self.n_witness
        )?;
        writeln!(f, "  {bar}")?;
        writeln!(
            f,
            "  {:<20} {:>6}  {:>11}  {:>5}",
            "Category", "Instrs", "Constraints", "%"
        )?;
        writeln!(f, "  {bar}")?;

        // Sort by constraints desc, then by display order for ties
        let mut sorted = self.categories.clone();
        sorted.sort_by(|a, b| {
            b.constraints
                .cmp(&a.constraints)
                .then(a.category.display_order().cmp(&b.category.display_order()))
        });

        for entry in &sorted {
            let pct = if self.total_constraints > 0 {
                (entry.constraints as f64 / self.total_constraints as f64) * 100.0
            } else {
                0.0
            };
            writeln!(
                f,
                "  {:<20} {:>6}  {:>11}  {:>4.1}%",
                entry.category.to_string(),
                entry.count,
                entry.constraints,
                pct,
            )?;
        }

        writeln!(f, "  {bar}")?;
        writeln!(
            f,
            "  {:<20} {:>6}  {:>11}",
            "TOTAL", self.n_instructions, self.total_constraints
        )?;

        if let Some(top) = self.bottleneck() {
            if self.total_constraints > 0 {
                let pct = (top.constraints as f64 / self.total_constraints as f64) * 100.0;
                writeln!(f, "  Bottleneck: {} ({:.1}%)", top.category, pct)?;
            }
        }

        write!(f, "{}", "─".repeat(55))
    }
}
