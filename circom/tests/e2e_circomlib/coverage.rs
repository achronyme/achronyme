use super::*;

// ── Main test ────────────────────────────────────────────────────

#[test]
fn circomlib_e2e() {
    let files = find_circom_tests();
    assert!(!files.is_empty(), "no .circom test files found");

    let mut results: Vec<TestResult> = Vec::new();

    for file in &files {
        let result = run_circom_test(file);
        results.push(result);
    }

    // Print summary table
    eprintln!();
    eprintln!("┌─────────────────────────┬───────┬───────┬───────┬─────────────┐");
    eprintln!("│ Template                │ Parse │ Lower │ R1CS  │ Constraints │");
    eprintln!("├─────────────────────────┼───────┼───────┼───────┼─────────────┤");

    for r in &results {
        let parse = if r.parse { "  ✓  " } else { "  ✗  " };
        let lower = if r.lower { "  ✓  " } else { "  ✗  " };
        let r1cs = if r.r1cs { "  ✓  " } else { "  ✗  " };
        let constraints = match r.constraints {
            Some(n) => format!("{n:>11}"),
            None => "          -".to_string(),
        };
        eprintln!("│ {:<23} │{parse}│{lower}│{r1cs}│{constraints} │", r.name);
    }

    eprintln!("└─────────────────────────┴───────┴───────┴───────┴─────────────┘");

    let total = results.len();
    let parsed = results.iter().filter(|r| r.parse).count();
    let lowered = results.iter().filter(|r| r.lower).count();
    let proved = results.iter().filter(|r| r.r1cs).count();

    eprintln!();
    eprintln!(
        "circomlib coverage: {parsed}/{total} parse, {lowered}/{total} lower, {proved}/{total} r1cs"
    );
    eprintln!();

    // Print errors for failed tests
    let failures: Vec<&TestResult> = results.iter().filter(|r| r.error.is_some()).collect();
    if !failures.is_empty() {
        eprintln!("Failures:");
        for r in &failures {
            if let Some(err) = &r.error {
                eprintln!("  {}: {err}", r.name);
            }
        }
        eprintln!();
    }

    // Regressions: tests that LOWER successfully and have inputs, but fail R1CS.
    // Lower failures are "gaps" (unsupported features), not regressions.
    let regressions: Vec<&TestResult> = results
        .iter()
        .filter(|r| r.lower && !r.r1cs && r.error.as_deref() != Some("no inputs file"))
        .collect();

    if !regressions.is_empty() {
        eprintln!("REGRESSIONS (lowered but failed R1CS):");
        for r in &regressions {
            eprintln!("  {} — {}", r.name, r.error.as_deref().unwrap_or("unknown"));
        }
        panic!(
            "{} circom test(s) regressed — see details above",
            regressions.len()
        );
    }

    // Gaps: tests that fail at parse or lower (feature gaps, not regressions).
    let gaps: Vec<&TestResult> = results
        .iter()
        .filter(|r| !r.lower && r.error.as_deref() != Some("no inputs file"))
        .collect();
    if !gaps.is_empty() {
        eprintln!("Feature gaps (not regressions):");
        for r in &gaps {
            eprintln!("  {} — {}", r.name, r.error.as_deref().unwrap_or("unknown"));
        }
    }
}
