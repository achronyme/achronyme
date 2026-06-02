use super::examples::EXAMPLES;
use super::harness::{replay_one, run_example_capture, RowOutcome};
use super::pins::pin_for;
use super::*;

fn print_regen(key: &str, actual: &FrozenBaseline) {
    println!("\n=== regen baseline for `{key}` ===");
    println!("FrozenBaseline {{");
    println!("    pre_o1_hash: {:?},", actual.pre_o1_hash);
    println!("    pre_o1_count: {},", actual.pre_o1_count);
    println!("    post_o1_hash: {:?},", actual.post_o1_hash);
    println!("    post_o1_count: {},", actual.post_o1_count);
    println!("    num_variables: {},", actual.num_variables);
    println!("    public_inputs: {:?},", actual.public_inputs);
    println!("}}\n");
}
#[test]
fn cross_path_prove_baseline() {
    let workspace_root = workspace_root();
    eprintln!("workspace_root = {}", workspace_root.display());

    let regen = std::env::var("REGEN_FROZEN_BASELINES").is_ok();

    let total_started = Instant::now();
    let mut rows: Vec<RowOutcome> = Vec::new();

    for example in EXAMPLES {
        eprintln!(
            "\n=== {} ({}) — budget {:?} ===",
            example.label, example.rel_path, example.budget
        );
        let example_started = Instant::now();

        let captures = match run_example_capture(example, &workspace_root) {
            Ok(c) => c,
            Err(e) => {
                rows.push(RowOutcome {
                    file: example.label.into(),
                    block: "(file)".into(),
                    baseline: None,
                    wall_clock: example_started.elapsed(),
                    error: Some(format!("compile/vm: {e}")),
                });
                continue;
            }
        };
        eprintln!("  captured {} prove block(s)", captures.len());

        if captures.is_empty() {
            rows.push(RowOutcome {
                file: example.label.into(),
                block: "(no prove block)".into(),
                baseline: None,
                wall_clock: example_started.elapsed(),
                error: Some("no Prove opcodes encountered".into()),
            });
            continue;
        }

        for cap in &captures {
            if example_started.elapsed() > example.budget {
                rows.push(RowOutcome {
                    file: example.label.into(),
                    block: cap
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("(anonymous #{})", cap.seq)),
                    baseline: None,
                    wall_clock: Duration::ZERO,
                    error: Some(format!("budget exhausted ({:?})", example.budget)),
                });
                continue;
            }
            let row = replay_one(cap, example.label);
            eprintln!(
                "  block {:?}: ok={} ({:?})",
                row.block,
                row.baseline.is_some(),
                row.wall_clock
            );
            rows.push(row);
        }
    }

    let total_elapsed = total_started.elapsed();

    // ---- markdown table -------------------------------------------
    println!("\n## Cross-path prove-block frozen baseline\n");
    println!("| file | block | ok | pre-O1 | post-O1 | vars | wall_clock | error |");
    println!("|------|-------|----|------:|-------:|----:|-----------:|-------|");
    for row in &rows {
        let (ok, pre, post, vars) = match &row.baseline {
            Some(b) => (
                "yes",
                b.pre_o1_count.to_string(),
                b.post_o1_count.to_string(),
                b.num_variables.to_string(),
            ),
            None => ("no", "—".into(), "—".into(), "—".into()),
        };
        let err = row.error.as_deref().unwrap_or("");
        println!(
            "| {} | {} | {} | {} | {} | {} | {:.3}s | {} |",
            row.file,
            row.block,
            ok,
            pre,
            post,
            vars,
            row.wall_clock.as_secs_f64(),
            err.replace('|', "\\|"),
        );
    }

    // ---- pin compare or regen -------------------------------------
    let mut violations: Vec<String> = Vec::new();
    let mut pinned = 0usize;

    for row in &rows {
        let baseline = match &row.baseline {
            Some(b) => b,
            None => {
                violations.push(format!(
                    "{}/{}: no baseline produced ({})",
                    row.file,
                    row.block,
                    row.error.as_deref().unwrap_or("unknown")
                ));
                continue;
            }
        };
        let key = format!("{}/{}", row.file, row.block);

        if regen {
            print_regen(&key, baseline);
            continue;
        }

        let expected = match pin_for(&key) {
            Some(p) => p,
            None => {
                violations.push(format!(
                    "{key}: no pin found in pin_for() — add an arm or run REGEN_FROZEN_BASELINES=1"
                ));
                continue;
            }
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_frozen_baseline_matches(baseline, &expected);
        }));
        match result {
            Ok(()) => pinned += 1,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = e.downcast_ref::<&str>() {
                    (*s).to_string()
                } else {
                    "<panic with non-string payload>".into()
                };
                violations.push(format!(
                    "{key}: {}",
                    msg.lines().next().unwrap_or("<empty panic>")
                ));
            }
        }
    }

    println!("\n### Summary\n");
    println!(
        "**{pinned} / {} prove blocks matched pinned baseline.**",
        rows.len()
    );
    println!("Total runtime: {:.2}s.", total_elapsed.as_secs_f64());

    if regen {
        eprintln!(
            "\nREGEN mode: skipping assertion. Copy printed literals into pin_*() functions."
        );
        return;
    }

    if !violations.is_empty() {
        panic!(
            "cross_path_prove_baseline: {} violation(s):\n  - {}",
            violations.len(),
            violations.join("\n  - ")
        );
    }
}

/// CARGO_MANIFEST_DIR is `cli/`; the workspace root is one level up.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest)
}
