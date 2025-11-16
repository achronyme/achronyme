// Detailed analysis of the parsing behavior

use achronyme_parser::pest_parser;

fn parse_and_show(label: &str, source: &str) {
    print!("{}: ", label);
    match pest_parser::parse(source) {
        Ok(_) => println!("OK"),
        Err(e) => {
            println!("FAIL");
            println!("  Error: {}", e.to_string().lines().take(5).collect::<Vec<_>>().join("\n  "));
        }
    }
}

#[test]
fn detailed_analysis() {
    println!("\n=== Detailed Parsing Analysis ===\n");

    // Test standalone expressions
    println!("--- Standalone Expressions ---");
    parse_and_show("Lambda: b => c", r#"b => c"#);
    parse_and_show("Lambda: b => \"string\"", r#"b => "string""#);
    parse_and_show("Comparison with lambda: a == b => c", r#"a == b => c"#);
    parse_and_show("Comparison with lambda: a == b => \"string\"", r#"a == b => "string""#);
    parse_and_show("Comparison to number: a == 5", r#"a == 5"#);
    parse_and_show("Comparison to identifier: a == b", r#"a == b"#);

    println!("\n--- Match with Single Variable Pattern ---");
    parse_and_show("No guard", r#"match 1 { a => "yes" }"#);
    parse_and_show("Guard with true", r#"match 1 { a if true => "yes" }"#);
    parse_and_show("Guard with identifier", r#"match 1 { a if b => "yes" }"#);
    parse_and_show("Guard with number comparison", r#"match 1 { a if a > 5 => "yes" }"#);
    parse_and_show("Guard with identifier comparison", r#"match 1 { a if a == b => "yes" }"#);

    println!("\n--- Match with Record Pattern (1 field) ---");
    parse_and_show("No guard", r#"match obj { { x: a } => "yes" }"#);
    parse_and_show("Guard with true", r#"match obj { { x: a } if true => "yes" }"#);
    parse_and_show("Guard with identifier", r#"match obj { { x: a } if b => "yes" }"#);
    parse_and_show("Guard with number comparison", r#"match obj { { x: a } if a > 5 => "yes" }"#);
    parse_and_show("Guard with identifier comparison", r#"match obj { { x: a } if a == b => "yes" }"#);

    println!("\n--- Match with Record Pattern (2 fields) ---");
    parse_and_show("No guard", r#"match obj { { x: a, y: b } => "yes" }"#);
    parse_and_show("Guard with true", r#"match obj { { x: a, y: b } if true => "yes" }"#);
    parse_and_show("Guard with identifier", r#"match obj { { x: a, y: b } if c => "yes" }"#);
    parse_and_show("Guard with number comparison", r#"match obj { { x: a, y: b } if a > 5 => "yes" }"#);
    parse_and_show("Guard comparing bound vars", r#"match obj { { x: a, y: b } if a == b => "yes" }"#);
    parse_and_show("Guard with parenthesized comparison", r#"match obj { { x: a, y: b } if (a == b) => "yes" }"#);

    println!("\n--- Edge Cases ---");
    parse_and_show("Record pattern, guard ends with identifier", r#"match obj { { x: a, y: b } if b => "yes" }"#);
    parse_and_show("Record pattern, guard: a == c (c not bound)", r#"match obj { { x: a, y: b } if a == c => "yes" }"#);
    parse_and_show("Record pattern, guard: c == b (c not bound)", r#"match obj { { x: a, y: b } if c == b => "yes" }"#);

    println!("\n--- The Crucial Test ---");
    // In "a if a == b => result", does the parser see:
    // Option A: guard_expr = "a == b", then match_arm_arrow = "=>"
    // Option B: guard_expr = "a == (b => result)", and no match_arm_arrow
    //
    // The error "expected operator after string" suggests it's trying to parse
    // MORE after the string "result", which means Option B!
    parse_and_show("Minimal: a if a == b => \"result\"", r#"match 1 { a if a == b => "result" }"#);

    println!();
}
