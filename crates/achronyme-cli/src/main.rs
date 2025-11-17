use achronyme_eval::Evaluator;
use clap::{Parser, Subcommand};
use rustyline::error::ReadlineError;
use rustyline::{Editor, Config};
use std::fs;

mod highlighter;
mod lsp_completer;
mod repl_helper;
mod formatting;
mod symbols;
mod lint;

use repl_helper::ReplHelper;

/// Achronyme - Scientific Computing Language
#[derive(Parser)]
#[command(name = "achronyme")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Scientific computing language with gradual typing", long_about = None)]
#[command(author = "Achronyme Team")]
struct Cli {
    /// File to execute (.ach or .soc) or expression to evaluate
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    /// Evaluate an expression directly
    #[arg(short, long, value_name = "EXPR")]
    eval: Option<String>,

    /// Run in REPL mode (default when no input)
    #[arg(short, long)]
    interactive: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive REPL
    Repl,
    /// Run a script file
    Run {
        /// Path to the script file
        file: String,
    },
    /// Evaluate an expression
    Eval {
        /// Expression to evaluate
        expression: String,
    },
    /// Check syntax without executing
    Check {
        /// File to check
        file: String,
    },
    /// Format Achronyme source files
    Format {
        /// File to format
        file: String,
        /// Check if file is properly formatted (don't modify)
        #[arg(long)]
        check: bool,
        /// Show diff instead of modifying file
        #[arg(long)]
        diff: bool,
    },
    /// Check for parse errors
    Lint {
        /// File to lint
        file: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// List symbols in a file
    Symbols {
        /// File to scan
        file: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    // Handle subcommands first
    if let Some(command) = cli.command {
        match command {
            Commands::Repl => run_repl(),
            Commands::Run { file } => run_file(&file),
            Commands::Eval { expression } => run_expression(&expression),
            Commands::Check { file } => check_syntax(&file),
            Commands::Format { file, check, diff } => format_command(&file, check, diff),
            Commands::Lint { file, json } => lint_command(&file, json),
            Commands::Symbols { file, json } => symbols_command(&file, json),
        }
        return;
    }

    // Handle --eval flag
    if let Some(expr) = cli.eval {
        run_expression(&expr);
        return;
    }

    // Handle --interactive flag
    if cli.interactive {
        run_repl();
        return;
    }

    // Handle positional input
    match cli.input {
        None => run_repl(),
        Some(input) => {
            if input.ends_with(".ach") || input.ends_with(".soc") {
                run_file(&input);
            } else {
                run_expression(&input);
            }
        }
    }
}

fn check_syntax(filename: &str) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    match achronyme_parser::parse(&contents) {
        Ok(_) => {
            println!("Syntax OK: {}", filename);
        }
        Err(err) => {
            eprintln!("Syntax error in '{}':", filename);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
}

fn run_repl() {
    println!("Achronyme REPL v{}", env!("CARGO_PKG_VERSION"));
    println!("Type 'exit' or 'quit' to exit, 'help' for help, 'clear' to clear screen");
    println!();

    let config = Config::builder()
        .auto_add_history(true)
        .build();

    let helper = ReplHelper::new();
    let mut rl = Editor::with_config(config).expect("Failed to create editor");
    rl.set_helper(Some(helper));

    // Load history from file
    let history_path = dirs::home_dir()
        .map(|mut p| {
            p.push(".achronyme_history");
            p
        });

    if let Some(ref path) = history_path {
        let _ = rl.load_history(path);
    }

    let mut evaluator = Evaluator::new();
    let mut line_number = 1;
    let mut input_buffer = String::new();

    loop {
        let prompt = if input_buffer.is_empty() {
            format!("ach[{}]> ", line_number)
        } else {
            "     ...> ".to_string()
        };

        match rl.readline(&prompt) {
            Ok(line) => {
                // Add line to buffer
                if !input_buffer.is_empty() {
                    input_buffer.push('\n');
                }
                input_buffer.push_str(&line);

                let trimmed = input_buffer.trim();

                // Handle special commands (only when buffer is a single line)
                if input_buffer.lines().count() == 1 {
                    match trimmed {
                        "exit" | "quit" => {
                            println!("Goodbye!");
                            break;
                        }
                        "help" => {
                            print_help();
                            input_buffer.clear();
                            continue;
                        }
                        "clear" => {
                            clear_screen();
                            evaluator = Evaluator::new();
                            println!("Screen cleared and environment reset");
                            input_buffer.clear();
                            continue;
                        }
                        "cls" => {
                            clear_screen();
                            input_buffer.clear();
                            continue;
                        }
                        "" => {
                            input_buffer.clear();
                            continue;
                        }
                        _ => {}
                    }
                }

                // Check if expression should continue (is incomplete)
                if should_continue_reading(&input_buffer) {
                    continue; // Wait for more input
                }

                // Expression is complete, evaluate it
                match evaluate_expression(&mut evaluator, trimmed) {
                    Ok(result) => println!("{}", result),
                    Err(err) => eprintln!("Error: {}", err),
                }

                input_buffer.clear();
                line_number += 1;
            }
            Err(ReadlineError::Interrupted) => {
                println!("^C");
                input_buffer.clear();
                continue;
            }
            Err(ReadlineError::Eof) => {
                println!("Goodbye!");
                break;
            }
            Err(err) => {
                eprintln!("Error reading input: {}", err);
                break;
            }
        }
    }

    // Save history to file
    if let Some(path) = history_path {
        let _ = rl.save_history(&path);
    }
}

/// Check if we should continue reading more input (expression is incomplete)
/// Uses a hybrid approach: fast delimiter check + parser confirmation
fn should_continue_reading(input: &str) -> bool {
    // First: Quick check for balanced delimiters
    if !has_balanced_delimiters(input) {
        return true; // Definitely incomplete
    }

    // Second: If delimiters are balanced, try parsing to confirm
    // We use the parser to distinguish between "complete but invalid" vs "incomplete"
    match achronyme_parser::parse(input) {
        Ok(_) => false, // ✅ Complete and valid
        Err(e) => {
            // Check if it looks like an incomplete expression error
            let error_msg = e.to_string();
            // Pest reports "expected X, found EOI" when input ends prematurely
            error_msg.contains("expected") && error_msg.contains("EOI")
        }
    }
}

/// Fast check for balanced delimiters (parentheses, braces, brackets)
/// Also handles strings to avoid counting delimiters inside string literals
fn has_balanced_delimiters(input: &str) -> bool {
    let mut paren_count = 0;
    let mut brace_count = 0;
    let mut bracket_count = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for ch in input.chars() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '(' if !in_string => paren_count += 1,
            ')' if !in_string => {
                paren_count -= 1;
                if paren_count < 0 {
                    return false; // More closing than opening
                }
            }
            '{' if !in_string => brace_count += 1,
            '}' if !in_string => {
                brace_count -= 1;
                if brace_count < 0 {
                    return false; // More closing than opening
                }
            }
            '[' if !in_string => bracket_count += 1,
            ']' if !in_string => {
                bracket_count -= 1;
                if bracket_count < 0 {
                    return false; // More closing than opening
                }
            }
            _ => {}
        }
    }

    // Balanced if all counts are zero and not inside a string
    paren_count == 0 && brace_count == 0 && bracket_count == 0 && !in_string
}

fn clear_screen() {
    // Cross-platform screen clearing
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(&["/C", "cls"])
            .status();
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::process::Command::new("clear").status();
    }

    // Also try ANSI escape sequence as fallback
    print!("\x1B[2J\x1B[1;1H");
}

fn run_file(filename: &str) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    let mut evaluator = Evaluator::new();

    // Set the current file directory for relative imports
    evaluator.set_current_file_dir(filename);

    // Parse and evaluate the entire file using Pest
    match evaluate_expression(&mut evaluator, &contents) {
        Ok(result) => println!("{}", result),
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    }
}

fn run_expression(expr: &str) {
    let mut evaluator = Evaluator::new();

    match evaluate_expression(&mut evaluator, expr) {
        Ok(result) => println!("{}", result),
        Err(err) => {
            eprintln!("Error: {}", err);
            std::process::exit(1);
        }
    }
}

fn evaluate_expression(evaluator: &mut Evaluator, input: &str) -> Result<String, String> {
    // Parse and evaluate using Pest
    let result = evaluator.eval_str(input)?;

    // Format result
    Ok(format_value(&result))
}

fn format_value(value: &achronyme_types::value::Value) -> String {
    use achronyme_types::value::Value;

    match value {
        Value::Number(n) => {
            // Handle IEEE 754 special values
            if n.is_nan() {
                "NaN".to_string()
            } else if n.is_infinite() {
                if n.is_sign_positive() {
                    "Infinity".to_string()
                } else {
                    "-Infinity".to_string()
                }
            } else {
                format!("{}", n)
            }
        }
        Value::Boolean(b) => format!("{}", b),
        Value::String(s) => format!("\"{}\"", s),
        Value::Complex(c) => {
            if c.im >= 0.0 {
                format!("{}+{}i", c.re, c.im)
            } else {
                format!("{}{}i", c.re, c.im)
            }
        }
        Value::Vector(v) => {
            let elements: Vec<String> = v.iter()
                .map(|val| format_value(val))
                .collect();
            format!("[{}]", elements.join(", "))
        }
        Value::Tensor(t) => {
            // Format tensor based on rank
            match t.rank() {
                0 => {
                    let val = t.data()[0];
                    if val.is_nan() {
                        "NaN".to_string()
                    } else if val.is_infinite() {
                        if val.is_sign_positive() {
                            "Infinity".to_string()
                        } else {
                            "-Infinity".to_string()
                        }
                    } else {
                        format!("{}", val)
                    }
                }
                1 => {
                    // Vector
                    let elements: Vec<String> = t.data().iter()
                        .map(|&x| {
                            if x.is_nan() {
                                "NaN".to_string()
                            } else if x.is_infinite() {
                                if x.is_sign_positive() {
                                    "Infinity".to_string()
                                } else {
                                    "-Infinity".to_string()
                                }
                            } else {
                                format!("{}", x)
                            }
                        })
                        .collect();
                    format!("[{}]", elements.join(", "))
                }
                2 => {
                    // Matrix
                    let rows = t.shape()[0];
                    let cols = t.shape()[1];
                    let mut row_strings = Vec::new();
                    for i in 0..rows {
                        let mut row_elements = Vec::new();
                        for j in 0..cols {
                            if let Ok(val) = t.get(&[i, j]) {
                                row_elements.push(format!("{}", val));
                            }
                        }
                        row_strings.push(format!("[{}]", row_elements.join(", ")));
                    }
                    format!("[{}]", row_strings.join(",\n "))
                }
                _ => {
                    // Higher-order tensor (3D+) - use Display trait
                    format!("{}", t)
                }
            }
        }
        Value::ComplexTensor(ct) => {
            // Format complex tensor - use Display trait
            format!("{}", ct)
        }
        Value::Record(map) => {
            let mut fields: Vec<String> = map.iter()
                .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                .collect();
            fields.sort(); // Sort for consistent output
            format!("{{ {} }}", fields.join(", "))
        }
        Value::Edge { from, to, directed, properties } => {
            let arrow = if *directed { "->" } else { "<>" };
            if properties.is_empty() {
                format!("{} {} {}", from, arrow, to)
            } else {
                let props: Vec<String> = properties.iter()
                    .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                    .collect();
                format!("{} {} {}: {{ {} }}", from, arrow, to, props.join(", "))
            }
        }
        Value::Function(_) => "<function>".to_string(),
        Value::TailCall(_) => {
            // TailCall is an internal marker that should never reach the REPL
            // If it does, it indicates a bug in TCO implementation
            "<internal:tail-call>".to_string()
        }
        Value::EarlyReturn(_) => {
            // EarlyReturn is an internal marker that should never reach the REPL
            // If it does, it indicates a bug in return statement implementation
            "<internal:early-return>".to_string()
        }
        Value::MutableRef(rc) => {
            // Auto-deref mutable references for display
            format_value(&rc.borrow())
        }
        Value::Null => "null".to_string(),
        Value::Generator(gen_rc) => {
            let state = gen_rc.borrow();
            if state.done {
                "<generator:exhausted>".to_string()
            } else {
                "<generator>".to_string()
            }
        }
        Value::GeneratorYield(_) => {
            // GeneratorYield is an internal marker that should never reach the REPL
            "<internal:generator-yield>".to_string()
        }
        Value::Error { message, kind, .. } => {
            match kind {
                Some(k) => format!("Error({}: {})", k, message),
                None => format!("Error({})", message),
            }
        }
        Value::LoopBreak(_) => {
            "<internal:loop-break>".to_string()
        }
        Value::LoopContinue => {
            "<internal:loop-continue>".to_string()
        }
    }
}

fn print_help() {
    use nu_ansi_term::Color;

    println!("{}", Color::Green.bold().paint("Achronyme REPL Commands:"));
    println!("  {}        - Show this help message", Color::Cyan.paint("help"));
    println!("  {}       - Clear screen and reset environment", Color::Cyan.paint("clear"));
    println!("  {}        - Clear screen only (keep environment)", Color::Cyan.paint("cls"));
    println!("  {}  - Exit the REPL", Color::Cyan.paint("exit, quit"));
    println!();
    println!("{}", Color::Green.bold().paint("Features:"));
    println!("  - Syntax highlighting (automatic)");
    println!("  - Command history (use ↑/↓ arrows)");
    println!("  - Tab completion for built-in functions");
    println!("  - History saved to ~/.achronyme_history");
    println!();
    println!("{}", Color::Green.bold().paint("Examples:"));
    println!("  {}         - Basic arithmetic", Color::Yellow.paint("2 + 2"));
    println!("  {}  - Variable assignment", Color::Yellow.paint("let x = 5"));
    println!("  {}    - Lambda function", Color::Yellow.paint("let f = x => x^2"));
    println!("  {}  - Numerical derivative", Color::Yellow.paint("diff(f, 2, 1e-5)"));
    println!("  {}  - Numerical integration", Color::Yellow.paint("integral(sin, 0, 3.14159, 100)"));
    println!("  {}  - FFT magnitude", Color::Yellow.paint("fft_mag([1, 2, 3, 4])"));
}

// ============================================================================
// FORMAT COMMAND
// ============================================================================

fn format_command(filename: &str, check_only: bool, show_diff: bool) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    // Format the content
    let formatted = formatting::format_code(&contents);

    if check_only {
        if contents == formatted {
            println!("File is properly formatted: {}", filename);
        } else {
            eprintln!("File is not properly formatted: {}", filename);
            std::process::exit(1);
        }
    } else if show_diff {
        show_diff_output(&contents, &formatted, filename);
    } else {
        // Write the formatted content back
        match fs::write(filename, &formatted) {
            Ok(_) => println!("Formatted: {}", filename),
            Err(err) => {
                eprintln!("Error writing file '{}': {}", filename, err);
                std::process::exit(1);
            }
        }
    }
}

fn show_diff_output(original: &str, formatted: &str, filename: &str) {
    let original_lines: Vec<&str> = original.lines().collect();
    let formatted_lines: Vec<&str> = formatted.lines().collect();

    println!("--- a/{}", filename);
    println!("+++ b/{}", filename);

    let mut orig_idx = 0;
    let mut fmt_idx = 0;

    while orig_idx < original_lines.len() || fmt_idx < formatted_lines.len() {
        let orig_line = original_lines.get(orig_idx).copied().unwrap_or("");
        let fmt_line = formatted_lines.get(fmt_idx).copied().unwrap_or("");

        if orig_line == fmt_line {
            println!(" {}", orig_line);
            orig_idx += 1;
            fmt_idx += 1;
        } else {
            if !orig_line.is_empty() || orig_idx < original_lines.len() {
                println!("-{}", orig_line);
                orig_idx += 1;
            }
            if !fmt_line.is_empty() || fmt_idx < formatted_lines.len() {
                println!("+{}", fmt_line);
                fmt_idx += 1;
            }
        }
    }
}

// ============================================================================
// LINT COMMAND
// ============================================================================

fn lint_command(filename: &str, json_output: bool) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    let errors = lint::check_errors(&contents);

    if json_output {
        // Output as JSON
        match serde_json::to_string_pretty(&errors) {
            Ok(json) => println!("{}", json),
            Err(err) => {
                eprintln!("Error serializing JSON: {}", err);
                std::process::exit(1);
            }
        }
    } else {
        if errors.is_empty() {
            println!("No parse errors found: {}", filename);
        } else {
            eprintln!("Parse errors in '{}':", filename);
            for error in &errors {
                eprintln!(
                    "  {}:{}:{}: {} [{}]",
                    filename, error.line, error.column, error.message, error.severity
                );
            }
            std::process::exit(1);
        }
    }
}

// ============================================================================
// SYMBOLS COMMAND
// ============================================================================

fn symbols_command(filename: &str, json_output: bool) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    // Parse the file
    match achronyme_parser::parse(&contents) {
        Ok(ast) => {
            let symbols = symbols::extract_symbols(&ast, &contents);

            if json_output {
                match serde_json::to_string_pretty(&symbols) {
                    Ok(json) => println!("{}", json),
                    Err(err) => {
                        eprintln!("Error serializing JSON: {}", err);
                        std::process::exit(1);
                    }
                }
            } else {
                if symbols.is_empty() {
                    println!("No symbols found in: {}", filename);
                } else {
                    println!("Symbols in '{}':", filename);
                    for symbol in &symbols {
                        println!(
                            "  {} {} (line {})",
                            symbol.kind, symbol.name, symbol.line
                        );
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("Parse error in '{}': {}", filename, err);
            std::process::exit(1);
        }
    }
}
