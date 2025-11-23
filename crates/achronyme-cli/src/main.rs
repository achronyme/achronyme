use clap::{Parser, Subcommand};
use std::fs;

mod formatting;
mod symbols;
mod lint;

/// Achronyme - Scientific Computing Language
#[derive(Parser)]
#[command(name = "achronyme")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Scientific computing language with gradual typing", long_about = "Achronyme Development Toolkit\n\nProvides tools for developing, checking, and debugging Achronyme programs:\n  - Syntax and compilation checking\n  - Module inspection and bytecode analysis\n  - Code formatting and linting\n  - Script execution")]
#[command(author = "Achronyme Team")]
struct Cli {
    /// File to execute (.ach or .soc) or expression to evaluate
    #[arg(value_name = "INPUT")]
    input: Option<String>,

    /// Evaluate an expression directly
    #[arg(short, long, value_name = "EXPR")]
    eval: Option<String>,

    /// Show disassembled bytecode
    #[arg(long)]
    debug_bytecode: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
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
    /// Check syntax and compilation without executing
    Check {
        /// File to check
        file: String,
    },
    /// Inspect compiled module (show statistics and metadata)
    Inspect {
        /// File to inspect
        file: String,
        /// Show detailed bytecode statistics
        #[arg(long)]
        verbose: bool,
    },
    /// Disassemble bytecode
    Disassemble {
        /// File to disassemble
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

    let debug_bytecode = cli.debug_bytecode;

    // Handle subcommands first
    if let Some(command) = cli.command {
        match command {
            Commands::Run { file } => run_file(&file, debug_bytecode),
            Commands::Eval { expression } => run_expression(&expression),
            Commands::Check { file } => check_command(&file),
            Commands::Inspect { file, verbose } => inspect_command(&file, verbose),
            Commands::Disassemble { file } => disassemble_command(&file),
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

    // Handle positional input
    match cli.input {
        None => {
            // No input provided - show help
            eprintln!("Error: No input provided.");
            eprintln!();
            eprintln!("Usage: achronyme <COMMAND> or achronyme <FILE>");
            eprintln!();
            eprintln!("Try 'achronyme --help' for more information.");
            std::process::exit(1);
        }
        Some(input) => {
            if input.ends_with(".ach") || input.ends_with(".soc") {
                run_file(&input, debug_bytecode);
            } else {
                run_expression(&input);
            }
        }
    }
}

fn check_command(filename: &str) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    // Step 1: Parse
    let ast = match achronyme_parser::parse(&contents) {
        Ok(ast) => {
            println!("✓ Syntax OK");
            ast
        }
        Err(err) => {
            eprintln!("✗ Syntax error in '{}':", filename);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    // Step 2: Compile
    let mut compiler = achronyme_vm::Compiler::new(filename.to_string());
    match compiler.compile(&ast) {
        Ok(_module) => {
            println!("✓ Compilation OK");
            println!("\nFile '{}' is ready to execute", filename);
        }
        Err(err) => {
            eprintln!("✗ Compilation error in '{}':", filename);
            eprintln!("{}", err);
            std::process::exit(1);
        }
    }
}

fn inspect_command(filename: &str, verbose: bool) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    // Parse
    let ast = match achronyme_parser::parse(&contents) {
        Ok(ast) => ast,
        Err(err) => {
            eprintln!("Parse error: {:?}", err);
            std::process::exit(1);
        }
    };

    // Compile
    let mut compiler = achronyme_vm::Compiler::new(filename.to_string());
    let module = match compiler.compile(&ast) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("Compile error: {}", err);
            std::process::exit(1);
        }
    };

    // Display module information
    println!("Module: {}", module.name);
    println!();
    println!("Main Function:");
    println!("  Name: {}", module.main.name);
    println!("  Parameters: {}", module.main.param_count);
    println!("  Registers: {}", module.main.register_count);
    println!("  Instructions: {}", module.main.code.len());
    println!("  Upvalues: {}", module.main.upvalues.len());
    println!("  Nested Functions: {}", module.main.functions.len());
    println!();
    println!("Module Constants: {} values, {} strings",
             module.constants.constants.len(),
             module.constants.strings.len());

    if verbose {
        println!();
        println!("Detailed Constant Pool:");
        println!("  Values: {}", module.constants.constants.len());
        for (i, val) in module.constants.constants.iter().enumerate() {
            println!("    [{}] {}", i, format_value(val));
        }
        println!("  Strings: {}", module.constants.strings.len());
        for (i, s) in module.constants.strings.iter().enumerate() {
            println!("    [{}] \"{}\"", i, s);
        }

        if !module.main.functions.is_empty() {
            println!();
            println!("Nested Functions:");
            for (i, func) in module.main.functions.iter().enumerate() {
                println!("  [{}] {} (params: {}, registers: {}, instructions: {})",
                    i, func.name, func.param_count, func.register_count, func.code.len());
            }
        }
    }
}

fn disassemble_command(filename: &str) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    // Parse
    let ast = match achronyme_parser::parse(&contents) {
        Ok(ast) => ast,
        Err(err) => {
            eprintln!("Parse error: {:?}", err);
            std::process::exit(1);
        }
    };

    // Compile
    let mut compiler = achronyme_vm::Compiler::new(filename.to_string());
    let module = match compiler.compile(&ast) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("Compile error: {}", err);
            std::process::exit(1);
        }
    };

    // Disassemble using the existing utility
    println!("Disassembly of '{}':", filename);
    println!();
    achronyme_vm::disassemble_function(&module.main, filename);
}

fn run_file(filename: &str, debug_bytecode: bool) {
    let contents = match fs::read_to_string(filename) {
        Ok(contents) => contents,
        Err(err) => {
            eprintln!("Error reading file '{}': {}", filename, err);
            std::process::exit(1);
        }
    };

    // Parse
    let ast = match achronyme_parser::parse(&contents) {
        Ok(ast) => ast,
        Err(err) => {
            eprintln!("Parse error: {:?}", err);
            std::process::exit(1);
        }
    };

    // Compile
    let mut compiler = achronyme_vm::Compiler::new(filename.to_string());
    let module = match compiler.compile(&ast) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("Compile error: {}", err);
            std::process::exit(1);
        }
    };

    // Debug: Print bytecode if requested
    if debug_bytecode {
        achronyme_vm::disassemble_function(&module.main, filename);
    }

    // Execute
    let mut vm = achronyme_vm::VM::new();
    match vm.execute(module) {
        Ok(result) => println!("{}", format_vm_value(&result)),
        Err(err) => {
            eprintln!("Runtime error: {}", err);
            std::process::exit(1);
        }
    }
}

fn run_expression(expr: &str) {
    // Parse
    let ast = match achronyme_parser::parse(expr) {
        Ok(ast) => ast,
        Err(err) => {
            eprintln!("Parse error: {:?}", err);
            std::process::exit(1);
        }
    };

    // Compile
    let mut compiler = achronyme_vm::Compiler::new("<eval>".to_string());
    let module = match compiler.compile(&ast) {
        Ok(module) => module,
        Err(err) => {
            eprintln!("Compile error: {}", err);
            std::process::exit(1);
        }
    };

    // Execute
    let mut vm = achronyme_vm::VM::new();
    match vm.execute(module) {
        Ok(result) => println!("{}", format_vm_value(&result)),
        Err(err) => {
            eprintln!("Runtime error: {}", err);
            std::process::exit(1);
        }
    }
}

fn format_vm_value(value: &achronyme_types::value::Value) -> String {
    // VM values use the same type, so we can reuse format_value
    format_value(value)
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
            let elements: Vec<String> = v.borrow().iter()
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
            let mut fields: Vec<String> = map.borrow().iter()
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
        Value::Generator(_) => {
            // Generators are opaque type-erased handles, can't inspect internal state
            "<generator>".to_string()
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
        Value::Iterator(_) => {
            "<iterator>".to_string()
        }
        Value::Builder(_) => {
            "<builder>".to_string()
        }
    }
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
