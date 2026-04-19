//! Benchmark: measures the overhead of Vec allocation in native function calls.
//!
//! Compares scenarios with heavy native call volume (map/filter/reduce over
//! large lists) against pure-bytecode loops doing equivalent work.
//!
//! Run with: cargo test -p vm --test native_call_bench -- --nocapture

use akron::{CallFrame, VM};
use compiler::Compiler;
use memory::Function;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.import_strings(compiler.interner.strings);

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_func.constants.clone(),
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("{e}"))?;
    Ok(vm)
}

#[allow(dead_code)]
fn result_int(vm: &VM) -> i64 {
    vm.stack[0].as_int().expect("expected int in R[0]")
}

/// Run a source snippet `iterations` times, return (avg_ns, total_ms).
fn bench(label: &str, source: &str, iterations: usize) -> (u128, u128) {
    // Warm up (compile once, execute once)
    let _ = run(source);

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = run(source).expect("bench run failed");
    }
    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    let avg_ns = elapsed.as_nanos() / iterations as u128;

    eprintln!(
        "  {label:<45} {iterations:>4} iters │ total {total_ms:>6} ms │ avg {avg_ns:>10} ns/iter"
    );

    (avg_ns, total_ms)
}

// ---------------------------------------------------------------------------
// Test 1: Native calls via map() — each element = 1 native call to map +
// 1 closure call per element. Measures Vec alloc overhead at scale.
// ---------------------------------------------------------------------------

#[test]
fn bench_native_map_vs_loop() {
    eprintln!("\n{}", "=".repeat(70));
    eprintln!("  BENCHMARK: native map() vs manual loop (equivalent work)");
    eprintln!("{}", "=".repeat(70));

    let iters = 50;

    // Build a list of 1000 elements via loop
    let map_source = r#"
        let data = []
        mut i = 0
        while i < 1000 {
            data.push(i)
            i = i + 1
        }
        let result = data.map(fn(n) { n * 2 })
        let x = result.len()
    "#;

    // Equivalent work without native HOF — pure bytecode loop
    let loop_source = r#"
        let data = []
        mut i = 0
        while i < 1000 {
            data.push(i)
            i = i + 1
        }
        let result = []
        mut j = 0
        while j < data.len() {
            result.push(data[j] * 2)
            j = j + 1
        }
        let x = result.len()
    "#;

    let (map_ns, _) = bench("map(1000, fn(n) { n * 2 })", map_source, iters);
    let (loop_ns, _) = bench("while-loop equivalent", loop_source, iters);

    let diff = map_ns.saturating_sub(loop_ns);
    let pct = if loop_ns > 0 {
        (diff as f64 / loop_ns as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("\n  Delta: map is {diff} ns/iter slower ({pct:.1}% overhead)");
    eprintln!("  Note: map() does 1000 native calls (1000 Vec allocs)");
}

// ---------------------------------------------------------------------------
// Test 2: Chained HOFs — map + filter + reduce. Measures cumulative impact
// of many native calls in sequence.
// ---------------------------------------------------------------------------

#[test]
fn bench_chained_hofs() {
    eprintln!("\n{}", "=".repeat(70));
    eprintln!("  BENCHMARK: chained HOFs (map > filter > reduce)");
    eprintln!("{}", "=".repeat(70));

    let iters = 50;

    let chained_source = r#"
        let data = []
        mut i = 0
        while i < 500 {
            data.push(i)
            i = i + 1
        }
        let x = data.map(fn(n) { n * 3 })
            .filter(fn(n) { n % 2 == 0 })
            .reduce(0, fn(acc, n) { acc + n })
    "#;

    // Equivalent in pure bytecode
    let loop_source = r#"
        let data = []
        mut i = 0
        while i < 500 {
            data.push(i)
            i = i + 1
        }
        mut acc = 0
        mut j = 0
        while j < data.len() {
            let val = data[j] * 3
            if val % 2 == 0 {
                acc = acc + val
            }
            j = j + 1
        }
        let x = acc
    "#;

    let (chain_ns, _) = bench("map→filter→reduce (500 elems)", chained_source, iters);
    let (loop_ns, _) = bench("while-loop equivalent", loop_source, iters);

    let diff = chain_ns.saturating_sub(loop_ns);
    let pct = if loop_ns > 0 {
        (diff as f64 / loop_ns as f64) * 100.0
    } else {
        0.0
    };

    eprintln!("\n  Delta: chained HOFs are {diff} ns/iter slower ({pct:.1}% overhead)");
    eprintln!("  Note: ~1500 native calls (500 map + 500 filter + 250 reduce)");
}

// ---------------------------------------------------------------------------
// Test 3: Tight native call loop — call a simple native (len) many times
// to isolate the per-call overhead.
// ---------------------------------------------------------------------------

#[test]
fn bench_tight_native_calls() {
    eprintln!("\n{}", "=".repeat(70));
    eprintln!("  BENCHMARK: tight loop calling len() 10,000 times");
    eprintln!("{}", "=".repeat(70));

    let iters = 30;

    // 10k calls to len() — 1-arg native, isolates alloc overhead
    let native_source = r#"
        let data = [1, 2, 3]
        mut sum = 0
        mut i = 0
        while i < 10000 {
            sum = sum + data.len()
            i = i + 1
        }
        let x = sum
    "#;

    // Equivalent without native call — just add a constant
    let pure_source = r#"
        mut sum = 0
        mut i = 0
        while i < 10000 {
            sum = sum + 3
            i = i + 1
        }
        let x = sum
    "#;

    let (native_ns, _) = bench("len() x 10,000", native_source, iters);
    let (pure_ns, _) = bench("constant add x 10,000", pure_source, iters);

    let diff = native_ns.saturating_sub(pure_ns);
    let per_call = diff / 10_000;

    eprintln!("\n  Delta: {diff} ns/iter for 10,000 native calls");
    eprintln!("  Per-call overhead: ~{per_call} ns (includes Vec alloc + fn pointer call)");
}

// ---------------------------------------------------------------------------
// Test 4: Scaling test — same operation at different list sizes.
// ---------------------------------------------------------------------------

#[test]
fn bench_scaling() {
    eprintln!("\n{}", "=".repeat(70));
    eprintln!("  BENCHMARK: map() scaling (100, 500, 1000, 5000 elements)");
    eprintln!("{}", "=".repeat(70));

    let sizes = [100, 500, 1000, 5000];
    let iters = 20;

    let mut results = Vec::new();

    for &size in &sizes {
        let source = format!(
            r#"
            let data = []
            mut i = 0
            while i < {size} {{
                data.push(i)
                i = i + 1
            }}
            let result = data.map(fn(n) {{ n * 2 }})
            let x = result.len()
        "#
        );

        let (avg_ns, _) = bench(&format!("map({size} elems)"), &source, iters);
        results.push((size, avg_ns));
    }

    eprintln!("\n  Scaling analysis:");
    for window in results.windows(2) {
        let (s1, t1) = window[0];
        let (s2, t2) = window[1];
        let size_ratio = s2 as f64 / s1 as f64;
        let time_ratio = t2 as f64 / t1 as f64;
        eprintln!("    {s1:>5} → {s2:>5} elements: size x{size_ratio:.1}, time x{time_ratio:.1}");
    }
    eprintln!("  (Linear scaling = time ratio ≈ size ratio)");
}
