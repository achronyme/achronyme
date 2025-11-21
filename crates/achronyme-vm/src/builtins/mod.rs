//! Built-in functions module
//!
//! This module provides all built-in functions for the VM, organized by category:
//! - Math: Trigonometric, exponential, rounding, etc.
//! - String: Case conversion, trimming, searching, manipulation
//! - Vector: Modification, slicing, transformation
//! - I/O: Print, input
//! - Statistics: Sum, mean, standard deviation
//! - Linear Algebra: Dot, cross, norm, normalize
//! - Complex: Complex number operations
//! - Utils: Type inspection, conversion, special value checks
//! - Records: Object/map operations

pub mod array_advanced;
pub mod complex;
pub mod debug;
pub mod dsp;
pub mod graph;
pub mod hof;
pub mod io;
pub mod linalg;
pub mod math;
pub mod module_system;
pub mod numerical;
pub mod pert;
pub mod records;
pub mod registry;
pub mod statistics;
pub mod string;
pub mod utils;
pub mod vector;

use registry::BuiltinRegistry;

/// Create and populate the built-in function registry
///
/// This function registers all built-in functions and returns a ready-to-use registry.
/// The registry provides O(1) lookup by both name (for compiler) and index (for VM).
pub fn create_builtin_registry() -> BuiltinRegistry {
    let mut registry = BuiltinRegistry::new();

    // ========================================================================
    // Math Functions
    // ========================================================================

    // Trigonometric
    registry.register("sin", math::vm_sin(), 1);
    registry.register("cos", math::vm_cos(), 1);
    registry.register("tan", math::vm_tan(), 1);
    registry.register("asin", math::vm_asin(), 1);
    registry.register("acos", math::vm_acos(), 1);
    registry.register("atan", math::vm_atan(), 1);
    registry.register("atan2", math::vm_atan2, 2);

    // Hyperbolic
    registry.register("sinh", math::vm_sinh(), 1);
    registry.register("cosh", math::vm_cosh(), 1);
    registry.register("tanh", math::vm_tanh(), 1);

    // Exponential and Logarithmic
    registry.register("exp", math::vm_exp(), 1);
    registry.register("ln", math::vm_ln(), 1);
    registry.register("log", math::vm_log(), 2);
    registry.register("log10", math::vm_log10(), 1);
    registry.register("log2", math::vm_log2(), 1);

    // Rounding
    registry.register("floor", math::vm_floor(), 1);
    registry.register("ceil", math::vm_ceil(), 1);
    registry.register("round", math::vm_round(), 1);
    registry.register("trunc", math::vm_trunc(), 1);

    // Other Math
    registry.register("sqrt", math::vm_sqrt(), 1);
    registry.register("abs", math::vm_abs(), 1);
    registry.register("pow", math::vm_pow(), 2);
    registry.register("min", math::vm_min, -1); // variadic
    registry.register("max", math::vm_max, -1); // variadic
    registry.register("sign", math::vm_sign(), 1);
    registry.register("deg", math::vm_deg(), 1);
    registry.register("rad", math::vm_rad(), 1);
    registry.register("cbrt", math::vm_cbrt(), 1);

    // Constants
    registry.register("pi", math::vm_pi, 0);
    registry.register("e", math::vm_e, 0);

    // Precision Control
    registry.register("set_precision", math::vm_set_precision, 1);

    // ========================================================================
    // String Functions
    // ========================================================================

    // Length and access
    registry.register("len", string::vm_len, 1);
    registry.register("char_at", string::vm_char_at, 2);

    // Case conversion
    registry.register("upper", string::vm_upper, 1);
    registry.register("lower", string::vm_lower, 1);

    // Whitespace
    registry.register("trim", string::vm_trim, 1);
    registry.register("trim_start", string::vm_trim_start, 1);
    registry.register("trim_end", string::vm_trim_end, 1);

    // Search
    registry.register("contains", string::vm_contains, 2);
    registry.register("starts_with", string::vm_starts_with, 2);
    registry.register("ends_with", string::vm_ends_with, 2);

    // Manipulation
    registry.register("replace", string::vm_replace, 3);
    registry.register("split", string::vm_split, 2);
    registry.register("join", string::vm_join, 2);
    registry.register("substring", string::vm_substring, 3);
    registry.register("concat", string::vm_concat, 2);

    // ========================================================================
    // Vector Functions
    // ========================================================================

    // Modification
    registry.register("push", vector::vm_push, 2);
    registry.register("pop", vector::vm_pop, 1);
    registry.register("insert", vector::vm_insert, 3);
    registry.register("remove", vector::vm_remove, 2);

    // Slicing
    registry.register("slice", vector::vm_slice, 3);
    registry.register("concat_vec", vector::vm_concat_vec, 2);

    // Transformation
    registry.register("reverse", vector::vm_reverse, 1);
    registry.register("sort", vector::vm_sort, 1);

    // Query
    registry.register("first", vector::vm_first, 1);
    registry.register("last", vector::vm_last, 1);
    registry.register("is_empty", vector::vm_is_empty, 1);

    // ========================================================================
    // I/O Functions
    // ========================================================================

    registry.register("print", io::vm_print, -1); // variadic
    registry.register("println", io::vm_println, -1); // variadic
    registry.register("input", io::vm_input, -1); // 0 or 1 args

    // ========================================================================
    // Statistics Functions
    // ========================================================================

    registry.register("sum", statistics::vm_sum, 1);
    registry.register("mean", statistics::vm_mean, 1);
    registry.register("std", statistics::vm_std, 1);

    // ========================================================================
    // Linear Algebra Functions
    // ========================================================================

    registry.register("dot", linalg::vm_dot, 2);
    registry.register("cross", linalg::vm_cross, 2);
    registry.register("norm", linalg::vm_norm, 1);
    registry.register("normalize", linalg::vm_normalize, 1);
    registry.register("transpose", linalg::vm_transpose, 1);
    registry.register("det", linalg::vm_det, 1);
    registry.register("trace", linalg::vm_trace, 1);

    // ========================================================================
    // Complex Number Functions
    // ========================================================================

    registry.register("complex", complex::vm_complex, 2);
    registry.register("real", complex::vm_real, 1);
    registry.register("imag", complex::vm_imag, 1);
    registry.register("conj", complex::vm_conj, 1);
    registry.register("arg", complex::vm_arg, 1);
    registry.register("magnitude", complex::vm_magnitude, 1);
    registry.register("phase", complex::vm_phase, 1);
    registry.register("polar", complex::vm_polar, 2);
    registry.register("to_polar", complex::vm_to_polar, 1);

    // ========================================================================
    // Utility Functions
    // ========================================================================

    registry.register("typeof", utils::vm_typeof, 1);
    registry.register("str", utils::vm_str, 1);
    registry.register("isnan", utils::vm_isnan, 1);
    registry.register("isinf", utils::vm_isinf, 1);
    registry.register("isfinite", utils::vm_isfinite, 1);

    // ========================================================================
    // Debug/Introspection Functions
    // ========================================================================

    registry.register("describe", debug::vm_describe, 1);

    // ========================================================================
    // Record Functions
    // ========================================================================

    registry.register("keys", records::vm_keys, 1);
    registry.register("values", records::vm_values, 1);
    registry.register("has_field", records::vm_has_field, 2);

    // ========================================================================
    // Advanced Array Functions (Phase 4E)
    // ========================================================================

    registry.register("range", array_advanced::vm_range, -1); // 2-3 args
    registry.register("product", array_advanced::vm_product, 1);
    registry.register("zip", array_advanced::vm_zip, 2);
    registry.register("flatten", array_advanced::vm_flatten, -1); // 1-2 args
    registry.register("take", array_advanced::vm_take, 2);
    registry.register("drop", array_advanced::vm_drop, 2);
    registry.register("unique", array_advanced::vm_unique, 1);
    registry.register("chunk", array_advanced::vm_chunk, 2);

    // ========================================================================
    // Higher-Order Functions (HOF)
    // ========================================================================

    registry.register("map", hof::vm_map, 2);
    registry.register("filter", hof::vm_filter, 2);
    registry.register("reduce", hof::vm_reduce, 3);
    registry.register("pipe", hof::vm_pipe, -1); // variadic
    registry.register("any", hof::vm_any, 2);
    registry.register("all", hof::vm_all, 2);
    registry.register("find", hof::vm_find, 2);
    registry.register("findIndex", hof::vm_find_index, 2);
    registry.register("count", hof::vm_count, 2);

    // ========================================================================
    // Module System
    // ========================================================================

    registry.register("import", module_system::vm_import, 1);

    // ========================================================================
    // Digital Signal Processing (DSP) Functions
    // ========================================================================

    // FFT Functions
    registry.register("fft", dsp::vm_fft, 1);
    registry.register("ifft", dsp::vm_ifft, 1);
    registry.register("fft_mag", dsp::vm_fft_mag, 1);
    registry.register("fft_phase", dsp::vm_fft_phase, 1);

    // Convolution
    registry.register("conv", dsp::vm_conv, 2);
    registry.register("conv_fft", dsp::vm_conv_fft, 2);

    // Window Functions
    registry.register("hanning", dsp::vm_hanning, 1);
    registry.register("hamming", dsp::vm_hamming, 1);
    registry.register("blackman", dsp::vm_blackman, 1);
    registry.register("rectangular", dsp::vm_rectangular, 1);

    // Utility Functions
    registry.register("linspace", dsp::vm_linspace, 3);

    // ========================================================================
    // Numerical Analysis Functions (Phase 4I)
    // ========================================================================

    // Differentiation
    registry.register("diff", numerical::vm_diff, -1); // 2-3 args
    registry.register("diff2", numerical::vm_diff2, -1); // 2-3 args
    registry.register("diff3", numerical::vm_diff3, -1); // 2-3 args
    registry.register("gradient", numerical::vm_gradient, -1); // 2-3 args

    // Integration
    registry.register("integral", numerical::vm_integral, -1); // 3-4 args
    registry.register("simpson", numerical::vm_simpson, -1); // 3-4 args
    registry.register("romberg", numerical::vm_romberg, -1); // 3-4 args
    registry.register("quad", numerical::vm_quad, -1); // 3-4 args

    // Root Finding
    registry.register("solve", numerical::vm_solve, -1); // 3-4 args
    registry.register("newton", numerical::vm_newton, -1); // 2-4 args
    registry.register("secant", numerical::vm_secant, -1); // 3-4 args

    // ========================================================================
    // Graph Theory Functions (Phase 4K)
    // ========================================================================

    // Network Construction
    registry.register("network", graph::vm_network, -1); // 1-2 args
    registry.register("nodes", graph::vm_nodes, 1);
    registry.register("edges", graph::vm_edges, 1);
    registry.register("neighbors", graph::vm_neighbors, 2);
    registry.register("degree", graph::vm_degree, 2);

    // Traversal
    registry.register("bfs", graph::vm_bfs, 2);
    registry.register("dfs", graph::vm_dfs, 2);
    registry.register("bfs_path", graph::vm_bfs_path, 3);

    // Shortest Path
    registry.register("dijkstra", graph::vm_dijkstra, 3);

    // Minimum Spanning Tree
    registry.register("kruskal", graph::vm_kruskal, 1);
    registry.register("prim", graph::vm_prim, 2);

    // Connectivity
    registry.register("connected_components", graph::vm_connected_components, 1);
    registry.register("is_connected", graph::vm_is_connected, 1);
    registry.register("has_cycle", graph::vm_has_cycle, 1);

    // Topological Sort
    registry.register("topological_sort", graph::vm_topological_sort, 1);

    // ========================================================================
    // PERT/CPM Functions (Phase 4L)
    // ========================================================================

    // Critical Path Method
    registry.register("forward_pass", pert::vm_forward_pass, 1);
    registry.register("backward_pass", pert::vm_backward_pass, 1);
    registry.register("calculate_slack", pert::vm_calculate_slack, 1);
    registry.register("critical_path", pert::vm_critical_path, 1);
    registry.register("all_critical_paths", pert::vm_all_critical_paths, 1);
    registry.register("project_duration", pert::vm_project_duration, 1);

    // PERT Probabilistic
    registry.register("expected_time", pert::vm_expected_time, 3);
    registry.register("task_variance", pert::vm_task_variance, 3);
    registry.register("project_variance", pert::vm_project_variance, 1);
    registry.register("project_std_dev", pert::vm_project_std_dev, 1);
    registry.register("completion_probability", pert::vm_completion_probability, 2);
    registry.register("time_for_probability", pert::vm_time_for_probability, 2);

    // Comprehensive Analysis
    registry.register("pert_analysis", pert::vm_pert_analysis, 1);

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = create_builtin_registry();

        // Check some functions are registered
        assert!(registry.get_id("sin").is_some());
        assert!(registry.get_id("cos").is_some());
        assert!(registry.get_id("print").is_some());
        assert!(registry.get_id("len").is_some());

        // Check non-existent function
        assert!(registry.get_id("nonexistent").is_none());

        // Verify we have a good number of functions
        // Original: 56 functions
        // Added: 3 math (deg, rad, cbrt) + 3 stats + 7 linalg + 9 complex (incl. new ones) + 5 utils + 3 records + 8 array_advanced + 9 hof + 1 module + 11 dsp + 11 numerical = 62
        // Total: 118+ functions
        assert!(registry.len() > 115);
    }

    #[test]
    fn test_function_metadata() {
        let registry = create_builtin_registry();

        // Check sin metadata
        let sin_id = registry.get_id("sin").unwrap();
        let sin_meta = registry.get_metadata(sin_id).unwrap();
        assert_eq!(sin_meta.name, "sin");
        assert_eq!(sin_meta.arity, 1);

        // Check variadic function
        let print_id = registry.get_id("print").unwrap();
        let print_meta = registry.get_metadata(print_id).unwrap();
        assert_eq!(print_meta.name, "print");
        assert_eq!(print_meta.arity, -1);
    }
}
