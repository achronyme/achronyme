//! Function signature information for Achronyme
//! Provides signature help data that can be used by LSP server and CLI

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Complete function signature information
#[derive(Clone, Debug)]
pub struct FunctionSignature {
    pub name: String,
    pub signature: String,
    pub documentation: String,
    pub parameters: Vec<ParameterInfo>,
}

/// Information about a single parameter in a function signature
#[derive(Clone, Debug)]
pub struct ParameterInfo {
    pub label: String,
    pub documentation: String,
}

/// All function signatures cached at startup
pub static FUNCTION_SIGNATURES: Lazy<HashMap<String, FunctionSignature>> =
    Lazy::new(build_signatures);

/// Get the signature information for a built-in function
pub fn get_signature(name: &str) -> Option<&'static FunctionSignature> {
    FUNCTION_SIGNATURES.get(name)
}

/// Get all available function signatures
pub fn get_all_signatures() -> &'static HashMap<String, FunctionSignature> {
    &FUNCTION_SIGNATURES
}

fn build_signatures() -> HashMap<String, FunctionSignature> {
    let mut map = HashMap::new();

    // Math Functions
    map.insert(
        "sin".to_string(),
        FunctionSignature {
            name: "sin".to_string(),
            signature: "sin(x: Number) -> Number".to_string(),
            documentation: "Returns the sine of x (x in radians).".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The angle in radians".to_string(),
            }],
        },
    );

    map.insert(
        "cos".to_string(),
        FunctionSignature {
            name: "cos".to_string(),
            signature: "cos(x: Number) -> Number".to_string(),
            documentation: "Returns the cosine of x (x in radians).".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The angle in radians".to_string(),
            }],
        },
    );

    map.insert(
        "tan".to_string(),
        FunctionSignature {
            name: "tan".to_string(),
            signature: "tan(x: Number) -> Number".to_string(),
            documentation: "Returns the tangent of x (x in radians).".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The angle in radians".to_string(),
            }],
        },
    );

    map.insert(
        "sqrt".to_string(),
        FunctionSignature {
            name: "sqrt".to_string(),
            signature: "sqrt(x: Number) -> Number".to_string(),
            documentation: "Returns the square root of x.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The number to take the square root of (must be non-negative)"
                    .to_string(),
            }],
        },
    );

    map.insert(
        "pow".to_string(),
        FunctionSignature {
            name: "pow".to_string(),
            signature: "pow(base: Number, exp: Number) -> Number".to_string(),
            documentation: "Returns base raised to the power of exp.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "base: Number".to_string(),
                    documentation: "The base number".to_string(),
                },
                ParameterInfo {
                    label: "exp: Number".to_string(),
                    documentation: "The exponent".to_string(),
                },
            ],
        },
    );

    map.insert(
        "log".to_string(),
        FunctionSignature {
            name: "log".to_string(),
            signature: "log(x: Number, base: Number) -> Number".to_string(),
            documentation: "Returns the logarithm of x with the specified base.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "x: Number".to_string(),
                    documentation: "The number to compute the logarithm of".to_string(),
                },
                ParameterInfo {
                    label: "base: Number".to_string(),
                    documentation: "Base for logarithm".to_string(),
                },
            ],
        },
    );

    map.insert(
        "abs".to_string(),
        FunctionSignature {
            name: "abs".to_string(),
            signature: "abs(x: Number) -> Number".to_string(),
            documentation: "Returns the absolute value of x.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The number to get the absolute value of".to_string(),
            }],
        },
    );

    map.insert(
        "min".to_string(),
        FunctionSignature {
            name: "min".to_string(),
            signature: "min(a: Number, b: Number) -> Number".to_string(),
            documentation: "Returns the minimum of two numbers.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "a: Number".to_string(),
                    documentation: "First number to compare".to_string(),
                },
                ParameterInfo {
                    label: "b: Number".to_string(),
                    documentation: "Second number to compare".to_string(),
                },
            ],
        },
    );

    map.insert(
        "max".to_string(),
        FunctionSignature {
            name: "max".to_string(),
            signature: "max(a: Number, b: Number) -> Number".to_string(),
            documentation: "Returns the maximum of two numbers.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "a: Number".to_string(),
                    documentation: "First number to compare".to_string(),
                },
                ParameterInfo {
                    label: "b: Number".to_string(),
                    documentation: "Second number to compare".to_string(),
                },
            ],
        },
    );

    map.insert(
        "round".to_string(),
        FunctionSignature {
            name: "round".to_string(),
            signature: "round(x: Number) -> Number".to_string(),
            documentation: "Rounds x to the nearest integer.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The number to round".to_string(),
            }],
        },
    );

    map.insert(
        "floor".to_string(),
        FunctionSignature {
            name: "floor".to_string(),
            signature: "floor(x: Number) -> Number".to_string(),
            documentation: "Returns the largest integer less than or equal to x.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The number to round down".to_string(),
            }],
        },
    );

    map.insert(
        "ceil".to_string(),
        FunctionSignature {
            name: "ceil".to_string(),
            signature: "ceil(x: Number) -> Number".to_string(),
            documentation: "Returns the smallest integer greater than or equal to x.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The number to round up".to_string(),
            }],
        },
    );

    map.insert(
        "ln".to_string(),
        FunctionSignature {
            name: "ln".to_string(),
            signature: "ln(x: Number) -> Number".to_string(),
            documentation: "Returns the natural logarithm (base e) of x.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The number to compute the natural logarithm of".to_string(),
            }],
        },
    );

    map.insert(
        "exp".to_string(),
        FunctionSignature {
            name: "exp".to_string(),
            signature: "exp(x: Number) -> Number".to_string(),
            documentation: "Returns e raised to the power x.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "The exponent".to_string(),
            }],
        },
    );

    map.insert(
        "asin".to_string(),
        FunctionSignature {
            name: "asin".to_string(),
            signature: "asin(x: Number) -> Number".to_string(),
            documentation: "Returns the arc sine of x in radians.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "Value between -1 and 1".to_string(),
            }],
        },
    );

    map.insert(
        "acos".to_string(),
        FunctionSignature {
            name: "acos".to_string(),
            signature: "acos(x: Number) -> Number".to_string(),
            documentation: "Returns the arc cosine of x in radians.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "Value between -1 and 1".to_string(),
            }],
        },
    );

    map.insert(
        "atan".to_string(),
        FunctionSignature {
            name: "atan".to_string(),
            signature: "atan(x: Number) -> Number".to_string(),
            documentation: "Returns the arc tangent of x in radians.".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "Any number".to_string(),
            }],
        },
    );

    map.insert(
        "atan2".to_string(),
        FunctionSignature {
            name: "atan2".to_string(),
            signature: "atan2(y: Number, x: Number) -> Number".to_string(),
            documentation: "Returns the arc tangent of y/x in radians.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "y: Number".to_string(),
                    documentation: "Y coordinate".to_string(),
                },
                ParameterInfo {
                    label: "x: Number".to_string(),
                    documentation: "X coordinate".to_string(),
                },
            ],
        },
    );

    map.insert(
        "gcd".to_string(),
        FunctionSignature {
            name: "gcd".to_string(),
            signature: "gcd(a: Number, b: Number) -> Number".to_string(),
            documentation: "Returns the greatest common divisor of a and b.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "a: Number".to_string(),
                    documentation: "First integer".to_string(),
                },
                ParameterInfo {
                    label: "b: Number".to_string(),
                    documentation: "Second integer".to_string(),
                },
            ],
        },
    );

    map.insert(
        "lcm".to_string(),
        FunctionSignature {
            name: "lcm".to_string(),
            signature: "lcm(a: Number, b: Number) -> Number".to_string(),
            documentation: "Returns the least common multiple of a and b.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "a: Number".to_string(),
                    documentation: "First integer".to_string(),
                },
                ParameterInfo {
                    label: "b: Number".to_string(),
                    documentation: "Second integer".to_string(),
                },
            ],
        },
    );

    map.insert(
        "factorial".to_string(),
        FunctionSignature {
            name: "factorial".to_string(),
            signature: "factorial(n: Number) -> Number".to_string(),
            documentation: "Returns the factorial of n (n!).".to_string(),
            parameters: vec![ParameterInfo {
                label: "n: Number".to_string(),
                documentation: "Non-negative integer".to_string(),
            }],
        },
    );

    // Array Functions
    map.insert(
        "map".to_string(),
        FunctionSignature {
            name: "map".to_string(),
            signature: "map(arr: Array, fn: Function) -> Array".to_string(),
            documentation:
                "Applies a function to each element of the array and returns a new array."
                    .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The input array".to_string(),
                },
                ParameterInfo {
                    label: "fn: Function".to_string(),
                    documentation: "Function to apply to each element".to_string(),
                },
            ],
        },
    );

    map.insert(
        "filter".to_string(),
        FunctionSignature {
            name: "filter".to_string(),
            signature: "filter(arr: Array, predicate: Function) -> Array".to_string(),
            documentation: "Returns a new array containing only elements for which the predicate function returns true.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The input array to filter".to_string(),
                },
                ParameterInfo {
                    label: "predicate: Function".to_string(),
                    documentation: "Predicate function that returns a boolean".to_string(),
                },
            ],
        },
    );

    map.insert(
        "reduce".to_string(),
        FunctionSignature {
            name: "reduce".to_string(),
            signature: "reduce(arr: Array, initial: Any, fn: Function) -> Any".to_string(),
            documentation:
                "Reduces the array to a single value by applying the function cumulatively."
                    .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The input array to reduce".to_string(),
                },
                ParameterInfo {
                    label: "initial: Any".to_string(),
                    documentation: "Initial value for the accumulator".to_string(),
                },
                ParameterInfo {
                    label: "fn: Function".to_string(),
                    documentation: "Reducer function (accumulator, current) -> new_accumulator"
                        .to_string(),
                },
            ],
        },
    );

    map.insert(
        "len".to_string(),
        FunctionSignature {
            name: "len".to_string(),
            signature: "len(arr: Array | String) -> Number".to_string(),
            documentation: "Returns the number of elements in the array or characters in string."
                .to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array | String".to_string(),
                documentation: "The array or string to get the length of".to_string(),
            }],
        },
    );

    map.insert(
        "push".to_string(),
        FunctionSignature {
            name: "push".to_string(),
            signature: "push(arr: Array, element: Any) -> Array".to_string(),
            documentation: "Returns a new array with the element added to the end.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The original array".to_string(),
                },
                ParameterInfo {
                    label: "element: Any".to_string(),
                    documentation: "The element to add".to_string(),
                },
            ],
        },
    );

    map.insert(
        "pop".to_string(),
        FunctionSignature {
            name: "pop".to_string(),
            signature: "pop(arr: Array) -> Array".to_string(),
            documentation: "Returns a new array with the last element removed.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "The array to remove the last element from".to_string(),
            }],
        },
    );

    map.insert(
        "slice".to_string(),
        FunctionSignature {
            name: "slice".to_string(),
            signature: "slice(arr: Array, start: Number, end: Number) -> Array".to_string(),
            documentation:
                "Extracts a portion of the array from start index to end index (exclusive)."
                    .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The array to slice".to_string(),
                },
                ParameterInfo {
                    label: "start: Number".to_string(),
                    documentation: "Starting index (inclusive)".to_string(),
                },
                ParameterInfo {
                    label: "end: Number".to_string(),
                    documentation: "Ending index (exclusive)".to_string(),
                },
            ],
        },
    );

    map.insert(
        "concat".to_string(),
        FunctionSignature {
            name: "concat".to_string(),
            signature: "concat(arr1: Array, arr2: Array) -> Array".to_string(),
            documentation: "Concatenates two arrays into a new array.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr1: Array".to_string(),
                    documentation: "First array".to_string(),
                },
                ParameterInfo {
                    label: "arr2: Array".to_string(),
                    documentation: "Second array to append".to_string(),
                },
            ],
        },
    );

    map.insert(
        "reverse".to_string(),
        FunctionSignature {
            name: "reverse".to_string(),
            signature: "reverse(arr: Array) -> Array".to_string(),
            documentation: "Returns a new array with elements in reverse order.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "The array to reverse".to_string(),
            }],
        },
    );

    map.insert(
        "sort".to_string(),
        FunctionSignature {
            name: "sort".to_string(),
            signature: "sort(arr: Array) -> Array".to_string(),
            documentation: "Returns a new array with elements sorted in ascending order."
                .to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "The array to sort".to_string(),
            }],
        },
    );

    map.insert(
        "find".to_string(),
        FunctionSignature {
            name: "find".to_string(),
            signature: "find(arr: Array, predicate: Function) -> Any | Null".to_string(),
            documentation: "Returns the first element for which the predicate returns true, or null if not found.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The array to search".to_string(),
                },
                ParameterInfo {
                    label: "predicate: Function".to_string(),
                    documentation: "Predicate function to test each element".to_string(),
                },
            ],
        },
    );

    map.insert(
        "indexOf".to_string(),
        FunctionSignature {
            name: "indexOf".to_string(),
            signature: "indexOf(arr: Array, element: Any) -> Number".to_string(),
            documentation:
                "Returns the index of the first occurrence of element, or -1 if not found."
                    .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The array to search in".to_string(),
                },
                ParameterInfo {
                    label: "element: Any".to_string(),
                    documentation: "The element to find".to_string(),
                },
            ],
        },
    );

    map.insert(
        "includes".to_string(),
        FunctionSignature {
            name: "includes".to_string(),
            signature: "includes(arr: Array, element: Any) -> Boolean".to_string(),
            documentation: "Returns true if the array contains the element.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The array to check".to_string(),
                },
                ParameterInfo {
                    label: "element: Any".to_string(),
                    documentation: "The element to look for".to_string(),
                },
            ],
        },
    );

    map.insert(
        "zip".to_string(),
        FunctionSignature {
            name: "zip".to_string(),
            signature: "zip(arr1: Array, arr2: Array) -> Array".to_string(),
            documentation: "Combines two arrays into an array of pairs.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr1: Array".to_string(),
                    documentation: "First array".to_string(),
                },
                ParameterInfo {
                    label: "arr2: Array".to_string(),
                    documentation: "Second array".to_string(),
                },
            ],
        },
    );

    map.insert(
        "take".to_string(),
        FunctionSignature {
            name: "take".to_string(),
            signature: "take(arr: Array, n: Number) -> Array".to_string(),
            documentation: "Returns the first n elements of the array.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The source array".to_string(),
                },
                ParameterInfo {
                    label: "n: Number".to_string(),
                    documentation: "Number of elements to take".to_string(),
                },
            ],
        },
    );

    map.insert(
        "drop".to_string(),
        FunctionSignature {
            name: "drop".to_string(),
            signature: "drop(arr: Array, n: Number) -> Array".to_string(),
            documentation: "Returns the array without the first n elements.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The source array".to_string(),
                },
                ParameterInfo {
                    label: "n: Number".to_string(),
                    documentation: "Number of elements to drop".to_string(),
                },
            ],
        },
    );

    map.insert(
        "unique".to_string(),
        FunctionSignature {
            name: "unique".to_string(),
            signature: "unique(arr: Array) -> Array".to_string(),
            documentation: "Returns a new array with duplicate elements removed.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "The array to remove duplicates from".to_string(),
            }],
        },
    );

    map.insert(
        "chunk".to_string(),
        FunctionSignature {
            name: "chunk".to_string(),
            signature: "chunk(arr: Array, size: Number) -> Array".to_string(),
            documentation: "Splits the array into chunks of the specified size.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "The array to split".to_string(),
                },
                ParameterInfo {
                    label: "size: Number".to_string(),
                    documentation: "Size of each chunk".to_string(),
                },
            ],
        },
    );

    map.insert(
        "range".to_string(),
        FunctionSignature {
            name: "range".to_string(),
            signature: "range(start: Number, end: Number) -> Array".to_string(),
            documentation: "Creates an array of numbers from start to end (exclusive).".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "start: Number".to_string(),
                    documentation: "Starting number".to_string(),
                },
                ParameterInfo {
                    label: "end: Number".to_string(),
                    documentation: "Ending number (exclusive)".to_string(),
                },
            ],
        },
    );

    // Statistical Functions
    map.insert(
        "mean".to_string(),
        FunctionSignature {
            name: "mean".to_string(),
            signature: "mean(arr: Array) -> Number".to_string(),
            documentation: "Returns the arithmetic mean (average) of the array elements."
                .to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "Array of numbers".to_string(),
            }],
        },
    );

    map.insert(
        "median".to_string(),
        FunctionSignature {
            name: "median".to_string(),
            signature: "median(arr: Array) -> Number".to_string(),
            documentation: "Returns the median value of the array.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "Array of numbers".to_string(),
            }],
        },
    );

    map.insert(
        "std".to_string(),
        FunctionSignature {
            name: "std".to_string(),
            signature: "std(arr: Array) -> Number".to_string(),
            documentation: "Returns the standard deviation of the array elements.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "Array of numbers".to_string(),
            }],
        },
    );

    map.insert(
        "variance".to_string(),
        FunctionSignature {
            name: "variance".to_string(),
            signature: "variance(arr: Array) -> Number".to_string(),
            documentation: "Returns the variance of the array elements.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "Array of numbers".to_string(),
            }],
        },
    );

    map.insert(
        "sum".to_string(),
        FunctionSignature {
            name: "sum".to_string(),
            signature: "sum(arr: Array) -> Number".to_string(),
            documentation: "Returns the sum of all elements in the array.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "Array of numbers to sum".to_string(),
            }],
        },
    );

    map.insert(
        "prod".to_string(),
        FunctionSignature {
            name: "prod".to_string(),
            signature: "prod(arr: Array) -> Number".to_string(),
            documentation: "Returns the product of all elements in the array.".to_string(),
            parameters: vec![ParameterInfo {
                label: "arr: Array".to_string(),
                documentation: "Array of numbers to multiply".to_string(),
            }],
        },
    );

    map.insert(
        "percentile".to_string(),
        FunctionSignature {
            name: "percentile".to_string(),
            signature: "percentile(arr: Array, p: Number) -> Number".to_string(),
            documentation: "Returns the p-th percentile of the array (0-100).".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "arr: Array".to_string(),
                    documentation: "Array of numbers".to_string(),
                },
                ParameterInfo {
                    label: "p: Number".to_string(),
                    documentation: "Percentile value (0-100)".to_string(),
                },
            ],
        },
    );

    // DSP Functions
    map.insert(
        "fft".to_string(),
        FunctionSignature {
            name: "fft".to_string(),
            signature: "fft(signal: Array) -> Array".to_string(),
            documentation: "Computes the Fast Fourier Transform of the input signal.".to_string(),
            parameters: vec![ParameterInfo {
                label: "signal: Array".to_string(),
                documentation: "Input signal (time domain)".to_string(),
            }],
        },
    );

    map.insert(
        "ifft".to_string(),
        FunctionSignature {
            name: "ifft".to_string(),
            signature: "ifft(spectrum: Array) -> Array".to_string(),
            documentation: "Computes the Inverse Fast Fourier Transform.".to_string(),
            parameters: vec![ParameterInfo {
                label: "spectrum: Array".to_string(),
                documentation: "Input spectrum (frequency domain)".to_string(),
            }],
        },
    );

    map.insert(
        "convolve".to_string(),
        FunctionSignature {
            name: "convolve".to_string(),
            signature: "convolve(signal: Array, kernel: Array) -> Array".to_string(),
            documentation: "Computes the convolution of two arrays.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "signal: Array".to_string(),
                    documentation: "First input array".to_string(),
                },
                ParameterInfo {
                    label: "kernel: Array".to_string(),
                    documentation: "Second input array (kernel)".to_string(),
                },
            ],
        },
    );

    // Linear Algebra Functions
    map.insert(
        "dot".to_string(),
        FunctionSignature {
            name: "dot".to_string(),
            signature: "dot(a: Array, b: Array) -> Number".to_string(),
            documentation: "Computes the dot product of two vectors.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "a: Array".to_string(),
                    documentation: "First vector".to_string(),
                },
                ParameterInfo {
                    label: "b: Array".to_string(),
                    documentation: "Second vector".to_string(),
                },
            ],
        },
    );

    map.insert(
        "cross".to_string(),
        FunctionSignature {
            name: "cross".to_string(),
            signature: "cross(a: Array, b: Array) -> Array".to_string(),
            documentation: "Computes the cross product of two 3D vectors.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "a: Array".to_string(),
                    documentation: "First 3D vector".to_string(),
                },
                ParameterInfo {
                    label: "b: Array".to_string(),
                    documentation: "Second 3D vector".to_string(),
                },
            ],
        },
    );

    map.insert(
        "norm".to_string(),
        FunctionSignature {
            name: "norm".to_string(),
            signature: "norm(v: Array) -> Number".to_string(),
            documentation: "Computes the Euclidean norm (length) of a vector.".to_string(),
            parameters: vec![ParameterInfo {
                label: "v: Array".to_string(),
                documentation: "The vector to compute the norm of".to_string(),
            }],
        },
    );

    map.insert(
        "transpose".to_string(),
        FunctionSignature {
            name: "transpose".to_string(),
            signature: "transpose(m: Array) -> Array".to_string(),
            documentation: "Returns the transpose of a matrix.".to_string(),
            parameters: vec![ParameterInfo {
                label: "m: Array".to_string(),
                documentation: "The matrix to transpose".to_string(),
            }],
        },
    );

    map.insert(
        "det".to_string(),
        FunctionSignature {
            name: "det".to_string(),
            signature: "det(m: Array) -> Number".to_string(),
            documentation: "Computes the determinant of a square matrix.".to_string(),
            parameters: vec![ParameterInfo {
                label: "m: Array".to_string(),
                documentation: "Square matrix".to_string(),
            }],
        },
    );

    map.insert(
        "inv".to_string(),
        FunctionSignature {
            name: "inv".to_string(),
            signature: "inv(m: Array) -> Array".to_string(),
            documentation: "Computes the inverse of a square matrix.".to_string(),
            parameters: vec![ParameterInfo {
                label: "m: Array".to_string(),
                documentation: "Square matrix (must be non-singular)".to_string(),
            }],
        },
    );

    // Numerical Functions
    map.insert(
        "diff".to_string(),
        FunctionSignature {
            name: "diff".to_string(),
            signature: "diff(fn: Function, x: Number) -> Number".to_string(),
            documentation: "Computes the numerical derivative of a function at point x."
                .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "fn: Function".to_string(),
                    documentation: "Function to differentiate".to_string(),
                },
                ParameterInfo {
                    label: "x: Number".to_string(),
                    documentation: "Point at which to evaluate the derivative".to_string(),
                },
            ],
        },
    );

    map.insert(
        "integral".to_string(),
        FunctionSignature {
            name: "integral".to_string(),
            signature: "integral(fn: Function, a: Number, b: Number) -> Number".to_string(),
            documentation: "Computes the numerical integral of a function over [a, b].".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "fn: Function".to_string(),
                    documentation: "Function to integrate".to_string(),
                },
                ParameterInfo {
                    label: "a: Number".to_string(),
                    documentation: "Lower bound of integration".to_string(),
                },
                ParameterInfo {
                    label: "b: Number".to_string(),
                    documentation: "Upper bound of integration".to_string(),
                },
            ],
        },
    );

    map.insert(
        "newton_raphson".to_string(),
        FunctionSignature {
            name: "newton_raphson".to_string(),
            signature: "newton_raphson(fn: Function, x0: Number) -> Number".to_string(),
            documentation: "Finds a root of the function using the Newton-Raphson method."
                .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "fn: Function".to_string(),
                    documentation: "Function to find root of".to_string(),
                },
                ParameterInfo {
                    label: "x0: Number".to_string(),
                    documentation: "Initial guess".to_string(),
                },
            ],
        },
    );

    map.insert(
        "bisection".to_string(),
        FunctionSignature {
            name: "bisection".to_string(),
            signature: "bisection(fn: Function, a: Number, b: Number) -> Number".to_string(),
            documentation: "Finds a root of the function in interval [a, b] using bisection."
                .to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "fn: Function".to_string(),
                    documentation: "Function to find root of".to_string(),
                },
                ParameterInfo {
                    label: "a: Number".to_string(),
                    documentation: "Lower bound of interval".to_string(),
                },
                ParameterInfo {
                    label: "b: Number".to_string(),
                    documentation: "Upper bound of interval".to_string(),
                },
            ],
        },
    );

    // Utility Functions
    map.insert(
        "typeof".to_string(),
        FunctionSignature {
            name: "typeof".to_string(),
            signature: "typeof(value: Any) -> String".to_string(),
            documentation: "Returns the type name of the value as a string.".to_string(),
            parameters: vec![ParameterInfo {
                label: "value: Any".to_string(),
                documentation: "Any value to get the type of".to_string(),
            }],
        },
    );

    map.insert(
        "str".to_string(),
        FunctionSignature {
            name: "str".to_string(),
            signature: "str(value: Any) -> String".to_string(),
            documentation: "Converts the value to its string representation.".to_string(),
            parameters: vec![ParameterInfo {
                label: "value: Any".to_string(),
                documentation: "Value to convert to string".to_string(),
            }],
        },
    );

    map.insert(
        "num".to_string(),
        FunctionSignature {
            name: "num".to_string(),
            signature: "num(value: Any) -> Number".to_string(),
            documentation: "Converts the value to a number.".to_string(),
            parameters: vec![ParameterInfo {
                label: "value: Any".to_string(),
                documentation: "Value to convert to number".to_string(),
            }],
        },
    );

    map.insert(
        "print".to_string(),
        FunctionSignature {
            name: "print".to_string(),
            signature: "print(value: Any) -> Null".to_string(),
            documentation: "Prints the value to the console and returns null.".to_string(),
            parameters: vec![ParameterInfo {
                label: "value: Any".to_string(),
                documentation: "Value to print".to_string(),
            }],
        },
    );

    map.insert(
        "assert".to_string(),
        FunctionSignature {
            name: "assert".to_string(),
            signature: "assert(condition: Boolean, message: String) -> Null".to_string(),
            documentation: "Throws an error if condition is false.".to_string(),
            parameters: vec![
                ParameterInfo {
                    label: "condition: Boolean".to_string(),
                    documentation: "Condition to check".to_string(),
                },
                ParameterInfo {
                    label: "message: String".to_string(),
                    documentation: "Error message if condition is false".to_string(),
                },
            ],
        },
    );

    map.insert(
        "isnan".to_string(),
        FunctionSignature {
            name: "isnan".to_string(),
            signature: "isnan(x: Number) -> Boolean".to_string(),
            documentation: "Returns true if x is NaN (Not a Number).".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "Number to check".to_string(),
            }],
        },
    );

    map.insert(
        "isinf".to_string(),
        FunctionSignature {
            name: "isinf".to_string(),
            signature: "isinf(x: Number) -> Boolean".to_string(),
            documentation: "Returns true if x is infinite (positive or negative).".to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "Number to check".to_string(),
            }],
        },
    );

    map.insert(
        "isfinite".to_string(),
        FunctionSignature {
            name: "isfinite".to_string(),
            signature: "isfinite(x: Number) -> Boolean".to_string(),
            documentation: "Returns true if x is a finite number (not NaN or infinite)."
                .to_string(),
            parameters: vec![ParameterInfo {
                label: "x: Number".to_string(),
                documentation: "Number to check".to_string(),
            }],
        },
    );

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_count() {
        let sigs = get_all_signatures();
        // We should have 56+ function signatures
        assert!(
            sigs.len() >= 50,
            "Expected at least 50 function signatures, got {}",
            sigs.len()
        );
    }

    #[test]
    fn test_get_signature_sin() {
        let sig = get_signature("sin");
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.name, "sin");
        assert_eq!(sig.signature, "sin(x: Number) -> Number");
        assert_eq!(sig.parameters.len(), 1);
    }

    #[test]
    fn test_get_signature_pow() {
        let sig = get_signature("pow");
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].label, "base: Number");
        assert_eq!(sig.parameters[1].label, "exp: Number");
    }

    #[test]
    fn test_get_signature_reduce() {
        let sig = get_signature("reduce");
        assert!(sig.is_some());
        let sig = sig.unwrap();
        assert_eq!(sig.parameters.len(), 3);
    }

    #[test]
    fn test_get_signature_unknown() {
        let sig = get_signature("unknown_function");
        assert!(sig.is_none());
    }

    #[test]
    fn test_specific_signatures_present() {
        let sigs = get_all_signatures();

        // Check math functions
        assert!(sigs.contains_key("sin"), "Missing sin");
        assert!(sigs.contains_key("cos"), "Missing cos");
        assert!(sigs.contains_key("sqrt"), "Missing sqrt");
        assert!(sigs.contains_key("pow"), "Missing pow");

        // Check array functions
        assert!(sigs.contains_key("map"), "Missing map");
        assert!(sigs.contains_key("filter"), "Missing filter");
        assert!(sigs.contains_key("reduce"), "Missing reduce");

        // Check statistical functions
        assert!(sigs.contains_key("mean"), "Missing mean");
        assert!(sigs.contains_key("std"), "Missing std");

        // Check utility functions
        assert!(sigs.contains_key("typeof"), "Missing typeof");
        assert!(sigs.contains_key("print"), "Missing print");
    }
}
