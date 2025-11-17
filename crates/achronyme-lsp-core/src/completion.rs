//! Core completion data for Achronyme language
//! Provides completion items that can be used by LSP server and CLI

use once_cell::sync::Lazy;

/// A completion entry that can be used by both LSP server and CLI
#[derive(Clone, Debug)]
pub struct CompletionEntry {
    pub label: String,
    pub kind: CompletionKind,
    pub detail: String,
    pub documentation: String,
    pub insert_text: String,
}

/// The kind of completion item
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompletionKind {
    Function,
    Keyword,
    Constant,
    Type,
}

impl CompletionKind {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            CompletionKind::Function => "function",
            CompletionKind::Keyword => "keyword",
            CompletionKind::Constant => "constant",
            CompletionKind::Type => "type",
        }
    }
}

/// All completion items cached at startup
pub static ALL_COMPLETIONS: Lazy<Vec<CompletionEntry>> = Lazy::new(build_all_completions);

/// Get all completion items
pub fn get_all_completions() -> &'static Vec<CompletionEntry> {
    &ALL_COMPLETIONS
}

/// Get only function completions
pub fn get_function_completions() -> Vec<&'static CompletionEntry> {
    ALL_COMPLETIONS
        .iter()
        .filter(|e| e.kind == CompletionKind::Function)
        .collect()
}

/// Get only keyword completions
pub fn get_keyword_completions() -> Vec<&'static CompletionEntry> {
    ALL_COMPLETIONS
        .iter()
        .filter(|e| e.kind == CompletionKind::Keyword)
        .collect()
}

/// Get only constant completions
pub fn get_constant_completions() -> Vec<&'static CompletionEntry> {
    ALL_COMPLETIONS
        .iter()
        .filter(|e| e.kind == CompletionKind::Constant)
        .collect()
}

/// Get only type completions
pub fn get_type_completions() -> Vec<&'static CompletionEntry> {
    ALL_COMPLETIONS
        .iter()
        .filter(|e| e.kind == CompletionKind::Type)
        .collect()
}

fn build_all_completions() -> Vec<CompletionEntry> {
    let mut items = Vec::new();

    items.extend(build_function_completions());
    items.extend(build_keyword_completions());
    items.extend(build_constant_completions());
    items.extend(build_type_completions());

    items
}

fn build_function_completions() -> Vec<CompletionEntry> {
    vec![
        // === MATH FUNCTIONS ===
        CompletionEntry {
            label: "sin".to_string(),
            kind: CompletionKind::Function,
            detail: "Trigonometric sine function".to_string(),
            documentation: "sin(x: Number) -> Number\n\nReturns the sine of x (in radians).\n\nExample:\n  sin(PI / 2)  // 1.0\n  sin(0)       // 0.0".to_string(),
            insert_text: "sin($1)".to_string(),
        },
        CompletionEntry {
            label: "cos".to_string(),
            kind: CompletionKind::Function,
            detail: "Trigonometric cosine function".to_string(),
            documentation: "cos(x: Number) -> Number\n\nReturns the cosine of x (in radians).\n\nExample:\n  cos(0)       // 1.0\n  cos(PI)      // -1.0".to_string(),
            insert_text: "cos($1)".to_string(),
        },
        CompletionEntry {
            label: "tan".to_string(),
            kind: CompletionKind::Function,
            detail: "Trigonometric tangent function".to_string(),
            documentation: "tan(x: Number) -> Number\n\nReturns the tangent of x (in radians).\n\nExample:\n  tan(0)       // 0.0\n  tan(PI / 4)  // 1.0".to_string(),
            insert_text: "tan($1)".to_string(),
        },
        CompletionEntry {
            label: "asin".to_string(),
            kind: CompletionKind::Function,
            detail: "Arc sine function".to_string(),
            documentation: "asin(x: Number) -> Number\n\nReturns the arc sine of x in radians.\n\nExample:\n  asin(1)      // PI / 2\n  asin(0)      // 0.0".to_string(),
            insert_text: "asin($1)".to_string(),
        },
        CompletionEntry {
            label: "acos".to_string(),
            kind: CompletionKind::Function,
            detail: "Arc cosine function".to_string(),
            documentation: "acos(x: Number) -> Number\n\nReturns the arc cosine of x in radians.\n\nExample:\n  acos(1)      // 0.0\n  acos(0)      // PI / 2".to_string(),
            insert_text: "acos($1)".to_string(),
        },
        CompletionEntry {
            label: "atan".to_string(),
            kind: CompletionKind::Function,
            detail: "Arc tangent function".to_string(),
            documentation: "atan(x: Number) -> Number\n\nReturns the arc tangent of x in radians.\n\nExample:\n  atan(1)      // PI / 4\n  atan(0)      // 0.0".to_string(),
            insert_text: "atan($1)".to_string(),
        },
        CompletionEntry {
            label: "atan2".to_string(),
            kind: CompletionKind::Function,
            detail: "Two-argument arc tangent".to_string(),
            documentation: "atan2(y: Number, x: Number) -> Number\n\nReturns the arc tangent of y/x in radians, using the signs to determine the quadrant.\n\nExample:\n  atan2(1, 1)  // PI / 4\n  atan2(-1, -1) // -3*PI/4".to_string(),
            insert_text: "atan2($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "sinh".to_string(),
            kind: CompletionKind::Function,
            detail: "Hyperbolic sine function".to_string(),
            documentation: "sinh(x: Number) -> Number\n\nReturns the hyperbolic sine of x.\n\nExample:\n  sinh(0)      // 0.0\n  sinh(1)      // 1.175...".to_string(),
            insert_text: "sinh($1)".to_string(),
        },
        CompletionEntry {
            label: "cosh".to_string(),
            kind: CompletionKind::Function,
            detail: "Hyperbolic cosine function".to_string(),
            documentation: "cosh(x: Number) -> Number\n\nReturns the hyperbolic cosine of x.\n\nExample:\n  cosh(0)      // 1.0\n  cosh(1)      // 1.543...".to_string(),
            insert_text: "cosh($1)".to_string(),
        },
        CompletionEntry {
            label: "tanh".to_string(),
            kind: CompletionKind::Function,
            detail: "Hyperbolic tangent function".to_string(),
            documentation: "tanh(x: Number) -> Number\n\nReturns the hyperbolic tangent of x.\n\nExample:\n  tanh(0)      // 0.0\n  tanh(1)      // 0.761...".to_string(),
            insert_text: "tanh($1)".to_string(),
        },
        CompletionEntry {
            label: "sqrt".to_string(),
            kind: CompletionKind::Function,
            detail: "Square root function".to_string(),
            documentation: "sqrt(x: Number) -> Number\n\nReturns the square root of x.\n\nExample:\n  sqrt(4)      // 2.0\n  sqrt(2)      // 1.414...".to_string(),
            insert_text: "sqrt($1)".to_string(),
        },
        CompletionEntry {
            label: "cbrt".to_string(),
            kind: CompletionKind::Function,
            detail: "Cube root function".to_string(),
            documentation: "cbrt(x: Number) -> Number\n\nReturns the cube root of x.\n\nExample:\n  cbrt(8)      // 2.0\n  cbrt(27)     // 3.0".to_string(),
            insert_text: "cbrt($1)".to_string(),
        },
        CompletionEntry {
            label: "exp".to_string(),
            kind: CompletionKind::Function,
            detail: "Exponential function".to_string(),
            documentation: "exp(x: Number) -> Number\n\nReturns e raised to the power x.\n\nExample:\n  exp(0)       // 1.0\n  exp(1)       // E".to_string(),
            insert_text: "exp($1)".to_string(),
        },
        CompletionEntry {
            label: "log".to_string(),
            kind: CompletionKind::Function,
            detail: "Logarithm with base".to_string(),
            documentation: "log(x: Number, base: Number) -> Number\n\nReturns the logarithm of x with the specified base.\n\nExample:\n  log(8, 2)    // 3.0\n  log(100, 10) // 2.0".to_string(),
            insert_text: "log($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "ln".to_string(),
            kind: CompletionKind::Function,
            detail: "Natural logarithm".to_string(),
            documentation: "ln(x: Number) -> Number\n\nReturns the natural logarithm (base e) of x.\n\nExample:\n  ln(E)        // 1.0\n  ln(1)        // 0.0".to_string(),
            insert_text: "ln($1)".to_string(),
        },
        CompletionEntry {
            label: "log10".to_string(),
            kind: CompletionKind::Function,
            detail: "Base-10 logarithm".to_string(),
            documentation: "log10(x: Number) -> Number\n\nReturns the base-10 logarithm of x.\n\nExample:\n  log10(100)   // 2.0\n  log10(1000)  // 3.0".to_string(),
            insert_text: "log10($1)".to_string(),
        },
        CompletionEntry {
            label: "log2".to_string(),
            kind: CompletionKind::Function,
            detail: "Base-2 logarithm".to_string(),
            documentation: "log2(x: Number) -> Number\n\nReturns the base-2 logarithm of x.\n\nExample:\n  log2(8)      // 3.0\n  log2(1024)   // 10.0".to_string(),
            insert_text: "log2($1)".to_string(),
        },
        CompletionEntry {
            label: "abs".to_string(),
            kind: CompletionKind::Function,
            detail: "Absolute value".to_string(),
            documentation: "abs(x: Number) -> Number\n\nReturns the absolute value of x.\n\nExample:\n  abs(-5)      // 5\n  abs(3)       // 3".to_string(),
            insert_text: "abs($1)".to_string(),
        },
        CompletionEntry {
            label: "ceil".to_string(),
            kind: CompletionKind::Function,
            detail: "Ceiling function".to_string(),
            documentation: "ceil(x: Number) -> Number\n\nReturns the smallest integer greater than or equal to x.\n\nExample:\n  ceil(4.2)    // 5.0\n  ceil(-4.8)   // -4.0".to_string(),
            insert_text: "ceil($1)".to_string(),
        },
        CompletionEntry {
            label: "floor".to_string(),
            kind: CompletionKind::Function,
            detail: "Floor function".to_string(),
            documentation: "floor(x: Number) -> Number\n\nReturns the largest integer less than or equal to x.\n\nExample:\n  floor(4.8)   // 4.0\n  floor(-4.2)  // -5.0".to_string(),
            insert_text: "floor($1)".to_string(),
        },
        CompletionEntry {
            label: "round".to_string(),
            kind: CompletionKind::Function,
            detail: "Rounding function".to_string(),
            documentation: "round(x: Number) -> Number\n\nRounds x to the nearest integer.\n\nExample:\n  round(4.5)   // 5.0\n  round(4.4)   // 4.0".to_string(),
            insert_text: "round($1)".to_string(),
        },
        CompletionEntry {
            label: "trunc".to_string(),
            kind: CompletionKind::Function,
            detail: "Truncation function".to_string(),
            documentation: "trunc(x: Number) -> Number\n\nReturns the integer part of x, removing any fractional digits.\n\nExample:\n  trunc(4.9)   // 4.0\n  trunc(-4.9)  // -4.0".to_string(),
            insert_text: "trunc($1)".to_string(),
        },
        CompletionEntry {
            label: "sign".to_string(),
            kind: CompletionKind::Function,
            detail: "Sign function".to_string(),
            documentation: "sign(x: Number) -> Number\n\nReturns -1, 0, or 1 depending on the sign of x.\n\nExample:\n  sign(-5)     // -1\n  sign(0)      // 0\n  sign(10)     // 1".to_string(),
            insert_text: "sign($1)".to_string(),
        },
        CompletionEntry {
            label: "pow".to_string(),
            kind: CompletionKind::Function,
            detail: "Power function".to_string(),
            documentation: "pow(base: Number, exp: Number) -> Number\n\nReturns base raised to the power exp.\n\nExample:\n  pow(2, 3)    // 8.0\n  pow(10, 2)   // 100.0".to_string(),
            insert_text: "pow($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "min".to_string(),
            kind: CompletionKind::Function,
            detail: "Minimum of two numbers".to_string(),
            documentation: "min(a: Number, b: Number) -> Number\n\nReturns the smaller of a and b.\n\nExample:\n  min(3, 7)    // 3\n  min(-1, 5)   // -1".to_string(),
            insert_text: "min($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "max".to_string(),
            kind: CompletionKind::Function,
            detail: "Maximum of two numbers".to_string(),
            documentation: "max(a: Number, b: Number) -> Number\n\nReturns the larger of a and b.\n\nExample:\n  max(3, 7)    // 7\n  max(-1, 5)   // 5".to_string(),
            insert_text: "max($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "gcd".to_string(),
            kind: CompletionKind::Function,
            detail: "Greatest common divisor".to_string(),
            documentation: "gcd(a: Number, b: Number) -> Number\n\nReturns the greatest common divisor of a and b.\n\nExample:\n  gcd(12, 8)   // 4\n  gcd(17, 13)  // 1".to_string(),
            insert_text: "gcd($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "lcm".to_string(),
            kind: CompletionKind::Function,
            detail: "Least common multiple".to_string(),
            documentation: "lcm(a: Number, b: Number) -> Number\n\nReturns the least common multiple of a and b.\n\nExample:\n  lcm(4, 6)    // 12\n  lcm(3, 5)    // 15".to_string(),
            insert_text: "lcm($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "factorial".to_string(),
            kind: CompletionKind::Function,
            detail: "Factorial function".to_string(),
            documentation: "factorial(n: Number) -> Number\n\nReturns the factorial of n (n!).\n\nExample:\n  factorial(5) // 120\n  factorial(0) // 1".to_string(),
            insert_text: "factorial($1)".to_string(),
        },
        // === ARRAY FUNCTIONS ===
        CompletionEntry {
            label: "len".to_string(),
            kind: CompletionKind::Function,
            detail: "Array/String length".to_string(),
            documentation: "len(arr: Array | String) -> Number\n\nReturns the length of an array or string.\n\nExample:\n  len([1, 2, 3])  // 3\n  len(\"hello\")    // 5".to_string(),
            insert_text: "len($1)".to_string(),
        },
        CompletionEntry {
            label: "push".to_string(),
            kind: CompletionKind::Function,
            detail: "Append to array".to_string(),
            documentation: "push(arr: Array, value: Any) -> Array\n\nReturns a new array with value appended to the end.\n\nExample:\n  push([1, 2], 3)  // [1, 2, 3]".to_string(),
            insert_text: "push($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "pop".to_string(),
            kind: CompletionKind::Function,
            detail: "Remove last element".to_string(),
            documentation: "pop(arr: Array) -> Array\n\nReturns a new array with the last element removed.\n\nExample:\n  pop([1, 2, 3])   // [1, 2]".to_string(),
            insert_text: "pop($1)".to_string(),
        },
        CompletionEntry {
            label: "shift".to_string(),
            kind: CompletionKind::Function,
            detail: "Remove first element".to_string(),
            documentation: "shift(arr: Array) -> Array\n\nReturns a new array with the first element removed.\n\nExample:\n  shift([1, 2, 3]) // [2, 3]".to_string(),
            insert_text: "shift($1)".to_string(),
        },
        CompletionEntry {
            label: "unshift".to_string(),
            kind: CompletionKind::Function,
            detail: "Prepend to array".to_string(),
            documentation: "unshift(arr: Array, value: Any) -> Array\n\nReturns a new array with value prepended.\n\nExample:\n  unshift([2, 3], 1) // [1, 2, 3]".to_string(),
            insert_text: "unshift($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "concat".to_string(),
            kind: CompletionKind::Function,
            detail: "Concatenate arrays".to_string(),
            documentation: "concat(arr1: Array, arr2: Array) -> Array\n\nReturns a new array with elements from both arrays.\n\nExample:\n  concat([1, 2], [3, 4]) // [1, 2, 3, 4]".to_string(),
            insert_text: "concat($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "reverse".to_string(),
            kind: CompletionKind::Function,
            detail: "Reverse array".to_string(),
            documentation: "reverse(arr: Array) -> Array\n\nReturns a new array with elements in reverse order.\n\nExample:\n  reverse([1, 2, 3]) // [3, 2, 1]".to_string(),
            insert_text: "reverse($1)".to_string(),
        },
        CompletionEntry {
            label: "sort".to_string(),
            kind: CompletionKind::Function,
            detail: "Sort array".to_string(),
            documentation: "sort(arr: Array) -> Array\n\nReturns a new array with elements sorted in ascending order.\n\nExample:\n  sort([3, 1, 2])    // [1, 2, 3]".to_string(),
            insert_text: "sort($1)".to_string(),
        },
        CompletionEntry {
            label: "map".to_string(),
            kind: CompletionKind::Function,
            detail: "Map function over array".to_string(),
            documentation: "map(arr: Array, fn: Function) -> Array\n\nApplies fn to each element and returns a new array.\n\nExample:\n  map([1, 2, 3], |x| x * 2) // [2, 4, 6]".to_string(),
            insert_text: "map($1, |$2| $3)".to_string(),
        },
        CompletionEntry {
            label: "filter".to_string(),
            kind: CompletionKind::Function,
            detail: "Filter array by predicate".to_string(),
            documentation: "filter(arr: Array, predicate: Function) -> Array\n\nReturns a new array containing only elements for which predicate returns true.\n\nExample:\n  filter([1, 2, 3, 4], |x| x > 2) // [3, 4]".to_string(),
            insert_text: "filter($1, |$2| $3)".to_string(),
        },
        CompletionEntry {
            label: "reduce".to_string(),
            kind: CompletionKind::Function,
            detail: "Reduce array to single value".to_string(),
            documentation: "reduce(arr: Array, initial: Any, fn: Function) -> Any\n\nReduces the array to a single value by applying fn to accumulator and each element.\n\nExample:\n  reduce([1, 2, 3], 0, |acc, x| acc + x) // 6".to_string(),
            insert_text: "reduce($1, $2, |$3, $4| $5)".to_string(),
        },
        CompletionEntry {
            label: "find".to_string(),
            kind: CompletionKind::Function,
            detail: "Find element in array".to_string(),
            documentation: "find(arr: Array, predicate: Function) -> Any | Null\n\nReturns the first element for which predicate returns true, or null.\n\nExample:\n  find([1, 2, 3], |x| x > 1) // 2".to_string(),
            insert_text: "find($1, |$2| $3)".to_string(),
        },
        CompletionEntry {
            label: "some".to_string(),
            kind: CompletionKind::Function,
            detail: "Test if any element matches".to_string(),
            documentation: "some(arr: Array, predicate: Function) -> Boolean\n\nReturns true if at least one element satisfies predicate.\n\nExample:\n  some([1, 2, 3], |x| x > 2) // true".to_string(),
            insert_text: "some($1, |$2| $3)".to_string(),
        },
        CompletionEntry {
            label: "every".to_string(),
            kind: CompletionKind::Function,
            detail: "Test if all elements match".to_string(),
            documentation: "every(arr: Array, predicate: Function) -> Boolean\n\nReturns true if all elements satisfy predicate.\n\nExample:\n  every([2, 4, 6], |x| x % 2 == 0) // true".to_string(),
            insert_text: "every($1, |$2| $3)".to_string(),
        },
        CompletionEntry {
            label: "includes".to_string(),
            kind: CompletionKind::Function,
            detail: "Check if array contains value".to_string(),
            documentation: "includes(arr: Array, value: Any) -> Boolean\n\nReturns true if the array contains value.\n\nExample:\n  includes([1, 2, 3], 2)  // true\n  includes([1, 2, 3], 4)  // false".to_string(),
            insert_text: "includes($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "indexOf".to_string(),
            kind: CompletionKind::Function,
            detail: "Find index of value".to_string(),
            documentation: "indexOf(arr: Array, value: Any) -> Number\n\nReturns the index of value in the array, or -1 if not found.\n\nExample:\n  indexOf([1, 2, 3], 2)  // 1\n  indexOf([1, 2, 3], 4)  // -1".to_string(),
            insert_text: "indexOf($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "slice".to_string(),
            kind: CompletionKind::Function,
            detail: "Extract sub-array".to_string(),
            documentation: "slice(arr: Array, start: Number, end: Number) -> Array\n\nReturns a new array from start (inclusive) to end (exclusive).\n\nExample:\n  slice([1, 2, 3, 4], 1, 3) // [2, 3]".to_string(),
            insert_text: "slice($1, $2, $3)".to_string(),
        },
        CompletionEntry {
            label: "splice".to_string(),
            kind: CompletionKind::Function,
            detail: "Replace elements in array".to_string(),
            documentation: "splice(arr: Array, start: Number, count: Number, ...items: Any) -> Array\n\nReturns a new array with count elements removed at start and optional items inserted.\n\nExample:\n  splice([1, 2, 3, 4], 1, 2, 5, 6) // [1, 5, 6, 4]".to_string(),
            insert_text: "splice($1, $2, $3)".to_string(),
        },
        CompletionEntry {
            label: "join".to_string(),
            kind: CompletionKind::Function,
            detail: "Join array into string".to_string(),
            documentation: "join(arr: Array, separator: String) -> String\n\nJoins array elements into a string with separator.\n\nExample:\n  join([1, 2, 3], \"-\") // \"1-2-3\"".to_string(),
            insert_text: "join($1, \"$2\")".to_string(),
        },
        CompletionEntry {
            label: "split".to_string(),
            kind: CompletionKind::Function,
            detail: "Split string into array".to_string(),
            documentation: "split(str: String, separator: String) -> Array\n\nSplits a string into an array by separator.\n\nExample:\n  split(\"a-b-c\", \"-\") // [\"a\", \"b\", \"c\"]".to_string(),
            insert_text: "split($1, \"$2\")".to_string(),
        },
        CompletionEntry {
            label: "zip".to_string(),
            kind: CompletionKind::Function,
            detail: "Zip two arrays".to_string(),
            documentation: "zip(arr1: Array, arr2: Array) -> Array\n\nCombines two arrays into an array of pairs.\n\nExample:\n  zip([1, 2], [\"a\", \"b\"]) // [[1, \"a\"], [2, \"b\"]]".to_string(),
            insert_text: "zip($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "flatten".to_string(),
            kind: CompletionKind::Function,
            detail: "Flatten nested array".to_string(),
            documentation: "flatten(arr: Array) -> Array\n\nFlattens a nested array by one level.\n\nExample:\n  flatten([[1, 2], [3, 4]]) // [1, 2, 3, 4]".to_string(),
            insert_text: "flatten($1)".to_string(),
        },
        CompletionEntry {
            label: "take".to_string(),
            kind: CompletionKind::Function,
            detail: "Take first n elements".to_string(),
            documentation: "take(arr: Array, n: Number) -> Array\n\nReturns a new array with the first n elements.\n\nExample:\n  take([1, 2, 3, 4], 2) // [1, 2]".to_string(),
            insert_text: "take($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "drop".to_string(),
            kind: CompletionKind::Function,
            detail: "Drop first n elements".to_string(),
            documentation: "drop(arr: Array, n: Number) -> Array\n\nReturns a new array with the first n elements removed.\n\nExample:\n  drop([1, 2, 3, 4], 2) // [3, 4]".to_string(),
            insert_text: "drop($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "unique".to_string(),
            kind: CompletionKind::Function,
            detail: "Remove duplicate elements".to_string(),
            documentation: "unique(arr: Array) -> Array\n\nReturns a new array with duplicate elements removed.\n\nExample:\n  unique([1, 2, 2, 3, 3]) // [1, 2, 3]".to_string(),
            insert_text: "unique($1)".to_string(),
        },
        CompletionEntry {
            label: "chunk".to_string(),
            kind: CompletionKind::Function,
            detail: "Split array into chunks".to_string(),
            documentation: "chunk(arr: Array, size: Number) -> Array\n\nSplits an array into chunks of specified size.\n\nExample:\n  chunk([1, 2, 3, 4, 5], 2) // [[1, 2], [3, 4], [5]]".to_string(),
            insert_text: "chunk($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "head".to_string(),
            kind: CompletionKind::Function,
            detail: "Get first element".to_string(),
            documentation: "head(arr: Array) -> Any\n\nReturns the first element of the array.\n\nExample:\n  head([1, 2, 3]) // 1".to_string(),
            insert_text: "head($1)".to_string(),
        },
        CompletionEntry {
            label: "tail".to_string(),
            kind: CompletionKind::Function,
            detail: "Get all except first".to_string(),
            documentation: "tail(arr: Array) -> Array\n\nReturns all elements except the first.\n\nExample:\n  tail([1, 2, 3]) // [2, 3]".to_string(),
            insert_text: "tail($1)".to_string(),
        },
        CompletionEntry {
            label: "range".to_string(),
            kind: CompletionKind::Function,
            detail: "Create range array".to_string(),
            documentation: "range(start: Number, end: Number) -> Array\n\nCreates an array of numbers from start to end (exclusive).\n\nExample:\n  range(1, 5)  // [1, 2, 3, 4]\n  range(0, 3)  // [0, 1, 2]".to_string(),
            insert_text: "range($1, $2)".to_string(),
        },
        // === STATISTICAL FUNCTIONS ===
        CompletionEntry {
            label: "mean".to_string(),
            kind: CompletionKind::Function,
            detail: "Arithmetic mean".to_string(),
            documentation: "mean(arr: Array) -> Number\n\nReturns the arithmetic mean (average) of the array.\n\nExample:\n  mean([1, 2, 3, 4, 5]) // 3.0".to_string(),
            insert_text: "mean($1)".to_string(),
        },
        CompletionEntry {
            label: "median".to_string(),
            kind: CompletionKind::Function,
            detail: "Median value".to_string(),
            documentation: "median(arr: Array) -> Number\n\nReturns the median value of the array.\n\nExample:\n  median([1, 2, 3, 4, 5]) // 3.0\n  median([1, 2, 3, 4])    // 2.5".to_string(),
            insert_text: "median($1)".to_string(),
        },
        CompletionEntry {
            label: "mode".to_string(),
            kind: CompletionKind::Function,
            detail: "Mode (most frequent value)".to_string(),
            documentation: "mode(arr: Array) -> Number\n\nReturns the most frequently occurring value in the array.\n\nExample:\n  mode([1, 2, 2, 3, 3, 3]) // 3".to_string(),
            insert_text: "mode($1)".to_string(),
        },
        CompletionEntry {
            label: "std".to_string(),
            kind: CompletionKind::Function,
            detail: "Standard deviation".to_string(),
            documentation: "std(arr: Array) -> Number\n\nReturns the standard deviation of the array.\n\nExample:\n  std([1, 2, 3, 4, 5]) // 1.414...".to_string(),
            insert_text: "std($1)".to_string(),
        },
        CompletionEntry {
            label: "variance".to_string(),
            kind: CompletionKind::Function,
            detail: "Variance".to_string(),
            documentation: "variance(arr: Array) -> Number\n\nReturns the variance of the array.\n\nExample:\n  variance([1, 2, 3, 4, 5]) // 2.0".to_string(),
            insert_text: "variance($1)".to_string(),
        },
        CompletionEntry {
            label: "sum".to_string(),
            kind: CompletionKind::Function,
            detail: "Sum of array".to_string(),
            documentation: "sum(arr: Array) -> Number\n\nReturns the sum of all elements in the array.\n\nExample:\n  sum([1, 2, 3, 4, 5]) // 15".to_string(),
            insert_text: "sum($1)".to_string(),
        },
        CompletionEntry {
            label: "prod".to_string(),
            kind: CompletionKind::Function,
            detail: "Product of array".to_string(),
            documentation: "prod(arr: Array) -> Number\n\nReturns the product of all elements in the array.\n\nExample:\n  prod([1, 2, 3, 4]) // 24".to_string(),
            insert_text: "prod($1)".to_string(),
        },
        CompletionEntry {
            label: "percentile".to_string(),
            kind: CompletionKind::Function,
            detail: "Percentile calculation".to_string(),
            documentation: "percentile(arr: Array, p: Number) -> Number\n\nReturns the p-th percentile of the array (0-100).\n\nExample:\n  percentile([1, 2, 3, 4, 5], 50) // 3.0".to_string(),
            insert_text: "percentile($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "quartiles".to_string(),
            kind: CompletionKind::Function,
            detail: "Quartile values".to_string(),
            documentation: "quartiles(arr: Array) -> Array\n\nReturns Q1, Q2 (median), and Q3 of the array.\n\nExample:\n  quartiles([1, 2, 3, 4, 5, 6, 7]) // [2.0, 4.0, 6.0]".to_string(),
            insert_text: "quartiles($1)".to_string(),
        },
        // === DSP (Digital Signal Processing) FUNCTIONS ===
        CompletionEntry {
            label: "fft".to_string(),
            kind: CompletionKind::Function,
            detail: "Fast Fourier Transform".to_string(),
            documentation: "fft(signal: Array) -> Array\n\nComputes the Fast Fourier Transform of the signal.\n\nExample:\n  let spectrum = fft(signal)".to_string(),
            insert_text: "fft($1)".to_string(),
        },
        CompletionEntry {
            label: "ifft".to_string(),
            kind: CompletionKind::Function,
            detail: "Inverse Fast Fourier Transform".to_string(),
            documentation: "ifft(spectrum: Array) -> Array\n\nComputes the Inverse Fast Fourier Transform.\n\nExample:\n  let signal = ifft(spectrum)".to_string(),
            insert_text: "ifft($1)".to_string(),
        },
        CompletionEntry {
            label: "fft_mag".to_string(),
            kind: CompletionKind::Function,
            detail: "FFT magnitude spectrum".to_string(),
            documentation: "fft_mag(signal: Array) -> Array\n\nReturns the magnitude spectrum of the FFT.\n\nExample:\n  let magnitudes = fft_mag(signal)".to_string(),
            insert_text: "fft_mag($1)".to_string(),
        },
        CompletionEntry {
            label: "fft_phase".to_string(),
            kind: CompletionKind::Function,
            detail: "FFT phase spectrum".to_string(),
            documentation: "fft_phase(signal: Array) -> Array\n\nReturns the phase spectrum of the FFT.\n\nExample:\n  let phases = fft_phase(signal)".to_string(),
            insert_text: "fft_phase($1)".to_string(),
        },
        CompletionEntry {
            label: "convolve".to_string(),
            kind: CompletionKind::Function,
            detail: "Convolution".to_string(),
            documentation: "convolve(signal: Array, kernel: Array) -> Array\n\nComputes the convolution of signal with kernel.\n\nExample:\n  let filtered = convolve(signal, kernel)".to_string(),
            insert_text: "convolve($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "correlate".to_string(),
            kind: CompletionKind::Function,
            detail: "Cross-correlation".to_string(),
            documentation: "correlate(a: Array, b: Array) -> Array\n\nComputes the cross-correlation of two signals.\n\nExample:\n  let corr = correlate(signal1, signal2)".to_string(),
            insert_text: "correlate($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "hanning".to_string(),
            kind: CompletionKind::Function,
            detail: "Hanning window".to_string(),
            documentation: "hanning(n: Number) -> Array\n\nGenerates a Hanning window of size n.\n\nExample:\n  let window = hanning(256)".to_string(),
            insert_text: "hanning($1)".to_string(),
        },
        CompletionEntry {
            label: "hamming".to_string(),
            kind: CompletionKind::Function,
            detail: "Hamming window".to_string(),
            documentation: "hamming(n: Number) -> Array\n\nGenerates a Hamming window of size n.\n\nExample:\n  let window = hamming(256)".to_string(),
            insert_text: "hamming($1)".to_string(),
        },
        CompletionEntry {
            label: "blackman".to_string(),
            kind: CompletionKind::Function,
            detail: "Blackman window".to_string(),
            documentation: "blackman(n: Number) -> Array\n\nGenerates a Blackman window of size n.\n\nExample:\n  let window = blackman(256)".to_string(),
            insert_text: "blackman($1)".to_string(),
        },
        // === LINEAR ALGEBRA FUNCTIONS ===
        CompletionEntry {
            label: "det".to_string(),
            kind: CompletionKind::Function,
            detail: "Matrix determinant".to_string(),
            documentation: "det(matrix: Array) -> Number\n\nComputes the determinant of a square matrix.\n\nExample:\n  det([[1, 2], [3, 4]]) // -2".to_string(),
            insert_text: "det($1)".to_string(),
        },
        CompletionEntry {
            label: "inv".to_string(),
            kind: CompletionKind::Function,
            detail: "Matrix inverse".to_string(),
            documentation: "inv(matrix: Array) -> Array\n\nComputes the inverse of a square matrix.\n\nExample:\n  inv([[1, 2], [3, 4]]) // [[-2, 1], [1.5, -0.5]]".to_string(),
            insert_text: "inv($1)".to_string(),
        },
        CompletionEntry {
            label: "transpose".to_string(),
            kind: CompletionKind::Function,
            detail: "Matrix transpose".to_string(),
            documentation: "transpose(matrix: Array) -> Array\n\nReturns the transpose of a matrix.\n\nExample:\n  transpose([[1, 2], [3, 4]]) // [[1, 3], [2, 4]]".to_string(),
            insert_text: "transpose($1)".to_string(),
        },
        CompletionEntry {
            label: "dot".to_string(),
            kind: CompletionKind::Function,
            detail: "Dot product".to_string(),
            documentation: "dot(a: Array, b: Array) -> Number\n\nComputes the dot product of two vectors.\n\nExample:\n  dot([1, 2, 3], [4, 5, 6]) // 32".to_string(),
            insert_text: "dot($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "cross".to_string(),
            kind: CompletionKind::Function,
            detail: "Cross product".to_string(),
            documentation: "cross(a: Array, b: Array) -> Array\n\nComputes the cross product of two 3D vectors.\n\nExample:\n  cross([1, 0, 0], [0, 1, 0]) // [0, 0, 1]".to_string(),
            insert_text: "cross($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "norm".to_string(),
            kind: CompletionKind::Function,
            detail: "Vector norm".to_string(),
            documentation: "norm(v: Array) -> Number\n\nComputes the Euclidean norm (magnitude) of a vector.\n\nExample:\n  norm([3, 4]) // 5.0".to_string(),
            insert_text: "norm($1)".to_string(),
        },
        CompletionEntry {
            label: "trace".to_string(),
            kind: CompletionKind::Function,
            detail: "Matrix trace".to_string(),
            documentation: "trace(matrix: Array) -> Number\n\nReturns the sum of diagonal elements of a matrix.\n\nExample:\n  trace([[1, 2], [3, 4]]) // 5".to_string(),
            insert_text: "trace($1)".to_string(),
        },
        CompletionEntry {
            label: "eigenvalues".to_string(),
            kind: CompletionKind::Function,
            detail: "Matrix eigenvalues".to_string(),
            documentation: "eigenvalues(matrix: Array) -> Array\n\nComputes the eigenvalues of a square matrix.\n\nExample:\n  let eigs = eigenvalues(matrix)".to_string(),
            insert_text: "eigenvalues($1)".to_string(),
        },
        CompletionEntry {
            label: "lu".to_string(),
            kind: CompletionKind::Function,
            detail: "LU decomposition".to_string(),
            documentation: "lu(matrix: Array) -> Record\n\nPerforms LU decomposition of a matrix.\n\nExample:\n  let { L, U } = lu(matrix)".to_string(),
            insert_text: "lu($1)".to_string(),
        },
        CompletionEntry {
            label: "qr".to_string(),
            kind: CompletionKind::Function,
            detail: "QR decomposition".to_string(),
            documentation: "qr(matrix: Array) -> Record\n\nPerforms QR decomposition of a matrix.\n\nExample:\n  let { Q, R } = qr(matrix)".to_string(),
            insert_text: "qr($1)".to_string(),
        },
        CompletionEntry {
            label: "svd".to_string(),
            kind: CompletionKind::Function,
            detail: "Singular Value Decomposition".to_string(),
            documentation: "svd(matrix: Array) -> Record\n\nPerforms Singular Value Decomposition.\n\nExample:\n  let { U, S, V } = svd(matrix)".to_string(),
            insert_text: "svd($1)".to_string(),
        },
        CompletionEntry {
            label: "cholesky".to_string(),
            kind: CompletionKind::Function,
            detail: "Cholesky decomposition".to_string(),
            documentation: "cholesky(matrix: Array) -> Array\n\nPerforms Cholesky decomposition of a positive-definite matrix.\n\nExample:\n  let L = cholesky(matrix)".to_string(),
            insert_text: "cholesky($1)".to_string(),
        },
        // === NUMERICAL METHODS ===
        CompletionEntry {
            label: "diff".to_string(),
            kind: CompletionKind::Function,
            detail: "Numerical differentiation".to_string(),
            documentation: "diff(fn: Function, x: Number) -> Number\n\nApproximates the derivative of fn at point x.\n\nExample:\n  diff(|x| x^2, 3) // 6.0".to_string(),
            insert_text: "diff(|$1| $2, $3)".to_string(),
        },
        CompletionEntry {
            label: "integral".to_string(),
            kind: CompletionKind::Function,
            detail: "Numerical integration".to_string(),
            documentation: "integral(fn: Function, a: Number, b: Number) -> Number\n\nApproximates the definite integral of fn from a to b.\n\nExample:\n  integral(|x| x^2, 0, 1) // 0.333...".to_string(),
            insert_text: "integral(|$1| $2, $3, $4)".to_string(),
        },
        CompletionEntry {
            label: "newton_raphson".to_string(),
            kind: CompletionKind::Function,
            detail: "Newton-Raphson root finding".to_string(),
            documentation: "newton_raphson(fn: Function, x0: Number) -> Number\n\nFinds a root of fn using Newton-Raphson method.\n\nExample:\n  newton_raphson(|x| x^2 - 2, 1) // sqrt(2)".to_string(),
            insert_text: "newton_raphson(|$1| $2, $3)".to_string(),
        },
        CompletionEntry {
            label: "bisection".to_string(),
            kind: CompletionKind::Function,
            detail: "Bisection root finding".to_string(),
            documentation: "bisection(fn: Function, a: Number, b: Number) -> Number\n\nFinds a root of fn in interval [a, b] using bisection.\n\nExample:\n  bisection(|x| x^2 - 2, 1, 2) // sqrt(2)".to_string(),
            insert_text: "bisection(|$1| $2, $3, $4)".to_string(),
        },
        CompletionEntry {
            label: "secant".to_string(),
            kind: CompletionKind::Function,
            detail: "Secant root finding".to_string(),
            documentation: "secant(fn: Function, x0: Number, x1: Number) -> Number\n\nFinds a root of fn using secant method.\n\nExample:\n  secant(|x| x^2 - 2, 1, 2) // sqrt(2)".to_string(),
            insert_text: "secant(|$1| $2, $3, $4)".to_string(),
        },
        // === UTILITY FUNCTIONS ===
        CompletionEntry {
            label: "typeof".to_string(),
            kind: CompletionKind::Function,
            detail: "Get type of value".to_string(),
            documentation: "typeof(value: Any) -> String\n\nReturns the type of value as a string.\n\nExample:\n  typeof(42)       // \"Number\"\n  typeof(\"hi\")     // \"String\"\n  typeof([1, 2])   // \"Array\"".to_string(),
            insert_text: "typeof($1)".to_string(),
        },
        CompletionEntry {
            label: "str".to_string(),
            kind: CompletionKind::Function,
            detail: "Convert to string".to_string(),
            documentation: "str(value: Any) -> String\n\nConverts value to its string representation.\n\nExample:\n  str(42)          // \"42\"\n  str([1, 2, 3])   // \"[1, 2, 3]\"".to_string(),
            insert_text: "str($1)".to_string(),
        },
        CompletionEntry {
            label: "num".to_string(),
            kind: CompletionKind::Function,
            detail: "Convert to number".to_string(),
            documentation: "num(value: String | Boolean) -> Number\n\nConverts value to a number.\n\nExample:\n  num(\"42\")       // 42\n  num(true)        // 1".to_string(),
            insert_text: "num($1)".to_string(),
        },
        CompletionEntry {
            label: "print".to_string(),
            kind: CompletionKind::Function,
            detail: "Print to stdout".to_string(),
            documentation: "print(value: Any) -> Null\n\nPrints value to standard output.\n\nExample:\n  print(\"Hello, World!\")\n  print([1, 2, 3])".to_string(),
            insert_text: "print($1)".to_string(),
        },
        CompletionEntry {
            label: "assert".to_string(),
            kind: CompletionKind::Function,
            detail: "Assert condition".to_string(),
            documentation: "assert(condition: Boolean, message: String) -> Null\n\nThrows an error if condition is false.\n\nExample:\n  assert(x > 0, \"x must be positive\")".to_string(),
            insert_text: "assert($1, \"$2\")".to_string(),
        },
        CompletionEntry {
            label: "isnan".to_string(),
            kind: CompletionKind::Function,
            detail: "Check if NaN".to_string(),
            documentation: "isnan(x: Number) -> Boolean\n\nReturns true if x is NaN (Not a Number).\n\nExample:\n  isnan(0/0)      // true\n  isnan(42)       // false".to_string(),
            insert_text: "isnan($1)".to_string(),
        },
        CompletionEntry {
            label: "isinf".to_string(),
            kind: CompletionKind::Function,
            detail: "Check if infinite".to_string(),
            documentation: "isinf(x: Number) -> Boolean\n\nReturns true if x is positive or negative infinity.\n\nExample:\n  isinf(1/0)      // true\n  isinf(42)       // false".to_string(),
            insert_text: "isinf($1)".to_string(),
        },
        CompletionEntry {
            label: "isfinite".to_string(),
            kind: CompletionKind::Function,
            detail: "Check if finite".to_string(),
            documentation: "isfinite(x: Number) -> Boolean\n\nReturns true if x is a finite number.\n\nExample:\n  isfinite(42)    // true\n  isfinite(1/0)   // false".to_string(),
            insert_text: "isfinite($1)".to_string(),
        },
        // === GRAPH ALGORITHMS ===
        CompletionEntry {
            label: "bfs".to_string(),
            kind: CompletionKind::Function,
            detail: "Breadth-first search".to_string(),
            documentation: "bfs(graph: Array, start: Number) -> Array\n\nPerforms breadth-first search on a graph.\n\nExample:\n  let path = bfs(graph, 0)".to_string(),
            insert_text: "bfs($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "dfs".to_string(),
            kind: CompletionKind::Function,
            detail: "Depth-first search".to_string(),
            documentation: "dfs(graph: Array, start: Number) -> Array\n\nPerforms depth-first search on a graph.\n\nExample:\n  let path = dfs(graph, 0)".to_string(),
            insert_text: "dfs($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "dijkstra".to_string(),
            kind: CompletionKind::Function,
            detail: "Dijkstra's shortest path".to_string(),
            documentation: "dijkstra(graph: Array, start: Number) -> Record\n\nFinds shortest paths from start using Dijkstra's algorithm.\n\nExample:\n  let { distances, paths } = dijkstra(graph, 0)".to_string(),
            insert_text: "dijkstra($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "kruskal".to_string(),
            kind: CompletionKind::Function,
            detail: "Kruskal's MST algorithm".to_string(),
            documentation: "kruskal(edges: Array) -> Array\n\nFinds minimum spanning tree using Kruskal's algorithm.\n\nExample:\n  let mst = kruskal(edges)".to_string(),
            insert_text: "kruskal($1)".to_string(),
        },
        CompletionEntry {
            label: "prim".to_string(),
            kind: CompletionKind::Function,
            detail: "Prim's MST algorithm".to_string(),
            documentation: "prim(graph: Array, start: Number) -> Array\n\nFinds minimum spanning tree using Prim's algorithm.\n\nExample:\n  let mst = prim(graph, 0)".to_string(),
            insert_text: "prim($1, $2)".to_string(),
        },
        CompletionEntry {
            label: "topological_sort".to_string(),
            kind: CompletionKind::Function,
            detail: "Topological sort".to_string(),
            documentation: "topological_sort(graph: Array) -> Array\n\nReturns a topological ordering of a directed acyclic graph.\n\nExample:\n  let order = topological_sort(dag)".to_string(),
            insert_text: "topological_sort($1)".to_string(),
        },
        CompletionEntry {
            label: "pert_cpm".to_string(),
            kind: CompletionKind::Function,
            detail: "PERT/CPM analysis".to_string(),
            documentation: "pert_cpm(tasks: Array) -> Record\n\nPerforms PERT/CPM project scheduling analysis.\n\nExample:\n  let { critical_path, duration } = pert_cpm(tasks)".to_string(),
            insert_text: "pert_cpm($1)".to_string(),
        },
        // === GENERATOR FUNCTIONS ===
        CompletionEntry {
            label: "generate".to_string(),
            kind: CompletionKind::Function,
            detail: "Create generator".to_string(),
            documentation: "generate { ... yield value ... }\n\nCreates a generator function that can yield multiple values.\n\nExample:\n  let gen = generate {\n    yield 1;\n    yield 2;\n    yield 3;\n  }".to_string(),
            insert_text: "generate {\n\t$1\n}".to_string(),
        },
    ]
}

fn build_keyword_completions() -> Vec<CompletionEntry> {
    vec![
        CompletionEntry {
            label: "let".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Declare immutable variable".to_string(),
            documentation: "Declares an immutable variable binding.\n\nExample:\n  let name = value\n  let name: Type = value".to_string(),
            insert_text: "let ".to_string(),
        },
        CompletionEntry {
            label: "mut".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Declare mutable variable".to_string(),
            documentation: "Declares a mutable variable binding.\n\nExample:\n  mut counter = 0\n  mut counter: Number = 0".to_string(),
            insert_text: "mut ".to_string(),
        },
        CompletionEntry {
            label: "if".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Conditional expression".to_string(),
            documentation: "Conditional branching expression.\n\nExample:\n  if condition { then_expr } else { else_expr }".to_string(),
            insert_text: "if ".to_string(),
        },
        CompletionEntry {
            label: "else".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Alternative branch".to_string(),
            documentation: "Alternative branch in conditional expression.\n\nExample:\n  if condition { ... } else { ... }".to_string(),
            insert_text: "else ".to_string(),
        },
        CompletionEntry {
            label: "while".to_string(),
            kind: CompletionKind::Keyword,
            detail: "While loop".to_string(),
            documentation: "Loop while condition is true.\n\nExample:\n  while(condition) { body }".to_string(),
            insert_text: "while ".to_string(),
        },
        CompletionEntry {
            label: "for".to_string(),
            kind: CompletionKind::Keyword,
            detail: "For loop".to_string(),
            documentation: "Iterate over a collection.\n\nExample:\n  for(item in iterable) { body }".to_string(),
            insert_text: "for ".to_string(),
        },
        CompletionEntry {
            label: "in".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Membership/iteration".to_string(),
            documentation: "Used in for loops to iterate over collections.\n\nExample:\n  for(item in collection) { ... }".to_string(),
            insert_text: "in ".to_string(),
        },
        CompletionEntry {
            label: "match".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Pattern matching".to_string(),
            documentation: "Pattern matching expression.\n\nExample:\n  match value {\n    pattern => result,\n    _ => default\n  }".to_string(),
            insert_text: "match ".to_string(),
        },
        CompletionEntry {
            label: "type".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Type alias".to_string(),
            documentation: "Define a type alias.\n\nExample:\n  type Name = TypeAnnotation".to_string(),
            insert_text: "type ".to_string(),
        },
        CompletionEntry {
            label: "import".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Import from module".to_string(),
            documentation: "Import items from another module.\n\nExample:\n  import { item1, item2 } from \"module\"".to_string(),
            insert_text: "import ".to_string(),
        },
        CompletionEntry {
            label: "export".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Export from module".to_string(),
            documentation: "Export items from the current module.\n\nExample:\n  export { item1, item2 }".to_string(),
            insert_text: "export ".to_string(),
        },
        CompletionEntry {
            label: "return".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Early return".to_string(),
            documentation: "Early return from a function.\n\nExample:\n  return value".to_string(),
            insert_text: "return ".to_string(),
        },
        CompletionEntry {
            label: "break".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Break from loop".to_string(),
            documentation: "Exit from the current loop.\n\nExample:\n  break".to_string(),
            insert_text: "break".to_string(),
        },
        CompletionEntry {
            label: "continue".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Continue to next iteration".to_string(),
            documentation: "Skip to the next iteration of the loop.\n\nExample:\n  continue".to_string(),
            insert_text: "continue".to_string(),
        },
        CompletionEntry {
            label: "try".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Error handling block".to_string(),
            documentation: "Try block for error handling.\n\nExample:\n  try { risky_code } catch(error) { handle_error }".to_string(),
            insert_text: "try ".to_string(),
        },
        CompletionEntry {
            label: "catch".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Handle errors".to_string(),
            documentation: "Catch and handle errors from try block.\n\nExample:\n  try { ... } catch(error) { ... }".to_string(),
            insert_text: "catch ".to_string(),
        },
        CompletionEntry {
            label: "throw".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Throw error".to_string(),
            documentation: "Throw an error.\n\nExample:\n  throw \"error message\"".to_string(),
            insert_text: "throw ".to_string(),
        },
        CompletionEntry {
            label: "yield".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Yield value from generator".to_string(),
            documentation: "Yield a value from a generator function.\n\nExample:\n  generate {\n    yield value\n  }".to_string(),
            insert_text: "yield ".to_string(),
        },
        CompletionEntry {
            label: "do".to_string(),
            kind: CompletionKind::Keyword,
            detail: "Do block".to_string(),
            documentation: "Block expression for sequencing statements.\n\nExample:\n  do {\n    statement1;\n    statement2;\n    result\n  }".to_string(),
            insert_text: "do ".to_string(),
        },
    ]
}

fn build_constant_completions() -> Vec<CompletionEntry> {
    vec![
        CompletionEntry {
            label: "PI".to_string(),
            kind: CompletionKind::Constant,
            detail: "Mathematical constant pi".to_string(),
            documentation: "The ratio of a circle's circumference to its diameter (~3.14159).\n\nExample:\n  PI  // 3.141592653589793".to_string(),
            insert_text: "PI".to_string(),
        },
        CompletionEntry {
            label: "E".to_string(),
            kind: CompletionKind::Constant,
            detail: "Euler's number".to_string(),
            documentation: "The base of natural logarithms (~2.71828).\n\nExample:\n  E   // 2.718281828459045".to_string(),
            insert_text: "E".to_string(),
        },
        CompletionEntry {
            label: "PHI".to_string(),
            kind: CompletionKind::Constant,
            detail: "Golden ratio".to_string(),
            documentation: "The golden ratio (~1.61803).\n\nExample:\n  PHI // 1.618033988749895".to_string(),
            insert_text: "PHI".to_string(),
        },
        CompletionEntry {
            label: "SQRT2".to_string(),
            kind: CompletionKind::Constant,
            detail: "Square root of 2".to_string(),
            documentation: "The square root of 2 (~1.41421).\n\nExample:\n  SQRT2 // 1.4142135623730951".to_string(),
            insert_text: "SQRT2".to_string(),
        },
        CompletionEntry {
            label: "Infinity".to_string(),
            kind: CompletionKind::Constant,
            detail: "Positive infinity".to_string(),
            documentation: "Represents positive infinity.\n\nExample:\n  Infinity".to_string(),
            insert_text: "Infinity".to_string(),
        },
        CompletionEntry {
            label: "NaN".to_string(),
            kind: CompletionKind::Constant,
            detail: "Not a Number".to_string(),
            documentation: "Represents a value that is not a valid number.\n\nExample:\n  NaN".to_string(),
            insert_text: "NaN".to_string(),
        },
        CompletionEntry {
            label: "null".to_string(),
            kind: CompletionKind::Constant,
            detail: "Null value".to_string(),
            documentation: "Represents the absence of a value.\n\nExample:\n  null".to_string(),
            insert_text: "null".to_string(),
        },
        CompletionEntry {
            label: "true".to_string(),
            kind: CompletionKind::Constant,
            detail: "Boolean true".to_string(),
            documentation: "Boolean literal representing truth.\n\nExample:\n  true".to_string(),
            insert_text: "true".to_string(),
        },
        CompletionEntry {
            label: "false".to_string(),
            kind: CompletionKind::Constant,
            detail: "Boolean false".to_string(),
            documentation: "Boolean literal representing falsity.\n\nExample:\n  false".to_string(),
            insert_text: "false".to_string(),
        },
    ]
}

fn build_type_completions() -> Vec<CompletionEntry> {
    vec![
        CompletionEntry {
            label: "Number".to_string(),
            kind: CompletionKind::Type,
            detail: "Numeric type".to_string(),
            documentation: "Represents numeric values (integers and floating-point).\n\nExample:\n  let x: Number = 42\n  let y: Number = 3.14".to_string(),
            insert_text: "Number".to_string(),
        },
        CompletionEntry {
            label: "String".to_string(),
            kind: CompletionKind::Type,
            detail: "String type".to_string(),
            documentation: "Represents text values.\n\nExample:\n  let name: String = \"hello\"".to_string(),
            insert_text: "String".to_string(),
        },
        CompletionEntry {
            label: "Boolean".to_string(),
            kind: CompletionKind::Type,
            detail: "Boolean type".to_string(),
            documentation: "Represents true or false values.\n\nExample:\n  let flag: Boolean = true".to_string(),
            insert_text: "Boolean".to_string(),
        },
        CompletionEntry {
            label: "Complex".to_string(),
            kind: CompletionKind::Type,
            detail: "Complex number type".to_string(),
            documentation: "Represents complex numbers with real and imaginary parts.\n\nExample:\n  let z: Complex = 3 + 4i".to_string(),
            insert_text: "Complex".to_string(),
        },
        CompletionEntry {
            label: "Vector".to_string(),
            kind: CompletionKind::Type,
            detail: "Vector type".to_string(),
            documentation: "Represents a mathematical vector.\n\nExample:\n  let v: Vector = [1, 2, 3]".to_string(),
            insert_text: "Vector".to_string(),
        },
        CompletionEntry {
            label: "Tensor".to_string(),
            kind: CompletionKind::Type,
            detail: "Tensor type".to_string(),
            documentation: "Represents multi-dimensional arrays.\n\nExample:\n  let t: Tensor = [[1, 2], [3, 4]]".to_string(),
            insert_text: "Tensor".to_string(),
        },
        CompletionEntry {
            label: "Generator".to_string(),
            kind: CompletionKind::Type,
            detail: "Generator type".to_string(),
            documentation: "Represents a generator that yields values lazily.\n\nExample:\n  let gen: Generator = generate { yield 1 }".to_string(),
            insert_text: "Generator".to_string(),
        },
        CompletionEntry {
            label: "Function".to_string(),
            kind: CompletionKind::Type,
            detail: "Function type".to_string(),
            documentation: "Represents a callable function.\n\nExample:\n  let f: Function = |x| x * 2".to_string(),
            insert_text: "Function".to_string(),
        },
        CompletionEntry {
            label: "Error".to_string(),
            kind: CompletionKind::Type,
            detail: "Error type".to_string(),
            documentation: "Represents an error value.\n\nExample:\n  let err: Error = throw \"oops\"".to_string(),
            insert_text: "Error".to_string(),
        },
        CompletionEntry {
            label: "Record".to_string(),
            kind: CompletionKind::Type,
            detail: "Record type".to_string(),
            documentation: "Represents a record (object) with named fields.\n\nExample:\n  let person: Record = { name: \"Alice\", age: 30 }".to_string(),
            insert_text: "Record".to_string(),
        },
        CompletionEntry {
            label: "Edge".to_string(),
            kind: CompletionKind::Type,
            detail: "Graph edge type".to_string(),
            documentation: "Represents an edge in a graph.\n\nExample:\n  let e: Edge = edge(a, b, weight)".to_string(),
            insert_text: "Edge".to_string(),
        },
        CompletionEntry {
            label: "Null".to_string(),
            kind: CompletionKind::Type,
            detail: "Null type".to_string(),
            documentation: "Represents the absence of a value.\n\nExample:\n  let nothing: Null = null".to_string(),
            insert_text: "Null".to_string(),
        },
        CompletionEntry {
            label: "Array".to_string(),
            kind: CompletionKind::Type,
            detail: "Array type".to_string(),
            documentation: "Represents a dynamic array of values.\n\nExample:\n  let arr: Array = [1, 2, 3]".to_string(),
            insert_text: "Array".to_string(),
        },
        CompletionEntry {
            label: "Any".to_string(),
            kind: CompletionKind::Type,
            detail: "Any type".to_string(),
            documentation: "Represents any type (dynamic typing).\n\nExample:\n  let x: Any = 42".to_string(),
            insert_text: "Any".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completion_count() {
        let completions = get_all_completions();
        // We should have 151+ items (109 functions + 19 keywords + 9 constants + 14 types)
        assert!(
            completions.len() >= 150,
            "Expected at least 150 completion items, got {}",
            completions.len()
        );
    }

    #[test]
    fn test_function_count() {
        let functions = get_function_completions();
        assert!(
            functions.len() >= 109,
            "Expected at least 109 functions, got {}",
            functions.len()
        );
    }

    #[test]
    fn test_keyword_count() {
        let keywords = get_keyword_completions();
        assert_eq!(keywords.len(), 19, "Expected 19 keywords");
    }

    #[test]
    fn test_constant_count() {
        let constants = get_constant_completions();
        assert_eq!(constants.len(), 9, "Expected 9 constants");
    }

    #[test]
    fn test_type_count() {
        let types = get_type_completions();
        assert_eq!(types.len(), 14, "Expected 14 types");
    }

    #[test]
    fn test_completion_kind_as_str() {
        assert_eq!(CompletionKind::Function.as_str(), "function");
        assert_eq!(CompletionKind::Keyword.as_str(), "keyword");
        assert_eq!(CompletionKind::Constant.as_str(), "constant");
        assert_eq!(CompletionKind::Type.as_str(), "type");
    }

    #[test]
    fn test_specific_functions_present() {
        let completions = get_all_completions();
        let names: Vec<&str> = completions.iter().map(|c| c.label.as_str()).collect();

        // Check math functions
        assert!(names.contains(&"sin"), "Missing sin");
        assert!(names.contains(&"cos"), "Missing cos");
        assert!(names.contains(&"sqrt"), "Missing sqrt");
        assert!(names.contains(&"factorial"), "Missing factorial");

        // Check array functions
        assert!(names.contains(&"map"), "Missing map");
        assert!(names.contains(&"filter"), "Missing filter");
        assert!(names.contains(&"reduce"), "Missing reduce");
        assert!(names.contains(&"len"), "Missing len");

        // Check DSP functions
        assert!(names.contains(&"fft"), "Missing fft");
        assert!(names.contains(&"convolve"), "Missing convolve");

        // Check linear algebra
        assert!(names.contains(&"det"), "Missing det");
        assert!(names.contains(&"inv"), "Missing inv");

        // Check graph algorithms
        assert!(names.contains(&"dijkstra"), "Missing dijkstra");
        assert!(names.contains(&"bfs"), "Missing bfs");
    }
}
