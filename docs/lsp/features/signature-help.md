---
title: "Signature Help"
description: "Function signature display and parameter hints"
section: "lsp-features"
order: 3
---

# Signature Help

Signature help displays function signatures and parameter information as you type function calls, making it easy to remember parameters and their types.

## Overview

When you type a function call with an opening parenthesis, the LSP server shows:
- **Function signature** - Full function declaration
- **Active parameter** - Which parameter you're currently typing
- **Parameter documentation** - Description of each parameter
- **Return type** - What the function returns

## Triggering Signature Help

**Automatic Triggers:**
- Type `(` after a function name
- Type `,` between parameters

**Manual Trigger:**
- `Ctrl+Shift+Space` (VS Code)
- `Ctrl+k` (Neovim, depends on setup)

**Example:**

```javascript
// Type "sin(" and signature appears:
sin(|
```

Shows:
```
sin(x: Number) -> Number
↑ Parameter 1
Returns the sine of x (x in radians)
```

## Supported Functions (56+ signatures)

The LSP server provides signatures for 56+ built-in functions:

### Mathematical Functions

```
sin(x: Number) -> Number
cos(x: Number) -> Number
tan(x: Number) -> Number
asin(x: Number) -> Number
acos(x: Number) -> Number
atan(x: Number) -> Number
atan2(y: Number, x: Number) -> Number
sqrt(x: Number) -> Number
cbrt(x: Number) -> Number
exp(x: Number) -> Number
ln(x: Number) -> Number
log(x: Number, base: Number) -> Number
log10(x: Number) -> Number
log2(x: Number) -> Number
abs(x: Number) -> Number
floor(x: Number) -> Number
ceil(x: Number) -> Number
round(x: Number) -> Number
min(a: Number, b: Number) -> Number
max(a: Number, b: Number) -> Number
pow(base: Number, exponent: Number) -> Number
```

### Array Functions

```
len(arr: Array) -> Number
map(f: Function, arr: Array) -> Array
filter(f: Function, arr: Array) -> Array
reduce(f: Function, initial: Any, arr: Array) -> Any
push(arr: Array, value: Any) -> Array
pop(arr: Array) -> Array
shift(arr: Array) -> Array
unshift(arr: Array, value: Any) -> Array
head(arr: Array) -> Any
tail(arr: Array) -> Array
slice(arr: Array, start: Number, end?: Number) -> Array
reverse(arr: Array) -> Array
flatten(arr: Array, depth?: Number) -> Array
concat(...arrays: Array[]) -> Array
```

### String Functions

```
length(str: String) -> Number
toUpperCase(str: String) -> String
toLowerCase(str: String) -> String
trim(str: String) -> String
split(str: String, sep: String) -> Array
join(arr: Array, sep: String) -> String
substring(str: String, start: Number, end?: Number) -> String
```

### Statistical Functions

```
mean(data: Array) -> Number
median(data: Array) -> Number
std(data: Array) -> Number
variance(data: Array) -> Number
quantile(data: Array, q: Number) -> Number
sum(arr: Array) -> Number
product(arr: Array) -> Number
```

### Signal Processing Functions

```
fft(signal: Array) -> Array
ifft(signal: Array) -> Array
convolve(a: Array, b: Array) -> Array
correlate(a: Array, b: Array) -> Array
hamming(length: Number) -> Array
hann(length: Number) -> Array
blackman(length: Number) -> Array
```

### Linear Algebra Functions

```
dot(a: Vector, b: Vector) -> Number
cross(a: Vector, b: Vector) -> Vector
norm(v: Vector) -> Number
det(m: Matrix) -> Number
inv(m: Matrix) -> Matrix
transpose(m: Matrix) -> Matrix
solve(A: Matrix, b: Vector) -> Vector
```

## Reading Signatures

### Basic Format

```
functionName(param1: Type, param2: Type, ...) -> ReturnType
```

**Example:**

```
map(f: Function, arr: Array) -> Array
```

This means:
- Function name: `map`
- Parameter 1: `f` of type `Function`
- Parameter 2: `arr` of type `Array`
- Returns: `Array`

### Optional Parameters

Optional parameters are marked with `?`:

```
slice(arr: Array, start: Number, end?: Number) -> Array
```

This means:
- `arr` - Required
- `start` - Required
- `end` - Optional (can be omitted)

### Variable Arguments

Functions accepting multiple arguments:

```
concat(...arrays: Array[]) -> Array
```

The `...` indicates the function takes any number of arrays.

## Understanding Parameter Documentation

Each parameter has documentation explaining its role:

**Example for `map`:**

```
map(f: Function, arr: Array) -> Array

Parameters:
  f: Function - Function to apply to each element
  arr: Array - Array to map over

Returns: Array - New array with function applied to each element

Example:
  map(x => x * 2, [1, 2, 3])  // [2, 4, 6]
```

## Using Signature Help

### Typing a Function Call

```javascript
// You type: sin(
// LSP shows:
sin(x: Number) -> Number
↑ Param 1 (active)

// You type: sin(3.14
// LSP still shows the signature with param 1 active
```

### Multiple Parameters

```javascript
// You type: map(|
// LSP shows:
map(f: Function, arr: Array) -> Array
↑ Param 1 (active)

// You type: map(x => x * 2, |
// LSP shows:
map(f: Function, arr: Array) -> Array
           ↑ Param 2 (now active)
```

### Nested Function Calls

Signature help works with nested functions:

```javascript
// You type: map(x => sqrt(|
// Shows signature for sqrt (innermost function)
sqrt(x: Number) -> Number

// When you close the sqrt call: map(x => sqrt(4), |
// Shows signature for map (outer function)
map(f: Function, arr: Array) -> Array
```

### Retrigger on Comma

When you type a comma, signature help updates to show the next parameter:

```javascript
// reduce(sum, |
reduce(f: Function, initial: Any, arr: Array) -> Any
                     ↑ Param 2 (now active)

// reduce(sum, 0, |
reduce(f: Function, initial: Any, arr: Array) -> Any
                                   ↑ Param 3 (now active)
```

## Keyboard Shortcuts

| Editor | Show Signature | Next/Previous |
|--------|----------------|---------------|
| VS Code | `Ctrl+Shift+Space` | `Up`/`Down` |
| Neovim | `Ctrl+k` (varies) | Varies |
| Emacs | `M-x lsp-signature-help-next-signature` | Varies |

## Editor-Specific Features

### VS Code

Signature help automatically appears when typing `(` and `,`.

Configuration:
```json
"[achronyme]": {
  "editor.parameterHints.enabled": true
}
```

**Tips:**
- Hover over the signature info to see full documentation
- Use `Up`/`Down` arrows if multiple overloads exist

### Neovim

Signature help requires additional setup.

With `lsp_signature.nvim`:

```lua
require 'lsp_signature'.setup({
  bind = true,
  handler_opts = {
    border = "rounded"
  }
})

lspconfig.achronyme.setup {}
```

### Emacs

`lsp-mode` provides signature help integration.

```elisp
(use-package lsp-signature
  :ensure t
  :hook (lsp-mode . lsp-signature-activate)
  :custom
  (lsp-signature-auto-activate t))
```

## Common Signature Patterns

### Functions Returning Arrays

```
map(f: Function, arr: Array) -> Array
filter(f: Function, arr: Array) -> Array
reverse(arr: Array) -> Array
```

### Reduction Functions

```
reduce(f: Function, initial: Any, arr: Array) -> Any
sum(arr: Array) -> Number
product(arr: Array) -> Number
```

### Mathematical Functions

Most math functions follow this pattern:

```
functionName(x: Number, ...) -> Number
```

Examples:
```
sin(x: Number) -> Number
sqrt(x: Number) -> Number
log(x: Number, base: Number) -> Number
```

### Higher-Order Functions

These take functions as parameters:

```
map(f: Function, arr: Array) -> Array
filter(f: Function, arr: Array) -> Array
reduce(f: Function, initial: Any, arr: Array) -> Any
```

## Tips and Tricks

### Remember Parameter Order

Signature help makes it easy to remember which parameter comes first:

```javascript
// Is it filter(arr, f) or filter(f, arr)?
// Type filter( and the signature tells you:
filter(f: Function, arr: Array) -> Array
// Function first!
```

### Check Return Types

Always check the return type to know what the function produces:

```javascript
// What does map return?
map(f: Function, arr: Array) -> Array
                                ↑ Returns Array

// What does reduce return?
reduce(f: Function, initial: Any, arr: Array) -> Any
                                                 ↑ Returns Any
```

### Optional Parameters

Look for `?` to know if a parameter is optional:

```javascript
// slice needs how many parameters?
slice(arr: Array, start: Number, end?: Number) -> Array
// Only arr and start are required; end is optional

// These work:
slice(arr, 0)
slice(arr, 0, 5)
```

## Disabling Signature Help

If you prefer manual reference:

**VS Code:**
```json
"editor.parameterHints.enabled": false
```

**Neovim:**
```lua
lspconfig.achronyme.setup {
  handlers = {
    ['textDocument/signatureHelp'] = function() end
  }
}
```

## Performance

Signature help:
- Shows immediately (<50ms)
- Updates smoothly as you type
- Works with deeply nested function calls
- Handles 56+ function signatures efficiently

## Future Enhancements

Planned improvements:
- Support for overloaded functions (multiple signatures)
- User-defined function signatures
- Generic type parameter display
- Callable type hints

---

**Next**: [Hover Information](hover.md)
