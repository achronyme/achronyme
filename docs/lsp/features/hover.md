---
title: "Hover Information"
description: "Rich documentation on hover in Achronyme LSP"
section: "lsp-features"
order: 4
---

# Hover Information

Hovering over code displays rich documentation and type information for functions, keywords, variables, and constants.

## Overview

When you hover your mouse over a name in your code, the LSP server shows:
- **Type information** - What type is this?
- **Full signature** - For functions, the complete declaration
- **Documentation** - Detailed description of what it does
- **Examples** - Usage examples where available

## How to Use

### Triggering Hover

Simply move your mouse over any identifier:

```javascript
let x = sin(3.14159)
        ↑ Hover here to see sin documentation
```

### Display

Hover information appears in a tooltip/popup with:
- **Bold title** - Function/keyword name
- **Code block** - Signature in code formatting
- **Markdown documentation** - Full description

**Example hover for `sin`:**

```
sin(x: Number) -> Number

Returns the sine of x (x in radians).

The input should be in radians, not degrees.
Use this for trigonometric calculations.

Example:
  sin(0)        // 0
  sin(PI / 2)   // 1
  sin(PI)       // 0 (approximately)
```

## Information Available on Hover

### Functions

Hover shows the complete function signature:

```
functionName(param1: Type, param2: Type, ...) -> ReturnType
```

With documentation:
- What the function does
- What each parameter means
- What it returns
- Practical examples

### Keywords

Hover shows keyword documentation:

```
let

Binds a name to an immutable value. The binding is constant and cannot be
reassigned, though the bound value might be mutable.

Example:
  let x = 42
  let f = x => x * 2
```

### Constants

Hover shows constant values:

```
PI: Number (3.14159...)

The mathematical constant π (pi).
The ratio of a circle's circumference to its diameter.

Useful for:
  - Trigonometry: sin(PI/2) = 1
  - Geometry: circumference = 2*PI*r
  - Physics calculations
```

### Variables

Hover shows variable definitions:

```
x: Number

Defined at line 5:
  let x = 42
```

## Hover Examples

### Mathematical Functions

**Hover on `sqrt`:**

```
sqrt(x: Number) -> Number

Returns the square root of x.

Works for all non-negative numbers.
For negative numbers, returns NaN.

Examples:
  sqrt(4)     // 2
  sqrt(2)     // 1.41421356...
  sqrt(0)     // 0
  sqrt(-1)    // NaN
```

### Array Functions

**Hover on `map`:**

```
map(f: Function, arr: Array) -> Array

Applies function f to each element of the array.

Returns a new array with the results, preserving the original array.

Parameters:
  f: Function - A function taking one element, returning a new value
  arr: Array - The array to transform

Examples:
  map(x => x * 2, [1, 2, 3])      // [2, 4, 6]
  map(x => x > 2, [1, 2, 3, 4])   // [false, false, true, true]
```

### Keywords

**Hover on `match`:**

```
match

Pattern matching expression for conditional logic.

Syntax:
  match value {
    pattern1 => result1
    pattern2 => result2
    _ => default_result
  }

Examples:
  let describe = x => match x {
    0 => "zero"
    n if (n < 0) => "negative"
    _ => "positive"
  }
```

**Hover on `for`:**

```
for

For-in loop iterating over array elements.

Syntax:
  for(variable in array) {
    // Body executed for each element
  }

Features:
  - Uses 'in' operator to bind each element
  - Can use 'break' to exit early
  - Can use 'continue' to skip to next iteration

Examples:
  for(x in [1, 2, 3]) {
    print(x)
  }
```

### Constants

**Hover on `E`:**

```
E: Number (2.71828...)

Euler's number, the base of natural logarithms.

Used for:
  - Exponential growth: exp(x) = e^x
  - Natural logarithm: ln(x) = log_e(x)
  - Compound interest calculations

Mathematical definition:
  e = lim (n → ∞) (1 + 1/n)^n
```

## Information by Category

### Mathematical Functions

All math functions show:
- Full signature
- Mathematical definition (when relevant)
- Input/output ranges
- Common uses
- Examples

### Statistical Functions

Hover shows:
- Formula or algorithm
- Parameters and return type
- When to use this function
- Example calculations

### Array/Collection Functions

Hover displays:
- What operation it performs
- Input/output shapes
- Lazy vs eager evaluation (where relevant)
- Common patterns

## Keyboard Navigation

For editors that support keyboard navigation of hover:

| Action | Key |
|--------|-----|
| Show hover | Hover mouse / Alt+K (varies) |
| Navigate links | Tab / Shift+Tab |
| Close | Esc |
| Focus | Click on hover |

## Hover in Different Editors

### VS Code

- Hover appears automatically when mouse is still
- Click the hover to pin it
- Scroll hover text with mouse wheel
- Close with Esc key

### Neovim

Hover is less automatic; requires configuration:

```lua
lspconfig.achronyme.setup {
  on_attach = function(client, bufnr)
    vim.keymap.set('n', 'K', vim.lsp.buf.hover, {buffer = bufnr})
  end
}
```

Then press `K` to show hover.

### Emacs

Press `M-x lsp-describe-thing-at-point` to show hover:

```elisp
(use-package lsp-mode
  :bind (:map lsp-mode-map
         ("M-h" . lsp-describe-thing-at-point)))
```

## Detailed Hover Content

### Code Examples in Hover

Hover documentation includes code examples:

**For `filter`:**

```
filter(f: Function, arr: Array) -> Array

Selects elements from array where f returns true.

Examples:
  let data = [1, 2, 3, 4, 5]
  filter(x => x > 2, data)       // [3, 4, 5]
  filter(x => x % 2 == 0, data)  // [2, 4]
```

### Type Information

Hover shows complete type information:

```
User-defined variable x

Type: Number
Defined at: line 5
Value: 42
```

### Cross-references

For functions and variables, hover may show:

```
map(f: Function, arr: Array) -> Array

Related:
  - filter(f, arr) - Select elements
  - reduce(f, init, arr) - Combine into single value

See also: higher-order functions
```

## Advanced Hover Features

### Hover for Complex Expressions

Hover over compound expressions to see evaluated type:

```javascript
let result = map(x => x * 2, data)
             ↑ Hover shows: Array
```

### Hover for Record Fields

For records, hover on field names shows field type:

```javascript
type User = {name: String, age: Number}
let u = {name: "Alice", age: 30}
         ↑ Hover on "name" shows: String field
```

## Customizing Hover Appearance

### VS Code

Configure hover appearance:

```json
"[achronyme]": {
  "editor.hover.enabled": true,
  "editor.hover.delay": 500,
  "editor.hover.sticky": true
}
```

### Neovim

Customize hover window:

```lua
vim.lsp.handlers['textDocument/hover'] = vim.lsp.with(
  vim.lsp.handlers.hover,
  { border = 'rounded' }
)
```

## Disabling Hover

If you don't want hover information:

**VS Code:**
```json
"editor.hover.enabled": false
```

**Neovim:**
```lua
lspconfig.achronyme.setup {
  handlers = {
    ['textDocument/hover'] = function() end
  }
}
```

## Performance Notes

Hover information:
- Loads instantly for built-in functions
- May take <100ms for user-defined symbols
- Shows smoothly with no lag
- Works even with syntax errors

## Tips for Using Hover

1. **Learn function signatures** - Hover shows exact parameter order
2. **Discover built-in functions** - Hover to see what's available
3. **Understand keywords** - Hover to see syntax and examples
4. **Check variable types** - Hover to confirm what type a variable has
5. **Find examples** - Hover shows practical usage examples

## Future Enhancements

Planned hover improvements:
- Inline type hints alongside code
- Go to definition links in hover
- Multi-language documentation
- Custom hover styling per category
- Semantic highlighting in hover examples

---

**Next**: [Navigation](navigation.md)
