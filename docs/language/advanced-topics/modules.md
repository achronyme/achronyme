---
title: "Modules"
description: "Organizing user code with imports and exports in Achronyme"
section: "advanced-topics"
order: 6
---

The Achronyme module system allows you to organize your code into reusable files and modules.

**Note:** The standard library functions (like `sin`, `cos`, `mean`, `println`) are **globally available** and do not need to be imported. The module system described here is for structuring **your own code**.

## Exporting Symbols

To make functions, variables, or records available to other files, use the `export` statement at the end of your file.

```javascript
// src/math_utils.soc

let double = x => x * 2
let square = x => x * x

// Private helper (not exported)
let _helper = x => x + 1

export { double, square }
```

You can export any top-level binding:

```javascript
let PI_APPROX = 3.14
let config = { debug: true }
let helper = x => x

export { PI_APPROX, config, helper }
```

## Importing Modules

To use code from another file, use the `import` statement with a relative path.

### Basic Import

```javascript
// main.soc
import { double, square } from "./src/math_utils"

let result = double(10)
let sq = square(5)
```

### Import Aliasing

You can rename imported symbols to avoid naming conflicts:

```javascript
import { double as timesTwo } from "./src/math_utils"

let result = timesTwo(10)
```

## Module Resolution

Paths in `import` are relative to the file containing the import statement.

*   `"./module"` - Looks for `module.soc` in the current directory.
*   `"../utils"` - Looks for `utils.soc` in the parent directory.
*   `"./src/component"` - Looks for `component.soc` in the `src` subdirectory.

The `.soc` extension is optional in the import path.

## Example Project Structure

```text
my_project/
├── main.soc
└── utils/
    ├── math.soc
    └── string.soc
```

**utils/math.soc**:
```javascript
let add = (a, b) => a + b
export { add }
```

**main.soc**:
```javascript
import { add } from "./utils/math"

print(add(1, 2))

```



## See Also



- [Variables](../core-language/variables.md) - Variable declarations and scope

- [Functions](../core-language/functions.md) - Defining functions

- [Records](../data-structures/records.md) - Using records as namespaces
