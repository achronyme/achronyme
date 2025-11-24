# Module System Example - User-Defined Modules

This example demonstrates how to organize your own Achronyme code into reusable modules using `import` and `export`.

**Note:** The standard library (math functions, statistics, etc.) is globally available and does not need to be imported. The module system is specifically for structuring your own application code.

## Project Structure

```
examples/soc/modules/
├── main.soc                      # Main application entry point
├── src/
│   ├── contador.soc              # Counter module with mutable state
│   ├── funcion1.soc              # Simple utility function
│   ├── funcion2.soc              # Another utility function
│   ├── makeAdder.soc             # Higher-order function factory
│   └── semaforo.soc              # State machine example
└── README.md                     # This file
```

## Running the Example

```bash
# Using the CLI
achronyme run examples/soc/modules/main.soc
```

## Key Concepts Demonstrated

1.  **Exporting Symbols**: Using `export { name }` to make functions or variables available to other files.
2.  **Importing Local Modules**: Using relative paths `import { name } from "./src/module"` to load user code.
3.  **Encapsulation**: Splitting logic into separate files for better maintainability.
4.  **Global Standard Library**: Using functions like `print`, `describe`, constants like `pi`, `e` directly without imports.