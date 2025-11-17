---
title: "I/O and Persistence"
description: "File I/O and environment save/restore in Achronyme"
section: "advanced-topics"
order: 5
---


Achronyme provides powerful capabilities for saving and restoring REPL sessions, enabling reproducible workflows and long-term storage of computational environments.

## Overview

The I/O and persistence module includes three core functions:
- **`save_env()`** - Save the current environment to a file
- **`restore_env()`** - Load a saved environment
- **`env_info()`** - Inspect metadata without loading

All functions work with the `.ach` (Achronyme Archive) binary format, which includes:
- **Custom 64-byte header** with version control and feature flags
- **MessagePack serialization** for cross-platform compatibility
- **Zstd compression** (configurable, level 1-22)
- **SHA-256 checksums** for integrity verification

---

## Quick Start

### Basic Workflow

```javascript
// Define some variables
let x = 42;
let data = [1, 2, 3, 4, 5];
let result = mean(data);

// Save your work
save_env("my_session.ach");

// Later, in a new session...
restore_env("my_session.ach");

// Variables are restored
print(x);        // 42
print(result);   // 3
```

---

## save_env - Save Environment

Saves the current REPL environment to an `.ach` file.

### Signatures

```javascript
// Simple: save everything to a file
save_env(path: String) -> Boolean

// Advanced: save with options
save_env({
    path: String,                    // Required
    compress: Boolean,               // Default: true
    compression_level: Number,       // Default: 3 (range: 1-22)
    description: String,             // Optional
    tags: [String],                  // Optional
    include_only: [String],          // Optional
    exclude: [String],               // Optional
    allow_overwrite: Boolean         // Default: false
}) -> Boolean
```

### Parameters

#### Simple Form
- `path` - File path where to save (String)

#### Advanced Form (Record)
- `path` - File path where to save (required, String)
- `compress` - Enable Zstd compression (default: `true`, Boolean)
- `compression_level` - Compression level 1-22 (default: `3`, Number)
  - 1 = fastest, less compression
  - 3 = balanced (recommended)
  - 22 = slowest, maximum compression
- `description` - Human-readable description (optional, String)
- `tags` - Tags for categorization (optional, Vector of Strings)
- `include_only` - Only save these variables (optional, Vector of Strings)
- `exclude` - Exclude these variables (optional, Vector of Strings)
  - Supports wildcards: `"temp_*"` excludes all variables starting with `temp_`
- `allow_overwrite` - Allow overwriting existing files (default: `false`, Boolean)

### Returns
- `true` if save succeeds
- Error string if save fails

### Examples

#### Basic Save

```javascript
let x = 42;
let name = "Achronyme";
let data = [1, 2, 3, 4, 5];

// Save everything
save_env("session.ach");
// Returns: true
```

#### Save with Compression Options

```javascript
// Maximum compression for archival
save_env({
    path: "archive.ach",
    compress: true,
    compression_level: 22,
    description: "Long-term archive",
    allow_overwrite: true
});

// Fast compression for temporary saves
save_env({
    path: "temp.ach",
    compress: true,
    compression_level: 1,
    allow_overwrite: true
});

// No compression (fastest)
save_env({
    path: "uncompressed.ach",
    compress: false,
    allow_overwrite: true
});
```

#### Save with Metadata

```javascript
save_env({
    path: "experiment_2024.ach",
    description: "Neural network training results",
    tags: ["ml", "experiment", "2024", "production"],
    allow_overwrite: true
});
```

#### Selective Save - Include Only

```javascript
// Only save specific variables
let x = 10;
let y = 20;
let temp = 99;
let debug_info = "not important";

save_env({
    path: "results.ach",
    include_only: ["x", "y"],
    allow_overwrite: true
});
// Only x and y are saved, temp and debug_info are excluded
```

#### Selective Save - Exclude Patterns

```javascript
let result = 42;
let data = [1, 2, 3];
let temp_1 = "ignore";
let temp_2 = "ignore";
let debug_var = "ignore";

save_env({
    path: "clean.ach",
    exclude: ["temp_*", "debug_var"],
    allow_overwrite: true
});
// Saves: result, data
// Excludes: temp_1, temp_2, debug_var
```

### Saved Value Types

The following types are fully supported:

| Type | Saved | Notes |
|------|-------|-------|
| Number | ✅ | Full precision |
| Boolean | ✅ | |
| String | ✅ | |
| Complex | ✅ | Real and imaginary parts |
| Vector | ✅ | Heterogeneous arrays |
| Tensor | ✅ | Shape and data preserved |
| ComplexTensor | ✅ | Complex number arrays |
| Record | ✅ | Nested records supported |
| Edge | ✅ | Graph edges with properties |
| Builtin Functions | ⚠️ | Name saved, not restored yet |
| User Lambdas | ❌ | Not serializable (future) |
| MutableRef | ✅ | Inner value is saved |

### Error Conditions

```javascript
// File already exists
save_env("existing.ach");
// Error: "File already exists: ..., Use allow_overwrite option."

// Invalid compression level
save_env({
    path: "test.ach",
    compression_level: 99
});
// Error: "compression_level must be between 1 and 22"

// Missing path in record
save_env({compress: true});
// Error: "save_env() record must contain 'path' as a String"
```

---

## restore_env - Restore Environment

Loads a saved environment from an `.ach` file.

### Signatures

```javascript
// Simple: merge without overwriting
restore_env(path: String) -> Boolean

// Advanced: restore with options
restore_env({
    path: String,                    // Required
    mode: String,                    // "merge" | "replace" | "namespace"
    overwrite: Boolean,              // Default: false
    namespace: String,               // Required if mode="namespace"
    include_only: [String],          // Optional
    exclude: [String],               // Optional
    verify_checksum: Boolean,        // Default: true
    strict_version: Boolean          // Default: false
}) -> Boolean
```

### Parameters

#### Simple Form
- `path` - File path to restore from (String)

#### Advanced Form (Record)
- `path` - File path to restore (required, String)
- `mode` - Restore mode (default: `"merge"`, String)
  - `"merge"` - Add variables, don't overwrite existing
  - `"replace"` - Clear environment and load all variables
  - `"namespace"` - Load as a record under a namespace
- `overwrite` - In merge mode, overwrite existing variables (default: `false`, Boolean)
- `namespace` - Namespace name (required if `mode="namespace"`, String)
- `include_only` - Only restore these variables (optional, Vector of Strings)
- `exclude` - Exclude these variables (optional, Vector of Strings)
- `verify_checksum` - Verify file integrity (default: `true`, Boolean)
- `strict_version` - Require exact version match (default: `false`, Boolean)

### Returns
- `true` if restore succeeds
- Error string if restore fails

### Examples

#### Basic Restore - Merge Mode

```javascript
// Current environment
let x = 99;
let z = 30;

// Restore (file contains: x=10, y=20)
restore_env("session.ach");

// After restore:
// x = 99  (not overwritten, original kept)
// y = 20  (added from file)
// z = 30  (unchanged)
```

#### Restore with Overwrite

```javascript
let x = 99;

restore_env({
    path: "session.ach",
    mode: "merge",
    overwrite: true
});

// After restore (file contains x=10):
// x = 10  (overwritten from file)
```

#### Replace Mode - Clean Slate

```javascript
// Current environment
let a = 1;
let b = 2;

// Replace everything
restore_env({
    path: "session.ach",
    mode: "replace"
});

// After restore (file contains: x=10, y=20):
// a = undefined (removed)
// b = undefined (removed)
// x = 10 (loaded from file)
// y = 20 (loaded from file)
```

#### Namespace Mode - Isolated Import

```javascript
// Load into a namespace
restore_env({
    path: "ml_model.ach",
    mode: "namespace",
    namespace: "model"
});

// Access via record
print(model.weights);
print(model.bias);
print(model.accuracy);

// Namespace is just a record
let keys_list = keys(model);
```

#### Selective Restore

```javascript
// Only restore specific variables
restore_env({
    path: "big_session.ach",
    include_only: ["result", "accuracy"],
    mode: "merge"
});

// Exclude temporary variables
restore_env({
    path: "session.ach",
    exclude: ["temp_*", "debug_*"],
    mode: "merge"
});
```

#### Version Control

```javascript
// Strict version checking
restore_env({
    path: "old_session.ach",
    strict_version: true
});
// Fails if file was created with different major version

// Permissive (default)
restore_env({
    path: "old_session.ach",
    strict_version: false
});
// Works if file is compatible (same or older major version)
```

### Restore Modes Comparison

| Mode | Keeps Existing? | Adds New? | Overwrites? |
|------|-----------------|-----------|-------------|
| `merge` (default) | ✅ Yes | ✅ Yes | ❌ No |
| `merge` + `overwrite: true` | ✅ Yes | ✅ Yes | ✅ Yes |
| `replace` | ❌ No | ✅ Yes | N/A |
| `namespace` | ✅ Yes | ✅ (as record) | ❌ No |

### Error Conditions

```javascript
// File not found
restore_env("nonexistent.ach");
// Error: "Failed to restore environment: ..."

// Invalid mode
restore_env({
    path: "session.ach",
    mode: "invalid"
});
// Error: "Invalid mode 'invalid', must be 'merge', 'replace', or 'namespace'"

// Namespace mode without namespace name
restore_env({
    path: "session.ach",
    mode: "namespace"
});
// Error: "namespace mode requires 'namespace' field"

// Checksum mismatch (file corrupted)
restore_env("corrupted.ach");
// Error: "Failed to restore environment: Checksum verification failed"
```

---

## env_info - Inspect Metadata

Retrieves metadata from an `.ach` file without loading the entire environment.

### Signature

```javascript
env_info(path: String) -> Record
```

### Parameters
- `path` - Path to `.ach` file (String)

### Returns

A record containing metadata:

```javascript
{
    created_by: String,         // "Achronyme v0.1.0"
    created_at: String,         // ISO 8601 timestamp
    platform: String,           // "windows x86_64"
    num_bindings: Number,       // Number of variables
    description: String,        // Optional description
    tags: [String],             // Optional tags
    binding_names: [String],    // List of variable names
    // ... custom fields
}
```

### Examples

#### Basic Inspection

```javascript
let info = env_info("session.ach");

print("Created:", info.created_at);
print("Platform:", info.platform);
print("Variables:", info.num_bindings);
print("Names:", str(info.binding_names));

// Output:
// Created: 2024-01-15T10:30:00Z
// Platform: windows x86_64
// Variables: 5
// Names: ["x", "y", "data", "result", "config"]
```

#### Check Before Restore

```javascript
let info = env_info("large_dataset.ach");

if info.num_bindings > 1000 {
    print("Warning: Large file with", info.num_bindings, "variables");
    print("This may take a while to load");
}

// Check if specific variable exists
if contains(info.binding_names, "critical_data") {
    restore_env("large_dataset.ach");
} else {
    print("Error: critical_data not found in file");
}
```

#### Display File Catalog

```javascript
let display_ach_info = (path) => do {
    let info = env_info(path);

    print("=== File Information ===");
    print("File:", path);
    print("Created:", info.created_at);
    print("Creator:", info.created_by);
    print("Platform:", info.platform);

    if info.description {
        print("Description:", info.description);
    }

    if len(info.tags) > 0 {
        print("Tags:", str(info.tags));
    }

    print("\n=== Content ===");
    print("Variables:", info.num_bindings);
    print("Names:", str(info.binding_names));
};

display_ach_info("experiment.ach");
```

#### Compare Files

```javascript
let compare_sessions = (path1, path2) => do {
    let info1 = env_info(path1);
    let info2 = env_info(path2);

    print("Session 1:", path1);
    print("  Variables:", info1.num_bindings);
    print("  Date:", info1.created_at);

    print("\nSession 2:", path2);
    print("  Variables:", info2.num_bindings);
    print("  Date:", info2.created_at);

    // Find common variables
    let common = filter(
        name => contains(info2.binding_names, name),
        info1.binding_names
    );

    print("\nCommon variables:", len(common));
    print(str(common));
};

compare_sessions("before.ach", "after.ach");
```

---

## File Format - `.ach` Specification

### Structure

```
[64-byte Header]
[Compressed MessagePack Body]
[32-byte SHA-256 Checksum]
```

### Header Format (64 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | Magic | `"ACH\0"` (0x41 0x43 0x48 0x00) |
| 4 | 2 | Version Major | Format version (currently 1) |
| 6 | 2 | Version Minor | Format minor version (currently 0) |
| 8 | 4 | Flags | Feature flags (compressed, etc.) |
| 12 | 8 | Timestamp | Unix timestamp |
| 20 | 16 | Achronyme Version | Null-terminated string |
| 36 | 1 | Compression | 0=None, 1=Zstd |
| 37 | 27 | Reserved | Reserved for future use |

### Body Format

MessagePack-encoded structure:
```rust
{
    metadata: {
        created_by: String,
        created_at: String,
        platform: String,
        num_bindings: u32,
        description: Option<String>,
        tags: Vec<String>,
        binding_names: Vec<String>,
        custom: HashMap<String, String>
    },
    bindings: HashMap<String, SerializedValue>
}
```

### Compression

- Algorithm: **Zstandard (Zstd)**
- Levels: 1-22
  - Level 3 (default): ~3:1 ratio, very fast
  - Level 22 (max): ~5:1 ratio, slower
- Applied to: MessagePack body only (not header/checksum)

### Integrity

- Algorithm: **SHA-256**
- Applied to: Compressed body (32 bytes appended)
- Verified on load (can be disabled with `verify_checksum: false`)

---

## Common Patterns

### Auto-Save Workflow

```javascript
// Auto-save after expensive computations
let expensive_computation = (data) => do {
    let result = pipe(
        data,
        arr => map(x => complex_operation(x), arr),
        arr => reduce((acc, x) => acc + x, 0, arr),
        r => r / len(data)
    );

    // Auto-save result
    save_env({
        path: "auto_save.ach",
        description: "Auto-saved after computation",
        allow_overwrite: true
    });

    result
};
```

### Checkpoint System

```javascript
// Save checkpoints during long workflows
let process_in_stages = (data) => do {
    // Stage 1
    let preprocessed = preprocess(data);
    save_env({
        path: "checkpoint_1_preprocessed.ach",
        description: "After preprocessing",
        allow_overwrite: true
    });

    // Stage 2
    let analyzed = analyze(preprocessed);
    save_env({
        path: "checkpoint_2_analyzed.ach",
        description: "After analysis",
        allow_overwrite: true
    });

    // Stage 3
    let results = finalize(analyzed);
    save_env({
        path: "checkpoint_3_final.ach",
        description: "Final results",
        allow_overwrite: true
    });

    results
};
```

### Session Templates

```javascript
// Create reusable environment templates
let create_template = (name) => do {
    // Define standard variables
    let pi = 3.14159265359;
    let e = 2.71828182846;
    let phi = 1.61803398875;

    // Define helper functions
    let deg_to_rad = (deg) => deg * pi / 180;
    let rad_to_deg = (rad) => rad * 180 / pi;

    save_env({
        path: name + "_template.ach",
        description: "Standard mathematical environment",
        tags: ["template", "math"],
        exclude: ["create_template"],  // Don't save this function
        allow_overwrite: true
    });
};

// Create template
create_template("math");

// Later, start new sessions from template
restore_env("math_template.ach");
```

### Experiment Tracking

```javascript
let run_experiment = (params, data) => do {
    let start_time = now();  // Hypothetical time function

    // Run experiment
    let results = train_model(params, data);

    // Save with comprehensive metadata
    save_env({
        path: "exp_" + params.name + ".ach",
        description: "Experiment: " + params.description,
        tags: [
            "experiment",
            "model_" + params.model_type,
            "date_" + start_time
        ],
        include_only: ["params", "results", "metrics"],
        allow_overwrite: true
    });

    print("Experiment saved to:", "exp_" + params.name + ".ach");
    results
};
```

### Collaborative Workflow

```javascript
// Person A: Save specific results
let share_results = () => do {
    let x = compute_x();
    let y = compute_y();
    let final = combine(x, y);

    save_env({
        path: "shared_results.ach",
        description: "Results for review",
        include_only: ["final", "x", "y"],
        tags: ["shared", "team_a"],
        allow_overwrite: true
    });
};

// Person B: Load in namespace to avoid conflicts
restore_env({
    path: "shared_results.ach",
    mode: "namespace",
    namespace: "team_a"
});

// Use results
let my_analysis = analyze(team_a.final);
```

---

## Best Practices

### 1. Use Descriptive Names

```javascript
// Good
save_env("neural_net_trained_2024_01_15.ach");

// Bad
save_env("temp.ach");
save_env("session1.ach");
```

### 2. Add Metadata

```javascript
// Always include description and tags for important saves
save_env({
    path: "final_model.ach",
    description: "Final model after hyperparameter tuning",
    tags: ["production", "v2.0", "optimized"],
    allow_overwrite: true
});
```

### 3. Clean Before Saving

```javascript
// Exclude temporary variables
save_env({
    path: "clean_session.ach",
    exclude: ["temp_*", "debug_*", "_*"],
    allow_overwrite: true
});
```

### 4. Version Your Saves

```javascript
let version_save = (base_name, version) => do {
    save_env({
        path: base_name + "_v" + str(version) + ".ach",
        description: "Version " + str(version),
        tags: ["versioned", "v" + str(version)],
        allow_overwrite: true
    });
};

version_save("my_project", 1);
version_save("my_project", 2);
```

### 5. Check Before Overwriting

```javascript
// Check if file exists using env_info
let safe_save = (path) => do {
    // Try to get info
    let exists = true;  // Simplified check

    if exists {
        print("Warning: File exists. Use allow_overwrite: true");
        false
    } else {
        save_env(path);
        true
    }
};
```

### 6. Validate After Restore

```javascript
let restore_and_validate = (path, expected_vars) => do {
    restore_env(path);

    // Check all expected variables exist
    let all_present = all(
        name => type(eval(name)) != "Undefined",  // Hypothetical eval
        expected_vars
    );

    if all_present {
        print("All variables restored successfully");
        true
    } else {
        print("Error: Some variables missing");
        false
    }
};
```

---

## Performance Considerations

### File Sizes

Typical compression ratios with default settings (level 3):

| Data Type | Original | Compressed | Ratio |
|-----------|----------|------------|-------|
| Numbers (1000) | ~8 KB | ~2-3 KB | ~3:1 |
| Strings | Varies | ~2-4:1 | |
| Tensors (10000) | ~80 KB | ~20-30 KB | ~3:1 |
| Mixed | Varies | ~3-4:1 | |

### Compression Trade-offs

```javascript
// Fast save (level 1) - Use for frequent auto-saves
save_env({
    path: "quick_save.ach",
    compression_level: 1,  // ~2x speedup
    allow_overwrite: true
});

// Balanced (level 3, default) - Use for normal saves
save_env({
    path: "normal_save.ach",
    compression_level: 3,  // Good balance
    allow_overwrite: true
});

// Maximum compression (level 22) - Use for archives
save_env({
    path: "archive.ach",
    compression_level: 22,  // ~2x smaller, ~10x slower
    allow_overwrite: true
});
```

### Large Environments

For environments with thousands of variables:

```javascript
// Use include_only for faster saves
save_env({
    path: "important_only.ach",
    include_only: ["critical_result", "final_model"],
    allow_overwrite: true
});

// Check size before loading
let info = env_info("huge_file.ach");
if info.num_bindings > 10000 {
    print("Large file detected, loading may take time");
}
```

---

## Error Handling

### Robust Save

```javascript
let robust_save = (path) => do {
    // Try to save
    let result = save_env({
        path: path,
        allow_overwrite: true
    });

    // Check result
    if type(result) == "Boolean" && result {
        print("Save successful:", path);
        true
    } else {
        print("Save failed:", path);
        print("Error:", str(result));
        false
    }
};
```

### Robust Restore

```javascript
let robust_restore = (path) => do {
    // Check file exists and is valid
    let info = env_info(path);

    if type(info) == "Record" {
        print("Found", info.num_bindings, "variables");

        // Restore
        let result = restore_env(path);

        if result {
            print("Restore successful");
            true
        } else {
            print("Restore failed");
            false
        }
    } else {
        print("Cannot read file:", path);
        false
    }
};
```

---

## Limitations

### Current Limitations

1. **User-defined functions** - Lambda functions cannot be serialized yet
   ```javascript
   let my_func = x => x + 1;
   save_env("test.ach");  // my_func will NOT be saved
   ```

2. **Builtin functions** - Names are saved but not restored
   ```javascript
   let my_sin = sin;
   save_env("test.ach");  // Reference is saved but not restored
   ```

3. **Circular references** - Not supported in records
   ```javascript
   let a = {value: 1};
   a.self = a;  // Circular reference
   save_env("test.ach");  // May fail
   ```

### Future Features

Planned for future versions:
- User-defined function serialization
- Builtin function restoration
- Module imports/exports integration
- Incremental saves (delta compression)
- Environment diff/merge tools
- Remote storage backends

---

## Troubleshooting

### File Won't Save

```javascript
// Problem: File exists
save_env("existing.ach");
// Error: File already exists

// Solution: Use allow_overwrite
save_env({
    path: "existing.ach",
    allow_overwrite: true
});
```

### Variables Not Restored

```javascript
// Problem: Forgot to use 'let' when defining
x = 42;  // Wrong! Variable not actually defined
save_env("test.ach");

// Solution: Use 'let' keyword
let x = 42;  // Correct
save_env("test.ach");
```

### Checksum Errors

```javascript
// Problem: File corrupted
restore_env("corrupted.ach");
// Error: Checksum verification failed

// Solution 1: Skip checksum (not recommended)
restore_env({
    path: "corrupted.ach",
    verify_checksum: false
});

// Solution 2: Re-save from backup
```

### Large File Performance

```javascript
// Problem: Restore is slow
restore_env("huge_file.ach");  // Takes forever

// Solution: Only load what you need
restore_env({
    path: "huge_file.ach",
    include_only: ["result", "final_data"]
});
```

---

## Implementation Details

### Module Location
- Implementation: `crates/achronyme-eval/src/function_modules/io.rs`
- Binary format: `crates/achronyme-env/src/`

### Dependencies
- **MessagePack** (rmp-serde 1.1+) - Serialization
- **Zstandard** (zstd 0.13+) - Compression
- **SHA-256** (sha2 0.10+) - Checksums

### File Format Version
- Current: **1.0**
- Backward compatible within major version
- Forward compatible: newer versions can read older files

---

## See Also

- [Variables](05-variables.md) - Variable declaration and scoping
- [Records](07-records.md) - Working with records
- [Utilities](25-utilities.md) - print, type, str functions
- [Best Practices](23-best-practices.md) - Code organization
