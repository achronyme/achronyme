---
title: "LSP Server Installation"
description: "How to install the Achronyme LSP server"
section: "lsp-getting-started"
order: 1
---

# Installing the Achronyme LSP Server

This guide covers the installation process for the Achronyme LSP server.

## Prerequisites

- **Rust 1.70+** (only if building from source)
- **Your favorite editor** with LSP client support
- **Achronyme compiler** (optional, for testing)

## Installation Methods

### Option 1: Build from Source (Recommended)

Building from source ensures you have the latest version and full control.

#### Clone the Repository

```bash
git clone https://github.com/achronyme/achronyme-core.git
cd achronyme-core
```

#### Build the LSP Server

```bash
cargo build --release -p achronyme-lsp
```

This will take a few minutes on first build. The compiled binary will be in:

**Linux/macOS:**
```bash
target/release/achronyme-lsp
```

**Windows:**
```bash
target/release/achronyme-lsp.exe
```

#### Verify Installation

Test the binary:

```bash
# On Linux/macOS:
./target/release/achronyme-lsp --help

# On Windows:
target\release\achronyme-lsp.exe --help
```

You should see help output confirming the installation.

### Option 2: From Workspace Cargo Installation

If you have the workspace set up:

```bash
cd achronyme-core
cargo install --path crates/achronyme-lsp
```

This installs the LSP server to your Cargo bin directory (usually `~/.cargo/bin/`).

Verify:

```bash
achronyme-lsp --help
```

## Installation Locations

### Linux/macOS

Typical installation locations after `cargo install`:

```
~/.cargo/bin/achronyme-lsp
```

Add to PATH if needed:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

Add to `~/.bashrc` or `~/.zshrc` for persistence.

### Windows

After `cargo install`, the binary is usually at:

```
%USERPROFILE%\.cargo\bin\achronyme-lsp.exe
```

This directory is typically already in your PATH.

Verify by opening Command Prompt and running:

```bash
achronyme-lsp --help
```

## Version Information

Check the installed version:

```bash
achronyme-lsp --version
```

Current version: **0.1.0**

## Uninstallation

If you installed via `cargo install`:

```bash
cargo uninstall achronyme-lsp
```

If you built from source, simply delete the binary.

## Troubleshooting Installation

### "Command not found"

If the command is not found after installation:

1. Verify the binary exists:
   ```bash
   ls -la ~/.cargo/bin/achronyme-lsp    # Linux/macOS
   dir %USERPROFILE%\.cargo\bin         # Windows
   ```

2. Check if `~/.cargo/bin` is in your PATH:
   ```bash
   echo $PATH                           # Linux/macOS
   echo %PATH%                          # Windows
   ```

3. If not in PATH, add it manually and restart your terminal/editor.

### Build Fails with Rust Error

Ensure you have the minimum required Rust version:

```bash
rustc --version
```

If you need to update:

```bash
rustup update
```

### "No such file or directory"

On some systems, you may need to specify the full path to the binary in your editor configuration. See [Editor Setup](editor-setup.md) for examples.

## Next Steps

After installation, proceed to:

1. **[Editor Setup](editor-setup.md)** - Configure your editor to use the LSP server
2. **[Configuration](configuration.md)** - Customize server behavior

## Getting Help

If installation still doesn't work:

1. Check the [Troubleshooting](../advanced/troubleshooting.md) section
2. Enable debug mode in your editor's LSP client configuration
3. Report issues on [GitHub](https://github.com/achronyme/achronyme-core/issues)

---

**Next**: [Editor Setup](editor-setup.md)
