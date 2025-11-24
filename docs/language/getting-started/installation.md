---
title: "Installation"
description: "Installation guide for Achronyme"
section: "getting-started"
order: 2
---

This guide will help you install Achronyme on your system.

## Option 1: Pre-built Binaries (Recommended)

Achronyme provides pre-built binaries for major platforms (Windows, macOS, Linux) generated automatically by our CI/CD pipeline.

1.  Go to the **[GitHub Releases](https://github.com/achronyme/achronyme-core/releases)** page.
2.  Download the latest archive for your operating system:
    *   **Windows**: `achronyme-windows-x64.zip`
    *   **macOS**: `achronyme-macos-x64.tar.gz`
    *   **Linux**: `achronyme-linux-x64.tar.gz`
3.  Extract the archive.
4.  Add the binary to your system's `PATH` for easy access.

## Option 2: Build from Source

If you have the Rust toolchain installed, you can build Achronyme from source.

1.  Clone the repository:
    ```bash
    git clone https://github.com/achronyme/achronyme-core.git
    cd achronyme-core
    ```

2.  Build using Cargo:
    ```bash
    cargo build --release
    ```

3.  The binary will be located at `target/release/achronyme` (or `achronyme.exe` on Windows).

## Verifying Installation

To verify that Achronyme is installed correctly, run:

```bash
achronyme --version
```

You should see the current version number printed to the console.