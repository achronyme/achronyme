# Achronyme (ZK-Edition)

> A register-based, high-performance Virtual Machine optimized for Zero-Knowledge Proofs and Cryptographic Primitives, written in Rust.

**Achronyme** is a domain-specific language (DSL) designed to bridge the gap between easy-to-write scripting and high-performance cryptographic engineering. Unlike general-purpose VMs, Achronyme treats **Finite Field Elements** and **Tensors** as first-class citizens, enabling efficient implementation of ZK-SNARK circuits and polynomial arithmetic.

---

## ⚡ Key Features

### 🛠 Architecture & Performance
* **NaN Boxing & Pointer Tagging**: Exploits IEEE 754 floating-point standard to pack type tags, pointers, and small integers into a single 64-bit value, minimizing memory footprint and maximizing cache locality.
* **Mark-and-Sweep Garbage Collection**: A custom-built GC that handles complex graph references and cyclic dependencies efficiently.
* **Register-Based VM**: Reduces instruction dispatch overhead compared to traditional stack-based VMs (like EVM), offering better mapping to modern hardware registers.

### 🔐 Cryptography First
* **Native BigInt Support**: 256-bit+ integer arithmetic handled directly in the Heap, bypassing floating-point precision errors.
* **Tensor Acceleration**: Native support for N-Dimensional arrays allows operations like FFTs (Fast Fourier Transforms) and MSMs (Multi-Scalar Multiplications) to run at native Rust speed.
* **Safe Memory Management**: Implements "Upvalue" closing and strict borrowing rules to prevent common memory vulnerabilities in secure environments.

---

## 🏗 Technical Architecture

### The Value Representation (NaN Boxing)
Achronyme uses a 64-bit tagging scheme to represent all runtime values:

| Bits (64) | Representation |
| :--- | :--- |
| `0..50` | **Payload** (SMI Integer, Heap Pointer, or Float Mantissa) |
| `51..63` | **Tag & QNAN Marker** (Identifies Type: `BigInt`, `Tensor`, `String`, etc.) |

This allows cheap copy-semantics for primitives and unified handling of complex objects.

### The Heap & GC
Memory is managed via Typed Arenas (Slabs) to ensure memory locality for similar objects. The Garbage Collector performs liveness analysis on the Stack, Globals, and Call Frames, automatically freeing unreachable cryptographic objects.

---

## 🚀 Getting Started

### Prerequisites
* Rust (latest stable)
* Cargo

### Building
```bash
cargo build --release