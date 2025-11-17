---
title: "Digital Signal Processing"
description: "FFT, convolution, and signal processing in Achronyme"
section: "specialized-modules"
order: 1
---


Achronyme provides comprehensive digital signal processing capabilities including Fast Fourier Transform (FFT), window functions, and convolution for analyzing and processing signals.

## Overview

| Category | Functions |
|----------|-----------|
| **FFT Operations** | fft, ifft, fft_mag, fft_phase |
| **Window Functions** | hanning, hamming, blackman, rectangular |
| **Filtering** | conv, conv_fft |
| **Signal Generation** | linspace |

All DSP functions use the high-performance **rustfft** library for FFT computations.

## FFT Operations

### Fast Fourier Transform - fft

Transform signal from time domain to frequency domain:

```javascript
// Simple signal
let signal = [1, 2, 3, 4, 5, 4, 3, 2]
let spectrum = fft(signal)  // Returns ComplexTensor

// Sine wave analysis
let t = linspace(0, 1, 1024)
let freq = 50
let signal = map(x => sin(2 * pi * freq * x), t)
let spectrum = fft(signal)
```

**Signature**: `fft(signal) -> ComplexTensor`

**Algorithm**: Cooley-Tukey FFT with mixed-radix support

**Input**: Vector or Tensor (real-valued signal)

**Output**: ComplexTensor (frequency spectrum)

**Performance**: Optimized for power-of-2 lengths, works for any size

### Inverse FFT - ifft

Reconstruct time-domain signal from frequency spectrum:

```javascript
// FFT roundtrip
let signal = [0, 0.707, 1, 0.707, 0, -0.707, -1, -0.707]
let spectrum = fft(signal)
let recovered = ifft(spectrum)  // Should match original

// Verify recovery
// recovered ≈ signal (within numerical precision)
```

**Signature**: `ifft(spectrum) -> Tensor`

**Algorithm**: Inverse FFT with 1/N scaling

**Input**: ComplexTensor (frequency spectrum)

**Output**: Tensor (real-valued signal)

**Note**: Automatically scales by 1/N

### FFT Magnitude - fft_mag

Compute magnitude spectrum:

```javascript
let signal = [1, 2, 3, 4, 5]
let magnitudes = fft_mag(signal)
// Returns magnitudes of frequency components

// With windowing
let t = linspace(0, 1, 1024)
let signal = map(x => sin(2*pi*50*x), t)
let windowed = signal * hanning(1024)
let spectrum = fft_mag(windowed)
```

**Signature**: `fft_mag(signal) -> Tensor`

**Formula**: `|z| = √(re² + im²)` for each frequency bin

**Input**: Real signal or ComplexTensor

**Output**: Tensor of magnitudes

**Use cases**:
- Spectral analysis
- Frequency identification
- Power spectrum estimation

### FFT Phase - fft_phase

Compute phase spectrum in radians:

```javascript
let signal = [1, 2, 3, 4, 5]
let phases = fft_phase(signal)
// Returns phases in radians [-π, π]

// Phase information useful for:
// - Signal reconstruction
// - Phase response analysis
// - Time delay estimation
```

**Signature**: `fft_phase(signal) -> Tensor`

**Formula**: `φ = atan2(im, re)` for each frequency bin

**Input**: Real signal or ComplexTensor

**Output**: Tensor of phases in radians

**Range**: [-π, π]

## Window Functions

Window functions reduce spectral leakage by smoothly tapering signal edges.

### Hanning Window

Most commonly used window function:

```javascript
let n = 1024
let window = hanning(n)

// Apply to signal
let signal = map(x => sin(2*pi*50*x), t)
let windowed = signal * window
let spectrum = fft_mag(windowed)
```

**Signature**: `hanning(n) -> Tensor`

**Formula**: `w(n) = 0.5 × (1 - cos(2πn/(N-1)))`

**Properties**:
- Smooth edges (starts/ends at 0)
- Good sidelobe suppression (-32 dB)
- Balanced performance
- Most popular choice

**Use when**: General-purpose spectral analysis

### Hamming Window

Better sidelobe suppression than Hanning:

```javascript
let window = hamming(256)
let windowed_signal = signal * window
```

**Signature**: `hamming(n) -> Tensor`

**Formula**: `w(n) = 0.54 - 0.46 × cos(2πn/(N-1))`

**Properties**:
- Non-zero endpoints (0.08)
- Better sidelobe suppression (-43 dB)
- Slightly wider main lobe

**Use when**: Need better rejection of spectral leakage

### Blackman Window

Best sidelobe suppression:

```javascript
let window = blackman(512)
let windowed = signal * window
```

**Signature**: `blackman(n) -> Tensor`

**Formula**: `w(n) = 0.42 - 0.5×cos(2πn/(N-1)) + 0.08×cos(4πn/(N-1))`

**Properties**:
- Excellent sidelobe suppression (-58 dB)
- Wider main lobe
- Best dynamic range

**Use when**: High dynamic range required, weak signals near strong ones

### Rectangular Window

No windowing (all ones):

```javascript
let window = rectangular(64)
// Equivalent to no windowing at all
```

**Signature**: `rectangular(n) -> Tensor`

**Formula**: `w(n) = 1.0` for all n

**Properties**:
- Narrowest main lobe
- Poor sidelobe suppression (-13 dB)
- Maximum frequency resolution

**Use when**: Maximum frequency resolution needed, spectral leakage not a concern

### Window Comparison

```javascript
let n = 64

// Generate all windows
let rect = rectangular(n)
let hann = hanning(n)
let hamm = hamming(n)
let black = blackman(n)

// Compare properties:
// - Rectangular: best resolution, worst leakage
// - Hanning: balanced
// - Hamming: better leakage rejection
// - Blackman: best leakage rejection, worst resolution
```

## Convolution

### Direct Convolution - conv

Standard convolution using direct computation:

```javascript
// Moving average filter
let signal = [1, 2, 3, 4, 5]
let kernel = [0.5, 0.5]  // Average of 2 samples
let smoothed = conv(signal, kernel)
// [0.5, 1.5, 2.5, 3.5, 4.5, 2.5]

// Gaussian-like smoothing
let kernel = [0.25, 0.5, 0.25]
let smoothed = conv(signal, kernel)
```

**Signature**: `conv(signal, kernel) -> Tensor`

**Algorithm**: Direct convolution
```
(f * g)[n] = Σ f[m] × g[n - m]
```

**Output length**: `signal.length + kernel.length - 1`

**Complexity**: O(N × M)

**Use when**: Small kernels (< 100 elements)

### FFT-based Convolution - conv_fft

Fast convolution using FFT:

```javascript
// Large signal/kernel
let signal = [...]  // 1000 elements
let kernel = [...]  // 200 elements
let result = conv_fft(signal, kernel)
// Much faster than conv() for large inputs
```

**Signature**: `conv_fft(signal, kernel) -> Tensor`

**Algorithm**: Convolution theorem
```
conv(f, g) = IFFT(FFT(f) × FFT(g))
```

**Complexity**: O(N log N)

**Use when**: Large signals or kernels (> 100 elements)

**Note**: Pads to next power-of-2 for efficiency

## Signal Generation

### Linear Space - linspace

Generate evenly-spaced values:

```javascript
// Time vector
let t = linspace(0, 1, 1024)  // 1024 points from 0 to 1

// Frequency axis
let freqs = linspace(0, 500, 256)  // 0 to 500 Hz

// Generate sine wave
let signal = map(x => sin(2*pi*10*x), linspace(0, 1, 100))
```

**Signature**: `linspace(start, end, n) -> Tensor`

**Formula**: `values[i] = start + step × i` where `step = (end - start) / (n - 1)`

**Requirements**: n ≥ 2

**Endpoints**: Includes both start and end values

## Practical Examples

### Basic Spectral Analysis

```javascript
// Setup
let sample_rate = 1000  // Hz
let duration = 1        // second
let n = sample_rate * duration

// Generate signal: 50 Hz sine wave
let t = linspace(0, duration, n)
let freq = 50
let signal = map(x => sin(2*pi*freq*x), t)

// Apply window to reduce leakage
let windowed = signal * hanning(n)

// Compute spectrum
let magnitudes = fft_mag(windowed)

// Result shows peak at 50 Hz bin
```

### Multiple Frequency Components

```javascript
// Mixed signal: 50 Hz + 120 Hz
let t = linspace(0, 1, 1000)
let signal = map(
    x => sin(2*pi*50*x) + 0.5*sin(2*pi*120*x),
    t
)

// Window and analyze
let spectrum = fft_mag(signal * hanning(1000))
// Shows peaks at bins corresponding to 50 and 120 Hz
```

### Noise Reduction with Filtering

```javascript
// Noisy signal
let signal = [1, 5, 2, 8, 3, 6, 4, 7]

// Low-pass filter (moving average)
let kernel = [0.2, 0.2, 0.2, 0.2, 0.2]  // 5-point average
let smoothed = conv(signal, kernel)
```

### Spectral Components

```javascript
// Analyze FFT output
let signal = [0, 0.707, 1, 0.707, 0, -0.707, -1, -0.707]
let spectrum = fft(signal)

// Extract information
let real_parts = real(spectrum)
let imag_parts = imag(spectrum)
let magnitudes = abs(spectrum)  // or use fft_mag(signal)
let phases = map(z => arg(z), spectrum)  // or use fft_phase(signal)

// Conjugate (useful for filtering)
let spectrum_conj = conj(spectrum)
```

### Signal Reconstruction

```javascript
// Forward transform
let signal = [1, 2, 3, 4, 5, 4, 3, 2, 1]
let spectrum = fft(signal)

// Manipulate in frequency domain
// (e.g., zero out high frequencies)

// Inverse transform
let recovered = ifft(spectrum)
// recovered ≈ signal
```

### Window Comparison

```javascript
let signal = map(x => sin(2*pi*50*x), linspace(0, 1, 512))

// Compare different windows
let no_window = fft_mag(signal)
let with_hanning = fft_mag(signal * hanning(512))
let with_hamming = fft_mag(signal * hamming(512))
let with_blackman = fft_mag(signal * blackman(512))

// Blackman has best sidelobe suppression
// Rectangular has best frequency resolution
```

### Frequency Estimation

```javascript
// Find dominant frequency
let signal = [...]  // Some signal
let magnitudes = fft_mag(signal)

// Find peak
let max_magnitude = max(magnitudes)
let peak_bin = 0  // Would need argmax function

// Convert bin to frequency
let sample_rate = 1000
let n = length(signal)
let freq_resolution = sample_rate / n
let dominant_freq = peak_bin * freq_resolution
```

## Complete DSP Pipeline

```javascript
// Full signal processing pipeline

// 1. Parameters
let sample_rate = 1024    // Samples per second
let duration = 1          // Seconds
let n = sample_rate * duration

// 2. Generate time vector
let t = linspace(0, duration, n)

// 3. Create signal (50 Hz sine)
let freq = 50
let signal = map(x => sin(2*pi*freq*x), t)

// 4. Apply window
let window = hanning(n)
let windowed = signal * window

// 5. Compute FFT
let spectrum = fft(windowed)

// 6. Extract magnitude and phase
let magnitudes = fft_mag(windowed)
let phases = fft_phase(windowed)

// 7. Analysis complete
// magnitudes shows frequency content
// phases shows phase relationships
```

## Advanced Techniques

### Zero-Padding for Interpolation

```javascript
// Zero-pad for frequency interpolation
let signal = [1, 2, 3, 4]
let padded = [...signal, 0, 0, 0, 0]  // Double the length
let spectrum = fft(padded)
// More frequency bins (interpolated)
```

### Spectral Filtering

```javascript
// Filter in frequency domain
let signal = [...]
let spectrum = fft(signal)

// Zero out high frequencies (low-pass)
// (Would need array manipulation)

let filtered = ifft(spectrum)
```

### Overlap-Add Convolution

```javascript
// For very long signals, process in chunks
// (Conceptual - would need implementation)
let process_chunk = (chunk, kernel) =>
    conv(chunk, kernel)

// Process signal in blocks
```

## Performance Considerations

### FFT Size

```javascript
// Power-of-2 sizes are fastest
fft(signal_512)    // Very fast
fft(signal_1024)   // Very fast
fft(signal_1000)   // Slower (not power-of-2)

// Pad to power-of-2 for best performance
let n = 1000
let padded_n = 1024  // Next power-of-2
// Pad signal to 1024 samples
```

### Convolution Method Selection

```javascript
// Small kernel: use direct convolution
let kernel_small = [0.25, 0.5, 0.25]
conv(signal, kernel_small)  // Fast

// Large kernel: use FFT convolution
let kernel_large = [...Array(200)]  // 200 elements
conv_fft(signal, kernel_large)  // Much faster
```

### Window Application

```javascript
// Pre-compute window for reuse
let window = hanning(1024)

// Apply to multiple signals
let spec1 = fft_mag(signal1 * window)
let spec2 = fft_mag(signal2 * window)
let spec3 = fft_mag(signal3 * window)
```

## Common Patterns

### Frequency Bin to Hz

```javascript
let sample_rate = 1000  // Hz
let n = 1024
let freq_resolution = sample_rate / n  // Hz per bin

// Bin k corresponds to:
let freq_at_bin = k => k * freq_resolution
```

### Nyquist Frequency

```javascript
// Maximum representable frequency
let sample_rate = 1000  // Hz
let nyquist = sample_rate / 2  // 500 Hz

// Frequencies above Nyquist alias
```

### Spectral Power

```javascript
// Power spectrum (magnitude squared)
let signal = [...]
let magnitudes = fft_mag(signal)
let power = map(x => x^2, magnitudes)
```

## Error Handling

```javascript
// linspace requires n >= 2
linspace(0, 1, 1)  // Error

// FFT works on any length, but power-of-2 is optimal
fft([1, 2, 3])  // Works, but consider padding

// Window length should match signal
let signal = [...Array(1024)]
let window = hanning(1024)  // ✅ Match lengths
let bad_window = hanning(512)  // ⚠️ Mismatch
```

## Summary

**FFT operations**: fft, ifft, fft_mag, fft_phase

**Window functions**: hanning, hamming, blackman, rectangular

**Filtering**: conv, conv_fft

**Signal generation**: linspace

**Key features**:
- High-performance rustfft backend
- ComplexTensor integration
- Power-of-2 optimization
- Full spectral analysis capabilities

**Best practices**:
- Use windowing to reduce spectral leakage
- Choose appropriate window for application
- Use FFT convolution for large kernels
- Pad to power-of-2 for best performance

**Common applications**:
- Frequency analysis
- Filter design and application
- Signal decomposition
- Spectral estimation
- Noise reduction

---

**Next**: [Graph Theory](18-graph-theory.md)

