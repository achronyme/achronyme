---
title: "UI Components"
description: "Reference for all native GUI widgets and controls"
section: "ui"
order: 2
---

# UI Components

Achronyme provides a rich set of native widgets for building interfaces.

## Basic Controls

### Labels

Display text with optional styling.

```javascript
ui_label("Basic text")
ui_label("Styled text", "text-red-500 font-bold text-2xl")
```

### Buttons

Trigger actions. Returns `true` if clicked in the current frame.

```javascript
if (ui_button("Save", "bg-blue-500 text-white")) {
    save_data()
}
```

### Text Input

Editable text field bound to a signal.

```javascript
let name = signal("Alice")

ui_text_input(name, "w-full")
// name.value updates automatically as user types
```

### Sliders

Numeric input within a range.

```javascript
let val = signal(50)

// ui_slider(signal, min, max, style)
ui_slider(val, 0, 100, "w-full")
```

## Selection Controls

### Checkbox

Boolean toggle.

```javascript
let active = signal(true)

ui_checkbox(active, "Enable Features", "")
```

### Radio Buttons

Mutually exclusive options.

```javascript
let mode = signal("fast")

ui_box("flex-row gap-4", () => do {
    ui_radio(mode, "fast", "Fast Mode")
    ui_radio(mode, "quality", "Quality Mode")
})
```

### Combobox

Dropdown selection.

```javascript
let selected = signal("Option A")
let options = ["Option A", "Option B", "Option C"]

ui_combobox(selected, options, "w-[200px]")
```

## Feedback & Display

### Progress Bar

Display progress from 0.0 to 1.0.

```javascript
ui_progress_bar(0.75, "w-full")
```

### Separator

Horizontal visual divider.

```javascript
ui_separator("my-2") // 'my-2' adds margin vertical
```

## Scientific Plotting

High-performance plotting for vectors and tensors.

```javascript
ui_plot("My Plot", {
    height: 300,
    x_label: "Time (s)",
    y_label: "Amplitude",
    series: [
        {
            name: "Signal A",
            type: "line",
            data: [[0, 1], [1, 2], [2, 1]], // or Tensor
            color: "#00ff00"
        },
        {
            name: "Points",
            type: "scatter",
            data: my_tensor,
            radius: 3
        }
    ]
})
```

**Optimized for Tensors**: Passing a `Tensor` to `data` uses a zero-copy (relative) path for rendering millions of points efficiently.
