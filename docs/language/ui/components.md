---
title: "UI Components"
description: "Reference for all native GUI widgets and controls"
section: "ui"
order: 2
---

# UI Components

Achronyme provides a rich set of native widgets for building interfaces.

## Quick Reference

| Function | Description |
|----------|-------------|
| `ui_label(text, style?)` | Display text |
| `ui_button(text, style?)` | Clickable button |
| `ui_text_input(signal, style?)` | Text field |
| `ui_slider(signal, min, max, style?)` | Numeric slider |
| `ui_checkbox(signal, label, style?)` | Boolean toggle |
| `ui_radio(signal, value, label)` | Radio option |
| `ui_combobox(signal, options, style?)` | Dropdown |
| `ui_progress_bar(value, style?)` | Progress indicator |
| `ui_separator(style?)` | Visual divider |
| `ui_box(style, children_fn)` | Container/layout |
| `ui_tabs(titles, signal, style?)` | Tab bar |
| `ui_collapsing(title, style?, children_fn)` | Expandable section |
| `ui_scroll_area(style?, children_fn)` | Scrollable region |
| `ui_plot(title, options)` | Scientific plotting |
| `ui_quit()` | Close application |

## Basic Controls

### Labels

Display text with optional styling.

```javascript
ui_label("Basic text")
ui_label("Styled text", "text-red-500 font-bold text-2xl")
```

**Signature:** `ui_label(text: String, style?: String)`

### Buttons

Trigger actions. Returns `true` if clicked in the current frame.

```javascript
if (ui_button("Save", "bg-blue-500 text-white")) {
    save_data()
}
```

**Signature:** `ui_button(text: String, style?: String) -> Bool`

### Text Input

Editable text field bound to a signal.

```javascript
let name = signal("Alice")

ui_text_input(name, "w-full")
// name.value updates automatically as user types
```

**Signature:** `ui_text_input(signal: Signal<String>, style?: String)`

### Sliders

Numeric input within a range.

```javascript
let val = signal(50)

// ui_slider(signal, min, max, style)
ui_slider(val, 0, 100, "w-full")
```

**Signature:** `ui_slider(signal: Signal<Number>, min: Number, max: Number, style?: String)`

## Selection Controls

### Checkbox

Boolean toggle.

```javascript
let active = signal(true)

ui_checkbox(active, "Enable Features", "")
```

**Signature:** `ui_checkbox(signal: Signal<Bool>, label: String, style?: String)`

### Radio Buttons

Mutually exclusive options. Returns `true` if clicked.

```javascript
let mode = signal("fast")

ui_box("flex-row gap-4", () => do {
    if (ui_radio(mode.value == "fast", "Fast Mode")) {
        mode.set("fast")
    }
    if (ui_radio(mode.value == "quality", "Quality Mode")) {
        mode.set("quality")
    }
})
```

**Signature:** `ui_radio(selected: Bool, label: String, style?: String) -> Bool`

### Combobox

Dropdown selection.

```javascript
let selected = signal("Option A")
let options = ["Option A", "Option B", "Option C"]

ui_combobox(selected, options, "w-[200px]")
```

**Signature:** `ui_combobox(signal: Signal<String>, options: Vector<String>, style?: String)`

## Feedback & Display

### Progress Bar

Display progress from 0.0 to 1.0.

```javascript
ui_progress_bar(0.75, "w-full")
```

**Signature:** `ui_progress_bar(value: Number, style?: String)`

### Separator

Horizontal visual divider.

```javascript
ui_separator("my-2") // 'my-2' adds margin vertical
```

**Signature:** `ui_separator(style?: String)`

## Layout Components

### Tabs

Create a horizontal tab bar for navigation.

```javascript
let tab_index = signal(0)

ui_tabs(["General", "Settings", "Logs"], tab_index, "")

if (tab_index.value == 0) {
    ui_label("General content here")
} else if (tab_index.value == 1) {
    ui_label("Settings content here")
} else {
    ui_label("Logs content here")
}
```

**Signature:** `ui_tabs(titles: Vector<String>, signal: Signal<Number>, style?: String)`

### Collapsing Header

Expandable/collapsible section with a header.

```javascript
ui_collapsing("Advanced Options", "", () => do {
    ui_checkbox(option1, "Enable X", "")
    ui_checkbox(option2, "Enable Y", "")
    ui_slider(threshold, 0, 100, "w-full")
})
```

**Signature:** `ui_collapsing(title: String, style?: String, children: Function)`

### Scroll Area

Scrollable container for long content.

```javascript
ui_scroll_area("h-[200px]", () => do {
    for (i in range(1, 100)) {
        ui_label("Item " + str(i))
    }
})
```

**Signature:** `ui_scroll_area(style?: String, children: Function)`

### Box Container

The primary layout primitive. See [Layout & Styling](layout-styling.md) for details.

```javascript
ui_box("flex-row gap-4 p-4 bg-gray-800 rounded-lg", () => do {
    ui_label("Left")
    ui_label("Right")
})
```

**Signature:** `ui_box(style: String, children: Function)`

## Application Control

### Quit

Close the application window programmatically.

```javascript
if (ui_button("Exit")) {
    ui_quit()
}
```

**Signature:** `ui_quit()`

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

### Plot Options

| Option | Type | Description |
|--------|------|-------------|
| `height` | Number | Plot height in pixels (default: 200) |
| `x_label` | String | X-axis label |
| `y_label` | String | Y-axis label |
| `series` | Vector | Array of series objects |

### Series Options

| Option | Type | Description |
|--------|------|-------------|
| `name` | String | Legend label |
| `type` | String | `"line"` or `"scatter"` |
| `data` | Vector/Tensor | Data points |
| `color` | String | Hex color (e.g., `"#ff0000"`) |
| `radius` | Number | Point radius (scatter only) |

### Data Formats

```javascript
// Format 1: Vector of [x, y] pairs
data: [[0, 1], [1, 4], [2, 9]]

// Format 2: Vector of y values (x auto-generated as indices)
data: [1, 4, 9, 16, 25]

// Format 3: 2D Tensor with shape [N, 2]
data: tensor([[0, 1], [1, 4], [2, 9]])

// Format 4: 1D Tensor (y values, x = indices)
data: tensor([1, 4, 9, 16, 25])
```

**Optimized for Tensors**: Passing a `Tensor` to `data` uses a fast path for rendering millions of points efficiently.
