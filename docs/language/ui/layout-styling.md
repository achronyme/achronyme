---
title: "Layout & Styling"
description: "Organizing and styling your UI with containers and Tailwind-like syntax"
section: "ui"
order: 3
---

# Layout & Styling

Achronyme uses a Tailwind CSS-inspired string syntax for styling UI components. This provides a familiar, declarative approach to building interfaces.

## The Box System

The core layout primitive is `ui_box`. It acts like a `div` in HTML or a `Flexbox` container.

```javascript
ui_box(style_string, children_lambda)
```

### Direction

Control flow direction with `flex-row` or `flex-col` (default).

```javascript
// Vertical stack (default)
ui_box("flex-col", () => do {
    ui_label("Top")
    ui_label("Bottom")
})

// Horizontal row
ui_box("flex-row", () => do {
    ui_button("Left")
    ui_button("Right")
})
```

## Sizing

### Fixed Dimensions

```javascript
ui_box("w-[300px] h-[200px]", () => { ... })  // Exact size
```

### Full Width/Height

```javascript
ui_box("w-full h-full", () => { ... })  // Expand to parent
```

## Spacing

### Gap (Between Items)

| Utility | Pixels |
|---------|--------|
| `gap-1` | 4px |
| `gap-2` | 8px |
| `gap-3` | 12px |
| `gap-4` | 16px |
| `gap-6` | 24px |
| `gap-8` | 32px |
| `gap-[Npx]` | N pixels |

```javascript
ui_box("flex-col gap-4", () => do {
    ui_button("Button 1")
    ui_button("Button 2")  // 16px gap between
})
```

### Padding (Inner Spacing)

| Utility | Description |
|---------|-------------|
| `p-{n}` | All sides |
| `px-{n}` | Left + Right |
| `py-{n}` | Top + Bottom |
| `pt-{n}` | Top only |
| `pb-{n}` | Bottom only |
| `pl-{n}` | Left only |
| `pr-{n}` | Right only |

### Margin (Outer Spacing)

| Utility | Description |
|---------|-------------|
| `m-{n}` | All sides |
| `mx-{n}` | Left + Right |
| `my-{n}` | Top + Bottom |
| `mt-{n}` | Top only |
| `mb-{n}` | Bottom only |
| `ml-{n}` | Left only |
| `mr-{n}` | Right only |

**Scale:** 1 unit = 4px (e.g., `p-4` = 16px)

## Alignment

### Cross-Axis Alignment (`items-*`)

Controls how children are aligned perpendicular to the main axis.

| Utility | Effect |
|---------|--------|
| `items-start` | Align to start |
| `items-center` | Center align |
| `items-end` | Align to end |

```javascript
// Center items vertically in a row
ui_box("flex-row items-center w-[300px]", () => do {
    ui_label("Left")
    ui_button("Right")
})
```

### Main-Axis Alignment (`justify-*`)

Controls how children are distributed along the main axis.

| Utility | Effect |
|---------|--------|
| `justify-start` | Pack to start |
| `justify-center` | Center pack |
| `justify-end` | Pack to end |

## Colors

### Background Colors

```javascript
ui_box("bg-blue-500", () => { ... })     // Preset color
ui_box("bg-[#1a1a1a]", () => { ... })    // Hex color
ui_box("bg-[#ff550080]", () => { ... })  // Hex with alpha
```

**Available Color Palettes:**

| Color | Shades |
|-------|--------|
| `gray` | 100, 200, 300, 400, 500, 600, 700, 800, 900 |
| `red` | 400, 500, 600 |
| `blue` | 400, 500, 600 |
| `green` | 400, 500, 600 |
| `yellow` | 400, 500, 600 |
| `purple` | 400, 500, 600 |
| `pink` | 400, 500, 600 |
| `orange` | 400, 500, 600 |
| `cyan` | 400, 500, 600 |
| `teal` | 400, 500, 600 |
| `indigo` | 400, 500, 600 |

**Special:** `bg-white`, `bg-black`, `bg-transparent`

### Text Colors

Same palette using `text-` prefix:

```javascript
ui_label("Error!", "text-red-500")
ui_label("Success", "text-green-500")
ui_label("Custom", "text-[#ff9900]")
```

### Opacity

```javascript
ui_box("bg-red-500 bg-opacity-50", () => { ... })  // 50% transparent
ui_label("Faded", "text-white text-opacity-75")    // 75% opacity text
```

Values: `0` to `100` in increments (e.g., `bg-opacity-25`, `bg-opacity-50`)

## Typography

### Font Sizes

| Utility | Size |
|---------|------|
| `text-xs` | 10px |
| `text-sm` | 12px |
| `text-base` | 14px (default) |
| `text-lg` | 18px |
| `text-xl` | 20px |
| `text-2xl` | 24px |
| `text-3xl` | 30px |
| `text-4xl` | 36px |
| `text-5xl` | 48px |
| `text-6xl` | 60px |

### Font Styles

| Utility | Effect |
|---------|--------|
| `font-bold` | Bold weight |
| `font-mono` | Monospace font |
| `italic` | Italic style |

### Text Alignment

| Utility | Effect |
|---------|--------|
| `text-left` | Left align |
| `text-center` | Center align |
| `text-right` | Right align |

## Borders & Corners

### Border Width

```javascript
ui_box("border", () => { ... })      // 1px border
ui_box("border-2", () => { ... })    // 2px border
```

### Border Color

```javascript
ui_box("border border-red-500", () => { ... })
ui_box("border border-[#ffffff]", () => { ... })
```

### Border Radius (Rounding)

| Utility | Radius |
|---------|--------|
| `rounded-none` | 0px |
| `rounded-sm` | 2px |
| `rounded` | 4px |
| `rounded-md` | 6px |
| `rounded-lg` | 8px |
| `rounded-xl` | 12px |
| `rounded-2xl` | 16px |
| `rounded-3xl` | 24px |
| `rounded-full` | 9999px (pill) |

## Shadows

| Utility | Effect |
|---------|--------|
| `shadow-none` | No shadow |
| `shadow-sm` | Subtle shadow |
| `shadow` | Small shadow |
| `shadow-md` | Medium shadow |
| `shadow-lg` | Large shadow |
| `shadow-xl` | Extra large |
| `shadow-2xl` | Massive shadow |

```javascript
ui_box("bg-white shadow-lg rounded-xl p-4", () => do {
    ui_label("Card Content")
})
```

## Advanced Layouts

### Tabs

Organize content into tabs.

```javascript
let tab_index = signal(0)

ui_tabs(["General", "Settings", "Logs"], tab_index, "")

if (tab_index.value == 0) {
    ui_label("General Content")
} else if (tab_index.value == 1) {
    ui_label("Settings Content")
}
```

### Collapsing Headers

Expandable sections.

```javascript
ui_collapsing("Advanced Options", "", () => do {
    ui_checkbox(setting1, "Enable X", "")
    ui_checkbox(setting2, "Enable Y", "")
})
```

### Scroll Areas

Scrollable content for long lists.

```javascript
ui_scroll_area("h-[200px]", () => do {
    for (i in range(1, 100)) {
        ui_label("Item " + str(i))
    }
})
```

## Known Limitations

### Centering Shrink-Wrapped Containers

Due to egui's immediate-mode architecture, `items-center` on a parent does not automatically center child containers that don't have explicit dimensions.

**Problem:**
```javascript
// Child boxes are NOT centered horizontally
ui_box("flex-col items-center", () => do {
    ui_box("bg-gray-500 p-4", () => do {  // This stays left-aligned
        ui_label("Content")
    })
})
```

**Solution:** Add explicit width to child containers:
```javascript
ui_box("flex-col items-center", () => do {
    ui_box("bg-gray-500 p-4 w-[300px]", () => do {  // Now centered!
        ui_label("Content")
    })
})
```

This is a fundamental limitation of immediate-mode GUIs where content size is not known before rendering.

## Complete Example

```javascript
let app = () => do {
    ui_box("bg-[#1a1a1a] w-full h-full p-6 flex-col items-center gap-4", () => do {

        ui_label("Dashboard", "text-white text-3xl font-bold")

        // Card with shadow
        ui_box("bg-gray-800 w-[400px] p-6 rounded-xl shadow-lg flex-col gap-4", () => do {
            ui_label("Statistics", "text-white text-xl")

            ui_box("flex-row gap-4", () => do {
                ui_box("bg-blue-500 p-4 rounded-lg flex-col items-center", () => do {
                    ui_label("1,234", "text-white text-2xl font-bold")
                    ui_label("Users", "text-blue-200 text-sm")
                })

                ui_box("bg-green-500 p-4 rounded-lg flex-col items-center", () => do {
                    ui_label("567", "text-white text-2xl font-bold")
                    ui_label("Sales", "text-green-200 text-sm")
                })
            })
        })

        ui_label("Footer", "text-gray-500 text-sm")
    })
}

gui_run(app, { title: "Dashboard", width: 600, height: 400 })
```
