---
title: "Layout & Styling"
description: "Organizing and styling your UI with containers and Tailwind-like syntax"
section: "ui"
order: 3
---

# Layout & Styling

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

## Styling Syntax

Achronyme uses a string-based styling syntax inspired by Tailwind CSS.

### Dimensions
- `w-full`, `h-full`: Expand to fill parent
- `w-[100px]`, `h-[50px]`: Fixed dimensions

### Spacing
- `p-4`: Padding (all sides)
- `gap-4`: Gap between items
- `m-2`: Margin (all sides)
- `my-2`: Margin vertical

### Colors
- `bg-red-500`: Background color
- `text-white`: Text color
- `bg-[#1a1a1a]`: Hex colors

### Borders & Corners
- `rounded-xl`: Border radius
- `border`: Default border
- `border-gray-500`: Border color

### Font
- `text-xl`: Font size
- `font-bold`: Bold weight
- `font-mono`: Monospace font

## Advanced Layouts

### Tabs

Organize content into tabs.

```javascript
let tab_index = signal(0)

ui_tabs(["General", "Settings", "Logs"], tab_index, (idx) => do {
    if (idx == 0) {
        ui_label("General Content")
    } else if (idx == 1) {
        ui_label("Settings Content")
    }
})
```

### Collapsing Headers

Expandable sections.

```javascript
ui_collapsing("Advanced Options", "", () => do {
    ui_checkbox(setting1, "Enable X")
    ui_checkbox(setting2, "Enable Y")
})
```

### Scroll Areas

Scrollable content for long lists.

```javascript
ui_scroll_area(() => do {
    for (i in 1..100) {
        ui_label("Item " + str(i))
    }
}, "h-[200px]")
```
