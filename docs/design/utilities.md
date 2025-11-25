# UI Style Utilities Design Specification

This document outlines the roadmap for enhancing the style parsing engine in `achronyme-gui`. The goal is to support a comprehensive subset of utility classes (inspired by Tailwind CSS) to enable rich, expressive, and responsive user interfaces directly from Achronyme scripts.

---

## Architecture: Layout Strategy Layer

### The Problem: CSS vs Egui Impedance Mismatch

| Aspect | CSS/Tailwind | Egui |
|--------|--------------|------|
| **Model** | Constraint-based (global) | Immediate mode (local) |
| **Height Calculation** | Post-layout: measures all children first | Pre-layout: asks "how much space is available?" |
| **`items-center`** | Centers within calculated line height | Centers within ALL available space |

**Example of the Problem:**
```
flex-row items-center  +  unbounded parent height
                           ↓
          Child centers in ENTIRE screen height
          (not just within the row's "line")
```

### Solution: 3-Layer Architecture

```
┌─────────────────────────────────────┐
│  1. StyleConfig (Parser)            │  ← Parses "bg-red-500 items-center"
│     - Only parses tokens            │
│     - No decision-making            │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  2. LayoutStrategy (layout.rs)      │  ← Makes intelligent decisions
│     - Receives StyleConfig + context│
│     - Produces EguiLayoutPlan       │
└─────────────────────────────────────┘
                  ↓
┌─────────────────────────────────────┐
│  3. Components (Renderer)           │  ← Only executes the plan
│     - Applies EguiLayoutPlan        │
│     - No decision logic             │
└─────────────────────────────────────┘
```

### Core Types

#### `LayoutContext`
Captures information about the parent container:
```rust
pub struct LayoutContext {
    pub available_width: Option<f32>,   // None = unbounded
    pub available_height: Option<f32>,  // None = unbounded
    pub is_root: bool,
}
```

#### `SizingStrategy`
Three strategies for handling container sizing:

| Strategy | When Used | Behavior |
|----------|-----------|----------|
| `UseAvailable` | Default case | Standard egui layout |
| `Fixed` | Explicit `w-[X]` or `h-[X]` | Apply dimensions, then layout |
| `ShrinkWrap` | Cross-align on unbounded axis | Use `ui.horizontal/vertical()` to size-to-content |

#### `EguiLayoutPlan`
The concrete instructions for egui:
```rust
pub struct EguiLayoutPlan {
    pub layout: Layout,              // Direction + alignment
    pub sizing_strategy: SizingStrategy,
    pub item_spacing: Option<Vec2>,  // Gap
}
```

### Strategy Resolution Rules

| User Intent | Context | Resolved Strategy |
|-------------|---------|-------------------|
| `flex-row items-center` | Height unbounded | `ShrinkWrap` (avoid explosion) |
| `flex-row items-center h-[50px]` | Height explicit | `Fixed` + direct `cross_align` |
| `flex-col items-center` | Width bounded | `UseAvailable` + direct `cross_align` |
| `flex-col items-center` | Width unbounded | `ShrinkWrap` |

---

## 1. Layout & Spacing (High Priority)

These utilities control the Flexbox-like behavior of `ui_box` containers.

### Direction
| Utility | Description | Strategy Notes |
|---------|-------------|----------------|
| `flex-row` | Horizontal layout (left-to-right) | Default cross-axis = vertical |
| `flex-col` | Vertical layout (top-to-bottom) | Default cross-axis = horizontal |

### Gap (Item Spacing)
| Utility | Pixels | Implementation |
|---------|--------|----------------|
| `gap-1` | 4px | `ui.spacing_mut().item_spacing` |
| `gap-2` | 8px | |
| `gap-4` | 16px | |
| `gap-[Npx]` | N pixels | Arbitrary value syntax |

**Scale:** 1 unit = 4px (standard Tailwind scale)

### Alignment (Cross Axis) - `items-*`
| Utility | egui Align | Strategy |
|---------|------------|----------|
| `items-start` | `Align::Min` | Direct if bounded, ShrinkWrap if not |
| `items-center` | `Align::Center` | **Critical**: ShrinkWrap if cross-axis unbounded |
| `items-end` | `Align::Max` | Direct if bounded, ShrinkWrap if not |
| `items-stretch` | N/A | Future: requires custom sizing logic |

**Strategy Decision Tree for `items-center`:**
```
Has explicit cross-dimension (h-[X] for row, w-[X] for col)?
  ├─ YES → Apply cross_align directly (Fixed strategy)
  └─ NO → Is cross-axis bounded by parent?
           ├─ YES → Apply cross_align directly (UseAvailable)
           └─ NO → Use ShrinkWrap strategy (avoid explosion)
```

### Justification (Main Axis) - `justify-*`
| Utility | egui Align | Notes |
|---------|------------|-------|
| `justify-start` | `Align::Min` | Always safe to apply |
| `justify-center` | `Align::Center` | Always safe to apply |
| `justify-end` | `Align::Max` | Always safe to apply |
| `justify-between` | Custom | Future: requires manual spacer calculation |
| `justify-around` | Custom | Future: requires manual spacer calculation |

**Note:** `justify-between` and `justify-around` require measuring content first, then calculating spacer sizes. Not yet implemented.

### Sizing
| Utility | Value | Implementation |
|---------|-------|----------------|
| `w-full` | `f32::INFINITY` | Expands to `ui.available_width()` |
| `h-full` | `f32::INFINITY` | Expands to `ui.available_height()` |
| `w-[Npx]` | N pixels | Fixed width, triggers `Fixed` strategy |
| `h-[Npx]` | N pixels | Fixed height, triggers `Fixed` strategy |

**Strategy Interaction:**
- Explicit `w-[X]` or `h-[X]` → `SizingStrategy::Fixed`
- This makes cross-alignment safe even on unbounded parent

---

## 2. Padding & Margin

### Padding (Inner Margin)
| Utility | Affected Sides | Implementation |
|---------|---------------|----------------|
| `p-{n}` | All | `Frame::inner_margin` |
| `px-{n}` | Left + Right | |
| `py-{n}` | Top + Bottom | |
| `pt-{n}` | Top | |
| `pb-{n}` | Bottom | |
| `pl-{n}` | Left | |
| `pr-{n}` | Right | |

### Margin (Outer Margin)
| Utility | Affected Sides | Implementation |
|---------|---------------|----------------|
| `m-{n}` | All | `Frame::outer_margin` |
| `mt-{n}` | Top | |
| `mb-{n}` | Bottom | |
| `ml-{n}` | Left | |
| `mr-{n}` | Right | |

**Scale:** Same as gap (1 unit = 4px)

---

## 3. Color Palette

### Background Colors - `bg-*`
| Base | Shades Available | Example |
|------|-----------------|---------|
| `gray` | 100-900 | `bg-gray-800` |
| `red` | 400, 500, 600 | `bg-red-500` |
| `blue` | 400, 500, 600 | `bg-blue-500` |
| `green` | 400, 500, 600 | `bg-green-500` |
| `yellow` | 400, 500, 600 | `bg-yellow-500` |
| `purple` | 400, 500, 600 | `bg-purple-500` |
| `cyan` | 400, 500, 600 | `bg-cyan-500` |
| `pink` | 400, 500, 600 | `bg-pink-500` |
| `orange` | 400, 500, 600 | `bg-orange-500` |
| `teal` | 400, 500, 600 | `bg-teal-500` |
| `indigo` | 400, 500, 600 | `bg-indigo-500` |
| `white` | - | `bg-white` |
| `black` | - | `bg-black` |
| `transparent` | - | `bg-transparent` |

### Arbitrary Colors
| Syntax | Example |
|--------|---------|
| `bg-[#RRGGBB]` | `bg-[#ff5500]` |
| `bg-[#RRGGBBAA]` | `bg-[#ff550080]` |

### Text Colors - `text-*`
Same palette as background colors, using `text-` prefix.

### Opacity (Future)
| Utility | Effect |
|---------|--------|
| `bg-opacity-{n}` | Modify alpha channel (0-100) |
| `text-opacity-{n}` | Modify text alpha channel |

---

## 4. Typography

### Font Size - `text-*`
| Utility | Pixels |
|---------|--------|
| `text-xs` | 10px |
| `text-sm` | 12px |
| `text-base` | 14px (default) |
| `text-lg` | 18px |
| `text-xl` | 20px |
| `text-2xl` | 24px |
| `text-3xl` | 30px |
| `text-4xl` | 36px |

### Font Weight & Style
| Utility | Effect | Implementation |
|---------|--------|----------------|
| `font-bold` | Bold text | `RichText::strong()` |
| `font-mono` | Monospace font | `FontFamily::Monospace` |
| `italic` | Italic text | `RichText::italics()` |

### Text Alignment
| Utility | Effect | Implementation |
|---------|--------|----------------|
| `text-left` | Align text left | `Align::Min` |
| `text-center` | Center text | `Align::Center` |
| `text-right` | Align text right | `Align::Max` |

---

## 5. Borders & Rounding

### Border Width
| Utility | Width | Notes |
|---------|-------|-------|
| `border` | 1px | Default gray color |
| `border-{n}` | N pixels | Numeric width |

### Border Color
| Utility | Example |
|---------|---------|
| `border-{color}` | `border-red-500` |
| `border-[#hex]` | `border-[#ff0000]` |

### Rounding
| Utility | Radius |
|---------|--------|
| `rounded` | 4px |
| `rounded-md` | 6px |
| `rounded-lg` | 8px |
| `rounded-xl` | 12px |
| `rounded-full` | 9999px (pill shape) |

### Specific Borders (Future)
| Utility | Effect |
|---------|--------|
| `border-t` | Top border only |
| `border-b` | Bottom border only |
| `border-l` | Left border only |
| `border-r` | Right border only |

---

## 6. Effects

### Shadows
| Utility | Effect | Implementation |
|---------|--------|----------------|
| `shadow-none` | No shadow | `Shadow::NONE` |
| `shadow-sm` | Extra small shadow | offset: (0, 1), blur: 2 |
| `shadow` | Small shadow | offset: (0, 1), blur: 3 |
| `shadow-md` | Medium shadow | offset: (0, 4), blur: 6 |
| `shadow-lg` | Large shadow | offset: (0, 10), blur: 15 |
| `shadow-xl` | Extra large shadow | offset: (0, 20), blur: 25 |
| `shadow-2xl` | 2x large shadow | offset: (0, 25), blur: 50 |

### Opacity
| Utility | Effect | Implementation |
|---------|--------|----------------|
| `bg-opacity-{n}` | Background opacity (0-100) | Modifies alpha channel |
| `text-opacity-{n}` | Text opacity (0-100) | Modifies alpha channel |

**Example:** `bg-red-500 bg-opacity-50` creates a 50% transparent red background.

---

## 7. Interaction (Future)

### Cursor
| Utility | Cursor Icon |
|---------|-------------|
| `cursor-pointer` | Hand pointer |
| `cursor-grab` | Grab hand |
| `cursor-text` | Text selection |

**Implementation:** `ui.output_mut().cursor_icon = CursorIcon::*`

---

## Implementation Status

| Category | Status | Notes |
|----------|--------|-------|
| Layout Direction | ✅ Done | `flex-row`, `flex-col` |
| Gap | ✅ Done | `gap-{n}` |
| Items Alignment | ✅ Done | With ShrinkWrap strategy |
| Justify | ⚠️ Partial | `start/center/end` work, `between/around` pending |
| Sizing | ✅ Done | `w-full`, `h-full`, `w-[X]`, `h-[X]` |
| Padding | ✅ Done | All variants (`p-`, `px-`, `py-`, `pt-`, `pb-`, `pl-`, `pr-`) |
| Margin | ✅ Done | All variants (`m-`, `mx-`, `my-`, `mt-`, `mb-`, `ml-`, `mr-`) |
| Colors (bg/text) | ✅ Done | Full palette + arbitrary |
| Typography | ✅ Done | Sizes (xs-6xl), bold, mono, italic |
| Text Alignment | ✅ Done | `text-left`, `text-center`, `text-right` |
| Borders | ✅ Done | Width, color, rounding (none, sm, md, lg, xl, 2xl, 3xl, full) |
| Shadows | ✅ Done | `shadow-none/sm/md/lg/xl/2xl` |
| Opacity | ✅ Done | `bg-opacity-{0-100}`, `text-opacity-{0-100}` |
| Cursors | ❌ Pending | |

---

## Examples

### Row with Centered Items (Safe)
```
ui_box "flex-row items-center gap-2" {
    ui_label "✓" "text-green-500"
    ui_label "Success" "text-white"
}
```
**Strategy:** `ShrinkWrap` (height unbounded) → items align naturally among themselves.

### Row with Fixed Height (Explicit Center)
```
ui_box "flex-row items-center h-[50px] bg-gray-800" {
    ui_label "Icon" "text-2xl"
    ui_label "Title" "text-lg"
}
```
**Strategy:** `Fixed` → `cross_align(Center)` applied directly, safe within 50px height.

### Centered Column
```
ui_box "flex-col items-center gap-4" {
    ui_label "Title" "text-2xl font-bold"
    ui_label "Subtitle" "text-gray-400"
}
```
**Strategy:** `UseAvailable` (width typically bounded) → `cross_align(Center)` applied directly.

### Full-Width Container
```
ui_box "w-full p-4 bg-gray-900 rounded-lg" {
    ui_label "Content" ""
}
```
**Strategy:** `Fixed { width: INFINITY }` → expands to available width.
