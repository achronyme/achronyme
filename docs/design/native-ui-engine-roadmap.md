# Achronyme Native UI Engine (AUI) - Design Specification

## 1. Motivation
The previous GUI implementation based on `egui` (Immediate Mode) reached its limits when trying to emulate web-like styling and layout capabilities (Retained Mode features like CSS Flexbox, shrink-wrapping with alignment, complex z-indexing). To provide a first-class UI experience for Achronyme developers, we need a custom engine tailored to the VM's capabilities and the language's reactive paradigm.

## 2. Core Philosophy
- **Retained Mode:** The UI is represented as a mutable tree of nodes (The "DOM"). Layout calculations are performed only when structure or styles change, not every frame.
- **Reactive by Default:** UI properties are bound directly to Achronyme `Signals`. Changes in data automatically mark nodes as "dirty" for re-layout or re-paint.
- **CSS-Inspired Layout:** A strict implementation of the Box Model and Flexbox (and eventually Grid).
- **GPU Accelerated:** Rendering via `wgpu` for maximum performance.

## 3. Architecture Overview

### A. The Scene Graph (The Tree)
Unlike `egui` where the UI is defined by code execution flow, AUI will maintain a persistent tree of `UiNode` structs.

```rust
struct UiNode {
    id: NodeId,
    type: NodeType, // Container, Text, Image, etc.
    style: Style,   // Computed styles
    layout: LayoutState, // Calculated position/size (x, y, w, h)
    children: Vec<NodeId>,
    // Bindings to VM Values
    event_handlers: HashMap<EventType, VmFunction>,
}
```

### B. The Layout Engine
We will integrate or implement a Flexbox solver (likely leveraging **Taffy**, a high-performance Rust layout library used by Bevy and others) to handle:
- `display: flex`
- `justify-content`, `align-items`
- `flex-grow`, `flex-shrink`
- `gap`, `margin`, `padding`

This solves the "centering shrink-wrapped items" problem natively via standard algorithms.

### C. The Rendering Pipeline
1.  **Update Phase:** Process VM signals and update the Tree state.
2.  **Layout Phase:** Traverse the tree (Taffy) to compute geometry for dirty nodes.
3.  **Paint Phase:** Generate a Display List (commands like `DrawRect`, `DrawText`) based on geometry and styles.
4.  **Rasterization:** Submit commands to the GPU (via `wgpu` or a lightweight renderer like `vello` or `skia`).

## 4. Integration with Achronyme VM

### Syntax
The syntax remains declarative, but the implementation changes from executing generic drawing commands to *constructing/updating the tree*.

```javascript
// This code constructs a Node tree, it doesn't just "draw"
ui_box("flex-col items-center", () => {
    ui_button("Click Me")
})
```

### Reactivity
When a Signal changes:
1.  The specific `UiNode` subscribed to that signal is flagged.
2.  Only that node (and necessary ancestors/descendants) is re-calculated.
3.  No need to re-run the entire UI closure every frame (huge performance win).

## 5. Roadmap

### Phase 1: Core Infrastructure (Crate: `achronyme-render`)
- [ ] Set up a windowing shell (using `winit`).
- [ ] Integrate `wgpu` for basic 2D rendering (rectangles, colors).
- [ ] Create the basic `Node` and `Tree` structures.

### Phase 2: Layout System
- [ ] Integrate `taffy` crate.
- [ ] Map Achronyme style strings (parsing logic we already have) to Taffy styles.
- [ ] Implement the Layout Pass loop.

### Phase 3: Interaction & VM Bridge
- [ ] Implement hit-testing (detecting which node is under the mouse).
- [ ] Event propagation (click, hover).
- [ ] Connect `achronyme-vm` Callbacks to Events.

### Phase 4: Text & Polish
- [ ] Text rendering (using `cosmic-text` or similar).
- [ ] Texture support.
- [ ] Animations.

## 6. Migration Strategy
We will freeze the current `achronyme-gui` (egui-based) as "Legacy" or "Prototype" and build the new engine in parallel. Once the new engine supports basic boxes and text, we will swap the `gui` module in the VM.
