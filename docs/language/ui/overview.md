---
title: "Native GUI System"
description: "Overview of the Achronyme Native GUI system, architecture, and getting started"
section: "ui"
order: 1
---

# Native GUI System

Achronyme features a high-performance, immediate-mode native GUI system powered by `egui`. It is designed for scientific tools, rapid prototyping, and reactive applications.

## Core Philosophy

1.  **Immediate Mode**: The UI is redrawn every frame. Logic and presentation are unified.
2.  **Reactive**: Built-in integration with Achronyme's `Signal` and `Effect` system.
3.  **Native**: Renders using the GPU (via OpenGL/Vulkan) for smooth 60 FPS performance.
4.  **Declarative Styling**: Uses a Tailwind-CSS inspired string syntax for rapid styling.

## Getting Started

To create a GUI application, you define a **render function** and pass it to `gui_run`.

```javascript
// 1. Define state (optional)
let count = signal(0)

// 2. Define render function
let app = () => do {
    // 3. Build UI hierarchy
    ui_box("p-4 flex-col gap-4", () => do {
        ui_label("Hello Achronyme!", "text-2xl font-bold")
        
        if (ui_button("Click Me")) {
            count.set(count.value + 1)
        }
        
        ui_label("Count: " + str(count.value))
    })
}

// 4. Run application (blocks until closed)
gui_run(app, {
    title: "My First App",
    width: 400,
    height: 300
})
```

## Application Lifecycle

The `gui_run` function starts the native event loop.

- **Blocking**: `gui_run` blocks the main thread until the window is closed.
- **Continuous Update**: The render function is called repeatedly (approx. 60 times per second) to draw the UI.
- **Persisted State**: Use global variables or `signal`s to maintain state between frames. Local variables inside the render function are reset every frame.

## Architecture: The VM Bridge

Achronyme uses a unique **Thread-Local VM Bridge** to allow the UI (running in a native event loop) to execute Achronyme code safely.

1.  `gui_run` sets a thread-local pointer to the active VM.
2.  The native window opens and starts its loop.
3.  When a frame needs rendering, the native code calls back into the VM using the stored pointer.
4.  This allows callbacks (like button clicks) to modify VM state immediately and safely.

## Stopping the Application

You can close the application programmatically (useful for tests or logic-based exit):

```javascript
if (should_close) {
    ui_quit()
}
```

## Next Steps

- **[Components](components.md)**: Explore available widgets like buttons, sliders, and plots.
- **[Layout & Styling](layout-styling.md)**: Learn how to arrange and style your interface.
- **[Reactivity](reactivity.md)**: Connect your UI to data signals.
