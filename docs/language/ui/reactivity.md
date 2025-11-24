---
title: "Reactive UI"
description: "Connecting UI components to data using Signals"
section: "ui"
order: 4
---

# Reactive UI

The true power of the Achronyme GUI comes from its deep integration with the **Reactive System**.

## Bidirectional Binding

UI controls like inputs and sliders bind directly to `Signal` objects.

1.  **Read**: The control displays the current `signal.value`.
2.  **Write**: When the user interacts, the control updates `signal.value`.
3.  **React**: Any `effect` depending on that signal runs immediately.

```javascript
let frequency = signal(440.0)

// 1. Bind slider to signal
ui_slider(frequency, 20.0, 2000.0)

// 2. Bind label to SAME signal
// Updates instantly when slider moves
ui_label("Freq: " + str(frequency.value) + " Hz")
```

## Derived UI State

You can use computed signals or effects to control UI state logic.

```javascript
let show_details = signal(false)

// Toggle button
if (ui_button("Toggle Details")) {
    show_details.set(!show_details.value)
}

// Conditional rendering
if (show_details.value) {
    ui_box("bg-gray-800 p-4", () => do {
        ui_label("Here are the details...")
    })
}
```

## Performance Note

The GUI runs in **Immediate Mode**, meaning the entire UI function is re-executed every frame (60 FPS).

- **Fast**: Logic logic `if (show.value)` is extremely cheap.
- **Avoid**: Heavy computations (like loading a file or training a model) directly in the render loop.
- **Solution**: Use `spawn` to run heavy tasks in the background and update a `signal` when done.

```javascript
let progress = signal(0.0)

// Background task
spawn(async () => do {
    // Heavy work...
    progress.set(0.5)
    // More work...
    progress.set(1.0)
})

// UI just reads the signal
ui_progress_bar(progress.value)
```
