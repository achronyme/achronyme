# Comparison: egui vs Iced for Achronyme

This document analyzes two leading Rust GUI frameworks, **egui** and **Iced**, to determine the best fit for Achronyme's architecture (v0.6.5).

**Context:**
- **VM Architecture:** `Rc<RefCell<T>>` based (Single Threaded, `!Send`).
- **Runtime:** `tokio::task::LocalSet` (Async, Single Threaded).
- **Reactivity:** SolidJS-style Signals (Mutable, Fine-grained, Push-based).
- **Goal:** Expose a "Render Function" API to scripts (e.g., `render: (ui) => { ... }`).

## 1. Architecture Overview

### **egui (Immediate Mode)**
- **Paradigm:** You write code that runs every frame. `ui.button("Click")` draws a button *and* returns whether it was clicked.
- **State:** "What you see is what you execute". The UI is a direct reflection of the current program state.
- **Data Flow:** Direct. The render loop borrows the application state, reads it, and emits draw commands.

### **Iced (Retained Mode / Elm Architecture)**
- **Paradigm:** Model-View-Update (MVU).
    1. **Model:** The state of your application.
    2. **View:** A pure function `Model -> WidgetTree`.
    3. **Update:** A function `(Model, Message) -> Model`.
- **State:** You must define a static `Message` enum and a `State` struct.
- **Data Flow:** Indirect. Events generate `Message`s, which mutate `State`, which triggers `View`.

---

## 2. Integration Analysis

### Challenge A: The `!Send` Constraint
Achronyme's `Value` types use `Rc<RefCell>`, meaning they cannot be sent between threads.

*   **Iced:** deeply integrates with async executors. While it *can* run single-threaded, its architecture strongly encourages separating the "View" generation from the "Logic". If the View generation happens on a different thread (common in retained mode optimizations), it breaks.
*   **egui:** allows full control over the event loop. We can run the `egui` update directly inside our existing `eframe` loop on the main thread, sharing the `Rc<RefCell<Environment>>` without issues.

### Challenge B: Dynamic vs Static Types
Achronyme is a dynamic language.

*   **Iced:** requires a static `Message` enum at compile time (e.g., `enum Msg { Increment, Decrement }`).
    *   *Problem:* Achronyme scripts define buttons and actions dynamically at runtime.
    *   *Workaround:* We would need a generic `Message::ExecuteLambda(Value)` and a complex dispatch system to route these back to the VM.
*   **egui:** does not require message types.
    *   *Solution:* In the render loop, if `ui.button(...).clicked()` is true, we simply execute the Achronyme closure *immediately* right there in the loop.
    *   *Fit:* **Perfect**. It matches the imperative nature of the interpreter.

### Challenge C: The Reactive System
Achronyme uses "Signals" and "Effects" (SolidJS style).

*   **Iced:** uses the "Virtual DOM" approach (diffing widget trees).
    *   *Mismatch:* Recreating the entire widget tree from Achronyme values every frame (converting `Value::Record` -> `Iced::Column` -> `Iced::Button`...) is expensive and complex.
*   **egui:** uses Immediate execution.
    *   *Fit:* Achronyme's `render` function acts as the "Effect".
    *   **Workflow:**
        1. Script: `render: (ui) => { ui.label(signal.get()) }`
        2. Signal `get()` registers the "GUI Repaint" as a dependency.
        3. Signal `set()` triggers `request_repaint()`.
        4. `egui` runs the `render` closure again.
    *   This creates a highly efficient, fine-grained reactive loop without a Virtual DOM overhead.

---

## 3. Comparison Matrix

| Feature | egui | Iced | Winner |
| :--- | :--- | :--- | :--- |
| **Architecture** | Immediate (Imperative) | Retained (MVU / Functional) | **egui** (Matches VM) |
| **Type System** | Dynamic-friendly | Static/Strongly typed | **egui** |
| **Threading** | Main-thread centric | Multi-thread friendly | **egui** (Due to `Rc`) |
| **State Sync** | Direct Borrowing | Message Passing | **egui** |
| **Widgets** | Comprehensive standard set | Modular, customizable | **Tie** |
| **Look & Feel** | Tool-like / Debugger-like | Native / Polished | **Iced** (Slightly) |
| **Async Support** | Via external executor | Built-in | **egui** (With our `LocalSet`) |

## 4. Conclusion & Recommendation

**Recommendation: Use `egui`**

While **Iced** is a fantastic library for pure Rust applications, it imposes an architecture (MVU + Static Types) that fights against the dynamic, interpreter-based nature of Achronyme. Bridging the two would require:
1. A complex "Virtual DOM" layer to translate Achronyme Records to Iced Widgets.
2. A message dispatch system to bridge the static/dynamic gap.

**egui**, on the other hand, allows us to treat the Achronyme `render` function as a direct extension of the Rust update loop. The integration is thinner, faster, and respects the `Rc` / `LocalSet` constraints natively.

### Proposed Architecture with egui

```rust
// simplified pseudocode
impl eframe::App for AchronymeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 1. Enter LocalSet context
        self.local_set.block_on(&self.runtime, async {
            // 2. Call the Achronyme "render" function defined in the script
            //    passing the `ctx` as an opaque handle.
            let render_fn = self.get_script_render_fn();
            
            // 3. The script executes immediate mode commands:
            //    ui.label("Hello");
            //    if ui.button("Click").clicked() { 
            //        // Run callback immediately
            //    }
            vm.call(render_fn, vec![ctx_handle]).await;
        });
    }
}
```
