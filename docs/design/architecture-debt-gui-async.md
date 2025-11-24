# Architecture Debt: GUI Event Loop vs. Async VM Execution

**Date:** 2025-11-24
**Status:** Critical Limitation
**Component:** VM / GUI Bridge / Async Runtime

## The Problem
Achronyme currently fails to execute asynchronous tasks (like HTTP requests or timers) properly while the GUI is running. Specifically, spawning a background task from a GUI callback (e.g., a button click) results in the task never executing or the UI freezing, depending on the implementation strategy used.

## Symptoms
1. **Deadlocked Tasks:** When `spawn(async_fn)` is called inside a `ui_button` callback, the task is scheduled on the `tokio::task::LocalSet`. However, because the GUI run loop (`eframe::run_native`) blocks the main thread, the `LocalSet` never gets a chance to poll its tasks. The task sits in the queue forever.
2. **Frozen UI:** If we attempt to `block_on` or `await` a future synchronously inside a callback to force execution, the entire GUI freezes until the operation completes. This degrades user experience (classic "App Not Responding").

## Root Cause Analysis

### 1. Single-Threaded Constraint (`!Send`)
The Achronyme VM relies heavily on `Rc<RefCell<T>>` for value management (garbage collection via reference counting).
- **Consequence:** `Value` types are `!Send`. They cannot be sent to another thread.
- **Constraint:** The entire VM must run on a single thread. We cannot simply offload the VM to a background thread using standard `tokio::spawn` (which requires `Send`). We are forced to use `tokio::task::spawn_local`.

### 2. Conflicting Event Loops
We effectively have two event loops fighting for control of the single thread:
- **Tokio Runtime (`LocalSet`):** Needs to poll futures to make progress on async tasks.
- **Winit / Eframe (GUI):** Needs to control the main thread to process OS window events and render frames. `eframe::run_native` is a blocking call on most platforms.

**Conflict:** When `eframe` takes control, `tokio` stops. Since the VM is trapped on that same thread, it halts.

## Failed Mitigation Attempts (Lessons Learned)
- **Forcing `multi_thread` Tokio:** Enabling the multi-thread runtime didn't help because `spawn_local` tasks are explicitly pinned to the thread they were spawned on (the main thread), which is blocked by the GUI.
- **`block_on` builtin:** We implemented a `block_on` function to force async completion. This "works" but violates the non-blocking principle, freezing the application window during network IO.

## Proposed Solution: "The Actor Model" Architecture

To solve this properly, we must decouple the VM execution from the GUI rendering.

### Strategy: VM on Background Thread
1. **Main Thread (GUI):** Owns the `eframe` loop. It does *not* run the VM directly. It only renders the UI based on state received from the VM and sends user events (clicks, input) back to the VM.
2. **Background Thread (Logic):** Runs the VM and the `tokio::task::LocalSet`.
   - Since the VM runs entirely on this thread, `Rc` is fine (no cross-thread sharing of `Value`s).
   - The `LocalSet` can run continuously (`run_until`), allowing `spawn`, `sleep`, and `http` to work perfectly.

### The Challenge: Communication (`!Send`)
Since `Value` is `!Send`, we cannot send `Value` objects directly between the Background Thread and the Main Thread via channels.

**Implementation Plan:**
1. **Serialized Protocol:** The VM and GUI communicate via a thread-safe protocol (e.g., enums or serialized JSON-like structures) that *is* `Send`.
   - VM -> GUI: `RenderOp::Label(text, style)`, `RenderOp::Button(id, text)`
   - GUI -> VM: `Event::Clicked(id)`, `Event::InputChanged(id, text)`
2. **Shadow DOM / Virtual DOM:** The GUI thread maintains a "Shadow State" of the UI components that the VM updates.
3. **Immediate Mode Bridge:** Since `egui` is immediate mode, the VM (background) could generate a "Display List" (vector of render commands) every frame (or on state change) and send it to the GUI thread to simply draw.

### Next Steps
1. Create a `Msg` enum for VM<->GUI communication.
2. Refactor `achronyme-cli` to spawn a dedicated thread for the VM logic.
3. Refactor `builtins/gui.rs` to stop calling `egui` directly and instead push commands to a `mpsc::channel`.
