# Architecture Debt: GUI Event Loop vs. Async VM Execution

**Date:** 2025-11-24
**Status:** RESOLVED
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

## Resolution: Migration to `Arc<RwLock<T>>`

We have migrated the entire VM and Value system from `Rc<RefCell<T>>` to `Arc<RwLock<T>>` (specifically using `parking_lot::RwLock` for performance).

### Key Changes
1. **Thread-Safe Values:** `Value` is now `Send + Sync`, allowing it to be shared across threads.
2. **Multi-threaded Executor:** We replaced `tokio::task::spawn_local` with `tokio::spawn`, enabling true background execution on the Tokio thread pool.
3. **GUI Integration:** The GUI runs on the main thread, while async tasks (including VM execution for those tasks) run on worker threads.
4. **Shared State:** Signals and other shared state use `Arc<RwLock<...>>` to safely synchronize between the GUI thread and background tasks.

This architecture allows `spawn(async_fn)` to work correctly even when called from a GUI callback, as the task is offloaded to a different thread and does not block the GUI event loop.
