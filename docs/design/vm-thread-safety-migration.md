# VM Thread-Safety Migration Plan

## Executive Summary

This document outlines the architectural migration plan to make the Achronyme VM fully thread-safe with interior mutability. This migration is essential for building a professional-grade programming language that can compete in the industry with proper UI responsiveness, true async capabilities, and parallel computation support.

**Target Version**: 0.8.0 or 1.0.0
**Estimated Effort**: 2-4 weeks
**Risk Level**: Medium-High (core architecture change)

---

## Part 1: Current Architecture Analysis

### 1.1 The Problem Statement

The current Achronyme VM architecture suffers from a fundamental incompatibility between:

1. **Single-threaded, synchronous VM execution** - The VM requires `&mut self` for all operations
2. **Event-driven, asynchronous UI** - winit/wgpu run in an event loop that expects non-blocking operations
3. **Reactive signal system** - Signals need to notify UI of changes, but the notification path is asynchronous

This manifests as **visible latency** between signal changes and UI updates, making the reactive system feel sluggish and unprofessional.

### 1.2 Current Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          CURRENT ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         SINGLE THREAD                                │   │
│  │                                                                      │   │
│  │   VM (&mut self)                                                     │   │
│  │   ┌──────────┐    ┌──────────┐    ┌──────────┐                      │   │
│  │   │  frames  │    │ globals  │    │generators│                      │   │
│  │   │ Vec<...> │    │Arc<RwLock│    │HashMap   │                      │   │
│  │   │ NOT SAFE │    │  SAFE    │    │ NOT SAFE │                      │   │
│  │   └──────────┘    └──────────┘    └──────────┘                      │   │
│  │         │                                                            │   │
│  │         ▼                                                            │   │
│  │   ┌──────────────────────────────────────────┐                      │   │
│  │   │         Event Loop (winit)               │                      │   │
│  │   │  - Borrows &mut VM                       │                      │   │
│  │   │  - Cannot release until loop ends        │                      │   │
│  │   │  - Signal notifications are ASYNC        │                      │   │
│  │   └──────────────────────────────────────────┘                      │   │
│  │         │                                                            │   │
│  │         ▼                                                            │   │
│  │   ┌──────────────────────────────────────────┐                      │   │
│  │   │         Thread-Local State               │                      │   │
│  │   │  - TRACKING_CONTEXT (effects)            │                      │   │
│  │   │  - BUILD_CONTEXT (UI tree)               │                      │   │
│  │   │  - ACTIVE_VM (raw pointer hack)          │                      │   │
│  │   └──────────────────────────────────────────┘                      │   │
│  │                                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  PROBLEMS:                                                                  │
│  ❌ UI freezes during VM execution                                         │
│  ❌ Signal updates have 1-2 frame latency                                  │
│  ❌ Cannot run background computations                                     │
│  ❌ Thread-locals prevent multi-threaded usage                             │
│  ❌ &mut self requirement prevents sharing                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Identified Thread-Safety Blockers

| Blocker | File Location | Type | Severity |
|---------|---------------|------|----------|
| `frames: Vec<CallFrame>` | `vm/mod.rs:35` | Mutable state | CRITICAL |
| `generators: HashMap<...>` | `vm/mod.rs:37` | Mutable state | CRITICAL |
| `TRACKING_CONTEXT` | `reactive.rs:12-13` | thread_local! | HIGH |
| `BUILD_CONTEXT` | `render_gui.rs:36` | thread_local! | HIGH |
| `ACTIVE_VM` | `gui.rs:13` | Raw pointer | HIGH |
| `Rc<RefCell<>>` in event loop | `render_gui.rs:323-326` | Not Send | MEDIUM |
| `&mut self` requirement | All VM methods | Exclusive borrow | CRITICAL |

### 1.4 Why This Matters for Industry Adoption

Professional programming languages provide:

| Feature | Industry Standard | Achronyme Current |
|---------|-------------------|-------------------|
| UI Responsiveness | 60fps guaranteed | Freezes during script |
| Background Tasks | Native support | Blocks main thread |
| Parallel Compute | Worker threads | Not possible |
| Async I/O | Non-blocking | Blocks event loop |
| Multi-window | Full support | Would freeze others |

---

## Part 2: Target Architecture

### 2.1 Design Goals

1. **Thread-Safe VM** - VM can be safely shared across threads via `Arc<VM>`
2. **Dedicated UI Thread** - Rendering never blocks, guaranteed 60fps
3. **Async Runtime Separation** - I/O operations don't affect UI
4. **Worker Thread Pool** - Parallel computation for CPU-intensive tasks
5. **Zero-Copy Signal Propagation** - Instant signal updates across threads

### 2.2 Target Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          TARGET ARCHITECTURE                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    VM Core (Arc<VM>, Send + Sync)                    │   │
│  │                                                                      │   │
│  │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │   │
│  │   │ Arc<RwLock<    │  │ Arc<RwLock<    │  │ Arc<RwLock<    │        │   │
│  │   │   Frames>>     │  │   Globals>>    │  │   Generators>> │        │   │
│  │   │   THREAD-SAFE  │  │   THREAD-SAFE  │  │   THREAD-SAFE  │        │   │
│  │   └────────────────┘  └────────────────┘  └────────────────┘        │   │
│  │                                                                      │   │
│  │   pub fn call_value(&self, ...) -> Result<Value>                    │   │
│  │   pub fn execute(&self, ...) -> Result<Value>                       │   │
│  │                                                                      │   │
│  │   unsafe impl Send for VM {}                                        │   │
│  │   unsafe impl Sync for VM {}                                        │   │
│  │                                                                      │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│              ┌──────────────────┼──────────────────┐                       │
│              │                  │                  │                       │
│              ▼                  ▼                  ▼                       │
│  ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐        │
│  │   UI Thread       │ │   Async Runtime   │ │   Worker Pool     │        │
│  │                   │ │                   │ │                   │        │
│  │ ┌───────────────┐ │ │ ┌───────────────┐ │ │ ┌───────────────┐ │        │
│  │ │ UIRuntime     │ │ │ │ Tokio Runtime │ │ │ │ ThreadPool    │ │        │
│  │ │ - wgpu render │ │ │ │ - HTTP client │ │ │ │ - parallel_map│ │        │
│  │ │ - winit events│ │ │ │ - File I/O    │ │ │ │ - CPU compute │ │        │
│  │ │ - 60fps loop  │ │ │ │ - Timers      │ │ │ │ - Background  │ │        │
│  │ └───────────────┘ │ │ └───────────────┘ │ │ └───────────────┘ │        │
│  │        │          │ │        │          │ │        │          │        │
│  └────────┼──────────┘ └────────┼──────────┘ └────────┼──────────┘        │
│           │                     │                     │                    │
│           └─────────────────────┴─────────────────────┘                    │
│                                 │                                          │
│                                 ▼                                          │
│           ┌─────────────────────────────────────────────┐                  │
│           │         Signal System (Global, Lock-Free)   │                  │
│           │                                             │                  │
│           │  Arc<RwLock<SignalState>>                   │                  │
│           │  - Subscribers: Vec<Weak<...>>              │                  │
│           │  - Cross-thread notification via channel    │                  │
│           │  - UI subscribes to relevant signals        │                  │
│           │                                             │                  │
│           └─────────────────────────────────────────────┘                  │
│                                                                            │
│  BENEFITS:                                                                 │
│  ✅ UI never freezes (dedicated thread)                                   │
│  ✅ Instant signal propagation (direct notification)                      │
│  ✅ True parallel computation (worker pool)                               │
│  ✅ Non-blocking async I/O (tokio runtime)                                │
│  ✅ Multiple windows supported                                            │
│  ✅ Professional-grade responsiveness                                     │
│                                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Communication Model

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     INTER-THREAD COMMUNICATION                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  VM Thread                              UI Thread                        │
│  ─────────                              ─────────                        │
│                                                                          │
│  signal.set(value)                                                       │
│       │                                                                  │
│       ├──► Update Arc<RwLock<SignalState>>                              │
│       │                                                                  │
│       ├──► notify_ui_channel.send(SignalChanged(id))  ──────────────►   │
│       │                                         │                        │
│       │                                         ▼                        │
│       │                              ┌─────────────────────┐             │
│       │                              │ UI receives message │             │
│       │                              │ - Reads new value   │             │
│       │                              │ - Updates widget    │             │
│       │                              │ - Requests redraw   │             │
│       │                              └─────────────────────┘             │
│       │                                         │                        │
│       │                                         ▼                        │
│       │                              Next frame renders instantly        │
│       ▼                                                                  │
│  Continue execution                                                      │
│                                                                          │
│  ────────────────────────────────────────────────────────────────────   │
│                                                                          │
│  UI Thread                              VM Thread                        │
│  ─────────                              ─────────                        │
│                                                                          │
│  User clicks button                                                      │
│       │                                                                  │
│       ├──► vm_command_channel.send(ButtonClicked(id))  ─────────────►   │
│       │                                         │                        │
│       │                                         ▼                        │
│       │                              ┌─────────────────────┐             │
│       │                              │ VM receives command │             │
│       │                              │ - Executes callback │             │
│       │                              │ - May call signal   │             │
│       │                              │   .set() (above)    │             │
│       │                              └─────────────────────┘             │
│       │                                                                  │
│       ▼                                                                  │
│  Continue rendering (never blocks)                                       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Part 3: Migration Phases

### Phase 1: VM Interior Mutability

**Goal**: Make VM struct thread-safe with `&self` methods instead of `&mut self`

**Duration**: 1 week

#### 1.1 Changes to VM Struct

```rust
// BEFORE (current)
pub struct VM {
    pub(crate) frames: Vec<InternalCallFrame>,
    pub(crate) globals: Shared<HashMap<String, Value>>,
    pub(crate) generators: HashMap<usize, SuspendedFrame>,
    pub(crate) builtins: BuiltinRegistry,
    pub(crate) intrinsics: IntrinsicRegistry,
    pub(crate) current_module: Option<String>,
    precision: Option<i32>,
    epsilon: f64,
    pub(crate) active_effects: Vec<Shared<EffectState>>,
}

// AFTER (target)
pub struct VM {
    /// Execution state - protected by RwLock for thread safety
    state: Arc<RwLock<VMState>>,

    /// Immutable after initialization - no lock needed
    pub(crate) builtins: Arc<BuiltinRegistry>,
    pub(crate) intrinsics: Arc<IntrinsicRegistry>,

    /// Configuration - rarely changes, RwLock for flexibility
    config: Arc<RwLock<VMConfig>>,
}

/// Mutable execution state, protected by RwLock
struct VMState {
    frames: Vec<InternalCallFrame>,
    generators: HashMap<usize, SuspendedFrame>,
    current_module: Option<String>,
    active_effects: Vec<Shared<EffectState>>,
}

/// Shared globals - separate lock for better concurrency
pub struct VMGlobals {
    globals: Arc<RwLock<HashMap<String, Value>>>,
}

/// Configuration that rarely changes
struct VMConfig {
    precision: Option<i32>,
    epsilon: f64,
}
```

#### 1.2 Method Signature Changes

```rust
// BEFORE
impl VM {
    pub fn call_value(&mut self, func: &Value, args: &[Value]) -> Result<Value, VmError>;
    pub fn execute(&mut self, bytecode: &[Instruction]) -> Result<Value, VmError>;
    pub fn set_global(&mut self, name: &str, value: Value);
}

// AFTER
impl VM {
    pub fn call_value(&self, func: &Value, args: &[Value]) -> Result<Value, VmError>;
    pub fn execute(&self, bytecode: &[Instruction]) -> Result<Value, VmError>;
    pub fn set_global(&self, name: &str, value: Value);
}
```

#### 1.3 Send + Sync Implementation

```rust
// Explicit thread-safety guarantees
// SAFETY: All mutable state is protected by RwLock
unsafe impl Send for VM {}
unsafe impl Sync for VM {}

// Also for registries
unsafe impl Send for BuiltinRegistry {}
unsafe impl Sync for BuiltinRegistry {}
unsafe impl Send for IntrinsicRegistry {}
unsafe impl Sync for IntrinsicRegistry {}
```

#### 1.4 Files to Modify

| File | Changes |
|------|---------|
| `crates/achronyme-vm/src/vm/mod.rs` | VM struct, state separation |
| `crates/achronyme-vm/src/vm/execution.rs` | `&mut self` → `&self` |
| `crates/achronyme-vm/src/vm/call.rs` | `&mut self` → `&self` |
| `crates/achronyme-vm/src/builtins/*.rs` | Update all builtin signatures |

#### 1.5 Testing Strategy

```rust
#[test]
fn test_vm_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<VM>();
}

#[test]
fn test_vm_is_sync() {
    fn assert_sync<T: Sync>() {}
    assert_sync::<VM>();
}

#[test]
fn test_vm_concurrent_access() {
    let vm = Arc::new(VM::new());
    let handles: Vec<_> = (0..4).map(|_| {
        let vm = Arc::clone(&vm);
        std::thread::spawn(move || {
            vm.call_value(&some_func, &[]).unwrap()
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }
}
```

---

### Phase 2: Eliminate Thread-Local State

**Goal**: Remove all thread_local! statics that prevent cross-thread operation

**Duration**: 3-5 days

#### 2.1 ExecutionContext Pattern

```rust
// BEFORE: Thread-local tracking
thread_local! {
    static TRACKING_CONTEXT: RefCell<Option<Shared<EffectState>>> = RefCell::new(None);
    static SIGNAL_NOTIFIER: RefCell<Option<Box<dyn Fn()>>> = RefCell::new(None);
}

// AFTER: Explicit context passing
pub struct ExecutionContext {
    /// Current effect being tracked (for dependency collection)
    pub tracking_effect: Option<Shared<EffectState>>,

    /// Channel to notify UI of signal changes
    pub ui_notifier: Option<Arc<dyn SignalNotifier + Send + Sync>>,

    /// Current UI build context (only during render)
    pub ui_context: Option<Arc<RwLock<UIBuildContext>>>,
}

pub trait SignalNotifier: Send + Sync {
    fn notify_signal_changed(&self, signal_id: u64);
}

// Context is passed through the call stack
impl VM {
    pub fn call_value_with_context(
        &self,
        ctx: &ExecutionContext,
        func: &Value,
        args: &[Value]
    ) -> Result<Value, VmError>;
}
```

#### 2.2 Signal System Updates

```rust
// BEFORE
pub fn vm_signal_get(_vm: &mut VM, signal_val: &Value, args: &[Value]) -> Result<Value, VmError> {
    // Uses TRACKING_CONTEXT thread-local
    TRACKING_CONTEXT.with(|ctx| { ... });
}

// AFTER
pub fn vm_signal_get(
    vm: &VM,
    ctx: &ExecutionContext,  // Explicit context
    signal_val: &Value,
    args: &[Value]
) -> Result<Value, VmError> {
    if let Some(effect) = &ctx.tracking_effect {
        // Register dependency using passed context
        register_dependency(signal_val, effect);
    }
    // ...
}
```

#### 2.3 BUILD_CONTEXT Replacement

```rust
// BEFORE: Thread-local UI context
thread_local! {
    static BUILD_CONTEXT: RefCell<Option<BuildContext>> = const { RefCell::new(None) };
}

// AFTER: Part of ExecutionContext, created per-render
pub struct UIBuildContext {
    pub app: AuiApp,
    pub parent_stack: Vec<NodeId>,
    pub signal_bindings: HashMap<u64, SignalBinding>,
    pub widget_nodes: HashMap<u64, NodeId>,
}

// Render function receives context explicitly
pub fn render_frame(vm: &VM, ctx: &ExecutionContext, render_fn: &Value) -> Result<(), VmError> {
    let ui_ctx = UIBuildContext::new();
    let ctx_with_ui = ctx.with_ui_context(ui_ctx);

    vm.call_value_with_context(&ctx_with_ui, render_fn, &[])?;

    Ok(())
}
```

#### 2.4 ACTIVE_VM Elimination

```rust
// BEFORE: Dangerous raw pointer hack
thread_local! {
    static ACTIVE_VM: RefCell<Option<*mut VM>> = RefCell::new(None);
}

// AFTER: No longer needed - VM is passed through context
// All callbacks receive &VM through closure capture or explicit parameter
```

#### 2.5 Files to Modify

| File | Changes |
|------|---------|
| `crates/achronyme-vm/src/builtins/reactive.rs` | Remove TRACKING_CONTEXT, SIGNAL_NOTIFIER |
| `crates/achronyme-vm/src/builtins/render_gui.rs` | Remove BUILD_CONTEXT |
| `crates/achronyme-vm/src/builtins/gui.rs` | Remove ACTIVE_VM |
| `crates/achronyme-vm/src/vm/mod.rs` | Add ExecutionContext parameter |
| All builtin functions | Add ctx parameter |

---

### Phase 3: UI Runtime Separation

**Goal**: Run UI in a dedicated thread with channel-based communication

**Duration**: 1 week

#### 3.1 UIRuntime Structure

```rust
pub struct UIRuntime {
    /// Channel to receive commands from VM
    command_rx: mpsc::UnboundedReceiver<UICommand>,

    /// Channel to send events to VM
    event_tx: mpsc::UnboundedSender<UIEvent>,

    /// The actual UI application state
    app: AuiApp,

    /// Cached signal values for rendering
    signal_cache: HashMap<u64, Value>,

    /// Window and renderer
    window: Option<Arc<Window>>,
    renderer: Option<WgpuRenderer>,
}

pub enum UICommand {
    /// Update a signal value in the UI cache
    SignalChanged { signal_id: u64, value: Value },

    /// Request a full UI rebuild
    Rebuild,

    /// Close the window
    Quit,
}

pub enum UIEvent {
    /// Button was clicked
    ButtonClicked { widget_id: u64 },

    /// Text input changed
    TextInputChanged { widget_id: u64, value: String },

    /// Slider value changed
    SliderChanged { widget_id: u64, value: f64 },

    /// Checkbox toggled
    CheckboxToggled { widget_id: u64, checked: bool },

    /// Window closed
    WindowClosed,
}
```

#### 3.2 Thread Spawning

```rust
pub fn gui_run(vm: &VM, render_fn: Value, config: WindowConfig) -> Result<(), VmError> {
    // Create communication channels
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<UICommand>();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<UIEvent>();

    // Clone VM for UI thread (now possible because VM is Send + Sync)
    let vm_for_render = Arc::clone(&vm);
    let render_fn_clone = render_fn.clone();

    // Spawn UI thread
    let ui_handle = std::thread::spawn(move || {
        let runtime = UIRuntime::new(cmd_rx, event_tx);
        runtime.run(vm_for_render, render_fn_clone);
    });

    // Create signal notifier that sends to UI thread
    let notifier = ChannelSignalNotifier::new(cmd_tx.clone());

    // Main loop: process UI events
    loop {
        match event_rx.recv() {
            Ok(UIEvent::ButtonClicked { widget_id }) => {
                // Execute button callback in VM
                // This may call signal.set() which notifies UI
            }
            Ok(UIEvent::WindowClosed) => break,
            // ... handle other events
        }
    }

    ui_handle.join().unwrap();
    Ok(())
}
```

#### 3.3 UI Thread Event Loop

```rust
impl UIRuntime {
    pub fn run(mut self, vm: Arc<VM>, render_fn: Value) {
        let event_loop = EventLoop::new().unwrap();

        event_loop.run(move |event, target| {
            // Check for commands from VM (non-blocking)
            while let Ok(cmd) = self.command_rx.try_recv() {
                match cmd {
                    UICommand::SignalChanged { signal_id, value } => {
                        self.signal_cache.insert(signal_id, value);
                        self.needs_redraw = true;
                    }
                    UICommand::Rebuild => {
                        self.rebuild_ui(&vm, &render_fn);
                    }
                    UICommand::Quit => {
                        target.exit();
                        return;
                    }
                }
            }

            // Handle window events
            match event {
                Event::WindowEvent { event: WindowEvent::RedrawRequested, .. } => {
                    self.render();
                }
                Event::WindowEvent { event: WindowEvent::MouseInput { .. }, .. } => {
                    if let Some(clicked) = self.check_button_click() {
                        self.event_tx.send(UIEvent::ButtonClicked {
                            widget_id: clicked
                        }).ok();
                    }
                }
                // ... other events
            }
        });
    }
}
```

#### 3.4 Signal Notifier Implementation

```rust
pub struct ChannelSignalNotifier {
    tx: mpsc::UnboundedSender<UICommand>,
}

impl SignalNotifier for ChannelSignalNotifier {
    fn notify_signal_changed(&self, signal_id: u64) {
        // Non-blocking send to UI thread
        let _ = self.tx.send(UICommand::SignalChanged {
            signal_id,
            value: get_signal_value(signal_id)
        });
    }
}
```

---

### Phase 4: Worker Thread Pool

**Goal**: Enable parallel computation for CPU-intensive operations

**Duration**: 3-5 days

#### 4.1 Worker Pool Structure

```rust
pub struct WorkerPool {
    /// Thread pool for CPU-bound work
    pool: rayon::ThreadPool,

    /// Channel for completed results
    result_tx: mpsc::UnboundedSender<WorkResult>,
    result_rx: mpsc::UnboundedReceiver<WorkResult>,
}

pub struct WorkResult {
    pub job_id: u64,
    pub result: Result<Value, VmError>,
}
```

#### 4.2 Parallel Builtins

```rust
// parallel_map(collection, func) -> collection
pub fn vm_parallel_map(vm: &VM, ctx: &ExecutionContext, args: &[Value]) -> Result<Value, VmError> {
    let collection = &args[0];
    let func = &args[1];

    let items: Vec<Value> = collection.as_vector()?.read().clone();

    // Use rayon for parallel iteration
    let results: Vec<Value> = items
        .par_iter()
        .map(|item| {
            // Each thread gets its own execution context
            let thread_ctx = ctx.for_worker_thread();
            vm.call_value_with_context(&thread_ctx, func, &[item.clone()])
                .unwrap_or(Value::Null)
        })
        .collect();

    Ok(Value::Vector(shared(results)))
}

// parallel_filter(collection, predicate) -> collection
pub fn vm_parallel_filter(vm: &VM, ctx: &ExecutionContext, args: &[Value]) -> Result<Value, VmError> {
    let collection = &args[0];
    let predicate = &args[1];

    let items: Vec<Value> = collection.as_vector()?.read().clone();

    let results: Vec<Value> = items
        .par_iter()
        .filter(|item| {
            let thread_ctx = ctx.for_worker_thread();
            vm.call_value_with_context(&thread_ctx, predicate, &[(*item).clone()])
                .map(|v| v.is_truthy())
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    Ok(Value::Vector(shared(results)))
}
```

#### 4.3 Background Job System

```rust
// spawn_background(func) -> JobHandle
pub fn vm_spawn_background(vm: &VM, ctx: &ExecutionContext, args: &[Value]) -> Result<Value, VmError> {
    let func = args[0].clone();
    let vm = Arc::clone(vm.as_arc());

    let job_id = generate_job_id();

    std::thread::spawn(move || {
        let ctx = ExecutionContext::for_background();
        let result = vm.call_value_with_context(&ctx, &func, &[]);

        // Store result for later retrieval
        BACKGROUND_RESULTS.lock().insert(job_id, result);
    });

    Ok(Value::JobHandle(job_id))
}

// await_job(handle) -> result
pub fn vm_await_job(vm: &VM, ctx: &ExecutionContext, args: &[Value]) -> Result<Value, VmError> {
    let job_id = args[0].as_job_handle()?;

    loop {
        if let Some(result) = BACKGROUND_RESULTS.lock().remove(&job_id) {
            return result;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
```

---

## Part 4: Risk Mitigation

### 4.1 Potential Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Deadlocks | Medium | High | Strict lock ordering, use `try_lock` where possible |
| Performance regression | Medium | Medium | Benchmark before/after, optimize hot paths |
| Breaking changes | High | Medium | Comprehensive test suite, gradual rollout |
| Subtle concurrency bugs | Medium | High | Thread sanitizer, stress tests |

### 4.2 Lock Ordering Convention

To prevent deadlocks, establish a strict lock ordering:

```
1. VMState (highest priority)
2. VMConfig
3. Globals
4. Individual signals (by signal_id, ascending)
5. UI state (lowest priority)

RULE: Never acquire a higher-priority lock while holding a lower-priority lock.
```

### 4.3 Testing Strategy

```rust
// Stress test for concurrency
#[test]
fn test_concurrent_signal_access() {
    let vm = Arc::new(VM::new());
    let signal = create_signal(&vm, Value::Number(0.0));

    let handles: Vec<_> = (0..100).map(|i| {
        let vm = Arc::clone(&vm);
        let signal = signal.clone();
        std::thread::spawn(move || {
            for _ in 0..1000 {
                let current = get_signal_value(&signal);
                set_signal_value(&vm, &signal, Value::Number(
                    current.as_number().unwrap() + 1.0
                ));
            }
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }

    // Should be 100 * 1000 = 100,000
    let final_value = get_signal_value(&signal).as_number().unwrap();
    assert_eq!(final_value, 100_000.0);
}
```

---

## Part 5: Migration Checklist

### Phase 1 Checklist
- [ ] Create VMState struct with RwLock protection
- [ ] Create VMConfig struct with RwLock protection
- [ ] Update VM struct to use Arc<RwLock<VMState>>
- [ ] Change all `&mut self` methods to `&self`
- [ ] Implement Send + Sync for VM
- [ ] Update all builtins to use new signatures
- [ ] Run full test suite
- [ ] Benchmark performance impact

### Phase 2 Checklist
- [ ] Create ExecutionContext struct
- [ ] Remove TRACKING_CONTEXT thread-local
- [ ] Remove SIGNAL_NOTIFIER thread-local
- [ ] Remove BUILD_CONTEXT thread-local
- [ ] Remove ACTIVE_VM thread-local
- [ ] Update all functions to pass ExecutionContext
- [ ] Run full test suite

### Phase 3 Checklist
- [ ] Create UIRuntime struct
- [ ] Create UICommand and UIEvent enums
- [ ] Implement channel-based communication
- [ ] Spawn UI thread in gui_run
- [ ] Implement ChannelSignalNotifier
- [ ] Test UI responsiveness (should be 60fps)
- [ ] Test signal update latency (should be <16ms)

### Phase 4 Checklist
- [ ] Add rayon dependency
- [ ] Create WorkerPool struct
- [ ] Implement parallel_map builtin
- [ ] Implement parallel_filter builtin
- [ ] Implement spawn_background builtin
- [ ] Implement await_job builtin
- [ ] Stress test parallel operations

---

## Part 6: Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| UI frame rate during script execution | 0-30fps (variable) | 60fps (constant) |
| Signal update latency | 16-50ms | <5ms |
| Max parallel threads | 1 | CPU cores |
| Background job support | No | Yes |
| Multi-window support | No | Yes |

---

## Appendix A: Code Examples

### A.1 Complete VM Struct (After Migration)

```rust
use std::sync::Arc;
use parking_lot::RwLock;

pub struct VM {
    /// Mutable execution state
    state: Arc<RwLock<VMState>>,

    /// Shared globals (separate lock for better concurrency)
    globals: Arc<RwLock<HashMap<String, Value>>>,

    /// Immutable after creation
    builtins: Arc<BuiltinRegistry>,
    intrinsics: Arc<IntrinsicRegistry>,

    /// Configuration
    config: Arc<RwLock<VMConfig>>,
}

struct VMState {
    frames: Vec<InternalCallFrame>,
    generators: HashMap<usize, SuspendedFrame>,
    current_module: Option<String>,
    active_effects: Vec<Shared<EffectState>>,
}

struct VMConfig {
    precision: Option<i32>,
    epsilon: f64,
}

impl VM {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(VMState {
                frames: Vec::new(),
                generators: HashMap::new(),
                current_module: None,
                active_effects: Vec::new(),
            })),
            globals: Arc::new(RwLock::new(HashMap::new())),
            builtins: Arc::new(BuiltinRegistry::new()),
            intrinsics: Arc::new(IntrinsicRegistry::new()),
            config: Arc::new(RwLock::new(VMConfig {
                precision: None,
                epsilon: 1e-10,
            })),
        }
    }

    pub fn call_value(&self, func: &Value, args: &[Value]) -> Result<Value, VmError> {
        let ctx = ExecutionContext::default();
        self.call_value_with_context(&ctx, func, args)
    }

    pub fn call_value_with_context(
        &self,
        ctx: &ExecutionContext,
        func: &Value,
        args: &[Value],
    ) -> Result<Value, VmError> {
        let mut state = self.state.write();
        // ... execution logic using state
    }
}

// Thread-safety guarantees
unsafe impl Send for VM {}
unsafe impl Sync for VM {}
```

### A.2 ExecutionContext Definition

```rust
pub struct ExecutionContext {
    /// Effect currently being tracked (for signal dependencies)
    pub tracking_effect: Option<Shared<EffectState>>,

    /// Notifier for signal changes (UI updates)
    pub signal_notifier: Option<Arc<dyn SignalNotifier + Send + Sync>>,

    /// UI build context (only during render)
    pub ui_context: Option<Arc<RwLock<UIBuildContext>>>,

    /// Parent context for nested calls
    parent: Option<Arc<ExecutionContext>>,
}

impl ExecutionContext {
    pub fn default() -> Self {
        Self {
            tracking_effect: None,
            signal_notifier: None,
            ui_context: None,
            parent: None,
        }
    }

    pub fn with_effect(&self, effect: Shared<EffectState>) -> Self {
        Self {
            tracking_effect: Some(effect),
            signal_notifier: self.signal_notifier.clone(),
            ui_context: self.ui_context.clone(),
            parent: Some(Arc::new(self.clone())),
        }
    }

    pub fn for_worker_thread(&self) -> Self {
        Self {
            tracking_effect: None,  // Workers don't track effects
            signal_notifier: self.signal_notifier.clone(),
            ui_context: None,  // Workers can't build UI
            parent: None,
        }
    }
}
```

---

## Appendix B: Comparison with Other Languages

### B.1 Dart/Flutter

```dart
// Dart uses Isolates - separate VMs with message passing
void main() async {
  // UI runs in main isolate
  runApp(MyApp());

  // Heavy computation in separate isolate
  final result = await compute(heavyWork, data);
}
```

**Achronyme equivalent after migration:**
```soc
// UI runs in dedicated thread
gui_run(app, { title: "My App" })

// Heavy computation in worker pool
let result = parallel_map(data, heavy_work)
```

### B.2 JavaScript/Electron

```javascript
// Main process handles app lifecycle
// Renderer process handles UI (separate V8 instance)
// Web Workers for CPU-intensive tasks

const worker = new Worker('heavy-task.js');
worker.postMessage(data);
worker.onmessage = (result) => updateUI(result);
```

**Achronyme equivalent after migration:**
```soc
// Similar pattern with spawn_background
let job = spawn_background(() => heavy_task(data))
// ... UI continues responsive ...
let result = await_job(job)
update_ui(result)
```

---

## References

1. Rust Book - Fearless Concurrency: https://doc.rust-lang.org/book/ch16-00-concurrency.html
2. parking_lot crate documentation: https://docs.rs/parking_lot
3. winit event loop documentation: https://docs.rs/winit
4. rayon parallel iterator documentation: https://docs.rs/rayon
5. Flutter architecture: https://flutter.dev/docs/resources/architectural-overview
