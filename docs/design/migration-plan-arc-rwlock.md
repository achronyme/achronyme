# Plan de Migración: Rc<RefCell<T>> → Arc<RwLock<T>>

**Fecha:** 2025-11-24
**Estado:** Propuesto
**Objetivo:** Hacer el sistema de valores thread-safe para permitir async real con GUI

---

## Resumen Ejecutivo

Este plan detalla la migración del sistema de valores de Achronyme de `Rc<RefCell<T>>` (single-threaded) a `Arc<RwLock<T>>` (multi-threaded). El objetivo es resolver el problema documentado en `architecture-debt-gui-async.md`: permitir que `spawn()` funcione correctamente mientras el GUI está corriendo.

### Resultado Esperado

```javascript
// Este código "simplemente funcionará" después de la migración
let data = signal(null)

let app = () => do {
    if (ui_button("Fetch")) {
        spawn(async () => do {
            let result = await http_get("https://api.example.com")
            data.set(result)  // ✓ Funciona desde otro hilo
        })
    }
    ui_label("Datos: " + str(data.value))
}

gui_run(app)
```

---

## Fase 0: Preparación

### 0.1 Agregar dependencias

**Archivo:** `crates/achronyme-types/Cargo.toml`
```toml
[dependencies]
parking_lot = "0.12"  # RwLock más eficiente que std
```

**Archivo:** `crates/achronyme-vm/Cargo.toml`
```toml
[dependencies]
parking_lot = "0.12"
```

### 0.2 Crear módulo de compatibilidad

**Archivo nuevo:** `crates/achronyme-types/src/sync.rs`
```rust
//! Tipos de sincronización unificados para facilitar la migración
//!
//! Usamos parking_lot porque:
//! - No tiene poisoning (más ergonómico)
//! - Mejor rendimiento en casos sin contención
//! - API compatible con std

pub use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use std::sync::Arc;

/// Alias para el patrón común Arc<RwLock<T>>
pub type Shared<T> = Arc<RwLock<T>>;

/// Helper para crear Shared<T> fácilmente
pub fn shared<T>(value: T) -> Shared<T> {
    Arc::new(RwLock::new(value))
}
```

---

## Fase 1: Migrar Tipos Core (achronyme-types)

### 1.1 Value enum

**Archivo:** `crates/achronyme-types/src/value.rs`

#### Cambios en imports
```rust
// ANTES
use std::cell::RefCell;
use std::rc::Rc;

// DESPUÉS
use crate::sync::{Arc, RwLock, Shared, shared};
use std::sync::Weak;  // Cambia de std::rc::Weak
```

#### Cambios en variantes

| Línea | Antes | Después |
|-------|-------|---------|
| 51 | `Vector(Rc<RefCell<Vec<Value>>>)` | `Vector(Shared<Vec<Value>>)` |
| 58 | `Record(Rc<RefCell<HashMap<String, Value>>>)` | `Record(Shared<HashMap<String, Value>>)` |
| 69 | `MutableRef(Rc<RefCell<Value>>)` | `MutableRef(Shared<Value>)` |
| 77 | `Generator(Rc<dyn Any>)` | `Generator(Arc<dyn Any + Send + Sync>)` |
| 102 | `Iterator(Rc<dyn Any>)` | `Iterator(Arc<dyn Any + Send + Sync>)` |
| 106 | `Builder(Rc<dyn Any>)` | `Builder(Arc<dyn Any + Send + Sync>)` |
| 120 | `Sender(Rc<RefCell<...>>)` | `Sender(Arc<tokio::sync::mpsc::UnboundedSender<Value>>)` |
| 122 | `Receiver(Rc<RefCell<...>>)` | `Receiver(Arc<tokio::sync::Mutex<...>>)` |
| 126 | `MutexGuard(Rc<RefCell<...>>)` | `MutexGuard(Arc<tokio::sync::OwnedMutexGuard<Value>>)` |
| 128 | `Signal(Rc<RefCell<SignalState>>)` | `Signal(Shared<SignalState>)` |

#### Cambios en SignalState

```rust
// ANTES (líneas 131-138)
pub struct SignalState {
    pub value: Value,
    pub subscribers: Vec<std::rc::Weak<RefCell<EffectState>>>,
}

// DESPUÉS
pub struct SignalState {
    pub value: Value,
    pub subscribers: Vec<std::sync::Weak<RwLock<EffectState>>>,
}
```

#### Cambios en EffectState

```rust
// ANTES (líneas 141-150)
pub struct EffectState {
    pub callback: Value,
    pub dependencies: Vec<std::rc::Rc<RefCell<SignalState>>>,
}

// DESPUÉS
pub struct EffectState {
    pub callback: Value,
    pub dependencies: Vec<Shared<SignalState>>,
}
```

#### Cambios en helpers (líneas 159-244)

```rust
// ANTES
pub fn is_numeric_vector(vec: &Rc<RefCell<Vec<Value>>>) -> bool {
    vec.borrow().iter().all(...)
}

// DESPUÉS
pub fn is_numeric_vector(vec: &Shared<Vec<Value>>) -> bool {
    vec.read().iter().all(...)
}
```

Aplicar el mismo patrón a:
- `to_real_tensor()` (línea 169)
- `to_complex_tensor()` (línea 186)
- `from_real_tensor()` (línea 204)
- `from_complex_tensor()` (línea 214)
- `new_mutable()` (línea 232)
- `deref()` (línea 239)
- `assign()` (línea 248)

#### Cambios en PartialEq (líneas 347-421)

```rust
// ANTES
(Value::Vector(a), Value::Vector(b)) => Rc::ptr_eq(a, b),

// DESPUÉS
(Value::Vector(a), Value::Vector(b)) => Arc::ptr_eq(a, b),
```

Aplicar a todas las comparaciones `ptr_eq`.

### 1.2 VmFuture

**Archivo:** `crates/achronyme-types/src/value.rs` (líneas 25-42)

```rust
// ANTES
pub struct VmFuture(pub Shared<Pin<Box<dyn Future<Output = Value>>>>);

impl VmFuture {
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Value> + 'static,
    {
        VmFuture(future.boxed_local().shared())
    }
}

// DESPUÉS
pub struct VmFuture(pub futures::future::Shared<Pin<Box<dyn Future<Output = Value> + Send>>>);

impl VmFuture {
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Value> + Send + 'static,
    {
        VmFuture(future.boxed().shared())  // boxed() en lugar de boxed_local()
    }
}
```

### 1.3 Function types

**Archivo:** `crates/achronyme-types/src/function.rs`

```rust
// ANTES (línea 51)
VmClosure(Rc<dyn Any>),

// DESPUÉS
VmClosure(Arc<dyn Any + Send + Sync>),
```

### 1.4 Environment (si se usa en runtime)

**Archivo:** `crates/achronyme-types/src/environment.rs`

```rust
// ANTES
parent: Option<Rc<RefCell<Environment>>>,

// DESPUÉS
parent: Option<Shared<Environment>>,
```

---

## Fase 2: Migrar VM Core (achronyme-vm)

### 2.1 VM struct

**Archivo:** `crates/achronyme-vm/src/vm/mod.rs`

```rust
// ANTES (línea 40)
pub(crate) globals: Rc<RefCell<HashMap<String, Value>>>,

// DESPUÉS
pub(crate) globals: Shared<HashMap<String, Value>>,
```

```rust
// ANTES (línea 63)
pub(crate) active_effects: Vec<Rc<RefCell<EffectState>>>,

// DESPUÉS
pub(crate) active_effects: Vec<Shared<EffectState>>,
```

```rust
// ANTES (línea 71)
globals: Rc::new(RefCell::new(HashMap::new())),

// DESPUÉS
globals: shared(HashMap::new()),
```

### 2.2 Closure y Upvalues

**Archivo:** `crates/achronyme-vm/src/bytecode.rs`

```rust
// ANTES (línea 193)
pub upvalues: Vec<Rc<RefCell<Value>>>,

// DESPUÉS
pub upvalues: Vec<Shared<Value>>,
```

**Archivo:** `crates/achronyme-vm/src/vm/frame.rs`

```rust
// ANTES (línea 98)
pub upvalues: Vec<Rc<RefCell<Value>>>,

// DESPUÉS
pub upvalues: Vec<Shared<Value>>,
```

### 2.3 Generator state

**Archivo:** `crates/achronyme-vm/src/vm/generator.rs`

```rust
// ANTES (línea 24)
pub type VmGeneratorRef = Rc<RefCell<VmGeneratorState>>;

// DESPUÉS
pub type VmGeneratorRef = Shared<VmGeneratorState>;
```

### 2.4 Iterator y Builder

**Archivo:** `crates/achronyme-vm/src/vm/iterator.rs`

```rust
// ANTES (línea 20)
data: Rc<RefCell<Vec<Value>>>,

// DESPUÉS
data: Shared<Vec<Value>>,
```

**Archivo:** `crates/achronyme-vm/src/vm/execution/iterators.rs`

```rust
// ANTES (línea 16)
source: Rc<RefCell<Vec<Value>>>,

// DESPUÉS
source: Shared<Vec<Value>>,
```

---

## Fase 3: Migrar Builtins

### 3.1 Patrón de migración para .borrow() → .read()

En todos los archivos de builtins, aplicar:

```rust
// ANTES
let vec = rc.borrow();
let mut vec = rc.borrow_mut();

// DESPUÉS
let vec = arc.read();
let mut vec = arc.write();
```

### 3.2 Archivos a migrar (en orden)

1. **reactive.rs** - Sistema de signals (crítico)
2. **concurrency.rs** - Canales y mutex
3. **vector.rs** - Operaciones de vectores
4. **array_advanced.rs** - Operaciones avanzadas
5. **records.rs** - Operaciones de records
6. **complex.rs** - Números complejos
7. **encoding.rs** - JSON/Base64
8. **env.rs** - Variables de entorno
9. **linalg.rs** - Álgebra lineal
10. **math.rs** - Funciones matemáticas
11. **numerical.rs** - Métodos numéricos
12. **string.rs** - Operaciones de strings
13. **statistics.rs** - Estadísticas
14. **utils.rs** - Utilidades

### 3.3 reactive.rs (Detalle especial)

**Archivo:** `crates/achronyme-vm/src/builtins/reactive.rs`

Este archivo requiere cambios especiales por el sistema de tracking.

```rust
// ANTES (líneas 12-14)
thread_local! {
    static TRACKING_CONTEXT: RefCell<Option<Rc<RefCell<EffectState>>>> = RefCell::new(None);
}

// DESPUÉS - Usar Mutex para thread-safety
use parking_lot::Mutex;
use std::sync::Arc;

static TRACKING_CONTEXT: Mutex<Option<Arc<RwLock<EffectState>>>> = Mutex::new(None);
```

```rust
// ANTES (línea 30)
Ok(Value::Signal(Rc::new(RefCell::new(state))))

// DESPUÉS
Ok(Value::Signal(shared(state)))
```

```rust
// ANTES (línea 118)
let weak_effect = Rc::downgrade(current_effect);

// DESPUÉS
let weak_effect = Arc::downgrade(current_effect);
```

### 3.4 async_ops.rs (Cambio crítico)

**Archivo:** `crates/achronyme-vm/src/builtins/async_ops.rs`

```rust
// ANTES (líneas 93-98)
let future = async move { child_vm.run().await };

// We use spawn_local because Value is !Send (Rc)
let handle = tokio::task::spawn_local(future);

// DESPUÉS - Ahora podemos usar spawn regular!
let future = async move { child_vm.run().await };

// Value ahora es Send, podemos usar spawn multi-threaded
let handle = tokio::spawn(future);
```

---

## Fase 4: Migrar GUI

### 4.1 Eliminar thread_local para VM

**Archivo:** `crates/achronyme-vm/src/builtins/gui.rs`

```rust
// ANTES (líneas 13-15)
thread_local! {
    static ACTIVE_VM: RefCell<Option<*mut VM>> = RefCell::new(None);
}

// DESPUÉS - Usar Arc<Mutex> para acceso thread-safe
use std::sync::Arc;
use parking_lot::Mutex;

static ACTIVE_VM: Mutex<Option<Arc<Mutex<VM>>>> = Mutex::new(None);
```

```rust
// ANTES (líneas 88, 95-97)
ACTIVE_VM.with(|cell| {
    *cell.borrow_mut() = Some(vm as *mut VM);
});
// ...
ACTIVE_VM.with(|cell| {
    *cell.borrow_mut() = None;
});

// DESPUÉS
{
    let mut active = ACTIVE_VM.lock();
    *active = Some(Arc::new(Mutex::new(vm)));
}
// ...
{
    let mut active = ACTIVE_VM.lock();
    *active = None;
}
```

### 4.2 Bridge UI context

**Archivo:** `crates/achronyme-gui/src/bridge.rs`

```rust
// ANTES (líneas 10-12)
thread_local! {
    static CURRENT_UI: RefCell<Option<*mut Ui>> = RefCell::new(None);
}

// DESPUÉS - El UI context puede seguir siendo thread_local
// porque egui siempre corre en el main thread
// Solo necesitamos cambiar RefCell por Mutex para consistencia
use parking_lot::Mutex;

thread_local! {
    static CURRENT_UI: Mutex<Option<*mut Ui>> = Mutex::new(None);
}
```

---

## Fase 5: Migrar Runtime (CLI)

### 5.1 Cambiar de LocalSet a multi-thread

**Archivo:** `crates/achronyme-cli/src/main.rs`

```rust
// ANTES (líneas 96-106)
#[tokio::main(flavor = "current_thread")]
async fn main() {
    // ...
    let local = tokio::task::LocalSet::new();

    local
        .run_until(async move {
            // ...
        })
        .await;
}

// DESPUÉS
#[tokio::main]  // Default: multi-thread
async fn main() {
    // Ya no necesitamos LocalSet
    // El código async puede correr en cualquier hilo

    if let Some(command) = cli.command {
        match command {
            Commands::Run { file, debug_bytecode } => {
                run_file(&file, debug_bytecode || debug).await
            }
            // ...
        }
    }
}
```

### 5.2 Actualizar tests

Todos los tests que usan `LocalSet` deben actualizarse:

```rust
// ANTES
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap();

let local = tokio::task::LocalSet::new();
local.block_on(&rt, async { ... })

// DESPUÉS
let rt = tokio::runtime::Runtime::new().unwrap();
rt.block_on(async { ... })
```

**Archivos a actualizar:**
- `crates/achronyme-vm/src/tests/vm_integration_tests/helpers.rs`
- `crates/achronyme-vm/src/tests/builtins.rs`
- `crates/achronyme-vm/src/tests/array_advanced_integration.rs`
- `crates/achronyme-vm/src/tests/vm_integration_tests/async_await.rs`
- `crates/achronyme-vm/src/tests/vm_integration_tests/concurrency.rs`
- `crates/achronyme-vm/src/tests/vm_integration_tests/exceptions.rs`

---

## Fase 6: Arquitectura GUI + Async

### 6.1 Nueva arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                        PROCESO                                  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Main Thread (GUI)                                        │  │
│  │                                                           │  │
│  │  eframe::run_native()                                     │  │
│  │      └─ render_fn() cada frame                            │  │
│  │          ├─ signal.read() → Lee valor actual              │  │
│  │          ├─ ui_button() click → signal.write()            │  │
│  │          └─ spawn() → Crea task en thread pool            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                    Arc<RwLock<Signal>>                          │
│                              │                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Tokio Thread Pool (Worker Threads)                       │  │
│  │                                                           │  │
│  │  Task 1: await http_get() → signal.write(result)          │  │
│  │  Task 2: await sleep() → signal.write(...)                │  │
│  │  Task N: ...                                              │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.2 Flujo de datos

1. **Usuario hace click en botón**
   - `ui_button()` retorna `true`
   - Código del usuario llama `spawn(async_fn)`

2. **spawn() crea task**
   - `tokio::spawn(future)` (no `spawn_local`)
   - Task se ejecuta en thread pool de tokio

3. **Task completa operación async**
   - `await http_get(...)` completa
   - `signal.write()` actualiza valor (thread-safe via `Arc<RwLock>`)

4. **Siguiente frame del GUI**
   - `signal.read()` lee nuevo valor
   - UI se actualiza automáticamente

---

## Fase 7: Verificación

### 7.1 Checklist de compilación

- [ ] `cargo build -p achronyme-types` compila sin errores
- [ ] `cargo build -p achronyme-vm` compila sin errores
- [ ] `cargo build -p achronyme-gui` compila sin errores
- [ ] `cargo build -p achronyme-cli` compila sin errores
- [ ] `cargo build --workspace` compila sin errores

### 7.2 Checklist de tests

- [ ] `cargo test -p achronyme-types` pasa
- [ ] `cargo test -p achronyme-vm` pasa
- [ ] `cargo test -p achronyme-gui` pasa
- [ ] `cargo test -p achronyme-cli` pasa
- [ ] `cargo test --workspace` pasa

### 7.3 Tests de integración GUI + Async

Crear nuevo test:

**Archivo:** `examples/soc/40-gui-async-integration.soc`
```javascript
// Test: spawn() funciona dentro de GUI
let counter = signal(0)
let loading = signal(false)

let app = () => do {
    ui_label("Counter: " + str(counter.value))

    if (loading.value) {
        ui_label("Loading...")
    }

    if (ui_button("Increment Async")) {
        loading.set(true)
        spawn(async () => do {
            await sleep(100)
            counter.set(counter.peek() + 1)
            loading.set(false)
        })
    }

    // Auto-close después de 5 segundos
    if (counter.value >= 3) {
        ui_quit()
    }
}

gui_run(app, { title: "Async Test", width: 300, height: 200 })
println("Test passed: GUI + Async works!")
```

### 7.4 Verificar que ejemplos existentes funcionan

- [ ] `examples/soc/30-native-gui.soc`
- [ ] `examples/soc/31-native-plot.soc`
- [ ] `examples/soc/32-gui-styling.soc`
- [ ] `examples/soc/33-sine-wave.soc`
- [ ] `examples/soc/34-gui-components.soc`
- [ ] `examples/soc/35-gui-lifecycle.soc`

---

## Fase 8: Documentación

### 8.1 Actualizar architecture-debt-gui-async.md

Marcar como **RESUELTO** y documentar la solución.

### 8.2 Actualizar CHANGELOG.md

```markdown
## [0.7.0] - 2025-XX-XX

### Changed
- **BREAKING (interno)**: Migración de `Rc<RefCell<T>>` a `Arc<RwLock<T>>`
  - El sistema de valores ahora es thread-safe
  - `spawn()` usa `tokio::spawn` en lugar de `spawn_local`
  - Mejor rendimiento en operaciones async

### Fixed
- `spawn()` ahora funciona correctamente dentro de callbacks de GUI
- Las operaciones async ya no bloquean el event loop del GUI
```

---

## Consideraciones de Rendimiento

### Overhead esperado

| Operación | Rc<RefCell> | Arc<RwLock> | Diferencia |
|-----------|-------------|-------------|------------|
| Clone | ~2 ns | ~5 ns | +3 ns |
| Read | ~3 ns | ~10 ns | +7 ns |
| Write | ~5 ns | ~15 ns | +10 ns |

**Impacto real:** Insignificante para un lenguaje interpretado donde cada operación de VM toma microsegundos.

### Optimizaciones futuras (opcionales)

1. **Copy-on-Write para vectores pequeños**
2. **Thread-local caching para lecturas frecuentes**
3. **Lock-free counters para reference counting**

---

## Riesgos y Mitigaciones

| Riesgo | Probabilidad | Impacto | Mitigación |
|--------|--------------|---------|------------|
| Deadlocks | Media | Alto | Usar `parking_lot` (no tiene poisoning), ordenar locks |
| Regresión de rendimiento | Baja | Medio | Benchmarks antes/después |
| Bugs de concurrencia | Media | Alto | Tests exhaustivos, `loom` para model checking |
| Incompatibilidad con código existente | Baja | Bajo | La API de usuario no cambia |

---

## Orden de Implementación Recomendado

1. **Fase 0**: Preparación (1 hora)
2. **Fase 1**: Tipos core (4 horas)
3. **Fase 2**: VM core (3 horas)
4. **Fase 3**: Builtins (6 horas)
5. **Fase 4**: GUI (2 horas)
6. **Fase 5**: Runtime (1 hora)
7. **Fase 6**: Integración (2 horas)
8. **Fase 7**: Verificación (2 horas)
9. **Fase 8**: Documentación (1 hora)

**Total estimado:** ~22 horas de trabajo

---

## Conclusión

Esta migración resuelve el problema fundamental de GUI + Async sin cambiar la API del usuario. El código de Achronyme existente seguirá funcionando exactamente igual, pero ahora `spawn()` funcionará correctamente en cualquier contexto, incluyendo callbacks de GUI.

La clave es que `Arc<RwLock<T>>` proporciona las mismas garantías semánticas que `Rc<RefCell<T>>` (shared mutable state), pero con thread-safety adicional que permite la ejecución multi-threaded.
