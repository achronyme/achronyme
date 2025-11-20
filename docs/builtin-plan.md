

### 1\. Nueva Arquitectura: "The Native Interface"

Ya no llamaremos a las funciones directamente desde el nodo AST. Necesitamos una capa de abstracción intermedia (Middleware/Adapter) entre el bytecode de la VM y tu lógica de Rust existente.

#### Diferencias Clave:

| Característica | Tree Walker (Legacy) | VM (Nuevo) |
| :--- | :--- | :--- |
| **Input** | `Vec<AstNode>`, `&mut Environment` | `&[Value]` (slices de registros), `&mut VM` |
| **Resolución** | Búsqueda en HashMap en cada llamada | Índice directo (`u16`) resuelto al compilar |
| **Estado** | Mutaba `Environment` recursivo | Muta `VM State` o retorna nuevo `Value` |
| **HOFs** | Evaluaba AST bajo demanda | **Compiler Intrinsics** (transformación a bucles) |

### 2\. Estructura de Datos Propuesta

Necesitas un registro centralizado que mapee un índice numérico a un puntero de función nativa.

**Archivo:** `crates/achronyme-vm/src/builtins/registry.rs`

```rust
pub type NativeFn = fn(&mut VM, &[Value]) -> Result<Value, VmError>;

pub struct BuiltinMetadata {
    pub name: String,
    pub func: NativeFn,
    pub arity: u8, // Cantidad de argumentos esperados
}

pub struct BuiltinRegistry {
    // Mapeo rápido para el Compiler: String -> Index
    pub name_to_id: HashMap<String, u16>,
    // Mapeo rápido para la VM: Index -> Puntero de Función
    pub functions: Vec<BuiltinMetadata>,
}

impl BuiltinRegistry {
    pub fn register(&mut self, name: &str, func: NativeFn, arity: u8) {
        let id = self.functions.len() as u16;
        self.name_to_id.insert(name.to_string(), id);
        self.functions.push(BuiltinMetadata { name: name.to_string(), func, arity });
    }
    
    // O(1) access durante runtime
    pub fn get_fn(&self, id: u16) -> Option<NativeFn> {
        self.functions.get(id as usize).map(|m| m.func)
    }
}
```

### 3\. Plan de Refactorización (Extracción de Lógica)

El mayor riesgo es que tu lógica actual (seno, coseno, multiplicación de matrices) esté "sucia" con referencias al `Evaluator` o `Environment` del Tree Walker.

**Estrategia:** Refactorizar `achronyme-eval` a `achronyme-stdlib`.

1.  **Paso 1: Crear `crates/achronyme-stdlib`** (o usar `achronyme-types` si prefieres no crear otro crate).
2.  **Paso 2: Mover lógica pura.** Toma las funciones matemáticas de `achronyme-eval` y muévelas al nuevo crate.
      * *Antes (en eval):* `fn eval_sin(arg: &AstNode, env: &mut Env) -> Value { ... }`
      * *Después (en stdlib):* `fn math_sin(val: f64) -> f64 { val.sin() }`
3.  **Paso 3: Crear Adaptadores en la VM.**
      * En la VM, crea la función que desempaqueta el `Value`, llama a `math_sin`, y empaqueta el resultado.

### 4\. Implementación Técnica Paso a Paso

#### Paso 4.1: Opcode `CALL_BUILTIN`

Necesitas un opcode específico. Usar `CALL` normal es ineficiente porque implica crear un `CallFrame` completo para una función que es nativa de Rust.

**Opcode:** `CALL_BUILTIN dst, builtin_idx, argc`

```rust
// En el loop de la VM:
OpCode::CallBuiltin => {
    let dst = instruction.a;
    let builtin_idx = instruction.bx; // u16
    let argc = instruction.c; // O leer argumento siguiente si soporta > 255 args

    // 1. Obtener los argumentos de los registros
    // (El compilador debe haber puesto los args en un rango contiguo o pasamos punteros)
    let args_start_reg = ...; 
    let args = self.registers.slice(args_start_reg, argc);

    // 2. Buscar la función (Array lookup, muy rápido)
    let native_fn = self.builtins.get_fn(builtin_idx).unwrap();

    // 3. Ejecutar
    let result = native_fn(self, args)?;

    // 4. Guardar resultado
    self.registers.set(dst, result);
}
```

#### Paso 4.2: Higher-Order Functions (El reto técnico)

Funciones como `map`, `filter`, `reduce` **no deben ser funciones nativas estándar** en la VM si quieres rendimiento. Pasar un closure de la VM a Rust y que Rust llame de vuelta a la VM (`call_back`) es costoso y complejo (reentrancia).

**Solución Recomendada: Compiler Intrinsics (Expansión en línea)**

Cuando el compilador vea `map(fn, list)`, no emite `CALL_BUILTIN`. Emite bytecode equivalente a un bucle `for`.

**Ejemplo de transformación en el Compilador:**

```rust
// Código usuario:
// map(lista, mi_funcion)

// El compilador genera bytecode equivalente a:
// let __res = new_vector(len(lista));
// for __item in lista {
//    push(__res, mi_funcion(__item));
// }
```

*Si decides implementarlas como funciones nativas por simplicidad inicial:* Necesitarás un mecanismo en la VM para que Rust pueda invocar `vm.call_function(...)` dentro de la implementación de `builtin_map`.

#### Paso 4.3: Módulos y Namespacing

El sistema de módulos actual probablemente usa rutas de archivo. En la VM:

1.  El compilador resuelve `import math`.
2.  Busca en el `BuiltinRegistry` funciones con prefijo (ej. `math::sin` o simplemente las carga en el scope global del módulo compilado).
3.  Genera bytecode que referencia los índices correctos.

### 5\. Riesgos y Mitigación

| Riesgo | Impacto | Mitigación |
| :--- | :--- | :--- |
| **Reentrancia en VM** | Deadlocks o pánicos si una función nativa intenta llamar a la VM de nuevo (ej. `sort` con comparador custom). | Evitar reentrancia en funciones nativas simples. Para complejas, diseñar la VM para ser reentrante o usar *Compiler Intrinsics*. |
| **GC / Memory Leaks** | Los `Value` pasados a funciones nativas podrían perderse si hay pánicos. | Usar `Rc` correctamente. Asegurar que `VmError` propague correctamente y limpie el stack. |
| **Divergencia de Comportamiento** | La función en la VM se comporta distinto al Tree Walker. | Usar los mismos Unit Tests existentes, solo cambiando el "runner" de Evaluator a VM. |

### 6\. Checklist de Trabajo para tu Equipo

1.  **Infraestructura (Día 1-2):**

      * [ ] Crear `BuiltinRegistry` en la VM.
      * [ ] Implementar Opcode `CALL_BUILTIN`.
      * [ ] Modificar el compilador para detectar nombres de funciones built-in y emitir `CALL_BUILTIN` en lugar de `CALL`.

2.  **Migración Masiva (Día 3-10):**

      * *Patrón de Fábrica:* Crear macros en Rust para envolver funciones simples (`f64 -> f64`) automáticamente en la firma `NativeFn`.
      * [ ] Grupo Matemáticas (`sin`, `cos`, `sqrt`, etc.).
      * [ ] Grupo Strings (`len`, `split`, `replace`).
      * [ ] Grupo Arrays (`push`, `pop`, `len`).

3.  **Funciones Especiales (Día 11-15):**

      * [ ] Implementar `print` (acceso a stdout).
      * [ ] Implementar `input` (acceso a stdin/bloqueante).
      * [ ] Decidir estrategia para `map`/`filter`: ¿Intrinsics o Callbacks? (Recomiendo Intrinsics para v1).

4.  **Testing:**

      * [ ] Portar la suite de tests de `achronyme-eval` para que corra sobre la VM.

### Ejemplo de un "Wrapper" para la VM

Este código muestra cómo adaptarías una función existente para la VM:

```rust
// En crates/achronyme-vm/src/builtins/math.rs

use crate::vm::VM;
use crate::value::Value;
use crate::error::VmError;

// Función pura (lógica extraída)
fn math_sin(n: f64) -> f64 {
    n.sin()
}

// Wrapper para la VM
pub fn vm_sin(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    // Validación de tipos y aridad
    if args.len() != 1 {
        return Err(VmError::Runtime("sin() espera 1 argumento".into()));
    }

    match &args[0] {
        Value::Number(n) => Ok(Value::Number(math_sin(*n))),
        // Soporte para broadcasting (si aplica)
        Value::Vector(vec) => {
             // lógica de vectorización...
             todo!()
        },
        _ => Err(VmError::Type("Se esperaba un número".into()))
    }
}
```