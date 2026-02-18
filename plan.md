# Plan de Implementación: R1CS Compiler Backend

## Contexto

Achronyme tiene un lenguaje funcional completo (parser pest, compilador a bytecode, VM de registros) y un crate `constraints` funcional (R1CS, Poseidon, WitnessBuilder). El objetivo es conectar ambos: que el compilador pueda traducir un subconjunto del AST directamente a circuitos R1CS.

**Arquitectura elegida:** Backend paralelo (Opción B). Un `R1CSCompiler` separado que recorre el AST de pest y emite constraints en vez de bytecode. El compilador de VM no se modifica.

**Modelo de dos modos:** El lenguaje completo corre en la VM (closures, strings, I/O). Los bloques `circuit` compilan a R1CS via el R1CSCompiler. La VM sirve como witness calculator.

---

## Fase 0: Cableado (Conectar compiler ↔ constraints)

### 0.1 — Agregar dependencia de constraints al compiler

**Archivo:** `compiler/Cargo.toml`

Agregar `constraints = { path = "../constraints" }` a `[dependencies]`.

**Verificación:** `cargo build -p compiler` compila sin errores.

### 0.2 — Crear el módulo `r1cs_backend` en compiler

**Archivo nuevo:** `compiler/src/r1cs_backend.rs`

Struct principal:

```rust
use constraints::r1cs::{ConstraintSystem, LinearCombination, Variable};
use constraints::witness::WitnessBuilder;
use memory::FieldElement;
use std::collections::HashMap;

pub struct R1CSCompiler {
    pub cs: ConstraintSystem,
    /// Mapa de nombre de variable Achronyme → Variable R1CS
    pub bindings: HashMap<String, Variable>,
    /// Variables marcadas como public input
    pub public_inputs: Vec<String>,
    /// Variables marcadas como witness
    pub witnesses: Vec<String>,
}
```

Métodos iniciales:
- `new() -> Self`
- `declare_public(&mut self, name: &str) -> Variable`
- `declare_witness(&mut self, name: &str) -> Variable`
- `lookup(&self, name: &str) -> Result<Variable, R1CSError>`
- `compile_circuit(source: &str) -> Result<R1CSCompiler, R1CSError>` (entry point)

**Archivo nuevo:** `compiler/src/r1cs_error.rs`

```rust
pub enum R1CSError {
    UndeclaredVariable(String),
    UnsupportedOperation(String),
    TypeNotConstrainable(String),
    UnboundedLoop,
    ParseError(String),
}
```

**Archivo:** `compiler/src/lib.rs` — agregar `pub mod r1cs_backend; pub mod r1cs_error;`

**Verificación:** Compila. Tests unitarios para `declare_public`, `declare_witness`, `lookup`.

### 0.3 — Definir el subconjunto de gramática soportado

El R1CSCompiler acepta **solo** estas reglas del AST pest:

| Regla pest | Soporte R1CS | Traducción |
|---|---|---|
| `let_decl` | `let x = expr` | Evalúa expr → LC, bind al nombre |
| `number` (entero) | Literal de campo | `FieldElement::from_u64(n)` como constante |
| `identifier` | Referencia a wire | Lookup en `bindings` → LC |
| `add_expr` (+, -) | Operación lineal | `LC + LC` (sin constraint nuevo) |
| `mul_expr` (*, /) | Multiplicación | `cs.mul_lc(a, b)` → constraint + variable nueva |
| `pow_expr` (^) | Solo exponente literal ≤5 | Cadena de `mul_lc` |
| `cmp_expr` (==) | Solo en `assert_eq` | `cs.enforce_equal(a, b)` |
| `call_op` | Solo builtins ZK | Dispatch a `poseidon_hash_circuit`, etc. |
| `for` | Solo con range literal | Unroll estático |
| `if` | MUX constraint | `cond * a + (1-cond) * b` |
| `block` | Secuencia de stmts | Compilar cada stmt en orden |

**Rechazado con error claro:**
- `string`, `list_literal`, `map_literal` → `TypeNotConstrainable`
- `print_stmt` → `UnsupportedOperation("print cannot be constrained")`
- `fn_expr` (closures) → `UnsupportedOperation("closures not supported in circuits")`
- `forever` → `UnboundedLoop`
- `while` sin bound estático → `UnboundedLoop`
- `mut_decl` → `UnsupportedOperation("mutable variables not supported in circuits; use let")`

**Verificación:** Tests que compilan expresiones simples y tests que verifican errores claros para operaciones no soportadas.

---

## Fase 1: Compilación de expresiones aritméticas

### 1.1 — Compilar átomos

**Método:** `compile_atom(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError>`

- `number` → `LinearCombination::from_constant(FieldElement::from_u64(n))`
- `identifier` → lookup en `bindings`, retornar `LinearCombination::from_variable(var)`
- Otros átomos → `R1CSError::TypeNotConstrainable`

**Verificación:** Test que compila `42` y `x` (previamente declarado).

### 1.2 — Compilar expresiones binarias

**Método:** `compile_expr(&mut self, pair: Pair<Rule>) -> Result<LinearCombination, R1CSError>`

Recorre las capas de precedencia del AST pest:

- `add_expr`: `compile_expr(left) + compile_expr(right)` → operación sobre LCs, **sin constraint**
- `sub`: `compile_expr(left) - compile_expr(right)` → operación sobre LCs
- `mul_expr`: `cs.mul_lc(&lc_a, &lc_b)` → **genera constraint**, retorna LC del resultado
- `div`: `a * b_inv = 1` + `result = a * b_inv` → **2 constraints**

**Caso especial — multiplicación por constante:** Si uno de los operandos es puramente constante (LC con solo término ONE), usar `lc * scalar` en vez de `mul_lc`. Esto no genera constraint.

**Verificación:**
- Test: `let x = a + b` → 0 constraints
- Test: `let x = a * b` → 1 constraint
- Test: `let x = a * 3` → 0 constraints (escalar, no constraint)
- Test: `let x = a * b + c * d` → 2 constraints

### 1.3 — Compilar declaraciones let

**Método:** `compile_let(&mut self, pair: Pair<Rule>) -> Result<(), R1CSError>`

```
let_decl → nombre + expresión
```

1. Compilar la expresión → LC resultado
2. Si el LC tiene un solo término con coeff=1 (es una variable directa), bind el nombre a esa variable
3. Si el LC es complejo, materializar: `alloc_witness()` + `enforce_equal(lc, var)` → constraint
4. Guardar en `bindings[nombre] = variable`

**Verificación:** Test end-to-end: `let x = a * b; let y = x + 1` → 1 constraint, witness verifica.

### 1.4 — Compilar assert_eq

Reconocer el patrón `assert_eq(expr1, expr2)` (call a builtin):

```rust
let lc_a = self.compile_expr(arg1)?;
let lc_b = self.compile_expr(arg2)?;
self.cs.enforce_equal(lc_a, lc_b);
```

**Verificación:** Test: circuito `assert_eq(a * b, c)` con witness correcto verifica, con witness incorrecto falla.

---

## Fase 2: Control de flujo en circuitos

### 2.1 — For con unrolling estático

Solo soportar `for i in 0..N` donde N es un literal entero.

```rust
fn compile_for(&mut self, pair: Pair<Rule>) -> Result<(), R1CSError> {
    let var_name = ...;
    let (start, end) = parse_range_literal(...)?; // Error si no es literal
    for i in start..end {
        // Bind `var_name` a constante `i`
        self.bindings.insert(var_name.clone(), ...); // constante, no variable
        self.compile_block(body)?;
    }
}
```

**Verificación:** Test: `for i in 0..3 { let x_i = a * a }` genera 3 constraints.

### 2.2 — If como MUX constraint

```
if cond { a } else { b }
```

Se traduce a: `result = cond * a + (1 - cond) * b`

Requiere:
1. `cond` debe ser boolean (0 o 1) → agregar constraint: `cond * (1 - cond) = 0`
2. Compilar ambas ramas
3. Generar MUX: `result = cond * (a - b) + b`

Esto son 2 constraints (boolean check + MUX multiplication).

**Verificación:** Test: `if flag { a } else { b }` con flag=1 retorna a, con flag=0 retorna b.

---

## Fase 3: Builtins ZK

### 3.1 — Dispatch de builtins en compile_call

Cuando el R1CSCompiler encuentra una llamada a función, verificar si es un builtin ZK:

```rust
fn compile_call(&mut self, name: &str, args: Vec<LC>) -> Result<LC, R1CSError> {
    match name {
        "poseidon" => self.builtin_poseidon(args),
        "merkle_verify" => self.builtin_merkle_verify(args),
        "assert_eq" => self.builtin_assert_eq(args),
        "mux" => self.builtin_mux(args),
        _ => Err(R1CSError::UnsupportedOperation(format!("{name} is not a circuit builtin")))
    }
}
```

### 3.2 — Builtin: poseidon(left, right)

Wrapper directo sobre `poseidon_hash_circuit`:

```rust
fn builtin_poseidon(&mut self, args: Vec<LC>) -> Result<LC, R1CSError> {
    // Materializar args a variables si son LCs complejas
    let left_var = self.materialize(args[0])?;
    let right_var = self.materialize(args[1])?;
    let params = PoseidonParams::bn254_t3(); // cached
    let hash_var = poseidon_hash_circuit(&mut self.cs, &params, left_var, right_var);
    Ok(LinearCombination::from_variable(hash_var))
}
```

**Verificación:** Test: `let h = poseidon(a, b)` genera 360 constraints. Witness con hash nativo coincide.

### 3.3 — Builtin: merkle_verify (Merkle membership proof)

Circuito paramétrico para verificación de Merkle path:

```rust
fn builtin_merkle_verify(&mut self, args: Vec<LC>) -> Result<LC, R1CSError> {
    // args: leaf, root, path[], indices[]
    // Para cada nivel: poseidon(mux(index, path, current), mux(index, current, path))
    // assert_eq(resultado, root)
}
```

Esto usa `poseidon` + `mux` internamente.

**Verificación:** Test: Merkle tree de profundidad 3, verificar membership correcto e incorrecto.

---

## Fase 4: Witness generation via VM

### 4.1 — Witness calculator

El witness se genera ejecutando el circuito nativamente (no en R1CS). Crear helper:

```rust
pub struct WitnessCalculator {
    pub r1cs_compiler: R1CSCompiler,  // tiene el circuito compilado
}

impl WitnessCalculator {
    /// Dado public inputs + private inputs, ejecuta nativamente y llena el WitnessBuilder
    pub fn generate(&self, inputs: HashMap<String, FieldElement>) -> Result<Vec<FieldElement>, R1CSError> {
        let mut wb = WitnessBuilder::new(&self.r1cs_compiler.cs);
        // Asignar inputs conocidos
        for (name, value) in &inputs {
            let var = self.r1cs_compiler.lookup(name)?;
            wb.set(var, *value);
        }
        // Replay del circuito nativamente para calcular intermedios
        // (replicar lógica de compilación pero ejecutando en vez de constraining)
        ...
        Ok(wb.build())
    }
}
```

**Alternativa más simple para Fase 4:** En vez de un witness calculator automático, generar código Rust que haga el replay (como el test `test_poseidon_circuit_matches_native` actual). El usuario provee inputs, el sistema calcula todo lo demás.

**Verificación:** Test end-to-end: compilar circuito → generar witness → `cs.verify(&witness)` pasa.

---

## Fase 5: Exportación y CLI

### 5.1 — Exportar R1CS en formato snarkjs

Serializar el `ConstraintSystem` al formato binario `.r1cs` que snarkjs espera:

```
Header: magic + version + sections
Section 1: Header (field size, prime, num_variables, num_outputs, num_constraints)
Section 2: Constraints (sparse A, B, C matrices)
Section 3: Wire-to-label mapping
```

Referencia: https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md

**Archivo nuevo:** `constraints/src/export.rs`

**Verificación:** Exportar circuito Poseidon → cargar con snarkjs → `snarkjs r1cs info circuit.r1cs` muestra 360 constraints.

### 5.2 — Exportar witness en formato snarkjs

Serializar `Vec<FieldElement>` al formato `.wtns`:

```
Header: magic + version
Section 1: field size + prime
Section 2: witness values (little-endian 32-byte each)
```

**Archivo nuevo:** `constraints/src/witness_export.rs`

### 5.3 — Comando CLI: `ach circuit`

**Archivo:** `cli/src/commands/circuit.rs`

```
ach circuit compile input.ach -o circuit.r1cs    # Compila a R1CS
ach circuit witness input.ach -o witness.wtns     # Genera witness
ach circuit info input.ach                        # Muestra stats del circuito
```

**Verificación:** Pipeline completo:
```bash
ach circuit compile merkle.ach -o circuit.r1cs
ach circuit witness merkle.ach --input '{"leaf": "42", "root": "..."}' -o witness.wtns
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit.zkey
snarkjs groth16 prove circuit.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
# → OK!
```

---

## Fase 6: Demo — Merkle Membership Proof

### 6.1 — Circuito de ejemplo

**Archivo:** `examples/merkle_membership.ach`

```
circuit prove_membership {
    witness leaf, path_0, path_1, path_2, idx_0, idx_1, idx_2
    public root

    let current = poseidon(leaf, leaf)

    let left_0 = mux(idx_0, path_0, current)
    let right_0 = mux(idx_0, current, path_0)
    let current = poseidon(left_0, right_0)

    let left_1 = mux(idx_1, path_1, current)
    let right_1 = mux(idx_1, current, path_1)
    let current = poseidon(left_1, right_1)

    let left_2 = mux(idx_2, path_2, current)
    let right_2 = mux(idx_2, current, path_2)
    let current = poseidon(left_2, right_2)

    assert_eq(current, root)
}
```

### 6.2 — Test end-to-end en Rust

1. Construir Merkle tree nativo (3 niveles, 8 hojas)
2. Compilar circuito con R1CSCompiler
3. Generar witness
4. Verificar con `cs.verify()`
5. Exportar a snarkjs y verificar externamente

---

## Orden de ejecución y dependencias

```
Fase 0 (Cableado)
  0.1 Cargo.toml ──→ 0.2 R1CSCompiler struct ──→ 0.3 Subconjunto definido
                                                          │
Fase 1 (Expresiones)                                      │
  1.1 Átomos ──→ 1.2 Binarias ──→ 1.3 Let ──→ 1.4 assert_eq
                                                    │
Fase 2 (Control flow)                               │
  2.1 For unrolling ──→ 2.2 If/MUX                  │
                              │                      │
Fase 3 (Builtins)             │                      │
  3.1 Dispatch ──→ 3.2 Poseidon ──→ 3.3 Merkle      │
                                          │          │
Fase 4 (Witness)                          │          │
  4.1 WitnessCalculator ─────────────────┘           │
                                                     │
Fase 5 (Export + CLI)                                │
  5.1 R1CS export ──→ 5.2 Witness export ──→ 5.3 CLI│
                                                     │
Fase 6 (Demo)                                        │
  6.1 Ejemplo ──→ 6.2 Test E2E ─────────────────────┘
```

## Hito clave

Al completar Fase 3, tenemos el material para:
- Video/blogpost: "Merkle membership proof en Achronyme"
- Application a Ethereum Foundation ESP
- Demo funcional para hackathons

## Notas técnicas

- **LinearCombination como tipo central:** En el R1CSCompiler, cada expresión retorna un `LinearCombination`, no un `Variable`. Esto permite que sumas y restas sean gratis (operaciones sobre LCs sin constraints). Solo multiplicaciones y materializaciones generan constraints.
- **Caching de PoseidonParams:** `PoseidonParams::bn254_t3()` genera round constants determinísticamente. Cachear una sola instancia por compilación.
- **El fix de materialización en rondas parciales** (sesión actual) es prerequisito para que Poseidon funcione en circuitos.
