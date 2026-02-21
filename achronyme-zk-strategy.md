# Achronyme → ZK DSL: Estrategia Técnica y de Mercado

> Última actualización: Febrero 2026
> Estado: Fases 0-10 completadas, integración VM↔ZK Niveles 1-3 operativos, 2 auditorías resueltas. **646 tests, 2 backends, proofs Groth16 como valores first-class.**

---

## 1. Posicionamiento: El Océano Azul

El mercado de cómputo verificable está polarizado en dos extremos:

```
zkVMs Genéricas                              zkDSLs Puros
(RISC Zero, SP1, Jolt)                       (Cairo, Noir, Circom)
┌─────────────────────┐                      ┌─────────────────────┐
│ Prueban RISC-V/WASM │                      │ Circuitos eficientes│
│ Rust/C puro         │                      │ Sintaxis restrictiva│
│ Proofs pesadas      │                      │ Sin abstracciones   │
│ Lento, costoso      │                      │ dinámicas de alto   │
│                     │                      │ nivel               │
└─────────────────────┘                      └─────────────────────┘
         \                                          /
          \          ACHRONYME                     /
           \    ┌──────────────────┐             /
            └──>│ Expresivo (clos- │<───────────┘
                │ ures, recursión, │
                │ GC) + compilación│
                │ optimizada a     │
                │ circuitos ZK     │
                └──────────────────┘
```

**Achronyme NO es otra zkVM ni otro zkDSL restrictivo.** Es un lenguaje de alto nivel con dualidad de ejecución:

- **Modo VM:** Ejecución completa (closures, recursión, GC, strings, I/O) — off-chain, alta velocidad.
- **Modo Circuit:** El mismo lenguaje (subconjunto constrainable) compila a R1CS/Plonkish — on-chain, verificable.

La VM calcula witnesses; el circuit compiler emite constraints. Esta dualidad resuelve el problema fundamental de DX en ZK: el desarrollador escribe lógica legible, Achronyme decide qué va al circuito y qué se ejecuta off-chain.

---

## 2. Landscape Competitivo (Febrero 2026)

| Proyecto | Backing | Fortaleza | Debilidad |
|----------|---------|-----------|-----------|
| **Circom** | Comunidad | Estándar de facto, snarkjs | Bajo nivel, DX terrible |
| **Noir** (Aztec) | $100M+ funding | Rust-like, backend-agnostic (ACIR), pre-1.0 | Requiere entender unconstrained/constrained, sin abstracciones dinámicas reales |
| **Cairo** (StarkWare) | $250M+ | STARKs nativos, StarkNet | Atado a un ecosistema, sintaxis peculiar |
| **Leo** (Aleo/Provable) | $200M+ | Privacidad nativa | Atado a Aleo, adopción limitada |
| **o1js** (Mina) | $50M+ | TypeScript, pruebas en browser | Lento, ecosistema pequeño |
| **SP1** (Succinct) | $55M | Rust puro, RISC-V | Proofs inmensamente pesadas |
| **ZKCC** | 1 dev | Identity wallets EU | Muy early, Lua-based |

**Ninguno ha ganado la carrera.** La debilidad compartida: falta de DX real, comunidades pequeñas, testing primitivo.

---

## 3. Dónde Competir (y Dónde No)

### Evitar

1. **No replicar Noir** — Backend-agnostic Rust-like ya existe con $100M de funding.
2. **No competir en proving speed** — Guerra de infraestructura para equipos de 20+ criptógrafos.
3. **No atarse a una blockchain** — DSLs acoplados (Leo→Aleo) limitan adopción.
4. **No construir una zkVM genérica** — Probar RISC-V/WASM completo es innecesariamente costoso para un DSL.

### Atacar

#### Gap 1: Developer Experience
Escribir circuitos ZK se siente como programación de los 80s. Achronyme posiciona la **sintaxis funcional/matemática** como puente natural a constraints. El desarrollador piensa en funciones, Achronyme piensa en ecuaciones.

#### Gap 2: Testing y Detección de Bugs
Circuitos under-constrained son bugs de seguridad catastróficos. **Taint analysis en compile-time** (propagación Public/Private, detección de variables no-constrainadas) es un diferenciador que ningún DSL actual ofrece de forma nativa.

#### Gap 3: Computación Científica Verificada
DeFi Quants y ZKML necesitan ejecutar modelos propietarios off-chain sin revelar pesos algorítmicos, probando solo el resultado on-chain. El modelo dual VM+Circuit de Achronyme encaja naturalmente: la VM ejecuta el modelo completo, el circuit compiler prueba el resultado.

#### Gap 4: Identidad y Credenciales Verificables
EU Digital Identity Wallet, passports ZK, pruebas de humanidad. Nicho donde un equipo pequeño puede hacer impacto real — las implementaciones actuales son C++ difícil de auditar o están atadas a ecosistemas específicos.

---

## 4. Arquitectura Técnica

### Stack Actual (Febrero 2026)

```
┌──────────────────────────────────────────────────┐
│              Achronyme DSL Layer                  │
│   (pest PEG grammar, funcional/matemática)       │
├──────────────────────────────────────────────────┤
│         Taint Analysis + Bool Propagation         │
│   (Public/Witness/Constant tracking, under-      │
│    constraint detection, boolean optimization)    │
├──────────────────────────────────────────────────┤
│         SSA Intermediate Representation           │
│   (Const fold, DCE, bool_prop, LC simplify)       │
├──────────────┬──────────────┬────────────────────┤
│   R1CS       │  Plonkish    │   (Future)         │
│   Backend    │  Backend     │   STARK/AIR        │
│   (Groth16)  │  (Halo2,     │                    │
│   646 tests  │   Plonky3)   │                    │
├──────────────┴──────────────┴────────────────────┤
│  Export: .r1cs/.wtns (snarkjs compat)            │
├──────────────────────────────────────────────────┤
│  CLI: circuit --backend r1cs|plonkish            │
│       run | compile | disassemble | repl         │
└──────────────────────────────────────────────────┘
         FieldElement (BN254 Montgomery, [u64;4])
```

### VM: Motor de Ejecución Dual

```
┌──────────────────────────────────────────────────┐
│   NaN-Boxing Value System (64-bit tagged union)   │
│                                                   │
│   TAG_INT (i32)  ──→ Contadores, índices          │
│   TAG_NUMBER (f64) → Aritmética general           │
│   TAG_FIELD (BN254) → Crypto / ZK ←── CLAVE      │
│   TAG_PROOF (Groth16) → Proofs first-class ←─ NEW │
│   TAG_STRING ──→ I/O, debugging                   │
│   TAG_LIST/MAP → Estructuras de datos             │
│   TAG_CLOSURE ─→ Funciones first-class            │
│                                                   │
│   Promoción: INT→Field (auto), Float×Field (error)│
├──────────────────────────────────────────────────┤
│   Register-based VM (65K stack, mark-sweep GC)    │
│   60+ opcodes, closures, upvalues, iterators      │
└──────────────────────────────────────────────────┘
```

**Estado actual**: VM y pipeline ZK están completamente integrados. La VM ejecuta lógica general y delega secciones ZK al pipeline IR→R1CS→snarkjs en runtime. Los bloques `prove {}` generan proofs Groth16 reales como valores first-class (`TAG_PROOF`), inspeccionables via `proof_json()`, `proof_public()`, `proof_vkey()`. El IR Evaluator valida inputs antes de compilar constraints. Fallback graceful a verify-only cuando snarkjs no está disponible.

### Decisiones Arquitectónicas Clave

**1. SSA IR (Fase 5) ✅ Completado**
IR en Static Single Assignment entre el parser y los backends:
- Variables inmutables por definición — SSA es el mapeo natural.
- Pases de optimización: constant folding global, DCE, boolean propagation.
- Desacopla los backends: el mismo IR compila a R1CS o Plonkish.
- Cada constraint eliminada reduce gas y tiempo de prueba.

**2. Taint Analysis (Fase 7) ✅ Completado**
Forward + backward analysis sobre el IR:
- Tags `Constant`/`Public`/`Witness` con propagación de merge.
- Backward fixpoint desde `AssertEq`/`Assert` detecta variables under-constrained.
- Warning `UnusedInput` para declaraciones nunca referenciadas.

**3. NO Memory Checking Arguments**
El reviewer externo sugirió implementar modelos de memoria offline (Permutation/Sumcheck, estilo SP1/Jolt). **Rechazado.** Eso es arquitectura de zkVM genérica, no de DSL. El modelo dual de Achronyme (VM para ejecución dinámica, circuit compiler para el subconjunto constrainable) es la solución correcta — es exactamente lo que hacen Noir (unconstrained vs constrained) y Cairo (hints vs constraints). Si en el futuro se necesitan accesos a arrays dentro de circuitos, se implementan lookup arguments puntuales.

**4. Plonkish como segundo backend (Fase 8) ✅ Completado**
R1CS/Groth16 primero por compatibilidad snarkjs. Plonkish operativo con custom gates, lookup tables y range checks O(1). Ambos backends auditados y con copy-constraint soundness verificada.

**5. Integración VM↔ZK: La Próxima Frontera**

Análisis de viabilidad completado (Febrero 2026). El NaN-boxing se preserva — `TAG_FIELD` ya existe y coexiste con strings, listas, closures. No es necesario eliminar `f64` ni reducir la expresividad del lenguaje.

*Ver sección 9 para el plan de integración detallado.*

---

## 5. Roadmap de Desarrollo

### Fases Completadas

#### Fase 0: Cableado ✅
- `R1CSCompiler`, `ConstraintSystem`, wire layout snarkjs-compatible

#### Fase 1: Compilación Aritmética ✅
- Pipeline expresión → LC, constant folding, `multiply_lcs`/`divide_lcs`/`pow_by_squaring`
- **34 tests**

#### Fase 2: Control de Flujo ✅
- `for` con unrolling estático, `if/else` como MUX (2 constraints), blocks
- Rechazo de `while`/`forever`/`fn`/`break`/`continue`

#### Fase 3: Builtins ZK ✅
- `poseidon(left, right)` (~361 constraints), `mux(cond, a, b)` (2 constraints)
- `materialize_lc` helper, lazy PoseidonParams
- **71 tests**

#### Fase 4: Witness Generation ✅
- `WitnessOp` trace + `WitnessGenerator` replay
- Covers Multiply, Inverse, AssignLC, PoseidonHash, IsZero, BitExtract
- **85 compiler tests, 155 workspace**

#### Fase 5: SSA IR ✅
- Crate `ir/` con `SsaVar`, `Instruction`, `IrProgram`
- `IrLowering` (AST→IR), `compile_ir` (IR→R1CS)
- Optimization passes: constant folding + DCE
- **222 workspace tests**

#### Fase 6: Export & CLI ✅
- `.r1cs`/`.wtns` en formato binario iden3 (snarkjs compatible)
- CLI `circuit` subcommand con `--public`, `--witness`, `--inputs`
- **244 workspace tests**

#### Fase 7: Demo E2E ✅
- `public`/`witness` declaraciones in-source, `lower_self_contained()`
- Taint analysis (forward+backward), depth-3 Merkle E2E
- Groth16 snarkjs integration test
- **257 workspace tests**

#### Fase 8: Backend Plonkish ✅
- `PlonkishSystem` (gates, lookups, copies), `PlonkishCompiler` (IR→Plonkish)
- `RangeCheck`: R1CS O(bits), Plonkish O(1) via lookup
- CLI `--backend r1cs|plonkish`
- **301 workspace tests**

#### Fase 9: Operadores & Audit ✅
- `!=`, `<=`, `>=`, `&&`, `||`, `!`, `assert(expr)`, `true`/`false`
- IsZero gadget, 253-bit decomposition para ordenamiento
- `SourceSpan` error reporting, VM opcodes nuevos
- Audit fix: Plonkish IsZero soundness, Poseidon capacity wire, proptest
- **421 workspace tests** (post Phase 9c)

#### Deep Audit (C1-C4, H1-H5, M1-M8) ✅
- **C1-C4**: Plonkish `constrain_constant()` — copy constraints para soundness
- **H1-H5**: R1CS nPubIn/nPubOut swap, DuplicateInput, selector-based lookups
- **M1-M8**: Bounded IsLt/IsLe, bool propagation, LC simplify, circomlibjs Poseidon, big integer literals, negative CLI inputs, taint Sub/Div self-folding
- **518 workspace tests** (post deep audit)

#### Fase 10: Arrays, Functions, Crypto ✅
- Arrays: `[a, b, c]`, `a[i]`, `public/witness x[N]`, `for elem in arr`, `len(arr)`
- Functions: `fn f(x, y) { ... }` con inline expansion, recursion guard
- `poseidon_many(...)` variable-arity, `merkle_verify(root, leaf, path, indices)`
- **558 workspace tests** → **574 tras últimos fixes**

### Estado del Codebase

| Métrica | Valor |
|---------|-------|
| Tests passing | 646 |
| Backends | R1CS (Groth16) + Plonkish |
| VM↔ZK Integration | Nivel 1-3 (IR Evaluator + `prove {}` + proofs first-class) |
| Proof generation | Groth16 via snarkjs (con fallback verify-only) |
| Audit findings | 100% resueltos (C1-4, H1-5, M1-8, L1-4, T1-5) |
| Optimization passes | const_fold, DCE, bool_prop, LC simplify |
| Export formats | .r1cs v1, .wtns v2 (snarkjs compatible) |
| Value types | 10 tags (Number, Int, Nil, Bool, String, List, Map, Function, Field, **Proof**) |
| Builtins | poseidon, poseidon_many, mux, assert, assert_eq, range_check, merkle_verify, len |
| Natives | 12 (print, len, typeof, assert, time, push, pop, keys, field, proof_json, proof_public, proof_vkey) |
| IR instructions | 19 (Const, Input, Add, Sub, Mul, Div, Neg, Mux, AssertEq, PoseidonHash, RangeCheck, Not, And, Or, IsEq, IsNeq, IsLt, IsLe, Assert) |
| VM opcodes | 61 (incluyendo Prove = 160) |

---

## 6. Capitalización Sin Vender Software

### Tier 1: Grants ($5K-$250K)

| Programa | Monto | Foco |
|----------|-------|------|
| **Ethereum Foundation ESP** | $10K-$250K | ZK tooling, public goods |
| **EF ZK Grants** | Variable | Proyectos ZK específicamente |
| **Aztec Grants** | $20K+ | Herramientas para ecosistema Noir/ZK |
| **ZKSync (ZK Nation)** | Variable | Gobernanza onchain |
| **Polygon** | Variable | zkEVM tooling |
| **Gitcoin Rounds** | Variable | Quadratic funding |
| **Solana SuperTeam** | Hasta $10K | Microgrants, fuerte en LATAM |

**Requisitos:** MVP funcional, repo open-source activo, proposal con milestones concretos y budget desglosado. Ciclo típico: 2-12 semanas.

**Estado**: El proyecto ya supera los requisitos de MVP — pipeline E2E funcional, 2 backends, 574 tests, 2 auditorías completas.

### Tier 2: Retroactive Public Goods Funding
- **Optimism RPGF** — Financia retroactivamente proyectos que demostraron valor.
- **Protocol Guild** — Contribuidores a infraestructura core de Ethereum.
- **Octant** — Yield de staking de Golem Foundation hacia public goods.

### Tier 3: Consultoría Técnica Derivada
- **Auditoría de circuitos ZK** — Mercado en crecimiento explosivo.
- **Workshops y educación** — Las foundations pagan por contenido educativo de calidad.
- **Integración custom** — Empresas que necesitan ZK en sus productos.

### Tier 4: Token/DAO (largo plazo, si hay masa crítica)
Token de gobernanza para roadmap, incentivos de comunidad, y treasury para desarrollo.

---

## 7. Distribución y Adopción

### Canales

1. **cargo install** — CLI instalable en un comando.
2. **Playground web** — WASM sandbox para escribir y probar circuitos sin instalar nada.
3. **GitHub Template Repos** — Boilerplates para casos de uso comunes.
4. **Docker images** — Para CI/CD y proving servers.

### Comunidad

1. **Documentación excepcional** — Factor #1 en surveys de adopción. Tutorials interactivos + referencia API + conceptuales.
2. **Presencia en hackathons** — ETHGlobal, ETHLatam, ZK Hack. Premios para proyectos con Achronyme.
3. **Contenido técnico** — Blog posts, papers, videos resolviendo problemas reales.
4. **Circuit library** — Colección curada: voting, identity proof, merkle proof, range proof.
5. **Discord/Telegram activo** — Soporte directo. Ecosistemas ZK son suficientemente pequeños.

### El Ángulo LATAM

Ventaja que la mayoría de proyectos ZK no tienen:
- DSL ZK con mejor documentación en español.
- Conexión con SuperTeam chapters de Solana en LATAM.
- Eventos: ETHLatam, Blockchain Summit Latam, DevConnect.
- LATAM está empujando DeFi hacia casos de uso del mundo real — hay demanda creciente y poca oferta de tooling ZK en español.

---

## 8. Resumen Ejecutivo

### Ventaja competitiva

1. **Dualidad de ejecución** — VM completa (closures, recursión, GC) + circuit compiler (R1CS/Plonkish). El desarrollador escribe una vez, Achronyme decide qué se prueba.
2. **Foco matemático nativo** — Otros DSLs vienen del mundo de la programación. Achronyme viene de las matemáticas.
3. **Seguridad en compile-time** — Taint analysis detecta circuitos under-constrained y fugas de datos privados antes de generar una sola prueba.
4. **Testing first-class** — 574 tests, 2 auditorías criptográficas completas, proptest para soundness.
5. **Posición LATAM** — Demanda creciente, poca oferta, comunidad técnica en español.

### Mercado

El mercado ZK tiene $11.7B+ en market cap. La Ethereum Foundation inyectó $32.65M en Q1 2025 solo hacia ZK research y tooling. La narrativa actual corona al cómputo verificable (coprocesadores ZK, ZKML) como el endgame de escalabilidad y privacidad.

### Principio rector

**No intentes ser Noir. Sé el lenguaje que hace que las matemáticas se conviertan en pruebas cero-conocimiento de forma natural.**

---

## 9. Integración VM↔ZK: Plan de Convergencia

### Estado actual de la VM

La VM ya tiene soporte nativo para field elements a través del NaN-boxing:

```
TAG_FIELD = 8  →  Arena<FieldElement> en heap
               →  Promoción automática INT→Field
               →  Rechazo Float×Field (no-determinístico)
               →  Aritmética completa: add, sub, mul, div, neg, pow
```

El NaN-boxing **se preserva** — `TAG_FIELD` coexiste con `TAG_STRING`, `TAG_LIST`, `TAG_CLOSURE`, etc. No hay necesidad de eliminar `f64` ni reducir la expresividad. Los tres tracks numéricos son complementarios:

| Track | Tag | Bits | Uso |
|-------|-----|------|-----|
| Enteros | `TAG_INT` | i32 (32-bit) | Contadores de loop, índices |
| Flotantes | `TAG_NUMBER` | f64 (64-bit) | Aritmética general, `sqrt()` |
| Campo | `TAG_FIELD` | BN254 (256-bit, heap) | Crypto, witness, constraints |

### Integración completada: VM↔ZK en runtime

```
Antes:
  achronyme run program.ach     →  Bytecode → VM (ejecuta y descarta)
  achronyme circuit program.ach →  AST → IR → R1CS/Plonkish (constraints)

Ahora:
  achronyme run program.ach     →  Bytecode → VM → prove {} → IR → R1CS → verify ✓
  achronyme circuit program.ach →  AST → IR → eval → R1CS/Plonkish + witness
```

### Niveles de integración

#### Nivel 1: IR Evaluator + Unified Witness ✅ Completado

`ir::eval::evaluate()` ejecuta SSA programs con inputs concretos — validación temprana de assertions, divisiones por cero, e inputs faltantes antes de compilar constraints.

`compile_ir_with_witness()` en ambos backends (R1CS + Plonkish) unifica evaluación + compilación + witness en un solo paso. Elimina la necesidad de coordinar `compile_ir()` + `WitnessGenerator` por separado.

- `fill_poseidon_witness()` extraído como función standalone reutilizable
- CLI `circuit` actualizado para usar el pipeline unificado
- **613 tests** (39 nuevos)

#### Nivel 2: Bloques `prove { }` en la VM ✅ Completado

Constructo del lenguaje donde la VM ejecuta lógica general y delega secciones ZK:

```
let secret = field(42)
let nonce = field(0)
let h = poseidon_hash(secret, nonce)  // VM computa el hash

prove {
    witness s
    public h
    assert_eq(poseidon(s, 0), h)       // Circuit verifica
}
```

**Implementación**:
- `prove_expr` en la gramática (keyword + atom expression)
- Opcode `Prove = 160` (ABx: R[A]=capture map, K[Bx]=source string)
- Pre-scan en compile-time extrae nombres `public`/`witness` del bloque
- Captura automática de variables del scope → `BuildMap` → `FieldElement` map
- `ProveHandler` trait en VM (dependency injection), `DefaultProveHandler` en CLI
- Pipeline: strip braces → `lower_self_contained` → optimize → `compile_ir_with_witness` → verify
- Errors se propagan como `ProveBlockFailed`
- **637 tests** (24 nuevos, incluyendo Poseidon E2E)

#### Nivel 3: Proofs como Valores First-Class ✅ Completado

`prove {}` evoluciona para generar proofs Groth16 reales y devolverlos como valores first-class:

```
let secret = field(42)
let p = prove {
    witness secret
    assert_eq(secret, 42)
}
let json = proof_json(p)    // Extraer proof serializable
print(json)
```

**Implementación**:
- `ProofObject` struct (proof_json, public_json, vkey_json) en heap con `TAG_PROOF=9`
- `ProveResult` enum: `VerifiedOnly` (sin snarkjs) | `Proof { ... }` (con snarkjs)
- `DefaultProveHandler` con pipeline Groth16 completo: r1cs→ptau ceremony→zkey→prove→verify
- Caching de `.zkey` en `~/.achronyme/cache/` por hash del r1cs
- `snarkjs_available()` para fallback graceful
- 3 natives: `proof_json(p)`, `proof_public(p)`, `proof_vkey(p)`
- `--ptau <path>` flag para reusar powers-of-tau externos
- **646 tests** (9 nuevos)

#### Nivel 4: Siguiente paso

- Keyword `circuit` como syntactic sugar para `fn` + `prove`
- `verify_proof(proof, vkey)` nativo en la VM
- Prover nativo Rust (arkworks/bellman) para eliminar dependencia de Node.js
- Export Plonkish a formato binario

### Análisis de deuda técnica (auditoría interna, Febrero 2026)

La auditoría de 6 agentes identificó áreas de mejora previas a la integración:

| Área | Hallazgo | Impacto | Prioridad |
|------|----------|---------|-----------|
| `memory/heap.rs` | 8 métodos `alloc_*` + 8 bloques `sweep` copy-pasted | ~300 LOC eliminables con genéricos | Media |
| `constraints/plonkish.rs` | Lookup verification O(M·N²) con `Vec::contains` | Catastrófico para tablas grandes | Alta |
| `compiler/` | `compile_circuit()` AST-directo duplica `compile_ir()` | ~500 LOC muertos | Media |
| `compiler/` | Bytecode compiler (`codegen.rs`) sin uso en pipeline ZK | ~1,100 LOC pero necesario para VM | Baja* |
| `ir/lower.rs` | Monolito de 1,674 líneas, funciones re-parsean source | Escalabilidad limitada | Media |
| Parser | ~188 referencias `Rule::*` dispersas, sin AST intermedio | Acoplamiento total al parser | Alta |

*El bytecode compiler es pieza esencial de la integración VM↔ZK — `compile_prove` en `control_flow.rs` genera el opcode `Prove` que delega al pipeline IR→R1CS.

### Prioridades de la próxima fase

1. **Fix lookup O(N²)** en Plonkish → `HashSet` (quick win, alta importancia)
2. **`verify_proof()` nativo** — verificar proofs Groth16 dentro de la VM
3. **Prover nativo Rust** — eliminar dependencia de Node.js/snarkjs
4. **VM nativa Poseidon** — `poseidon()` como función nativa en la VM
5. **Eliminar `compile_circuit()` directo** (duplicado de `compile_ir()`)
6. **AST intermedio** → desacoplar pest del resto del pipeline
7. **Export Plonkish** → formato binario (actualmente solo R1CS exporta)
8. **Ceremonia segura** — reemplazar entropía hardcoded en trusted setup
