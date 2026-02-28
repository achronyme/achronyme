# Achronyme: Estrategia Técnica y de Mercado

> Última actualización: Febrero 2026
> Estado: v0.1.0-beta.1 — 1,008 tests, 2 backends con provers nativos Rust, 2 auditorías criptográficas limpias, pipeline E2E funcional.

---

## 1. Posicionamiento

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

## 2. Landscape Competitivo

| Proyecto | Backing | Fortaleza | Debilidad |
|----------|---------|-----------|-----------|
| **Circom** | Comunidad | Estándar de facto, snarkjs | Bajo nivel, DX terrible |
| **Noir** (Aztec) | $100M+ funding | Rust-like, backend-agnostic (ACIR) | Requiere entender unconstrained/constrained, sin abstracciones dinámicas reales |
| **Cairo** (StarkWare) | $250M+ | STARKs nativos, StarkNet | Atado a un ecosistema, sintaxis peculiar |
| **Leo** (Aleo/Provable) | $200M+ | Privacidad nativa | Atado a Aleo, adopción limitada |
| **o1js** (Mina) | $50M+ | TypeScript, pruebas en browser | Lento, ecosistema pequeño |
| **SP1** (Succinct) | $55M | Rust puro, RISC-V | Proofs inmensamente pesadas |

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

### Stack

```
┌──────────────────────────────────────────────────┐
│              Achronyme DSL Layer                  │
│   (Hand-written Pratt parser, AST intermedio)    │
├──────────────────────────────────────────────────┤
│         Taint Analysis + Bool Propagation         │
│   (Public/Witness/Constant tracking, under-      │
│    constraint detection, boolean optimization)    │
├──────────────────────────────────────────────────┤
│         SSA Intermediate Representation           │
│   (Const fold, DCE, bool_prop, LC simplify)       │
├──────────────┬───────────────────────────────────┤
│   R1CS       │  Plonkish                         │
│   Backend    │  Backend                          │
│   (Groth16   │  (KZG-PlonK                       │
│    ark-groth │   halo2-PSE                       │
│    16, nativ)│   nativo)                         │
├──────────────┴───────────────────────────────────┤
│  Export: .r1cs/.wtns (snarkjs compat)            │
│  Solidity verifier (--solidity)                  │
├──────────────────────────────────────────────────┤
│  CLI: circuit --backend r1cs|plonkish            │
│       run | compile | disassemble                │
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
│   TAG_FIELD (BN254) → Crypto / ZK                 │
│   TAG_PROOF (Groth16/PlonK) → Proofs first-class  │
│   TAG_BIGINT256/512 → Aritmética de precisión fija│
│   TAG_STRING ──→ I/O, debugging                   │
│   TAG_LIST/MAP → Estructuras de datos             │
│   TAG_CLOSURE ─→ Funciones first-class            │
│                                                   │
│   Overflow: INT → error (uso explícito de 0p)     │
│   Float×Field → TypeError (no-determinístico)     │
├──────────────────────────────────────────────────┤
│   Register-based VM (65K stack, mark-sweep GC)    │
│   36 opcodes, closures, upvalues, iterators       │
│   32 natives, 20 IR instructions                  │
└──────────────────────────────────────────────────┘
```

### Provers Nativos

Ambos backends tienen provers nativos en Rust — **no hay dependencia de Node.js/snarkjs** para generar proofs:

- **Groth16**: ark-groth16 + ark-bn254 (`cli/src/groth16.rs`). Setup, prove, verify in-process. Caching de `.zkey` por hash SHA256 del R1CS.
- **PlonK**: halo2 KZG (`cli/src/halo2_proof.rs`). PSE fork. ParamsKZG setup con caching por `k`. ProverSHPLONK + VerifierSHPLONK.

Ambos seleccionables via `--prove-backend r1cs|plonkish` en la CLI.

### Decisiones Arquitectónicas Clave

**1. SSA IR** — IR en Static Single Assignment entre el parser y los backends. Variables inmutables por definición. Pases de optimización: constant folding, DCE, boolean propagation. Desacopla los backends: el mismo IR compila a R1CS o Plonkish.

**2. Taint Analysis** — Forward + backward analysis sobre el IR. Tags `Constant`/`Public`/`Witness` con propagación de merge. Backward fixpoint desde `AssertEq`/`Assert` detecta variables under-constrained. Warning `UnusedInput` para declaraciones nunca referenciadas.

**3. NO Memory Checking Arguments** — El modelo dual de Achronyme (VM para ejecución dinámica, circuit compiler para el subconjunto constrainable) es la solución correcta. Si en el futuro se necesitan accesos a arrays dentro de circuitos, se implementan lookup arguments puntuales.

**4. Parser desacoplado** — Parser hand-written (Pratt + recursive descent) con AST intermedio propio. Sin dependencia de pest ni gramáticas PEG. El AST es la interfaz estable entre el parser y el resto del pipeline.

### Integración VM↔ZK

```
achronyme run program.ach     →  Bytecode → VM → prove {} → IR → R1CS/Plonkish → proof ✓
achronyme circuit program.ach →  AST → IR → eval → R1CS/Plonkish + witness + proof
```

Los 3 niveles de integración están completados:

1. **IR Evaluator + Unified Witness** — `compile_ir_with_witness()` en ambos backends unifica evaluación + compilación + witness en un solo paso.
2. **Bloques `prove {}`** — La VM ejecuta lógica general y delega secciones ZK al pipeline IR→backend→proof. Captura automática de variables del scope.
3. **Proofs como Valores First-Class** — `prove {}` genera proofs reales (Groth16 o PlonK) como valores del lenguaje. `proof_json()`, `proof_public()`, `proof_vkey()`, `verify_proof()`.

---

## 5. Estado del Codebase

| Métrica | Valor |
|---------|-------|
| Versión | 0.1.0-beta.1 |
| Tests passing | 1,008 |
| Backends | R1CS (Groth16/ark) + Plonkish (KZG-PlonK/halo2) |
| Provers | Nativos Rust (ark-groth16 + halo2-PSE), in-process |
| Audit findings | 100% resueltos (C1-4, H1-5, M1-8, L1-4, T1-5) |
| Optimization passes | const_fold, DCE, bool_prop, LC simplify |
| Export formats | .r1cs v1, .wtns v2 (snarkjs compatible), Solidity verifier |
| Value types | Int, Number, Nil, Bool, String, List, Map, Closure, Field, Proof, BigInt256, BigInt512 |
| VM natives | 32 (core, strings, collections, crypto, proof, bigint) |
| IR instructions | 20 |
| VM opcodes | 36 |
| GC | Mark-sweep funcional, tri-color, arena-based slot reuse |
| Parser | Hand-written Pratt, AST intermedio, sin pest |

### Builtins de Circuito

| Builtin | Descripción | R1CS cost | Plonkish cost |
|---------|-------------|-----------|---------------|
| `assert_eq(a, b)` | Enforce equality | 1 | 1 |
| `assert(expr)` | Enforce boolean true | 2 | 2 |
| `poseidon(a, b)` | Poseidon 2-to-1 hash | 361 | 361 |
| `poseidon_many(a, b, c, ...)` | Left-fold Poseidon | 361*(n-1) | 361*(n-1) |
| `mux(cond, a, b)` | Conditional select | 2 | 1 |
| `range_check(x, bits)` | Value fits in N bits | bits+1 | 1 (lookup) |
| `merkle_verify(root, leaf, path, indices)` | Merkle membership proof | ~1090/level | ~1090/level |
| `len(arr)` | Compile-time array length | 0 | 0 |

---

## 6. Roadmap

### Completado

| Fase | Hito | Tests |
|------|------|-------|
| 0-3 | Cableado, aritmética, control flow, builtins ZK | 71 |
| 4 | Witness generation (WitnessOp trace + replay) | 155 |
| 5 | SSA IR (SsaVar, IrLowering, const_fold, DCE) | 222 |
| 6 | Export .r1cs/.wtns + CLI circuit | 244 |
| 7 | Demo E2E, taint analysis, Merkle E2E | 257 |
| 8 | Backend Plonkish (gates, lookups, copies) | 301 |
| 9 | Operadores completos + audit Phase 9 | 421 |
| — | Deep audit 8-agent (C1-C4, H1-H5, M1-M8) | 518 |
| 10 | Arrays, functions, poseidon_many, merkle_verify | 574 |
| 10a | Type annotation soundness (Bool enforcement) | — |
| 10b | Remove silent Int→Field promotion | — |
| 11 | Maturity: VM natives, proof verification, error tracking | 646 |
| — | Field literals (0p syntax), BigInt256/512 | 1,008 |
| — | Native provers (ark-groth16 + halo2-KZG), Solidity verifier | — |
| — | Hand-written parser (desacoplado de pest) | — |

### Siguiente: v0.1.0 (First Stable Release)

| Prioridad | Item | Esfuerzo |
|-----------|------|----------|
| Alta | Sistema de imports/módulos (`import "path"`) | Medio |
| Alta | REPL funcional | Bajo |
| Media | Mensajes de error educativos en IrLowering | Bajo |
| Media | Stdlib: `map`, `filter`, `reduce` para listas | Medio |
| Media | Export Plonkish binario | Medio |

### v0.2.0 — LSP + VS Code Extension

| Item | Esfuerzo |
|------|----------|
| LSP básico (diagnostics, go-to-definition) | Medio |
| TextMate grammar para syntax highlighting | Bajo |
| VS Code extension packaging | Bajo |

### v0.3.0 — Playground (WASM)

| Item | Esfuerzo |
|------|----------|
| Compilar VM + compiler a WASM | Medio |
| Frontend web (editor + output) | Medio |
| Tutoriales interactivos | Medio |

### v1.0.0 — Stable API Freeze

| Item | Esfuerzo |
|------|----------|
| Multi-curva via trait Field (BLS12-381, Pasta) | Alto |
| API pública estabilizada para crates.io | Medio |
| Breaking-change freeze | — |

---

## 7. Debilidades Técnicas Abiertas

### Bloquean adopción

| # | Debilidad | Impacto | Esfuerzo |
|---|-----------|---------|----------|
| D2 | **Una sola curva (BN254)** | No interoperable con BLS12-381 (EIP-2537), Pasta (Halo2/Zcash), ni campos STARK. | Alto — genericizar `FieldElement` sobre un trait `Field` |
| D4 | **Sin imports / sistema de módulos** | Todo es un archivo. Circuitos grandes son inmanejables. | Medio — `import "path"` con resolución de nombres |

### Degradan DX

| # | Debilidad | Impacto | Esfuerzo |
|---|-----------|---------|----------|
| D7 | **Comparaciones caras (~760 constraints)** | `x < y` es prohibitivo en circuitos sensibles al tamaño. Batching o range proofs más eficientes no implementados. | Alto |
| D8 | **Sin LSP / IDE support** | No hay autocompletado, go-to-definition, ni syntax highlighting oficial. | Medio |
| D9 | **REPL no funcional** | Registrado en CLI pero es un stub. | Bajo |
| D12 | **Sin export Plonkish binario** | El backend Plonkish compila y prueba pero no genera artefactos exportables. | Medio |

### Resueltas (desde la última revisión)

| # | Debilidad | Resolución |
|---|-----------|------------|
| ~~D1~~ | ~~Sin verificador on-chain~~ | `--solidity` genera contratos Solidity verificadores |
| ~~D3~~ | ~~GC placeholder~~ | Mark-sweep funcional, tri-color, arena-based, threshold adaptativo |
| ~~D5~~ | ~~Errores no educativos~~ | Errores con line numbers y function names (`last_error_location`) |
| ~~D6~~ | ~~Sin stdlib~~ | 32 natives: strings (substring, indexOf, split, trim, replace, toUpper, toLower, chars), collections (push, pop, keys), crypto (poseidon, poseidon_many, verify_proof), bigint (8 ops) |
| ~~D10~~ | ~~Lookup O(N²)~~ | `HashSet` para membership O(1) |
| ~~D11~~ | ~~Dependencia snarkjs~~ | Provers nativos Rust: ark-groth16 + halo2-KZG, in-process |

### Pending Tests

| # | Descripción |
|---|-------------|
| T7 | Poseidon zero inputs E2E through circuit pipeline |
| T8 | range_check edge cases (bits=0, 1, 253, max valid) |
| T9 | Missing Plonkish equivalents (for loops, if/else, poseidon+expr) |
| T10 | Witness corruption detection |
| T11 | Field serialization round-trip multi-limb |
| T12 | `from_decimal_str` edge cases |
| T13 | snarkjs integration tests in CI |
| T14 | CLI integration tests |

---

## 8. Capitalización

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

**Estado**: El proyecto supera ampliamente los requisitos de MVP — pipeline E2E, 2 backends con provers nativos, 1,008 tests, 2 auditorías criptográficas completas, Solidity verifier.

### Tier 2: Retroactive Public Goods Funding
- **Optimism RPGF** — Financia retroactivamente proyectos que demostraron valor.
- **Protocol Guild** — Contribuidores a infraestructura core de Ethereum.
- **Octant** — Yield de staking de Golem Foundation hacia public goods.

### Tier 3: Consultoría Técnica Derivada
- **Auditoría de circuitos ZK** — Mercado en crecimiento explosivo.
- **Workshops y educación** — Las foundations pagan por contenido educativo de calidad.
- **Integración custom** — Empresas que necesitan ZK en sus productos.

---

## 9. Estrategia Multi-Nicho

### Los 4 nichos y por qué no son mutuamente exclusivos

```
                    SDK embebible (Rust crate)
                    ┌─────────────────────┐
                    │  achronyme::prove!   │
                    │  Compila circuitos   │
                    │  inline desde Rust   │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     Educación          Solvencia      Credenciales
   ┌──────────────┐  ┌────────────┐  ┌──────────────┐
   │ Playground   │  │ Proof of   │  │ Selective    │
   │ web (WASM)   │  │ Reserves   │  │ disclosure   │
   │ Tutoriales   │  │ Audit      │  │ Age/identity │
   │ Cursos       │  │ DeFi       │  │ W3C VC       │
   └──────────────┘  └────────────┘  └──────────────┘
```

**El SDK es la base.** Educación, solvencia y credenciales son aplicaciones verticales que lo consumen.

### Secuencia

**Fase A: SDK horizontal (prerequisito)**
Exponer el pipeline IR→backend→proof como crate Rust embebible. Estabilizar la API pública, separar runtime de CLI (ya logrado con `ProveHandler` trait), publicar en crates.io.

**Fase B: Un vertical de demostración**
1. **Proof of Solvency** — Clientes inmediatos (exchanges post-FTX). `merkle_verify` + `poseidon` ya cubren el 80%.
2. **Selective Disclosure / Age Proof** — Más simple. Requiere EdDSA/ECDSA sobre BN254 como builtin.
3. **Educación** — Playground WASM + tutoriales progresivos. Menor barrera, menor impacto comercial directo.

**Fase C: Expansión**
Una vez que un vertical funciona, los otros son variaciones del mismo SDK. Los 4 nichos comparten >90% del stack técnico.

---

## 10. Distribución y Adopción

### Canales

1. **cargo install** — CLI instalable en un comando.
2. **Playground web** — WASM sandbox para escribir y probar circuitos sin instalar nada.
3. **GitHub Template Repos** — Boilerplates para casos de uso comunes.
4. **Docker images** — Para CI/CD y proving servers.

### Comunidad

1. **Documentación excepcional** — Factor #1 en adopción. Tutorials interactivos + referencia API + conceptuales.
2. **Presencia en hackathons** — ETHGlobal, ETHLatam, ZK Hack.
3. **Contenido técnico** — Blog posts, papers, videos resolviendo problemas reales.
4. **Circuit library** — Colección curada: voting, identity proof, merkle proof, range proof.
5. **Discord/Telegram activo** — Soporte directo.

### El Ángulo LATAM

- DSL ZK con mejor documentación en español.
- Conexión con SuperTeam chapters de Solana en LATAM.
- Eventos: ETHLatam, Blockchain Summit Latam, DevConnect.
- Demanda creciente de tooling ZK en español, poca oferta.

---

## 11. Riesgos de Mercado

### El elefante en la sala: Noir

Noir (Aztec) tiene $100M+ de funding, 15+ ingenieros, y ataca el mismo gap de DX. Su modelo `constrained`/`unconstrained` es conceptualmente similar a la dualidad VM/circuit de Achronyme. Diferencias clave:

- Noir NO tiene VM general (no hay closures, GC, I/O fuera de circuitos)
- Noir NO genera proofs inline como valores del lenguaje
- Noir SÍ tiene ecosystem (packages, IDE, community)
- Noir SÍ tiene backend-agnostic IR (ACIR) que soporta múltiples provers

**Conclusión**: No competir en "mejor DSL ZK general". Competir en "proofs como parte del lenguaje" (prove blocks) y en verticales específicos donde la ejecución dual es ventaja real.

### Timing

El mercado ZK está en una ventana de ~18-24 meses antes de que los ganadores se consoliden. Los grants de Ethereum Foundation y Aztec están activos ahora. Después de esa ventana, los ecosistemas se cierran alrededor de 2-3 stacks dominantes.

### El riesgo real

No es técnico. Es que el proyecto se quede como "impresionante repo de GitHub que nadie usa". La diferencia entre un proyecto técnicamente bueno y uno adoptado es: **un usuario que resolvió un problema real con él y lo contó**.

---

## 12. Ventaja Competitiva (Resumen)

1. **Dualidad de ejecución** — VM completa (closures, recursión, GC) + circuit compiler (R1CS/Plonkish). El desarrollador escribe una vez, Achronyme decide qué se prueba.
2. **Proofs como valores del lenguaje** — `prove {}` genera proofs Groth16/PlonK reales inline. Ningún otro DSL ZK ofrece esto.
3. **Provers nativos Rust** — ark-groth16 + halo2-KZG, in-process. Sin dependencias externas.
4. **Seguridad en compile-time** — Taint analysis detecta circuitos under-constrained antes de generar una sola prueba.
5. **Testing** — 1,008 tests, 2 auditorías criptográficas completas, proptest para soundness.
6. **Posición LATAM** — Demanda creciente, poca oferta, comunidad técnica en español.

### Principio rector

**No intentes ser Noir. Sé el lenguaje que hace que las matemáticas se conviertan en pruebas cero-conocimiento de forma natural.**
