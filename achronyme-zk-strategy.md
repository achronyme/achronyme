# Achronyme → ZK DSL: Estrategia Técnica y de Mercado

> Última actualización: Febrero 2026
> Estado: Fases 0-1 completadas (R1CS scaffold + compilación aritmética, 34+ tests)

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

### Stack Actual (Completado)

```
┌──────────────────────────────────────────────────┐
│              Achronyme DSL Layer                  │
│   (pest PEG grammar, expresiones funcionales)    │
├──────────────────────┬───────────────────────────┤
│   Bytecode Compiler  │    R1CS Compiler          │
│   (VM target)        │    (Circuit target)       │
│   - closures, GC     │    - aritmética ✓         │
│   - recursión        │    - let bindings ✓       │
│   - strings, I/O     │    - assert_eq ✓          │
│   - full language     │    - constant folding ✓   │
├──────────────────────┤    - control flow (WIP)   │
│   Register-based VM  ├───────────────────────────┤
│   (witness calc.)    │    ConstraintSystem       │
│                      │    - enforce(A*B=C)       │
│                      │    - mul_lc, inv_lc       │
│                      │    - verify(witness)      │
└──────────────────────┴───────────────────────────┘
         FieldElement (BN254 Montgomery, [u64;4])
```

### Arquitectura Target (Post Fase 5)

```
┌──────────────────────────────────────────────────┐
│              Achronyme DSL Layer                  │
│   (pest PEG grammar, funcional/matemática)       │
├──────────────────────────────────────────────────┤
│            Taint Analysis Layer                   │
│   (Public/Private propagation, under-constraint  │
│    detection, compile-time safety guarantees)     │
├──────────────────────────────────────────────────┤
│            SSA Intermediate Representation        │
│   (Constant folding, DCE, constraint dedup,      │
│    common subexpression elimination)              │
├──────────────┬──────────────┬────────────────────┤
│   R1CS       │  Plonkish    │   (Future)         │
│   Backend    │  Backend     │   STARK/AIR        │
│   (Groth16)  │  (Halo2,     │                    │
│              │   Plonky3)   │                    │
├──────────────┴──────────────┴────────────────────┤
│   Export: .r1cs/.wtns (snarkjs), Solidity verifier│
└──────────────────────────────────────────────────┘
```

### Decisiones Arquitectónicas Clave

**1. SSA IR (Fase 5)**
Actualmente AST → R1CS directo. Después de tener circuitos funcionales (control flow + builtins), insertar un IR en Static Single Assignment entre el parser y los backends. Justificación:
- Las variables en circuitos ZK son inmutables por definición — SSA es el mapeo natural.
- Habilita pases de optimización agresivos: constant folding global, dead code elimination, constraint deduplication, common subexpression elimination.
- Desacopla los backends: el mismo IR compila a R1CS (Groth16) o Plonkish (Halo2/Plonky3).
- Cada constraint eliminada reduce gas y tiempo de prueba directamente.

**2. Taint Analysis (Fase 2-3, incremental)**
Sistema de tipos afín que propaga tags `Public`/`Private`/`Derived(from)` por el flujo de datos:
- Error si un valor `Private` se usa donde se espera `Public` sin pasar por un constraint.
- Warning si una variable declarada nunca aparece en ningún constraint (potencialmente under-constrained).
- Garantías de soundness en compile-time, no en proving-time.

**3. NO Memory Checking Arguments**
El reviewer externo sugirió implementar modelos de memoria offline (Permutation/Sumcheck, estilo SP1/Jolt). **Rechazado.** Eso es arquitectura de zkVM genérica, no de DSL. El modelo dual de Achronyme (VM para ejecución dinámica, circuit compiler para el subconjunto constrainable) es la solución correcta — es exactamente lo que hacen Noir (unconstrained vs constrained) y Cairo (hints vs constraints). Si en el futuro se necesitan accesos a arrays dentro de circuitos, se implementan lookup arguments puntuales.

**4. Plonkish como segundo backend (Fase 8)**
R1CS/Groth16 primero porque:
- Compatibilidad inmediata con snarkjs (proving en browser).
- Proofs más pequeñas (~200 bytes) y verificación más barata on-chain.
- Ecosistema de trusted setup ceremonies ya existe.

Plonkish después porque:
- Custom gates y lookup tables hacen bit-shifts, XORs y hashing órdenes de magnitud más eficientes.
- Es el estándar moderno (Halo2, Plonky3).
- El SSA IR hace viable tener múltiples backends sin reescribir el compilador.

---

## 5. Roadmap de Desarrollo (8 Fases)

### Fases Completadas

#### Fase 0: Cableado ✅
- `R1CSCompiler` struct con `declare_public/witness`, `lookup`, `lookup_lc`
- `ConstraintSystem` con `enforce(A*B=C)`, `enforce_equal`, `mul_lc`, `inv_lc`, `verify(witness)`
- `R1CSError` con 5 variantes descriptivas
- Wire layout snarkjs-compatible: `[ONE, pub1..pubN, wit1..witM, intermediates...]`

#### Fase 1: Compilación Aritmética ✅
- Pipeline completo expresión → `LinearCombination`
- Constant folding: `const * var = 0 constraints`, `var * var = 1 constraint`
- `multiply_lcs` / `divide_lcs` / `pow_by_squaring` con costos óptimos
- `assert_eq` builtin (1 constraint)
- Let-binding lazy (almacena LC, no materializa)
- Negación como scalar mul (0 constraints)
- Rechazo explícito de tipos no-constrainable (string, bool, nil, list, map)
- **34 tests pasando** (8 básicos + 20 expresiones + 6 integración con witness verification)

### Fases Pendientes

#### Fase 2: Control de Flujo en Circuitos
- **For con unrolling estático:** `for i in 0..N { body }` → N copias del body con `i` como constante
- **If/Else como MUX:** `if cond { a } else { b }` → boolean check (1c) + MUX multiplication (1c) = 2 constraints
- **Block compilation:** Secuencia de statements dentro de `{ }`
- **Gramática:** Agregar `range_expr` (`start..end`) al parser pest
- **Rechazo:** `while` → `UnboundedLoop`, `forever` → `UnboundedLoop`, `fn_expr` → closures no soportadas
- **~20 tests nuevos** con verificación de witness

#### Fase 3: Builtins ZK
- **Dispatch de builtins** en `compile_postfix_expr`: `poseidon()`, `merkle_verify()`, `mux()`
- **Poseidon hash circuit:** Wrapper sobre `poseidon_hash_circuit`, ~360 constraints
- **Merkle verify:** Circuito paramétrico usando Poseidon + MUX internamente
- **Materialización:** LCs complejas → witness variables antes de pasar a builtins

#### Fase 2-3+ (Paralelo): Taint Analysis Básico
- Tags `Public`/`Private`/`Derived` propagados en el flujo de datos
- Error en compile-time si Private fluye a Public sin constraint
- Warning si variable declarada nunca se constraina (under-constrained)
- Integración incremental sobre `R1CSCompiler` existente

#### Fase 4: Witness Generation
- `WitnessCalculator`: dado inputs → ejecuta circuito nativamente → llena witness completo
- Replay de la lógica del circuit compiler pero evaluando en vez de constraining
- Test E2E: compilar → generar witness → `cs.verify(&witness)` pasa

#### Fase 5: SSA Intermediate Representation
- IR en SSA entre parser y backends
- Pases de optimización: constant folding global, DCE, constraint dedup, CSE
- Nuevo crate `ir/` en el workspace
- Los backends R1CS (y futuro Plonkish) consumen el IR, no el AST

#### Fase 6: Exportación y CLI
- Exportar `.r1cs` y `.wtns` en formato binario snarkjs
- CLI: `ach circuit compile`, `ach circuit witness`, `ach circuit info`
- Pipeline completo: compile → witness → snarkjs prove → snarkjs verify

#### Fase 7: Demo End-to-End
- Merkle membership proof: compile → prove → verify con snarkjs/Groth16
- Circuito de ejemplo documentado (`examples/merkle_membership.ach`)
- Blog post / video técnico demostrativo

#### Fase 8: Backend Plonkish
- Segundo backend desde el SSA IR
- Custom gates y lookup tables
- Reducción de circuitos de millones a miles de constraints para operaciones bitwise/hashing
- Base para ZKML eficiente

### Diagrama de Dependencias

```
Fase 0 ✅ ──→ Fase 1 ✅ ──→ Fase 2 ──→ Fase 3 ──────→ Fase 4 ──→ Fase 5 ──→ Fase 6 ──→ Fase 7
                               │           │                         │
                               └── Taint ──┘                        │
                                (paralelo)                          ↓
                                                                 Fase 8
```

### Hitos Clave

| Después de... | Acción |
|---------------|--------|
| **Fase 3** | Aplicar a Ethereum Foundation ESP con demo Poseidon/Merkle circuit |
| **Fase 5** | Blog post técnico: arquitectura SSA→R1CS, diferenciador vs competencia |
| **Fase 7** | Demo completa E2E para hackathons (ETHLatam, ZK Hack) |
| **Fase 8** | El backend Plonkish abre la puerta a ZKML y coprocesadores eficientes |

---

## 6. Capitalización Sin Vender Software

### Tier 1: Grants ($5K-$250K, inmediato post Fase 3)

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

### Tier 2: Retroactive Public Goods Funding (post Fase 7)
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
4. **Testing first-class** — Cultura TDD convertida en framework de testing ZK que no existe en ningún otro DSL.
5. **Posición LATAM** — Demanda creciente, poca oferta, comunidad técnica en español.

### Mercado

El mercado ZK tiene $11.7B+ en market cap. La Ethereum Foundation inyectó $32.65M en Q1 2025 solo hacia ZK research y tooling. La narrativa actual corona al cómputo verificable (coprocesadores ZK, ZKML) como el endgame de escalabilidad y privacidad.

### Principio rector

**No intentes ser Noir. Sé el lenguaje que hace que las matemáticas se conviertan en pruebas cero-conocimiento de forma natural.**
