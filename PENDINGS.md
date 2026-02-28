# Pendientes

> Items abiertos organizados por prioridad. Los hallazgos de las 2 auditorías
> criptográficas (Phase 9 + Phase 10 deep audit) están 100% resueltos — ver
> commits `649c4bb`..`081324f` para el historial completo.

---

## Lenguaje & Compilador

- [ ] **Sistema de imports/módulos** — Todo es un archivo. Circuitos grandes son inmanejables. Implementar `import "path"` con resolución de nombres.
- [ ] **REPL** — Registrado en CLI pero es un stub (`cli/src/repl.rs`). Necesita readline, loop de ejecución, y pipeline de compilación incremental.
- [ ] **Stdlib: iteradores funcionales** — `map`, `filter`, `reduce` para listas. Actualmente no hay equivalentes.
- [ ] **Global mutability check en compile-time** — Solo se verifica en runtime (`vm/src/machine/globals.rs`). Mover a compile-time donde sea posible.
- [ ] **MAX_UNROLL sin memory guard** — `MAX_UNROLL_ITERATIONS = 10,000` limita iteraciones pero no hay budget de instrucciones acumulativo. Un circuito con múltiples loops grandes puede agotar memoria. Agregar instruction count budget o check progresivo.

## Circuitos & Backends

- [ ] **Export Plonkish binario** — El backend Plonkish compila, prueba y verifica, pero no genera artefactos binarios exportables.
- [ ] **verify_signature(pub_key, msg, sig)** — Verificación de firmas (EdDSA/ECDSA sobre BN254) como builtin de circuito. Necesario para verticales de identidad/credenciales.
- [ ] **Comparaciones caras (~760 constraints)** — `x < y` sin `range_check` previo usa decomposición de 253 bits. Con bounds previos baja a ~30 constraints, pero el caso general sigue siendo costoso.

## Testing

- [ ] **T7**: `poseidon(0,0)` solo testeado nativamente, no a través del pipeline de circuito
- [ ] **T8**: `range_check` edge cases — bits=0, bits=1, bits=253, max valid value (2^bits-1)
- [ ] **T9**: Equivalentes Plonkish faltantes — for loops, if/else, poseidon con expresiones, power
- [ ] **T10**: Detección de corrupción de witness — corromper valor intermedio, verify debe fallar
- [ ] **T11**: Field serialization round-trip para valores multi-limb
- [ ] **T12**: `from_decimal_str` edge cases — "0", p, p+1, chars inválidos, string vacío
- [ ] **T13**: Tests de integración snarkjs en CI — actualmente `#[ignore]`, necesitan Node.js
- [ ] **T14**: Tests de integración CLI — zero coverage para el comando `circuit`

## Futuro (sin prioridad definida)

- [ ] **Tensor System** — `TAG_TENSOR` para representación de polinomios y operaciones ZKML (FFT/MSM). No está en el roadmap inmediato.
- [ ] **Multi-curva** — Genericizar `FieldElement` sobre un trait `Field` para soportar BLS12-381, Pasta, campos STARK. Planeado para v1.0.0.
