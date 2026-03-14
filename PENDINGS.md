# Pendientes

> Items abiertos organizados por prioridad. Los hallazgos de las 2 auditorías
> criptográficas (Phase 9 + Phase 10 deep audit) están 100% resueltos — ver
> commits `649c4bb`..`081324f` para el historial completo.

---

## Lenguaje & Compilador

- [x] **Stdlib: iteradores funcionales** — `map`, `filter`, `reduce`, `for_each`, `find`, `any`, `all`, `sort`, `flat_map`, `zip` implementados en `vm/src/stdlib/collections.rs`.
- [ ] **Global mutability check en compile-time** — Solo se verifica en runtime (`vm/src/machine/globals.rs`). Mover a compile-time donde sea posible.
- [ ] **MAX_UNROLL sin memory guard** — `MAX_UNROLL_ITERATIONS = 10,000` limita iteraciones pero no hay budget de instrucciones acumulativo. Un circuito con múltiples loops grandes puede agotar memoria. Agregar instruction count budget o check progresivo.

## Circuitos & Backends

- [ ] **Export Plonkish binario** — El backend Plonkish compila, prueba y verifica, pero no genera artefactos binarios exportables.
- [ ] **verify_signature(pub_key, msg, sig)** — Verificación de firmas (EdDSA/ECDSA sobre BN254) como builtin de circuito. Necesario para verticales de identidad/credenciales.
- [ ] **Comparaciones caras (~760 constraints)** — `x < y` sin `range_check` previo usa decomposición de 253 bits. Con bounds previos baja a ~30 constraints, pero el caso general sigue siendo costoso.

## Testing

- [x] **T7**: `poseidon(0,0)` testeado en ambos backends (`test_poseidon_zero_zero_r1cs`, `test_plonkish_poseidon_zero_zero`)
- [x] **T8**: `range_check` edge cases — bits=0, bits=1, bits=253, max valid value (2^bits-1), todos cubiertos en R1CS y Plonkish
- [x] **T9**: Equivalentes Plonkish — for loops, if/else, poseidon con expresiones, power, todos testeados
- [x] **T10**: Detección de corrupción de witness — tests de wrong witness, malicious division, assert false
- [x] **T11**: Field serialization round-trip — LE bytes, decimal strings, valores multi-limb (2^256+1, 2^257, 10^100)
- [x] **T12**: `from_decimal_str` edge cases — "0", p, p+1, string vacío, chars inválidos, overflow
- [ ] **T13**: Tests de integración snarkjs en CI — actualmente `#[ignore]`, necesitan Node.js
- [x] **T14**: Tests de integración CLI — 20 tests cubriendo ambos backends, flags, JSON export, error formats

## Futuro (sin prioridad definida)

- [ ] **Tensor System** — `TAG_TENSOR` para representación de polinomios y operaciones ZKML (FFT/MSM). No está en el roadmap inmediato.
- [ ] **Multi-curva** — Genericizar `FieldElement` sobre un trait `Field` para soportar BLS12-381, Pasta, campos STARK. Planeado para v1.0.0.
