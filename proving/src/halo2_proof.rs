//! Native Plonkish proof generation using PSE halo2 with KZG on BN254.
//!
//! Maps the `PlonkishCompiler` output to a halo2 `Circuit` and generates
//! real KZG-PlonK proofs (setup, prove, verify) — in-process, no external deps.

use std::path::Path;

use compiler::plonkish_backend::PlonkishCompiler;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::plonk::{
    self, create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column as H2Column,
    ConstraintSystem, Fixed, Instance, Selector, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_proofs::SerdeFormat;
use memory::FieldElement;
use rand::rngs::OsRng;
use vm::ProveResult;

// ============================================================================
// Field conversion
// ============================================================================

/// Convert an Achronyme `FieldElement` (BN254 Fr) to a halo2 `Fr`.
fn fe_to_halo2(fe: &FieldElement) -> Result<Fr, String> {
    let bytes = fe.to_le_bytes();
    let mut repr = [0u8; 32];
    repr.copy_from_slice(&bytes);
    Option::from(Fr::from_repr(repr)).ok_or_else(|| "invalid BN254 field element".to_string())
}

/// Convert a halo2 `Fr` back to decimal string via `FieldElement`.
fn fr_to_decimal(f: &Fr) -> String {
    let repr = f.to_repr();
    let bytes: &[u8] = repr.as_ref();
    let mut le_bytes = [0u8; 32];
    le_bytes[..bytes.len()].copy_from_slice(bytes);
    let fe = FieldElement::from_le_bytes(&le_bytes).expect("valid Fr in range");
    fe.to_decimal_string()
}

// ============================================================================
// Circuit parameters
// ============================================================================

#[derive(Clone, Debug, Default)]
struct CircuitParams {
    range_table_bits: Vec<u32>,
}

// ============================================================================
// Circuit config (column handles from configure)
// ============================================================================

#[derive(Clone, Debug)]
struct AchronymeConfig {
    s_arith: Selector,
    /// Fixed columns for range lookup selectors (not dynamic Selectors —
    /// dynamic selectors are compressed by halo2 and break lookup arguments).
    range_sel_fixed: Vec<H2Column<Fixed>>,
    /// Fixed columns for range lookup tables (not TableColumn —
    /// lookup_any requires Expression-based tables).
    range_table_fixed: Vec<H2Column<Fixed>>,
    col_constant: H2Column<Fixed>,
    col_a: H2Column<Advice>,
    col_b: H2Column<Advice>,
    col_c: H2Column<Advice>,
    col_d: H2Column<Advice>,
    #[allow(dead_code)]
    col_instance: H2Column<Instance>,
}

// ============================================================================
// Circuit struct
// ============================================================================

/// Adapter circuit that maps Achronyme's PlonkishCompiler output to halo2.
struct AchronymePlonkishCircuit {
    params: CircuitParams,
    compiler: PlonkishCompiler,
    num_circuit_rows: usize,
}

impl Circuit<Fr> for AchronymePlonkishCircuit {
    type Config = AchronymeConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = CircuitParams;

    fn without_witnesses(&self) -> Self {
        AchronymePlonkishCircuit {
            params: self.params.clone(),
            compiler: PlonkishCompiler::new(),
            num_circuit_rows: self.num_circuit_rows,
        }
    }

    fn params(&self) -> Self::Params {
        self.params.clone()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<Fr>,
        params: Self::Params,
    ) -> Self::Config {
        configure_impl(meta, &params)
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        configure_impl(meta, &CircuitParams::default())
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let sys = &self.compiler.system;
        let num_rows = self.num_circuit_rows;

        // Range lookup tables are assigned as fixed columns in the main region
        // (not via assign_table, since we use lookup_any with fixed columns).

        // Single region for the main circuit
        layouter.assign_region(
            || "main",
            |mut region| {
                // Track assigned advice cells for copy constraints
                let mut assigned_advice: Vec<
                    Vec<Option<halo2_proofs::circuit::AssignedCell<Fr, Fr>>>,
                > = vec![vec![None; num_rows]; 4];

                // Also track assigned fixed cells for copy constraints between
                // advice and fixed (constant) columns
                let mut assigned_constant: Vec<Option<halo2_proofs::circuit::Cell>> =
                    vec![None; num_rows];

                // Assign fixed values (selectors + constant column)
                #[allow(clippy::needless_range_loop)]
                for row in 0..num_rows {
                    let s_arith_val = sys.assignments.get(self.compiler.col_s_arith, row);
                    if !s_arith_val.is_zero() {
                        config.s_arith.enable(&mut region, row)?;
                    }

                    // Assign range selector fixed columns (1 = active, 0 = inactive)
                    for (i, &bits) in self.params.range_table_bits.iter().enumerate() {
                        let sel_fr =
                            if let Some(&sel_col) = self.compiler.range_selectors.get(&bits) {
                                let sel_val = sys.assignments.get(sel_col, row);
                                fe_to_halo2(&sel_val).map_err(|_| plonk::Error::Synthesis)?
                            } else {
                                Fr::zero() // empty circuit (keygen)
                            };
                        region.assign_fixed(
                            || format!("range_sel_{bits}[{row}]"),
                            config.range_sel_fixed[i],
                            row,
                            || Value::known(sel_fr),
                        )?;
                    }

                    let const_val = sys.assignments.get(self.compiler.col_constant, row);
                    let const_fr = fe_to_halo2(&const_val).map_err(|_| plonk::Error::Synthesis)?;
                    let fixed_cell = region.assign_fixed(
                        || format!("constant[{row}]"),
                        config.col_constant,
                        row,
                        || Value::known(const_fr),
                    )?;
                    assigned_constant[row] = Some(fixed_cell.cell());
                }

                // Assign range table fixed columns.
                // Each table column contains 0..2^bits-1 at the first 2^bits rows,
                // and 0 at all remaining rows. The lookup_any argument checks that
                // (sel * input) is in the multiset of table values.
                for (i, &bits) in self.params.range_table_bits.iter().enumerate() {
                    let table_size = 1usize << bits;
                    for row in 0..num_rows {
                        let val = if row < table_size {
                            Fr::from(row as u64)
                        } else {
                            Fr::zero()
                        };
                        region.assign_fixed(
                            || format!("range_table_{bits}[{row}]"),
                            config.range_table_fixed[i],
                            row,
                            || Value::known(val),
                        )?;
                    }
                }

                // Assign advice columns
                let advice_cols = [
                    (self.compiler.col_a, config.col_a, 0usize),
                    (self.compiler.col_b, config.col_b, 1),
                    (self.compiler.col_c, config.col_c, 2),
                    (self.compiler.col_d, config.col_d, 3),
                ];

                for &(achr_col, h2_col, idx) in &advice_cols {
                    #[allow(clippy::needless_range_loop)]
                    for row in 0..num_rows {
                        let val = sys.assignments.get(achr_col, row);
                        let val_fr = fe_to_halo2(&val).map_err(|_| plonk::Error::Synthesis)?;
                        let cell = region.assign_advice(
                            || format!("advice_{idx}[{row}]"),
                            h2_col,
                            row,
                            || Value::known(val_fr),
                        )?;
                        assigned_advice[idx][row] = Some(cell);
                    }
                }

                // Apply copy constraints
                for copy in &sys.copies {
                    let left_cell = resolve_cell(
                        &copy.left,
                        &assigned_advice,
                        &assigned_constant,
                        &self.compiler,
                    );
                    let right_cell = resolve_cell(
                        &copy.right,
                        &assigned_advice,
                        &assigned_constant,
                        &self.compiler,
                    );
                    if let (Some(l), Some(r)) = (left_cell, right_cell) {
                        region.constrain_equal(l, r)?;
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

// ============================================================================
// Configure implementation
// ============================================================================

fn configure_impl(meta: &mut ConstraintSystem<Fr>, params: &CircuitParams) -> AchronymeConfig {
    let col_constant = meta.fixed_column();
    let col_a = meta.advice_column();
    let col_b = meta.advice_column();
    let col_c = meta.advice_column();
    let col_d = meta.advice_column();
    let col_instance = meta.instance_column();

    meta.enable_equality(col_constant);
    meta.enable_equality(col_a);
    meta.enable_equality(col_b);
    meta.enable_equality(col_c);
    meta.enable_equality(col_d);
    meta.enable_equality(col_instance);

    let s_arith = meta.selector();

    // Arithmetic gate: s_arith * (a * b + c - d) = 0
    meta.create_gate("arithmetic", |vc| {
        let s = vc.query_selector(s_arith);
        let a = vc.query_advice(col_a, Rotation::cur());
        let b = vc.query_advice(col_b, Rotation::cur());
        let c = vc.query_advice(col_c, Rotation::cur());
        let d = vc.query_advice(col_d, Rotation::cur());
        vec![s * (a * b + c - d)]
    });

    // Range check lookups — one fixed selector + one fixed table per bit-width.
    // Uses lookup_any() with fixed columns (NOT dynamic Selectors) to avoid
    // the halo2 selector compression bug that breaks lookup arguments.
    // Pattern from PSE zkEVM-circuits: bilateral multiplication (s*input, s*table).
    let mut range_sel_fixed = Vec::new();
    let mut range_table_fixed = Vec::new();
    for &bits in &params.range_table_bits {
        let sel_col = meta.fixed_column();
        let table_col = meta.fixed_column();
        meta.enable_equality(sel_col);
        meta.enable_equality(table_col);
        range_sel_fixed.push(sel_col);
        range_table_fixed.push(table_col);

        meta.lookup_any(format!("range_{bits}"), |vc| {
            let s = vc.query_fixed(sel_col, Rotation::cur());
            let input = vc.query_advice(col_a, Rotation::cur());
            let table = vc.query_fixed(table_col, Rotation::cur());
            // Unilateral: s * input must be in the table multiset.
            // When s=0: LHS=0, and 0 is in the table (range starts at 0).
            // When s=1: LHS=input, must be in {0..2^bits-1}.
            vec![(s * input, table)]
        });
    }

    AchronymeConfig {
        s_arith,
        range_sel_fixed,
        range_table_fixed,
        col_constant,
        col_a,
        col_b,
        col_c,
        col_d,
        col_instance,
    }
}

// ============================================================================
// Helper: resolve Achronyme CellRef → halo2 Cell
// ============================================================================

fn resolve_cell(
    cell: &constraints::plonkish::CellRef,
    assigned_advice: &[Vec<Option<halo2_proofs::circuit::AssignedCell<Fr, Fr>>>],
    assigned_constant: &[Option<halo2_proofs::circuit::Cell>],
    compiler: &PlonkishCompiler,
) -> Option<halo2_proofs::circuit::Cell> {
    let col = cell.column;
    let row = cell.row;

    // Check advice columns
    if col == compiler.col_a {
        return assigned_advice
            .first()?
            .get(row)?
            .as_ref()
            .map(|c| c.cell());
    } else if col == compiler.col_b {
        return assigned_advice.get(1)?.get(row)?.as_ref().map(|c| c.cell());
    } else if col == compiler.col_c {
        return assigned_advice.get(2)?.get(row)?.as_ref().map(|c| c.cell());
    } else if col == compiler.col_d {
        return assigned_advice.get(3)?.get(row)?.as_ref().map(|c| c.cell());
    }

    // Check constant (fixed) column
    if col == compiler.col_constant {
        return assigned_constant.get(row).copied().flatten();
    }

    // Instance column — not directly handled in copy constraints
    None
}

// ============================================================================
// Proof generation entry point
// ============================================================================

/// Generate a native Plonkish proof using halo2 KZG, taking ownership of the compiler.
pub fn generate_plonkish_proof(
    compiler: PlonkishCompiler,
    cache_dir: &Path,
) -> Result<ProveResult, String> {
    let num_rows = compiler.num_circuit_rows();

    // 2^k must be >= num_rows + blinding rows (~5-10)
    let min_rows = num_rows + 10;
    let k = ((min_rows as f64).log2().ceil() as u32).max(4);

    let range_table_bits = compiler.range_tables_bits();
    let params = CircuitParams {
        range_table_bits: range_table_bits.clone(),
    };

    // Collect instance values (public inputs)
    let instance_values: Vec<Fr> = compiler
        .public_inputs
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let val = compiler.system.assignments.get(compiler.col_instance, i);
            fe_to_halo2(&val)
        })
        .collect::<Result<Vec<Fr>, String>>()?;

    // KZG params (cached by k)
    let params_path = cache_dir.join("plonkish").join(format!("params_k{k}.bin"));
    let kzg_params = load_or_create_kzg_params(k, &params_path)?;

    // Keygen with empty circuit (same structure, no witness)
    let keygen_circuit = AchronymePlonkishCircuit {
        params: params.clone(),
        compiler: PlonkishCompiler::new(),
        num_circuit_rows: num_rows,
    };

    let vk = keygen_vk(&kzg_params, &keygen_circuit)
        .map_err(|e| format!("halo2 keygen_vk failed: {e:?}"))?;
    let pk = keygen_pk(&kzg_params, vk.clone(), &keygen_circuit)
        .map_err(|e| format!("halo2 keygen_pk failed: {e:?}"))?;

    // Prove circuit with real witness
    let prove_circuit = AchronymePlonkishCircuit {
        params: params.clone(),
        compiler,
        num_circuit_rows: num_rows,
    };

    let mut transcript = Blake2bWrite::<Vec<u8>, G1Affine, Challenge255<G1Affine>>::init(vec![]);
    let instance_slice: &[Fr] = &instance_values;
    let instances: &[&[Fr]] = &[instance_slice];

    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        OsRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        AchronymePlonkishCircuit,
    >(
        &kzg_params,
        &pk,
        &[prove_circuit],
        &[instances],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| format!("halo2 proof creation failed: {e:?}"))?;

    let proof_bytes = transcript.finalize();

    // Verify (sanity check)
    let mut verifier_transcript =
        Blake2bRead::<&[u8], G1Affine, Challenge255<G1Affine>>::init(proof_bytes.as_slice());
    let strategy = SingleStrategy::new(&kzg_params);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &kzg_params,
        &vk,
        strategy,
        &[instances],
        &mut verifier_transcript,
    )
    .map_err(|e| format!("halo2 proof verification failed: {e:?}"))?;

    // Serialize to JSON
    let proof_json = serialize_proof_json(&proof_bytes, &instance_values, k)?;
    let public_json = serialize_public_json(&instance_values)?;
    let vkey_json = serialize_vkey_json(&vk, k)?;

    Ok(ProveResult::Proof {
        proof_json,
        public_json,
        vkey_json,
    })
}

// ============================================================================
// KZG params management
// ============================================================================

fn load_or_create_kzg_params(k: u32, path: &Path) -> Result<ParamsKZG<Bn256>, String> {
    if path.exists() {
        let data = std::fs::read(path).map_err(|e| format!("failed to read KZG params: {e}"))?;
        let params = ParamsKZG::<Bn256>::read(&mut &data[..])
            .map_err(|e| format!("failed to deserialize KZG params: {e}"))?;
        return Ok(params);
    }

    eprintln!("generating KZG params for k={k} (this may take a moment)...");
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create KZG params dir: {e}"))?;
    }
    let mut buf = Vec::new();
    params
        .write(&mut buf)
        .map_err(|e| format!("failed to serialize KZG params: {e}"))?;
    std::fs::write(path, &buf).map_err(|e| format!("failed to write KZG params: {e}"))?;

    Ok(params)
}

// ============================================================================
// JSON serialization
// ============================================================================

fn serialize_proof_json(
    proof_bytes: &[u8],
    public_inputs: &[Fr],
    k: u32,
) -> Result<String, String> {
    let proof_hex = format!("0x{}", hex_encode(proof_bytes));
    let public: Vec<String> = public_inputs.iter().map(fr_to_decimal).collect();
    let obj = serde_json::json!({
        "protocol": "plonk",
        "curve": "bn128",
        "proof": proof_hex,
        "public_inputs": public,
        "k": k
    });
    serde_json::to_string_pretty(&obj).map_err(|e| format!("proof JSON serialization failed: {e}"))
}

fn serialize_public_json(inputs: &[Fr]) -> Result<String, String> {
    let arr: Vec<String> = inputs.iter().map(fr_to_decimal).collect();
    serde_json::to_string_pretty(&arr).map_err(|e| format!("public JSON serialization failed: {e}"))
}

fn serialize_vkey_json(vk: &VerifyingKey<G1Affine>, k: u32) -> Result<String, String> {
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes, SerdeFormat::RawBytes)
        .map_err(|e| format!("vkey serialization failed: {e}"))?;
    let vk_hex = format!("0x{}", hex_encode(&vk_bytes));
    let obj = serde_json::json!({
        "protocol": "plonk",
        "curve": "bn128",
        "k": k,
        "vkey": vk_hex
    });
    serde_json::to_string_pretty(&obj).map_err(|e| format!("vkey JSON serialization failed: {e}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
