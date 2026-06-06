use std::collections::HashMap;

use circom::{compile_template_library, instantiate_template_into};
use ir_core::IrType;
use ir_forge::types::{CircuitExpr, FieldConst, ProveIR};
use ir_forge::ExtendedInstruction;
use memory::{Bn254Fr, FieldElement};

use super::common::{dummy_span, lib_dirs, workspace_root};

/// Drive `instantiate_template_into` for Sha256(N) with the given
/// signal-input shape, build a synthetic ProveIR mirroring what an
/// `.ach prove { let r = Sha256(N)([...]) }` block produces, run
/// Lysis, and report. Used to bisect which axis triggers walker
/// `UndefinedSsaVar` for N < 64.
fn probe_embedded_sha256(n_bits: u64, all_const: bool, label: &str) {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("Embedded Sha256({n_bits}) {label} — synthetic ProveIR + Lysis");
    eprintln!("================================================================");

    let template_args = vec![FieldConst::from_u64(n_bits)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..n_bits {
        let key = format!("in_{i}");
        let expr = if all_const {
            CircuitExpr::Const(FieldConst::from_u64(0))
        } else {
            CircuitExpr::Var(format!("user_in_{i}"))
        };
        signal_inputs.insert(key, expr);
    }

    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256 succeeds");

    eprintln!(
        "  body.len()={}, outputs.len()={}",
        instantiation.body.len(),
        instantiation.outputs.len()
    );

    // Mirror the .ach prove block's witness-input wiring.
    let mut witness_inputs = Vec::new();
    if !all_const {
        for i in 0..n_bits {
            witness_inputs.push(ir_forge::types::ProveInputDecl {
                name: format!("user_in_{i}"),
                array_size: None,
                ir_type: IrType::Field,
            });
        }
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    match synthetic.instantiate_lysis::<Bn254Fr>(&captures) {
        Ok(prog) => eprintln!("  Lysis OK — {} flat instructions", prog.len()),
        Err(e) => eprintln!("  Lysis FAILED: {e}"),
    }
}

#[test]
#[ignore]
fn probe_embedded_sha256_8_const() {
    probe_embedded_sha256(8, true, "all-Const inputs");
}

#[test]
#[ignore]
fn probe_embedded_sha256_8_var() {
    probe_embedded_sha256(8, false, "all-Var inputs");
}

#[test]
#[ignore]
fn probe_embedded_sha256_64_const() {
    probe_embedded_sha256(64, true, "all-Const inputs");
}

/// One Const + (n_bits-1) Var inputs — disambiguates "any Const
/// triggers the bug" vs "fully-Const wiring is the trigger".
fn probe_embedded_sha256_one_const(n_bits: u64, label: &str) {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("Embedded Sha256({n_bits}) {label} — synthetic ProveIR + Lysis");
    eprintln!("================================================================");

    let template_args = vec![FieldConst::from_u64(n_bits)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..n_bits {
        let key = format!("in_{i}");
        let expr = if i == 0 {
            CircuitExpr::Const(FieldConst::from_u64(0))
        } else {
            CircuitExpr::Var(format!("user_in_{i}"))
        };
        signal_inputs.insert(key, expr);
    }

    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256 succeeds");

    let mut witness_inputs = Vec::new();
    for i in 1..n_bits {
        witness_inputs.push(ir_forge::types::ProveInputDecl {
            name: format!("user_in_{i}"),
            array_size: None,
            ir_type: IrType::Field,
        });
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    match synthetic.instantiate_lysis::<Bn254Fr>(&captures) {
        Ok(prog) => eprintln!("  Lysis OK — {} flat instructions", prog.len()),
        Err(e) => eprintln!("  Lysis FAILED: {e}"),
    }
}

#[test]
#[ignore]
fn probe_embedded_sha256_8_one_const_rest_var() {
    probe_embedded_sha256_one_const(8, "in_0=Const, rest=Var");
}

/// Same dump but for the working case (Var inputs). Compares with
/// the failing-case dump to spot the structural divergence.
#[test]
#[ignore]
fn probe_embedded_sha256_8_var_dump_first_30() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    let template_args = vec![FieldConst::from_u64(8)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..8u64 {
        signal_inputs.insert(format!("in_{i}"), CircuitExpr::Var(format!("user_in_{i}")));
    }
    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256(8) succeeds");

    let mut witness_inputs = Vec::new();
    for i in 0..8u64 {
        witness_inputs.push(ir_forge::types::ProveInputDecl {
            name: format!("user_in_{i}"),
            array_size: None,
            ir_type: IrType::Field,
        });
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended = synthetic
        .instantiate_extended::<Bn254Fr>(&captures)
        .expect("instantiate_extended succeeds");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("First 30 ExtendedInstructions (Sha256(8) Var, embedded - WORKS)");
    eprintln!("================================================================");
    for (i, inst) in extended.body.iter().take(30).enumerate() {
        eprintln!("[{i:3}] {inst:?}");
    }
}

/// Walk the extended instruction stream for the failing case and
/// report (def_idx, use_idxs[]) for the first 5 SsaVars. Pinpoints
/// the use that the walker fails on.
#[test]
#[ignore]
fn probe_embedded_sha256_8_const_track_low_ssa() {
    use ir_core::Instruction;

    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    let template_args = vec![FieldConst::from_u64(8)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..8u64 {
        signal_inputs.insert(
            format!("in_{i}"),
            CircuitExpr::Const(FieldConst::from_u64(0)),
        );
    }
    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate succeeds");

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended = synthetic
        .instantiate_extended::<Bn254Fr>(&captures)
        .expect("instantiate_extended succeeds");

    fn collect_uses<F: memory::FieldBackend>(
        inst: &ExtendedInstruction<F>,
        path: &str,
        target: ir_core::SsaVar,
        out: &mut Vec<String>,
    ) {
        match inst {
            ExtendedInstruction::Plain(i) => {
                if instruction_uses(i, target) {
                    out.push(format!("{path}: Plain({:?})", short_inst(i)));
                }
            }
            ExtendedInstruction::LoopUnroll { body, .. } => {
                for (j, nested) in body.iter().enumerate() {
                    collect_uses(nested, &format!("{path}.LoopUnroll[{j}]"), target, out);
                }
            }
            ExtendedInstruction::TemplateBody { body, captures, .. } => {
                if captures.contains(&target) {
                    out.push(format!("{path}: TemplateBody captures={:?}", captures));
                }
                for (j, nested) in body.iter().enumerate() {
                    collect_uses(nested, &format!("{path}.TemplateBody[{j}]"), target, out);
                }
            }
            ExtendedInstruction::TemplateCall { captures, .. } if captures.contains(&target) => {
                out.push(format!("{path}: TemplateCall captures={:?}", captures));
            }
            _ => {}
        }
    }

    fn instruction_uses<F: memory::FieldBackend>(
        inst: &Instruction<F>,
        target: ir_core::SsaVar,
    ) -> bool {
        let mut found = false;
        macro_rules! check {
            ($v:expr) => {
                if *$v == target {
                    found = true;
                }
            };
        }
        match inst {
            Instruction::Const { .. } | Instruction::Input { .. } => {}
            Instruction::Add { lhs, rhs, .. }
            | Instruction::Sub { lhs, rhs, .. }
            | Instruction::Mul { lhs, rhs, .. }
            | Instruction::Div { lhs, rhs, .. } => {
                check!(lhs);
                check!(rhs);
            }
            Instruction::AssertEq { lhs, rhs, .. } => {
                check!(lhs);
                check!(rhs);
            }
            _ => {}
        }
        found
    }

    fn short_inst<F: memory::FieldBackend>(inst: &Instruction<F>) -> String {
        format!("{inst:?}").chars().take(120).collect::<String>()
    }

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SsaVar(0) tracking — Sha256(8) Const embedded");
    eprintln!("================================================================");
    eprintln!("Total top-level extended insts: {}", extended.body.len());
    let target = ir_core::SsaVar(0);
    let mut uses: Vec<String> = Vec::new();
    for (i, inst) in extended.body.iter().enumerate() {
        collect_uses(inst, &format!("[{i}]"), target, &mut uses);
    }
    eprintln!("Uses of SsaVar(0):");
    for (i, u) in uses.iter().take(20).enumerate() {
        eprintln!("  [{i}] {u}");
    }
    if uses.len() > 20 {
        eprintln!("  ... ({} more)", uses.len() - 20);
    }
}

/// Drive the failing case through `instantiate_extended` and dump
/// the first 30 ExtendedInstructions so we can spot where SsaVar %0
/// is defined vs used.
#[test]
#[ignore]
fn probe_embedded_sha256_8_const_dump_first_30() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    let template_args = vec![FieldConst::from_u64(8)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..8u64 {
        signal_inputs.insert(
            format!("in_{i}"),
            CircuitExpr::Const(FieldConst::from_u64(0)),
        );
    }
    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256(8) succeeds");

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended = synthetic
        .instantiate_extended::<Bn254Fr>(&captures)
        .expect("instantiate_extended succeeds");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("First 30 ExtendedInstructions (Sha256(8) Const, embedded)");
    eprintln!("================================================================");
    for (i, inst) in extended.body.iter().take(30).enumerate() {
        eprintln!("[{i:3}] {inst:?}");
    }
}
