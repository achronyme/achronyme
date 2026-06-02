use memory::FieldBackend;

#[derive(Default)]
struct LysisOpcodeProfile {
    load_capture: usize,
    load_const: usize,
    load_input: usize,
    enter_scope: usize,
    exit_scope: usize,
    jump: usize,
    jump_if: usize,
    return_: usize,
    halt: usize,
    trap: usize,
    loop_unroll: usize,
    loop_rolled: usize,
    loop_range: usize,
    loop_unroll_iters: u64,
    loop_unroll_body_bytes: u64,
    define_template: usize,
    instantiate_template: usize,
    template_output: usize,
    emit_const: usize,
    emit_add: usize,
    emit_sub: usize,
    emit_mul: usize,
    emit_neg: usize,
    emit_mux: usize,
    emit_decompose: usize,
    emit_decompose_bits: usize,
    emit_assert_eq: usize,
    emit_assert_eq_msg: usize,
    emit_range_check: usize,
    emit_witness_call: usize,
    emit_witness_call_inputs: usize,
    emit_witness_call_outputs: usize,
    emit_witness_call_heap: usize,
    emit_witness_call_heap_inputs: usize,
    emit_witness_call_heap_outputs: usize,
    emit_poseidon_hash: usize,
    emit_is_eq: usize,
    emit_is_lt: usize,
    emit_int_div: usize,
    emit_int_mod: usize,
    emit_div: usize,
    store_heap: usize,
    load_heap: usize,
    instantiate_targets: Vec<usize>,
}

pub(super) fn trace_lysis_program_profile<F: FieldBackend>(program: &lysis::Program<F>) {
    use lysis::Opcode;

    let mut p = LysisOpcodeProfile::default();
    for instr in &program.body {
        match &instr.opcode {
            Opcode::LoadCapture { .. } => p.load_capture += 1,
            Opcode::LoadConst { .. } => p.load_const += 1,
            Opcode::LoadInput { .. } => p.load_input += 1,
            Opcode::EnterScope => p.enter_scope += 1,
            Opcode::ExitScope => p.exit_scope += 1,
            Opcode::Jump { .. } => p.jump += 1,
            Opcode::JumpIf { .. } => p.jump_if += 1,
            Opcode::Return => p.return_ += 1,
            Opcode::Halt => p.halt += 1,
            Opcode::Trap { .. } => p.trap += 1,
            Opcode::LoopUnroll {
                start,
                end,
                body_len,
                ..
            } => {
                p.loop_unroll += 1;
                p.loop_unroll_iters += u64::from(end.saturating_sub(*start));
                p.loop_unroll_body_bytes += u64::from(*body_len);
            }
            Opcode::LoopRolled { .. } => p.loop_rolled += 1,
            Opcode::LoopRange { .. } => p.loop_range += 1,
            Opcode::DefineTemplate { .. } => p.define_template += 1,
            Opcode::InstantiateTemplate { template_id, .. } => {
                p.instantiate_template += 1;
                let target = *template_id as usize;
                if target >= p.instantiate_targets.len() {
                    p.instantiate_targets.resize(target + 1, 0);
                }
                p.instantiate_targets[target] += 1;
            }
            Opcode::TemplateOutput { .. } => p.template_output += 1,
            Opcode::EmitConst { .. } => p.emit_const += 1,
            Opcode::EmitAdd { .. } => p.emit_add += 1,
            Opcode::EmitSub { .. } => p.emit_sub += 1,
            Opcode::EmitMul { .. } => p.emit_mul += 1,
            Opcode::EmitNeg { .. } => p.emit_neg += 1,
            Opcode::EmitMux { .. } => p.emit_mux += 1,
            Opcode::EmitDecompose { n_bits, .. } => {
                p.emit_decompose += 1;
                p.emit_decompose_bits += usize::from(*n_bits);
            }
            Opcode::EmitAssertEq { .. } => p.emit_assert_eq += 1,
            Opcode::EmitAssertEqMsg { .. } => p.emit_assert_eq_msg += 1,
            Opcode::EmitRangeCheck { .. } => p.emit_range_check += 1,
            Opcode::EmitWitnessCall {
                in_regs, out_regs, ..
            } => {
                p.emit_witness_call += 1;
                p.emit_witness_call_inputs += in_regs.len();
                p.emit_witness_call_outputs += out_regs.len();
            }
            Opcode::EmitWitnessCallHeap {
                inputs, out_slots, ..
            } => {
                p.emit_witness_call_heap += 1;
                p.emit_witness_call_heap_inputs += inputs.len();
                p.emit_witness_call_heap_outputs += out_slots.len();
            }
            Opcode::EmitPoseidonHash { .. } => p.emit_poseidon_hash += 1,
            Opcode::EmitIsEq { .. } => p.emit_is_eq += 1,
            Opcode::EmitIsLt { .. } => p.emit_is_lt += 1,
            Opcode::EmitIntDiv { .. } => p.emit_int_div += 1,
            Opcode::EmitIntMod { .. } => p.emit_int_mod += 1,
            Opcode::EmitDiv { .. } => p.emit_div += 1,
            Opcode::StoreHeap { .. } => p.store_heap += 1,
            Opcode::LoadHeap { .. } => p.load_heap += 1,
        }
    }
    let template_body_bytes: u64 = program
        .templates
        .iter()
        .map(|t| u64::from(t.body_len))
        .sum();
    let max_template_body_bytes = program
        .templates
        .iter()
        .map(|t| t.body_len)
        .max()
        .unwrap_or(0);
    eprintln!(
        "[lysis-profile] body_len={} templates={} template_body_bytes={} max_template_body_bytes={} heap_size_hint={} const_pool_len={}",
        program.body.len(),
        program.templates.len(),
        template_body_bytes,
        max_template_body_bytes,
        program.header.heap_size_hint,
        program.const_pool.len(),
    );
    eprintln!(
        "[lysis-profile] control load_capture={} load_const={} load_input={} enter={} exit={} jump={} jump_if={} return={} halt={} trap={} loop_unroll={} loop_unroll_iters={} loop_unroll_body_bytes={} loop_rolled={} loop_range={} define_template={} instantiate_template={} template_output={} store_heap={} load_heap={}",
        p.load_capture,
        p.load_const,
        p.load_input,
        p.enter_scope,
        p.exit_scope,
        p.jump,
        p.jump_if,
        p.return_,
        p.halt,
        p.trap,
        p.loop_unroll,
        p.loop_unroll_iters,
        p.loop_unroll_body_bytes,
        p.loop_rolled,
        p.loop_range,
        p.define_template,
        p.instantiate_template,
        p.template_output,
        p.store_heap,
        p.load_heap,
    );
    let top_targets = top_usize(&p.instantiate_targets, 8)
        .into_iter()
        .map(|(id, count)| format!("{id}:{count}"))
        .collect::<Vec<_>>()
        .join(",");
    eprintln!("[lysis-profile] instantiate_targets={top_targets}");
    let small_target_sites = small_instantiate_target_sites(program, 8, 24).join(",");
    eprintln!("[lysis-profile] small_instantiate_target_sites={small_target_sites}");
    eprintln!(
        "[lysis-profile] emit const={} add={} sub={} mul={} neg={} mux={} decompose={} decompose_bits={} asserteq={} asserteq_msg={} range={} witness_call={} witness_inputs={} witness_outputs={} witness_call_heap={} witness_heap_inputs={} witness_heap_outputs={} poseidon={} iseq={} islt={} intdiv={} intmod={} div={}",
        p.emit_const,
        p.emit_add,
        p.emit_sub,
        p.emit_mul,
        p.emit_neg,
        p.emit_mux,
        p.emit_decompose,
        p.emit_decompose_bits,
        p.emit_assert_eq,
        p.emit_assert_eq_msg,
        p.emit_range_check,
        p.emit_witness_call,
        p.emit_witness_call_inputs,
        p.emit_witness_call_outputs,
        p.emit_witness_call_heap,
        p.emit_witness_call_heap_inputs,
        p.emit_witness_call_heap_outputs,
        p.emit_poseidon_hash,
        p.emit_is_eq,
        p.emit_is_lt,
        p.emit_int_div,
        p.emit_int_mod,
        p.emit_div,
    );
}

fn small_instantiate_target_sites<F: FieldBackend>(
    program: &lysis::Program<F>,
    target_limit: u16,
    site_limit: usize,
) -> Vec<String> {
    use lysis::Opcode;

    let mut sites = Vec::new();
    for instr in &program.body {
        let Opcode::InstantiateTemplate { template_id, .. } = &instr.opcode else {
            continue;
        };
        if *template_id >= target_limit {
            continue;
        }
        let owner = program
            .templates
            .iter()
            .find(|template| {
                let start = template.body_offset;
                let end = start.saturating_add(template.body_len);
                instr.offset >= start && instr.offset < end
            })
            .map(|template| template.id.to_string())
            .unwrap_or_else(|| "root".to_string());
        sites.push(format!("{template_id}@{owner}:{}", instr.offset));
        if sites.len() >= site_limit {
            break;
        }
    }
    sites
}

fn top_usize(values: &[usize], limit: usize) -> Vec<(usize, usize)> {
    let mut pairs = values
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, count)| *count > 0)
        .collect::<Vec<_>>();
    pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    pairs.truncate(limit);
    pairs
}
