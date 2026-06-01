use memory::field::FieldBackend;

use crate::bytecode::Opcode;
use crate::program::Program;

pub(super) struct LysisExecProfile {
    opcode_counts: [u64; 256],
    template_entries: Vec<u64>,
    template_dyn_ops: Vec<u64>,
    template_body_bytes: Vec<u32>,
    root_dyn_ops: u64,
    interval: u64,
    next_print: u64,
    pub(super) abort_after: Option<u64>,
}

impl LysisExecProfile {
    pub(super) fn from_env<F: FieldBackend>(program: &Program<F>) -> Option<Self> {
        if std::env::var("ACH_LYSIS_EXEC_PROFILE").as_deref() != Ok("1") {
            return None;
        }
        let max_template_id = program
            .templates
            .iter()
            .map(|template| template.id as usize)
            .max()
            .unwrap_or(0);
        let interval = std::env::var("ACH_LYSIS_EXEC_PROFILE_INTERVAL")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(10_000_000);
        let abort_after = std::env::var("ACH_LYSIS_EXEC_ABORT_AFTER_STEPS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0);
        let mut template_body_bytes = vec![0; max_template_id + 1];
        for template in &program.templates {
            template_body_bytes[template.id as usize] = template.body_len;
        }
        Some(Self {
            opcode_counts: [0; 256],
            template_entries: vec![0; max_template_id + 1],
            template_dyn_ops: vec![0; max_template_id + 1],
            template_body_bytes,
            root_dyn_ops: 0,
            interval,
            next_print: interval,
            abort_after,
        })
    }

    pub(super) fn record(
        &mut self,
        instr: &crate::program::Instr,
        template_id: Option<u16>,
        ran: u64,
    ) {
        self.opcode_counts[instr.opcode.code() as usize] += 1;
        if let Some(id) = template_id {
            if let Some(slot) = self.template_dyn_ops.get_mut(id as usize) {
                *slot += 1;
            }
        } else {
            self.root_dyn_ops += 1;
        }
        if let Opcode::InstantiateTemplate { template_id, .. } = &instr.opcode {
            if let Some(slot) = self.template_entries.get_mut(*template_id as usize) {
                *slot += 1;
            }
        }
        if ran >= self.next_print {
            self.print(ran);
            self.next_print = self.next_print.saturating_add(self.interval);
        }
    }

    pub(super) fn should_abort(&self, ran: u64) -> bool {
        self.abort_after
            .map(|abort_after| ran >= abort_after)
            .unwrap_or(false)
    }

    pub(super) fn print(&self, ran: u64) {
        let top_ops = top_u64(&self.template_dyn_ops, 8)
            .into_iter()
            .map(|(id, count)| {
                let entries = self.template_entries.get(id).copied().unwrap_or(0);
                let body_bytes = self.template_body_bytes.get(id).copied().unwrap_or(0);
                format!("{id}:{count}/{entries}/{body_bytes}")
            })
            .collect::<Vec<_>>()
            .join(",");
        let top_entries = top_u64(&self.template_entries, 8)
            .into_iter()
            .map(|(id, count)| {
                let dyn_ops = self.template_dyn_ops.get(id).copied().unwrap_or(0);
                let body_bytes = self.template_body_bytes.get(id).copied().unwrap_or(0);
                format!("{id}:{count}/{dyn_ops}/{body_bytes}")
            })
            .collect::<Vec<_>>()
            .join(",");
        eprintln!(
            "[lysis-exec-profile] steps={ran} root_ops={} top_template_dyn_ops/entries/body_bytes={}",
            self.root_dyn_ops, top_ops,
        );
        eprintln!(
            "[lysis-exec-profile] top_template_entries/dyn_ops/body_bytes={}",
            top_entries,
        );
        eprintln!(
            "[lysis-exec-profile] control load_const={} load_input={} return={} halt={} instantiate_template={} store_heap={} load_heap={}",
            self.count(Opcode::LoadConst { dst: 0, idx: 0 }),
            self.count(Opcode::LoadInput {
                dst: 0,
                name_idx: 0,
                vis: crate::intern::Visibility::Witness,
            }),
            self.count(Opcode::Return),
            self.count(Opcode::Halt),
            self.count(Opcode::InstantiateTemplate {
                template_id: 0,
                capture_regs: Box::new(Vec::new()),
                output_regs: Box::new(Vec::new()),
            }),
            self.count(Opcode::StoreHeap {
                src_reg: 0,
                slot: 0,
            }),
            self.count(Opcode::LoadHeap {
                dst_reg: 0,
                slot: 0,
            }),
        );
        eprintln!(
            "[lysis-exec-profile] emit add={} sub={} mul={} neg={} asserteq={} asserteq_msg={} witness_call={} witness_call_heap={} iseq={} islt={} div={}",
            self.count(Opcode::EmitAdd {
                dst: 0,
                lhs: 0,
                rhs: 0,
            }),
            self.count(Opcode::EmitSub {
                dst: 0,
                lhs: 0,
                rhs: 0,
            }),
            self.count(Opcode::EmitMul {
                dst: 0,
                lhs: 0,
                rhs: 0,
            }),
            self.count(Opcode::EmitNeg { dst: 0, operand: 0 }),
            self.count(Opcode::EmitAssertEq { lhs: 0, rhs: 0 }),
            self.count(Opcode::EmitAssertEqMsg {
                lhs: 0,
                rhs: 0,
                msg_idx: 0,
            }),
            self.count(Opcode::EmitWitnessCall {
                bytecode_const_idx: 0,
                in_regs: Box::new(Vec::new()),
                out_regs: Box::new(Vec::new()),
            }),
            self.count(Opcode::EmitWitnessCallHeap {
                bytecode_const_idx: 0,
                inputs: Box::new(Vec::new()),
                out_slots: Box::new(Vec::new()),
            }),
            self.count(Opcode::EmitIsEq {
                dst: 0,
                lhs: 0,
                rhs: 0,
            }),
            self.count(Opcode::EmitIsLt {
                dst: 0,
                lhs: 0,
                rhs: 0,
            }),
            self.count(Opcode::EmitDiv {
                dst: 0,
                lhs: 0,
                rhs: 0,
            }),
        );
    }

    fn count(&self, opcode: Opcode) -> u64 {
        self.opcode_counts[opcode.code() as usize]
    }
}

fn top_u64(values: &[u64], limit: usize) -> Vec<(usize, u64)> {
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
