use crate::ir::Instr;

pub(super) struct ArtikExecProfile {
    min_steps: u64,
    fadd: u64,
    fsub: u64,
    fmul: u64,
    fdiv: u64,
    finv: u64,
    fpow2: u64,
    fmul_run_len: u64,
    fmul_runs: u64,
    fmul_run_sum: u64,
    fmul_run_max: u64,
    batch_len: u64,
    batch_runs: u64,
    batch_sum: u64,
    batch_max: u64,
    batch_dsts: Vec<u32>,
}

impl ArtikExecProfile {
    pub(super) fn from_env() -> Option<Self> {
        if std::env::var("ACH_ARTIK_EXEC_PROFILE").as_deref() != Ok("1") {
            return None;
        }
        let min_steps = std::env::var("ACH_ARTIK_EXEC_PROFILE_MIN_STEPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1_000_000);
        Some(Self {
            min_steps,
            fadd: 0,
            fsub: 0,
            fmul: 0,
            fdiv: 0,
            finv: 0,
            fpow2: 0,
            fmul_run_len: 0,
            fmul_runs: 0,
            fmul_run_sum: 0,
            fmul_run_max: 0,
            batch_len: 0,
            batch_runs: 0,
            batch_sum: 0,
            batch_max: 0,
            batch_dsts: Vec::new(),
        })
    }

    pub(super) fn record(&mut self, instr: &Instr) {
        match instr {
            Instr::FAdd { .. } => {
                self.fadd += 1;
                self.flush_fmul();
            }
            Instr::FSub { .. } => {
                self.fsub += 1;
                self.flush_fmul();
            }
            Instr::FMul { dst, a, b } => {
                self.fmul += 1;
                self.fmul_run_len += 1;
                if self
                    .batch_dsts
                    .iter()
                    .any(|seen| seen == dst || seen == a || seen == b)
                {
                    self.flush_batch();
                }
                self.batch_len += 1;
                self.batch_dsts.push(*dst);
            }
            Instr::FDiv { .. } => {
                self.fdiv += 1;
                self.flush_fmul();
            }
            Instr::FInv { .. } => {
                self.finv += 1;
                self.flush_fmul();
            }
            Instr::FPow2 { .. } => {
                self.fpow2 += 1;
                self.flush_fmul();
            }
            _ => self.flush_fmul(),
        }
    }

    pub(super) fn finish(&mut self, steps: u64) {
        self.flush_fmul();
        if steps < self.min_steps {
            return;
        }
        let avg_run = average(self.fmul_run_sum, self.fmul_runs);
        let avg_batch = average(self.batch_sum, self.batch_runs);
        eprintln!(
            "[artik-exec-profile] steps={steps} fadd={} fsub={} fmul={} fdiv={} finv={} fpow2={}",
            self.fadd, self.fsub, self.fmul, self.fdiv, self.finv, self.fpow2,
        );
        eprintln!(
            "[artik-exec-profile] fmul_runs={} avg_run={avg_run:.2} max_run={} batchable_runs={} avg_batch={avg_batch:.2} max_batch={}",
            self.fmul_runs,
            self.fmul_run_max,
            self.batch_runs,
            self.batch_max,
        );
    }

    fn flush_fmul(&mut self) {
        if self.fmul_run_len > 0 {
            self.fmul_runs += 1;
            self.fmul_run_sum += self.fmul_run_len;
            self.fmul_run_max = self.fmul_run_max.max(self.fmul_run_len);
            self.fmul_run_len = 0;
        }
        self.flush_batch();
    }

    fn flush_batch(&mut self) {
        if self.batch_len > 0 {
            self.batch_runs += 1;
            self.batch_sum += self.batch_len;
            self.batch_max = self.batch_max.max(self.batch_len);
            self.batch_len = 0;
            self.batch_dsts.clear();
        }
    }
}

fn average(sum: u64, count: u64) -> f64 {
    if count == 0 {
        0.0
    } else {
        sum as f64 / count as f64
    }
}
