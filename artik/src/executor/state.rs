use super::*;

/// A single register's contents. `Undef` is the initial state for every
/// register; reading it is a trap.
#[derive(Clone)]
pub(super) enum Cell<F: FieldBackend> {
    Undef,
    Field(FieldElement<F>),
    Int(u64),
    Array(u32),
}

/// An array allocated during execution. Kept width-tagged so the
/// Load/Store semantics are obvious.
pub(super) enum ArrayBuf<F: FieldBackend> {
    Field(Vec<FieldElement<F>>),
    Int { w: IntW, data: Vec<u64> },
}

impl<F: FieldBackend> ArrayBuf<F> {
    pub(super) fn len(&self) -> u32 {
        match self {
            Self::Field(v) => v.len() as u32,
            Self::Int { data, .. } => data.len() as u32,
        }
    }
}

/// Per-step control-flow signal. The interpreter loop in
/// [`execute_with_budget`] consumes this to drive the frame stack.
/// `step` only classifies the instruction; all frame manipulation
/// (push on `Call`, pop on `Return`, argument / return wiring) happens
/// in the loop so the borrow of `state` stays simple.
pub(super) enum Flow {
    /// Move to the next instruction (PC += 1).
    Next,
    /// Jump to a resolved instruction index in the current subprogram.
    JumpTo(u32),
    /// `Call` fired — push a frame for `func_id`, copy `args` into its
    /// parameter registers, and record `rets` so the matching `Return`
    /// knows where to write back into this frame.
    Call {
        func_id: u32,
        args: Vec<u32>,
        rets: Vec<u32>,
    },
    /// `Return` fired — pop the current frame, copying the registers
    /// named in `srcs` into the caller's recorded return destinations.
    /// If the popped frame was the entry, execution halts.
    Return { srcs: Vec<u32> },
}

/// Maximum nesting of `Call` activations. circom forbids recursion, so
/// a correct lift produces an acyclic call graph whose depth is the
/// nesting of the source functions — a handful for circomlib. A larger
/// depth means malformed bytecode or a cyclic lift; fail loudly rather
/// than grow the stack unbounded.
const MAX_CALL_DEPTH: u32 = 256;

/// One call activation: which subprogram it runs, its private register
/// frame, its program counter, and where its return values go in the
/// caller's frame once it executes `Return`. The entry frame has an
/// empty `ret_dsts` (its `Return` halts execution).
pub(super) struct Frame<F: FieldBackend> {
    pub(super) func_id: u32,
    cells: Vec<Cell<F>>,
    pub(super) pc: u32,
    ret_dsts: Vec<u32>,
}

/// Executor state kept across instructions. A stack of call frames, a
/// program-global array store (so array handles cross frames with no
/// backing copy), a cumulative array-cell counter, and one
/// byte-offset-to-instruction-index map per subprogram (jump targets
/// are subprogram-local byte offsets).
pub(super) struct State<F: FieldBackend> {
    frames: Vec<Frame<F>>,
    pub(super) arrays: Vec<ArrayBuf<F>>,
    offset_maps: Vec<HashMap<u32, u32>>,
    /// Total cells allocated across all arrays so far. Incremented on
    /// every [`Instr::AllocArray`] and checked against
    /// [`MAX_ARRAY_MEMORY_CELLS`] before the allocation is accepted.
    pub(super) array_cells_used: u64,
}

impl<F: FieldBackend> State<F> {
    pub(super) fn new(prog: &Program) -> Result<Self, ArtikError> {
        if prog.subprograms.is_empty() || prog.entry >= prog.subprograms.len() {
            return Err(ArtikError::NoSubprograms);
        }
        // Validator already enforces the per-subprogram frame cap, but
        // re-check here so the executor never trusts a caller-built
        // `Program` that bypassed decode. Defense in depth against
        // direct Program construction.
        let mut offset_maps = Vec::with_capacity(prog.subprograms.len());
        for sub in &prog.subprograms {
            if sub.frame_size > crate::ir::MAX_FRAME_SIZE {
                return Err(ArtikError::FrameTooLarge {
                    frame_size: sub.frame_size,
                    max: crate::ir::MAX_FRAME_SIZE,
                });
            }
            let mut map = HashMap::with_capacity(sub.body.len());
            let mut offset: u32 = 0;
            for (idx, instr) in sub.body.iter().enumerate() {
                map.insert(offset, idx as u32);
                offset = offset.saturating_add(instr.encoded_size());
            }
            offset_maps.push(map);
        }

        let entry = &prog.subprograms[prog.entry];
        let entry_frame = Frame {
            func_id: prog.entry as u32,
            cells: vec![Cell::Undef; entry.frame_size as usize],
            pc: 0,
            ret_dsts: Vec::new(),
        };
        Ok(Self {
            frames: vec![entry_frame],
            arrays: Vec::new(),
            offset_maps,
            array_cells_used: 0,
        })
    }

    pub(super) fn top(&self) -> Result<&Frame<F>, ArtikError> {
        self.frames.last().ok_or(ArtikError::NoSubprograms)
    }

    pub(super) fn top_mut(&mut self) -> Result<&mut Frame<F>, ArtikError> {
        self.frames.last_mut().ok_or(ArtikError::NoSubprograms)
    }

    pub(super) fn read_field(&self, reg: u32) -> Result<&FieldElement<F>, ArtikError> {
        let cells = &self.top()?.cells;
        match cells.get(reg as usize) {
            Some(Cell::Field(v)) => Ok(v),
            Some(Cell::Undef) => Err(ArtikError::UndefinedRegister { reg }),
            Some(_) => Err(ArtikError::WrongCellKind { reg }),
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: cells.len() as u32,
            }),
        }
    }

    pub(super) fn read_int(&self, reg: u32) -> Result<u64, ArtikError> {
        let cells = &self.top()?.cells;
        match cells.get(reg as usize) {
            Some(Cell::Int(v)) => Ok(*v),
            Some(Cell::Undef) => Err(ArtikError::UndefinedRegister { reg }),
            Some(_) => Err(ArtikError::WrongCellKind { reg }),
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: cells.len() as u32,
            }),
        }
    }

    pub(super) fn read_array(&self, reg: u32) -> Result<u32, ArtikError> {
        let cells = &self.top()?.cells;
        match cells.get(reg as usize) {
            Some(Cell::Array(h)) => Ok(*h),
            Some(Cell::Undef) => Err(ArtikError::UndefinedRegister { reg }),
            Some(_) => Err(ArtikError::WrongCellKind { reg }),
            None => Err(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: cells.len() as u32,
            }),
        }
    }

    /// Clone a cell from the top frame by register, for the array
    /// store path which needs the source value without holding a
    /// borrow of `cells` across the `arrays` mutation.
    pub(super) fn read_cell_clone(&self, reg: u32) -> Result<Cell<F>, ArtikError> {
        let cells = &self.top()?.cells;
        cells
            .get(reg as usize)
            .cloned()
            .ok_or(ArtikError::RegisterOutOfRange {
                reg,
                frame_size: cells.len() as u32,
            })
    }

    pub(super) fn write(&mut self, reg: u32, cell: Cell<F>) -> Result<(), ArtikError> {
        let cells = &mut self.top_mut()?.cells;
        match cells.get_mut(reg as usize) {
            Some(slot) => {
                *slot = cell;
                Ok(())
            }
            None => {
                let frame_size = cells.len() as u32;
                Err(ArtikError::RegisterOutOfRange { reg, frame_size })
            }
        }
    }

    pub(super) fn resolve_jump(&self, target: u32) -> Result<u32, ArtikError> {
        let func_id = self.top()?.func_id as usize;
        self.offset_maps
            .get(func_id)
            .and_then(|m| m.get(&target))
            .copied()
            .ok_or(ArtikError::InvalidJumpTarget { target })
    }

    /// Push a frame for `callee`, binding `args` (registers in the
    /// current frame) into the callee's parameter registers
    /// `0..args.len()`. The current frame's pc is advanced past the
    /// `Call` (at `call_pc`) so that the matching `Return` resumes
    /// after it. `rets` records where the callee's return values land
    /// in this (caller) frame.
    pub(super) fn enter_call(
        &mut self,
        prog: &Program,
        callee: u32,
        args: &[u32],
        rets: Vec<u32>,
        call_pc: u32,
    ) -> Result<(), ArtikError> {
        if self.frames.len() as u32 >= MAX_CALL_DEPTH {
            return Err(ArtikError::CallDepthExceeded {
                max: MAX_CALL_DEPTH,
            });
        }
        let sub = prog
            .subprograms
            .get(callee as usize)
            .ok_or(ArtikError::UnknownSubprogram { func_id: callee })?;

        // Copy argument cells out of the caller frame first (immutable
        // borrow), then build the callee frame.
        let mut arg_cells = Vec::with_capacity(args.len());
        for a in args {
            arg_cells.push(self.read_cell_clone(*a)?);
        }
        let mut cells = vec![Cell::Undef; sub.frame_size as usize];
        for (i, c) in arg_cells.into_iter().enumerate() {
            if let Some(slot) = cells.get_mut(i) {
                *slot = c;
            } else {
                return Err(ArtikError::RegisterOutOfRange {
                    reg: i as u32,
                    frame_size: sub.frame_size,
                });
            }
        }

        self.top_mut()?.pc = call_pc + 1;
        self.frames.push(Frame {
            func_id: callee,
            cells,
            pc: 0,
            ret_dsts: rets,
        });
        Ok(())
    }

    /// Pop the current frame, copying the registers named in `srcs`
    /// into the caller frame at the popped frame's `ret_dsts`. Returns
    /// `true` if the popped frame was the entry (execution halts).
    pub(super) fn do_return(&mut self, srcs: &[u32]) -> Result<bool, ArtikError> {
        let mut ret_cells = Vec::with_capacity(srcs.len());
        for s in srcs {
            ret_cells.push(self.read_cell_clone(*s)?);
        }
        let popped = self.frames.pop().ok_or(ArtikError::NoSubprograms)?;
        if self.frames.is_empty() {
            return Ok(true);
        }
        let caller = self.top_mut()?;
        for (dst, cell) in popped.ret_dsts.iter().zip(ret_cells) {
            match caller.cells.get_mut(*dst as usize) {
                Some(slot) => *slot = cell,
                None => {
                    return Err(ArtikError::RegisterOutOfRange {
                        reg: *dst,
                        frame_size: caller.cells.len() as u32,
                    })
                }
            }
        }
        Ok(false)
    }
}
