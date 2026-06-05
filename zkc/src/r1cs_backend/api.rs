use super::*;

impl<F: FieldBackend> Default for R1CSCompiler<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> R1CSCompiler<F> {
    /// Create an empty R1CS compiler with a fresh constraint system.
    pub fn new() -> Self {
        Self {
            cs: ConstraintSystem::new(),
            bindings: HashMap::new(),
            public_inputs: Vec::new(),
            witnesses: Vec::new(),
            prime_id: PrimeId::Bn254,
            poseidon_params: None,
            witness_ops: SegmentedVec::new(),
            proven_boolean: std::collections::HashSet::new(),
            bool_enforced: std::collections::HashSet::new(),
            constraint_origins: Vec::new(),
            track_constraint_origins: true,
            track_input_metadata: true,
            forward_assert_eq_collapse: false,
            direct_linear_mul: false,
            record_witness_ops: true,
            substitution_map: None,
            lc_map: LcMap::new(),
            lc_cache_term_limit: None,
            used_ssa: UsedSsaSet::new(),
            range_bounds: HashMap::new(),
            divmod_cache: HashMap::new(),
            artik_program_intern: Vec::new(),
        }
    }

    /// Create an R1CS compiler that skips per-constraint origin tracking.
    ///
    /// `constraint_origins` is left empty across the full emission. Callers
    /// that don't need IR-instruction provenance (high-volume circuits that
    /// only run prove/verify, never inspect) save ~16 B per emitted
    /// constraint plus the parallel Vec's capacity-tail. On boss-fight-class
    /// circuits emitting ~10M constraints this is hundreds of MB of peak
    /// RSS.
    ///
    /// Note that `optimize_r1cs*` already clears `constraint_origins` after
    /// linear substitution rebuilds the constraint vec, so downstream
    /// readers must already tolerate an empty origins vec — `new_lean`
    /// extends that tolerance window to before the optimize step too.
    pub fn new_lean() -> Self {
        let mut c = Self::new();
        c.track_constraint_origins = false;
        c.track_input_metadata = false;
        c.forward_assert_eq_collapse = true;
        c
    }

    /// Create an R1CS compiler for proving paths that need named input
    /// metadata and witness ops, but do not need inspector provenance.
    ///
    /// This preserves the default constraint surface and witness-generation
    /// behavior while skipping `constraint_origins`, which are unused by
    /// native proving and expensive on large circuits.
    pub fn new_prover() -> Self {
        let mut c = Self::new();
        c.track_constraint_origins = false;
        c
    }

    /// Create a compiler that folds linear-constraint elimination into
    /// emission (incremental collapse). The underlying constraint system
    /// never materializes the unoptimized set: each linear constraint is
    /// absorbed into a substitution map at `enforce` time, so
    /// `cs.num_constraints()` tracks the post-elimination survivor count
    /// rather than the pre-optimization total. Builds on `new_lean` for
    /// origin tracking and fresh-private assert collapse, but restores input
    /// metadata so normal witness generation by declared names keeps working.
    /// After compilation, recover the substitution map for witness fixup via
    /// `cs.take_collapse_substitution_map()`.
    pub fn new_incremental() -> Self {
        let mut c = Self::new_lean();
        c.track_input_metadata = true;
        c.cs.enable_incremental_collapse();
        c
    }

    /// Create a lean compiler that emits multi-term LC products directly.
    ///
    /// This avoids building the linear materialization constraints that O1
    /// would later eliminate, so the resident constraint set tracks a shape
    /// closer to post-O1 during emission.
    pub fn new_direct_linear_mul() -> Self {
        let mut c = Self::new_lean();
        c.direct_linear_mul = true;
        c
    }

    /// Create a lean compile-only compiler that skips witness-op and
    /// constraint-row retention.
    ///
    /// Constraint and wire counts remain exact, but callers cannot serialize,
    /// optimize, prove, or verify from the returned in-memory rows. This mode
    /// is for sizing and compile-through probes that only need to exercise the
    /// emitter.
    pub fn new_compile_only_direct_linear_mul() -> Self {
        let mut c = Self::new_direct_linear_mul();
        c.record_witness_ops = false;
        c.cs.disable_constraint_retention();
        match std::env::var("ACH_R1CS_COMPILE_ONLY_COLLAPSE").as_deref() {
            Ok("1") | Ok("true") | Ok("full") => c.cs.enable_incremental_collapse(),
            Ok("count") | Ok("count-only") | Ok("discard") => {
                c.cs.enable_incremental_collapse_count_only();
            }
            _ => {}
        }
        if let Some(limit) = std::env::var("ACH_R1CS_LC_CACHE_TERM_LIMIT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            c.lc_cache_term_limit = Some(limit);
        }
        if let Some(keep_last) = std::env::var("ACH_R1CS_LC_MAP_KEEP_LAST")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
        {
            c.lc_map.set_keep_last_vars(Some(keep_last));
            c.used_ssa.set_keep_last_vars(Some(keep_last));
        }
        if let Some(keep_prefix) = std::env::var("ACH_R1CS_LC_MAP_KEEP_PREFIX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
        {
            c.lc_map.set_keep_prefix_vars(keep_prefix);
            c.used_ssa.set_keep_prefix_vars(keep_prefix);
        }
        c
    }

    pub fn lc_map_shape_counts(&self) -> LcMapShapeCounts {
        self.lc_map.shape_counts()
    }

    pub fn retained_stats(&self) -> R1CSRetainedStats {
        let shapes = self.lc_map.shape_counts();
        R1CSRetainedStats {
            lc_empty_slots: shapes.empty_slots,
            lc_zero_entries: shapes.zero_entries,
            lc_unit_variable_entries: shapes.unit_variable_entries,
            lc_single_term_entries: shapes.single_term_entries,
            lc_multi_term_entries: shapes.multi_term_entries,
            lc_stored_terms: shapes.stored_terms,
            used_ssa_words: self.used_ssa.word_count(),
            proven_boolean_len: self.proven_boolean.len(),
            bool_enforced_len: self.bool_enforced.len(),
            range_bounds_len: self.range_bounds.len(),
            divmod_cache_len: self.divmod_cache.len(),
            artik_program_intern_len: self.artik_program_intern.len(),
        }
    }

    pub(super) fn cache_lc(&mut self, result: SsaVar, lc: LinearCombination<F>) {
        let lc = match self.lc_cache_term_limit {
            Some(limit)
                if lc.terms().len() > limit
                    && lc.as_single_variable().is_none()
                    && lc.constant_value().is_none() =>
            {
                LinearCombination::from_variable(self.materialize_lc(&lc))
            }
            _ => lc,
        };
        self.lc_map.insert(result, lc);
    }

    pub(crate) fn push_witness_op(&mut self, op: WitnessOp<F>) {
        if self.record_witness_ops {
            self.witness_ops.push(op);
        }
    }

    /// Intern an Artik bytecode payload. Returns an `Arc<[u8]>` shared
    /// with prior emissions whose `program_bytes` are byte-identical;
    /// otherwise allocates a fresh `Arc` and registers it.
    ///
    /// Linear scan is intentional — see the field doc on
    /// `artik_program_intern` for the cardinality reasoning.
    pub(super) fn intern_artik_program(&mut self, bytes: &[u8]) -> Arc<[u8]> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let digest = hasher.finish();

        for (h, arc) in self.artik_program_intern.iter() {
            if *h == digest && arc.as_ref() == bytes {
                return arc.clone();
            }
        }
        let arc: Arc<[u8]> = Arc::from(bytes);
        self.artik_program_intern.push((digest, arc.clone()));
        arc
    }

    /// Number of unique Artik bytecode payloads currently interned.
    /// Test-only accessor — production code has no reason to inspect
    /// the intern table.
    #[cfg(test)]
    pub(crate) fn artik_program_intern_len(&self) -> usize {
        self.artik_program_intern.len()
    }

    /// Look up the cached `LinearCombination` for `var`. Returns an error if
    /// the variable was referenced before it was defined — a structural
    /// invariant of SSA form that the walker relies on.
    pub(super) fn lookup_lc(&mut self, var: &SsaVar) -> Result<LinearCombination<F>, R1CSError> {
        self.mark_ssa_used(*var);
        self.lookup_lc_untracked(var)
    }

    pub(super) fn lookup_lc_untracked(
        &self,
        var: &SsaVar,
    ) -> Result<LinearCombination<F>, R1CSError> {
        self.lc_map.get(var).ok_or_else(|| {
            R1CSError::UnsupportedOperation(format!("undefined SSA variable {:?}", var), None)
        })
    }

    pub(super) fn mark_ssa_used(&mut self, var: SsaVar) {
        self.used_ssa.mark(var);
    }

    pub(super) fn is_ssa_used(&self, var: SsaVar) -> bool {
        self.used_ssa.contains(var)
    }

    /// Set the proven-boolean set from bool_prop analysis.
    /// Variables in this set skip redundant boolean enforcement constraints.
    pub fn set_proven_boolean(&mut self, set: std::collections::HashSet<ir::types::SsaVar>) {
        self.proven_boolean = set;
    }

    /// Run linear constraint elimination on the compiled R1CS.
    ///
    /// Must be called after `compile_ir()` / `compile_ir_with_witness()`.
    /// Identifies constraints of the form `k * LC = LC` (linear, no real
    /// multiplication) and substitutes one wire with the LC, eliminating
    /// the constraint. Runs to fixpoint.
    ///
    /// Also updates `witness_ops` (removes ops for substituted targets,
    /// applies substitutions to source LCs) and `constraint_origins`.
    ///
    /// The substitution map is stored for witness post-fixup.
    pub fn optimize_r1cs(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_linear();
        self.install_finalize_substitutions(subs);
        stats
    }

    /// Install a finalize pass's substitution map: compose it with the
    /// incremental-collapse map (when collapse was enabled during
    /// emission), apply the result to `witness_ops`, and store it for
    /// witness reconstruction.
    ///
    /// When collapse is disabled (`take_collapse_substitution_map` →
    /// `None`) this is exactly the legacy path: store `finalize_subs`
    /// verbatim. When collapse ran, the finalize pass operated on the
    /// collapse survivors, so its map alone reconstructs only the wires
    /// *it* eliminated; the collapse map must be composed in (collapse
    /// applied first, finalize second) so a single witness fixup
    /// reconstructs every eliminated wire. Routing every finalize entry
    /// through here closes the trap where collapse + an O2 finalize would
    /// otherwise silently drop the collapse map.
    fn install_finalize_substitutions(&mut self, finalize_subs: SubstitutionMap<F>) {
        let subs = match self.cs.take_collapse_substitution_map() {
            Some(collapse_subs) => {
                constraints::r1cs_optimize::compose_substitution_maps(collapse_subs, &finalize_subs)
            }
            None => finalize_subs,
        };

        if !subs.is_empty() {
            // Drop ops that produce only eliminated wires and rewrite the
            // source LCs of the survivors. The composed map is canonical,
            // so this single pass is equivalent to applying collapse then
            // finalize in sequence.
            crate::witness::apply_substitutions_to_witness_ops(&mut self.witness_ops, &subs);

            // optimize_linear replaces the constraint vec wholesale, so the
            // old per-constraint origin indices no longer map to anything;
            // clear them (the inspector degrades gracefully without origins).
            self.constraint_origins.clear();

            self.substitution_map = Some(subs);
        }
    }

    /// Run O2 constraint simplification on the compiled R1CS.
    ///
    /// Includes O1 (linear elimination) plus DEDUCE: extracts linear
    /// constraints implied by quadratic constraints via Gaussian elimination
    /// on the monomial matrix. Matches circom `--O2`.
    pub fn optimize_r1cs_o2(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_o2();
        self.install_finalize_substitutions(subs);
        stats
    }

    /// Run O2 constraint simplification with sparse-row DEDUCE.
    ///
    /// Functionally identical to `optimize_r1cs_o2` but partitions the
    /// constraint set into connected components (Union-Find on shared
    /// quadratic monomials) and runs Gaussian elimination on each
    /// component independently using `BTreeMap`-row representation.
    /// This avoids the dense `k x q` matrix that OOMs on bit-heavy
    /// circuits like SHA-256, where both dimensions exceed 60k.
    ///
    /// Clusters larger than the configured threshold are skipped --
    /// they would still fit in RAM in sparse form but full reduction
    /// without Markowitz pivoting / fill-in management is not
    /// worthwhile in this conservative path. Skipping is safe; the
    /// cluster's quadratic constraints stay in the system unchanged.
    pub fn optimize_r1cs_o2_sparse(&mut self) -> R1CSOptimizeResult {
        let (subs, stats) = self.cs.optimize_o2_sparse();
        self.install_finalize_substitutions(subs);
        stats
    }

    /// Declare a public input variable and bind it to `name`.
    ///
    /// Public inputs must be declared before witnesses to maintain the
    /// snarkjs-compatible wire layout.
    pub fn declare_public(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_input();
        self.bindings.insert(name.to_string(), var);
        self.public_inputs.push(name.to_string());
        var
    }

    /// Declare a private witness variable and bind it to `name`.
    pub fn declare_witness(&mut self, name: &str) -> Variable {
        let var = self.cs.alloc_witness();
        self.bindings.insert(name.to_string(), var);
        self.witnesses.push(name.to_string());
        var
    }

    /// Materialize an LC if it exceeds the auto-materialization threshold.
    ///
    /// Prevents exponential LC term growth in long chains of Add/Sub
    /// (e.g. MDS matrix multiplication in Poseidon partial rounds).
    /// Adds at most 1 constraint per materialization.
    pub(super) fn auto_materialize(&mut self, lc: LinearCombination<F>) -> LinearCombination<F> {
        if lc.terms().len() > LC_AUTO_MATERIALIZE_THRESHOLD {
            let var = self.materialize_lc(&lc);
            LinearCombination::from_variable(var)
        } else {
            lc
        }
    }

    /// Look up a previously declared variable by name.
    pub fn lookup(&self, name: &str) -> Result<Variable, R1CSError> {
        self.bindings
            .get(name)
            .copied()
            .ok_or_else(|| R1CSError::UndeclaredVariable(name.to_string(), None))
    }

    /// Compile an SSA IR program into R1CS constraints.
    ///
    /// ```
    /// use zkc::r1cs_backend::R1CSCompiler;
    /// use ir::IrLowering;
    ///
    /// let prog: ir::types::IrProgram = IrLowering::lower_circuit("assert_eq(x * y, z)", &["z"], &["x", "y"]).unwrap();
    /// let mut rc = R1CSCompiler::new();
    /// rc.compile_ir(&prog).unwrap();
    /// assert!(rc.cs.num_constraints() > 0);
    /// ```
    pub fn compile_ir(&mut self, program: &IrProgram<F>) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
    {
        self.lc_map.clear();
        self.used_ssa.clear();
        self.range_bounds.clear();
        self.divmod_cache.clear();
        <Self as constraints::ConstraintBackend<F>>::compile_ir(self, program)
    }

    /// Streaming counterpart of [`compile_ir`](Self::compile_ir): consume
    /// owned instructions from any [`IntoIterator`] source so each
    /// `Instruction<F>` drops the moment its constraints are emitted.
    /// Lets the bridge feed a Lysis interner directly into the backend
    /// without ever materializing a `Vec<Instruction<F>>`.
    ///
    /// The per-program caches are cleared up front, matching the
    /// [`compile_ir`](Self::compile_ir) contract.
    pub fn compile_instructions<I>(&mut self, instructions: I) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
        I: IntoIterator<Item = IrInstruction<F>>,
    {
        self.lc_map.clear();
        self.used_ssa.clear();
        self.range_bounds.clear();
        self.divmod_cache.clear();
        <Self as constraints::ConstraintBackend<F>>::compile_instructions(self, instructions)
    }

    /// Multi-batch counterpart of
    /// [`compile_instructions`](Self::compile_instructions). Consumes
    /// owned instructions from any [`IntoIterator`] source like the
    /// single-batch entry point, but does **not** clear the per-program
    /// caches (`lc_map`, `range_bounds`, `divmod_cache`) on entry —
    /// state carries across calls so operands defined in an earlier
    /// batch remain resolvable in a later batch.
    ///
    /// Intended for feeding a single program in multiple batches, one
    /// batch per emission chunk from a chunk-draining lysis sink. The
    /// chunk-drain bridge minted in [`lysis::ChunkDrainingSink`] hands a
    /// `Vec<InstructionKind<F>>` to its consumer at every chunk seal;
    /// the consumer routes each chunk here so per-chunk allocations
    /// drop while operand lookup state survives the seal boundary.
    ///
    /// Caller manages cache lifecycle: invoke this on a freshly
    /// constructed [`R1CSCompiler::new`] for the first batch of a
    /// program, then continue invoking it for every subsequent batch of
    /// the same program. Reusing the compiler across distinct programs
    /// requires constructing a fresh instance — the trait's
    /// [`compile_ir`](Self::compile_ir) /
    /// [`compile_instructions`](Self::compile_instructions) entries
    /// keep the cache-clearing semantics for that case.
    ///
    /// `constraint_origins.ir_index` is the per-call iterator position
    /// (starting at 0 in every batch), not a program-global index.
    /// Consumers that depend on a program-global index must track batch
    /// starts externally.
    pub fn compile_instructions_streaming<I>(&mut self, instructions: I) -> Result<(), R1CSError>
    where
        F: PoseidonParamsProvider,
        I: IntoIterator<Item = IrInstruction<F>>,
    {
        <Self as constraints::ConstraintBackend<F>>::compile_instructions(self, instructions)
    }
}
