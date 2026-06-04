use std::collections::BTreeSet;

use memory::field::FieldBackend;

use crate::program::Program;

pub(super) fn root_body_range<F: FieldBackend>(program: &Program<F>) -> (usize, usize) {
    // Convention: the root body is the contiguous prefix of
    // `program.body` whose offsets are *not* inside any template
    // body. In practice the top-level body is everything up to the
    // first DefineTemplate-declared slice.
    let Some(first_template_offset) = program.templates.iter().map(|t| t.body_offset).min() else {
        return (0, program.body.len());
    };
    (0, lower_bound_offset_idx(program, first_template_offset))
}

/// Per-template-id lookup tables built from a program's `DefineTemplate`
/// slices: template metadata indexed by id, and each template's
/// `(start, end)` body-offset range indexed by id.
type TemplateTables = (
    Vec<Option<crate::program::Template>>,
    Vec<Option<(usize, usize)>>,
);

pub(super) fn build_template_tables<F: FieldBackend>(program: &Program<F>) -> TemplateTables {
    let Some(max_id) = program.templates.iter().map(|t| t.id as usize).max() else {
        return (Vec::new(), Vec::new());
    };
    let mut template_lookup = vec![None; max_id + 1];
    let mut body_ranges = vec![None; max_id + 1];
    let mut starts: Vec<(u32, usize)> = Vec::with_capacity(program.templates.len());
    let mut ends: Vec<(u32, usize)> = Vec::with_capacity(program.templates.len());
    for (decl_idx, template) in program.templates.iter().enumerate() {
        let id = template.id as usize;
        if template_lookup[id].is_none() {
            template_lookup[id] = Some(*template);
        }
        starts.push((template.body_offset, decl_idx));
        ends.push((
            template.body_offset.saturating_add(template.body_len),
            decl_idx,
        ));
    }
    starts.sort_unstable_by_key(|&(offset, _)| offset);
    ends.sort_unstable_by_key(|&(offset, _)| offset);

    let mut active: BTreeSet<usize> = BTreeSet::new();
    let mut next_start = 0usize;
    let mut next_end = 0usize;
    for (body_idx, instr) in program.body.iter().enumerate() {
        while next_end < ends.len() && ends[next_end].0 <= instr.offset {
            active.remove(&ends[next_end].1);
            next_end += 1;
        }
        while next_start < starts.len() && starts[next_start].0 <= instr.offset {
            active.insert(starts[next_start].1);
            next_start += 1;
        }
        if let Some(&decl_idx) = active.iter().next() {
            let id = program.templates[decl_idx].id as usize;
            match &mut body_ranges[id] {
                Some((_, end)) => *end = body_idx + 1,
                slot @ None => *slot = Some((body_idx, body_idx + 1)),
            }
        }
    }
    (template_lookup, body_ranges)
}

pub(super) fn exact_offset_idx<F: FieldBackend>(
    program: &Program<F>,
    offset: u32,
) -> Option<usize> {
    program
        .body
        .binary_search_by_key(&offset, |instr| instr.offset)
        .ok()
}

pub(super) fn lower_bound_offset_idx<F: FieldBackend>(program: &Program<F>, offset: u32) -> usize {
    program.body.partition_point(|instr| instr.offset < offset)
}
