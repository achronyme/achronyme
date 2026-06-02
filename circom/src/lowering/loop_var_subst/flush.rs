/// Given the slice `nodes[iter_start..iter_end]` covering one iteration's
/// emission, return the indices (relative to `iter_start`) of the
/// nodes that are NOT inside any flush range — i.e. the body-only
/// emission, the part that R1″ memoization can replay across iters.
///
/// `flush_ranges` are absolute indices into the same `nodes` Vec
/// (as produced by `LoweringContext::flush_tracker`). Ranges that
/// fall outside `[iter_start, iter_end)` are ignored — those flushes
/// belong to a different iteration.
///
/// The output indices are sorted ascending. This is a metadata
/// helper; it does not allocate node clones. Callers can map the
/// indices to owned nodes by cloning the corresponding entries.
pub fn body_only_indices(
    iter_start: usize,
    iter_end: usize,
    flush_ranges: &[(usize, usize)],
) -> Vec<usize> {
    if iter_end <= iter_start {
        return Vec::new();
    }
    let total = iter_end - iter_start;
    // Mark every absolute index in any flush range.
    let mut in_flush = vec![false; total];
    for &(start, end) in flush_ranges {
        // Clip the range to the iteration window.
        let lo = start.max(iter_start);
        let hi = end.min(iter_end);
        if lo >= hi {
            continue;
        }
        for i in lo..hi {
            in_flush[i - iter_start] = true;
        }
    }
    (0..total).filter(|i| !in_flush[*i]).collect()
}

/// Total node count in `flush_ranges` that falls inside the iteration
/// window `[iter_start, iter_end)`. Useful for shape statistics
/// without materializing the index vec.
pub fn flushed_node_count(
    iter_start: usize,
    iter_end: usize,
    flush_ranges: &[(usize, usize)],
) -> usize {
    flush_ranges
        .iter()
        .map(|&(start, end)| {
            let lo = start.max(iter_start);
            let hi = end.min(iter_end);
            hi.saturating_sub(lo)
        })
        .sum()
}
