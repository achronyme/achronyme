/// Compute the Levenshtein (edit) distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Find the best match for `name` among `candidates` within `max_distance`.
/// The effective distance threshold is scaled by name length to avoid
/// suggesting unrelated identifiers for short names (e.g., "ab" → distance 2
/// would match anything of length 2).
/// Returns the closest candidate, or `None` if nothing is close enough.
pub fn find_similar<'a>(
    name: &str,
    candidates: impl Iterator<Item = &'a str>,
    max_distance: usize,
) -> Option<&'a str> {
    // Scale threshold: for names <= 3 chars, allow at most 1 edit.
    let threshold = if name.len() <= 3 {
        max_distance.min(1)
    } else {
        max_distance
    };
    let mut best: Option<(&str, usize)> = None;
    for candidate in candidates {
        if candidate == name || candidate.starts_with('_') {
            continue;
        }
        let dist = levenshtein(name, candidate);
        if dist <= threshold && best.is_none_or(|(_, d)| dist < d) {
            best = Some((candidate, dist));
        }
    }
    best.map(|(s, _)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_identical() {
        assert_eq!(levenshtein("foo", "foo"), 0);
    }

    #[test]
    fn levenshtein_one_char_diff() {
        assert_eq!(levenshtein("foo", "fob"), 1);
    }

    #[test]
    fn levenshtein_insertion() {
        assert_eq!(levenshtein("foo", "fooo"), 1);
    }

    #[test]
    fn levenshtein_deletion() {
        assert_eq!(levenshtein("foo", "fo"), 1);
    }

    #[test]
    fn levenshtein_completely_different() {
        assert_eq!(levenshtein("abc", "xyz"), 3);
    }

    #[test]
    fn levenshtein_empty() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("", ""), 0);
    }

    #[test]
    fn find_similar_basic() {
        let names = vec!["foo", "bar", "baz"];
        assert_eq!(find_similar("fob", names.iter().copied(), 2), Some("foo"));
    }

    #[test]
    fn find_similar_no_match() {
        let names = vec!["foo", "bar"];
        assert_eq!(find_similar("xyz", names.iter().copied(), 2), None);
    }

    #[test]
    fn find_similar_exact_excluded() {
        let names = vec!["foo"];
        assert_eq!(find_similar("foo", names.iter().copied(), 2), None);
    }

    #[test]
    fn find_similar_underscore_excluded() {
        let names = vec!["_foo", "bar"];
        assert_eq!(find_similar("baz", names.iter().copied(), 2), Some("bar"));
    }
}
