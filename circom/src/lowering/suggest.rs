//! "Did you mean?" suggestion system for the Circom lowering pipeline.
//!
//! Uses Levenshtein distance to find similar identifiers when a variable,
//! signal, function, or template name is not found.

/// Compute the Levenshtein (edit) distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
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

/// Find the best match for `name` among `candidates` within edit distance 2.
///
/// For names <= 3 chars, allows at most 1 edit to avoid spurious matches.
/// Skips exact matches and `_`-prefixed names.
pub fn find_similar<'a>(
    name: &str,
    candidates: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
    let threshold = if name.len() <= 3 { 1 } else { 2 };
    let mut best: Option<(&str, usize)> = None;
    for candidate in candidates {
        if candidate == name || candidate.starts_with('_') {
            continue;
        }
        let dist = levenshtein(name, candidate);
        if dist <= threshold && best.as_ref().map_or(true, |(_, d)| dist < *d) {
            best = Some((candidate, dist));
        }
    }
    best.map(|(s, _)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("foo", "foo"), 0);
        assert_eq!(levenshtein("foo", "fob"), 1);
        assert_eq!(levenshtein("foo", "fooo"), 1);
        assert_eq!(levenshtein("", "abc"), 3);
    }

    #[test]
    fn find_similar_basic() {
        let names = vec!["foo", "bar", "baz"];
        assert_eq!(find_similar("fob", names.iter().copied()), Some("foo"));
    }

    #[test]
    fn find_similar_no_match() {
        let names = vec!["foo", "bar"];
        assert_eq!(find_similar("xyz", names.iter().copied()), None);
    }

    #[test]
    fn find_similar_short_name_strict() {
        // For short names (<=3), only 1 edit allowed
        let names = vec!["ab", "cd"];
        assert_eq!(find_similar("ac", names.iter().copied()), Some("ab"));
        // "xy" is 2 edits from "ab" — too far for a 2-char name
        assert_eq!(find_similar("xy", names.iter().copied()), None);
    }
}
