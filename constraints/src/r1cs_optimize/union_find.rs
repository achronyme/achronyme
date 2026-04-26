//! Vec-backed disjoint-set union (Union-Find) with path compression
//! and union by rank.
//!
//! Used by both `deduce_sparse` (clusters quadratic constraints by
//! shared monomial) and `linear_cluster` (clusters linear constraints
//! by shared variable index). The primitive itself is identical; only
//! the equivalence relation differs between consumers.

/// Vec-backed disjoint-set union with path compression + union by rank.
pub(super) struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl UnionFind {
    pub(super) fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    pub(super) fn find(&mut self, mut x: usize) -> usize {
        // Two-pass: walk to root, then compress every node on the path
        // to point directly at the root.
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        while self.parent[x] != root {
            let next = self.parent[x];
            self.parent[x] = root;
            x = next;
        }
        root
    }

    pub(super) fn union(&mut self, a: usize, b: usize) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        match self.rank[ra].cmp(&self.rank[rb]) {
            std::cmp::Ordering::Less => self.parent[ra] = rb,
            std::cmp::Ordering::Greater => self.parent[rb] = ra,
            std::cmp::Ordering::Equal => {
                self.parent[rb] = ra;
                self.rank[ra] += 1;
            }
        }
    }
}
