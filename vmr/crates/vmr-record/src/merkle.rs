//! Deterministic Merkle tree over hashed leaves, with inclusion proofs.
// ============================================================================
//  merkle.rs — deterministic Merkle tree over hashed leaves (TASKS 3.2)
//
//  Domain separation (fixed for v0.1):
//    leaf = SHA-256(0x00 || data)
//    node = SHA-256(0x01 || left || right)
//    empty tree root = SHA-256(0x02)
//
//  Leaf order is caller order (the spec's component order). No maps, no
//  randomness: the same leaves always produce the same root. At each level
//  nodes are paired left to right; an odd trailing node is promoted
//  unchanged to the next level.
//
//  Inclusion proofs (QA P3-08) are canonical: a proof names its leaf's
//  index and the tree's leaf count, and carries exactly one sibling hash per
//  level at which that leaf's node HAS a sibling — levels where it is
//  promoted contribute nothing. The verifier takes the leaf count from the
//  same trusted source as the root (for a record: training_input_count,
//  signed with training_input_merkle_root), derives the tree's shape from
//  (index, leaf count), and must consume the siblings exactly. A padded,
//  truncated or re-labelled proof therefore fails; for a given root, leaf
//  count and index exactly one proof verifies.
//
//  The root does not itself commit to the leaf count (the v0.1 root is
//  frozen: the vector's training_input_merkle_root depends on it), which is
//  why the verifier must be given the count rather than read it from the
//  proof.
// ============================================================================

use crate::error::Error;
use crate::hash::{sha256, DIGEST_LEN};

/// The root of the empty tree.
pub fn empty_root() -> [u8; DIGEST_LEN] {
    sha256(&[0x02])
}

/// The hash a leaf contributes to the tree.
pub fn hash_leaf(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut buf = Vec::with_capacity(1 + data.len());
    buf.push(0x00);
    buf.extend_from_slice(data);
    sha256(&buf)
}

fn hash_node(left: &[u8; DIGEST_LEN], right: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut buf = Vec::with_capacity(1 + 2 * DIGEST_LEN);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

/// The next level up: pairs combined left to right, an odd trailing node
/// promoted unchanged.
// Cannot panic (plan §5.8): `chunks(2)` yields slices of one or two nodes.
#[allow(clippy::unreachable)]
fn next_level(level: &[[u8; DIGEST_LEN]]) -> Vec<[u8; DIGEST_LEN]> {
    level
        .chunks(2)
        .map(|pair| match pair {
            [l, r] => hash_node(l, r),
            [only] => *only,
            _ => unreachable!("chunks(2) yields one or two nodes"),
        })
        .collect()
}

/// Compute the Merkle root over `leaves` (each hashed with [`hash_leaf`]).
/// An odd trailing node is promoted unchanged to the next level.
// Cannot panic (plan §5.8): `leaves` is non-empty past the first return, and
// every level keeps at least one node, so `level[0]` exists.
#[allow(clippy::indexing_slicing)]
pub fn merkle_root(leaves: &[impl AsRef<[u8]>]) -> [u8; DIGEST_LEN] {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<[u8; DIGEST_LEN]> =
        leaves.iter().map(|l| hash_leaf(l.as_ref())).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// The root of [`merkle_root`], computed one leaf at a time (spec §8.3,
/// informative; task 10.11b, D11b-7): at most one held node per level, so
/// memory grows with the logarithm of the leaf count, and the count need not
/// be known in advance.
///
/// `held[k]` is a node over 2^k leaves still waiting for its right neighbour.
/// At the end the held nodes are the tree's right edge: taken from the lowest
/// level up, each higher node `h` makes the carry `node(h, carry)`, which is
/// the promotion of an odd trailing node in the level-by-level construction.
#[derive(Debug, Clone, Default)]
pub struct MerkleStream {
    held: Vec<Option<[u8; DIGEST_LEN]>>,
    count: u64,
}

impl MerkleStream {
    /// A stream with no leaves.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add the next leaf, given its leaf data (hashed with [`hash_leaf`]).
    pub fn push(&mut self, leaf_data: &[u8]) {
        let mut carry = hash_leaf(leaf_data);
        let mut level = 0;
        loop {
            match self.held.get_mut(level) {
                None => {
                    self.held.push(Some(carry));
                    break;
                }
                Some(slot) => match slot.take() {
                    Some(left) => {
                        carry = hash_node(&left, &carry);
                        level += 1;
                    }
                    None => {
                        *slot = Some(carry);
                        break;
                    }
                },
            }
        }
        self.count += 1;
    }

    /// How many leaves were added.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The root over the leaves added: the empty root when there are none.
    pub fn finish(self) -> [u8; DIGEST_LEN] {
        let mut carry: Option<[u8; DIGEST_LEN]> = None;
        for node in self.held.into_iter().flatten() {
            carry = Some(match carry {
                None => node,
                Some(right) => hash_node(&node, &right),
            });
        }
        carry.unwrap_or_else(empty_root)
    }
}

/// A canonical inclusion proof for one leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// Position of the leaf in the caller's leaf order.
    pub index: usize,
    /// Number of leaves in the tree the proof was made for.
    pub leaf_count: usize,
    /// Sibling hashes, bottom-up: exactly one per level at which the leaf's
    /// node has a sibling (a node promoted alone at a level has none). The
    /// shape is fixed by `index` and `leaf_count`.
    pub siblings: Vec<[u8; DIGEST_LEN]>,
}

/// Build an inclusion proof for leaf `index` of `leaves`. An index out of
/// range (including any index into an empty tree) is `InvalidInput`.
// Cannot panic (plan §5.8): `level[sibling]` is read only under
// `sibling < level.len()`.
#[allow(clippy::indexing_slicing)]
pub fn inclusion_proof(
    leaves: &[impl AsRef<[u8]>],
    index: usize,
) -> Result<InclusionProof, Error> {
    if index >= leaves.len() {
        return Err(Error::InvalidInput(format!(
            "leaf index {index} out of range for {} leaves",
            leaves.len()
        )));
    }
    let mut level: Vec<[u8; DIGEST_LEN]> =
        leaves.iter().map(|l| hash_leaf(l.as_ref())).collect();
    let mut siblings = Vec::new();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = idx ^ 1;
        if sibling < level.len() {
            siblings.push(level[sibling]);
        } // else: idx is the odd trailing node, promoted without a sibling
        idx /= 2;
        level = next_level(&level);
    }
    Ok(InclusionProof {
        index,
        leaf_count: leaves.len(),
        siblings,
    })
}

/// Verify that `leaf_data` is leaf `proof.index` of the tree with `root` and
/// `leaf_count` leaves.
///
/// `leaf_count` must come from the same trusted source as `root` (it is not
/// read from the proof): the proof must have been made for exactly that many
/// leaves, the index must be in range, and the proof's siblings must be
/// consumed exactly — no more, no fewer.
pub fn verify_inclusion(
    root: &[u8; DIGEST_LEN],
    leaf_count: usize,
    leaf_data: &[u8],
    proof: &InclusionProof,
) -> bool {
    if proof.leaf_count != leaf_count || proof.index >= leaf_count {
        return false;
    }
    let mut current = hash_leaf(leaf_data);
    let (mut idx, mut len) = (proof.index, leaf_count);
    let mut siblings = proof.siblings.iter();
    while len > 1 {
        if idx % 2 == 1 {
            match siblings.next() {
                Some(left) => current = hash_node(left, &current),
                None => return false,
            }
        } else if idx + 1 < len {
            match siblings.next() {
                Some(right) => current = hash_node(&current, right),
                None => return false,
            }
        } // else: promoted at this level, no sibling
        idx /= 2;
        len = len.div_ceil(2);
    }
    siblings.next().is_none() && &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        assert_eq!(merkle_root(&[b"abc"]), hash_leaf(b"abc"));
    }

    #[test]
    fn empty_tree_root_is_defined() {
        let empty: &[&[u8]] = &[];
        assert_eq!(merkle_root(empty), empty_root());
    }

    #[test]
    fn four_leaves_known_value() {
        // Fixed structure: root = H(01 || H(01||L0||L1) || H(01||L2||L3))
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let root = merkle_root(&leaves);
        let manual = hash_node(
            &hash_node(&hash_leaf(b"a"), &hash_leaf(b"b")),
            &hash_node(&hash_leaf(b"c"), &hash_leaf(b"d")),
        );
        assert_eq!(root, manual);
    }

    #[test]
    fn odd_leaf_is_promoted() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root = merkle_root(&leaves);
        let manual = hash_node(&hash_node(&hash_leaf(b"a"), &hash_leaf(b"b")), &hash_leaf(b"c"));
        assert_eq!(root, manual);
    }

    #[test]
    fn inclusion_proof_round_trip() {
        // Every index of every tree size up to 17 (odd, even, powers of two).
        for n in 1..=17 {
            let leaves = leaves(n);
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = inclusion_proof(&leaves, i).unwrap();
                assert!(verify_inclusion(&root, n, leaf, &proof), "n={n} leaf {i}");
                assert!(!verify_inclusion(&root, n, b"other", &proof), "wrong data n={n} {i}");
                // Tampered sibling must fail.
                let mut bad = proof.clone();
                if let Some(h) = bad.siblings.first_mut() {
                    h[0] ^= 1;
                    assert!(!verify_inclusion(&root, n, leaf, &bad), "tampered n={n} {i}");
                }
            }
        }
    }

    #[test]
    fn proofs_are_canonical() {
        // QA P3-08: appending levels to a proof left it valid. Padded,
        // truncated and re-labelled proofs must all fail.
        for n in 1..=17 {
            let leaves = leaves(n);
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = inclusion_proof(&leaves, i).unwrap();

                let mut padded = proof.clone();
                padded.siblings.push(root);
                assert!(!verify_inclusion(&root, n, leaf, &padded), "padded n={n} {i}");

                if !proof.siblings.is_empty() {
                    let mut truncated = proof.clone();
                    truncated.siblings.pop();
                    assert!(!verify_inclusion(&root, n, leaf, &truncated), "trunc n={n} {i}");
                }

                // The proof's leaf count must be the trusted one.
                assert!(!verify_inclusion(&root, n + 1, leaf, &proof), "count n={n} {i}");
                let mut relabelled = proof.clone();
                relabelled.leaf_count = n + 1;
                assert!(!verify_inclusion(&root, n, leaf, &relabelled), "relabel n={n} {i}");

                // Another index with the same siblings fails.
                let mut moved = proof.clone();
                moved.index = (i + 1) % n;
                if n > 1 {
                    assert!(!verify_inclusion(&root, n, leaf, &moved), "moved n={n} {i}");
                }
            }
        }
    }

    #[test]
    fn padded_proof_does_not_verify() {
        // The QA's PROBE 7 case: leaf 3 of 7, proof padded by two levels.
        let leaves = leaves(7);
        let root = merkle_root(&leaves);
        let mut proof = inclusion_proof(&leaves, 3).unwrap();
        assert!(verify_inclusion(&root, 7, &leaves[3], &proof));
        proof.siblings.push([0u8; DIGEST_LEN]);
        proof.siblings.push([0u8; DIGEST_LEN]);
        assert!(!verify_inclusion(&root, 7, &leaves[3], &proof));
    }

    #[test]
    fn out_of_range_index_is_an_error_not_a_panic() {
        // QA P3-08: inclusion_proof asserted (a panic reachable from caller
        // input); it now returns an error, and verify rejects such indices.
        let l = leaves(3);
        assert!(matches!(inclusion_proof(&l, 3), Err(Error::InvalidInput(_))));
        let empty: &[&[u8]] = &[];
        assert!(inclusion_proof(empty, 0).is_err());
        let root = merkle_root(&l);
        let bogus = InclusionProof { index: 3, leaf_count: 3, siblings: vec![] };
        assert!(!verify_inclusion(&root, 3, &l[0], &bogus));
        let zero = InclusionProof { index: 0, leaf_count: 0, siblings: vec![] };
        assert!(!verify_inclusion(&empty_root(), 0, b"", &zero));
    }

    #[test]
    fn the_stream_gives_merkle_roots_root_for_every_count_up_to_1100() {
        // Task 10.11b, D11b-7: the streaming construction of spec §8.3 is the
        // level-by-level one, for every leaf count 0..=1100 (odd, even, powers
        // of two and one past them).
        let all = leaves(1100);
        let mut stream = MerkleStream::new();
        assert_eq!(stream.clone().finish(), empty_root());
        for (n, leaf) in all.iter().enumerate() {
            stream.push(leaf);
            assert_eq!(stream.count(), n as u64 + 1);
            assert_eq!(stream.clone().finish(), merkle_root(&all[..=n]), "n={}", n + 1);
        }
    }

    #[test]
    fn determinism() {
        let leaves: Vec<&[u8]> = vec![b"x", b"y", b"z"];
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }
}
