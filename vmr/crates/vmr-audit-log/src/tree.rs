// ============================================================================
//  tree.rs — the log's Merkle tree (`specs/audit-log-format-v0.1.md` §4.3).
//
//  RFC 9162 §2.1.1's tree, pairing left to right. For every non-empty size it
//  is the record format's §8.3 tree, so a root and an inclusion proof mean the
//  same in both. A leaf is an entry's JCS bytes.
// ============================================================================

//! The log's Merkle tree: the root over a run of leaves, an inclusion path, a
//! consistency proof's path, and the check of one.

use vmr_record::hash::{sha256, DIGEST_LEN};
use vmr_record::merkle::empty_root;

// ---------------------------------------------------------------------------
//  The tree (RFC 9162 §2.1.1, pairing left to right)
// ---------------------------------------------------------------------------

/// The hash of an interior node: `SHA-256(0x01 ‖ left ‖ right)`.
fn hash_node(left: &[u8; DIGEST_LEN], right: &[u8; DIGEST_LEN]) -> [u8; DIGEST_LEN] {
    let mut buf = Vec::with_capacity(1 + 2 * DIGEST_LEN);
    buf.push(0x01);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256(&buf)
}

/// One level up: pairs combined left to right, an odd trailing node promoted.
fn next_level(level: &[[u8; DIGEST_LEN]]) -> Vec<[u8; DIGEST_LEN]> {
    let mut out = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        match (level.get(i), level.get(i + 1)) {
            (Some(l), Some(r)) => out.push(hash_node(l, r)),
            (Some(only), None) => out.push(*only),
            _ => break,
        }
        i += 2;
    }
    out
}

/// The Merkle root over `leaf_hashes` (each already a leaf hash). Empty is the
/// empty-tree root `SHA-256(0x02)` (§4.3).
pub fn root_of(leaf_hashes: &[[u8; DIGEST_LEN]]) -> [u8; DIGEST_LEN] {
    if leaf_hashes.is_empty() {
        return empty_root();
    }
    let mut level = leaf_hashes.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level.into_iter().next().unwrap_or_else(empty_root)
}

/// The inclusion path for leaf `index` of a tree of leaf hashes: the siblings
/// bottom-up, exactly one per level at which the leaf's node has a sibling
/// (RFC 9162 §2.1.3.1's `PATH`). Equal to `vmr_record::merkle`'s siblings for
/// the same data, so `vmr_record::merkle::verify_inclusion` verifies it.
pub fn inclusion_path(leaf_hashes: &[[u8; DIGEST_LEN]], index: usize) -> Vec<[u8; DIGEST_LEN]> {
    let mut level = leaf_hashes.to_vec();
    let mut idx = index;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        if let Some(h) = level.get(idx ^ 1) {
            siblings.push(*h);
        }
        idx /= 2;
        level = next_level(&level);
    }
    siblings
}

/// The largest power of two strictly below `n` (RFC 9162's `k`), for `n >= 2`.
fn split(n: usize) -> usize {
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// RFC 9162 §2.1.4.1's `SUBPROOF(m, D[0:n], b)` over leaf hashes.
fn subproof(m: usize, hashes: &[[u8; DIGEST_LEN]], b: bool) -> Vec<[u8; DIGEST_LEN]> {
    let n = hashes.len();
    if m == n {
        return if b { Vec::new() } else { vec![root_of(hashes)] };
    }
    let k = split(n);
    let left = hashes.get(..k).unwrap_or(&[]);
    let right = hashes.get(k..).unwrap_or(&[]);
    if m <= k {
        let mut p = subproof(m, left, b);
        p.push(root_of(right));
        p
    } else {
        let mut p = subproof(m - k, right, false);
        p.push(root_of(left));
        p
    }
}

/// RFC 9162 §2.1.4.1's `PROOF(m, D[0:n])`: the consistency proof that the tree
/// of the first `m` leaf hashes is a prefix of `hashes` (`m <= hashes.len()`).
pub fn consistency_path(m: usize, hashes: &[[u8; DIGEST_LEN]]) -> Vec<[u8; DIGEST_LEN]> {
    if m == 0 || m > hashes.len() {
        return Vec::new();
    }
    subproof(m, hashes, true)
}

/// Verify a consistency proof (RFC 9162 §2.1.4.2): the tree of size `first`
/// with root `first_hash` is a prefix of the tree of size `second` with root
/// `second_hash`.
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_hash: &[u8; DIGEST_LEN],
    second_hash: &[u8; DIGEST_LEN],
    proof: &[[u8; DIGEST_LEN]],
) -> bool {
    if first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_hash == second_hash;
    }
    if first == 0 {
        return proof.is_empty();
    }

    // Prepend first_hash when `first` is an exact power of two (§2.1.4.2 step 1).
    let mut path: Vec<[u8; DIGEST_LEN]> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_hash);
    }
    path.extend_from_slice(proof);

    let mut fnode = first - 1;
    let mut snode = second - 1;
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }

    let mut iter = path.iter();
    let (mut fr, mut sr) = match iter.next() {
        Some(h) => (*h, *h),
        None => return false,
    };
    for c in iter {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = hash_node(c, &fr);
            sr = hash_node(c, &sr);
            if fnode & 1 == 0 {
                loop {
                    fnode >>= 1;
                    snode >>= 1;
                    if fnode & 1 == 1 || fnode == 0 {
                        break;
                    }
                }
            }
        } else {
            sr = hash_node(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    &fr == first_hash && &sr == second_hash && snode == 0
}
