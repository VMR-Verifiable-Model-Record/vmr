// ============================================================================
//  proof.rs — the inclusion and consistency proofs
//  (`specs/audit-log-format-v0.1.md` §7, §8).
//
//  A proof carries the signed checkpoints it is read against, so verifying one
//  needs no clock and no file: the pinned audit key, the proof's bytes, and
//  the profile whose entries the log holds.
// ============================================================================

//! The two proofs: building one from a log's leaves, and verifying one under a
//! pinned audit key (§7, §8).

use crate::checkpoint::{checkpoint_claims, verify_checkpoint_value};
use crate::entry::{validate_entry, AuditEntry};
use crate::error::Error;
use crate::json::{parse_document, parse_json_bounded};
use crate::profile::EntryProfile;
use crate::tree::{consistency_path, inclusion_path, verify_consistency};
use crate::{MAX_AUDIT_PATH_ELEMENTS, MAX_CONSISTENCY_PROOF_BYTES, MAX_CONSISTENCY_PROOF_ELEMENTS,
            MAX_INCLUSION_PROOF_BYTES};
use serde_json::{json, Value};
use vmr_record::hash::{format_hash, parse_hash, DIGEST_LEN};

/// Build an inclusion proof that the entry at `index` is in the log the signed
/// `checkpoint` covers (§7). `leaves` are the log's leaf hashes in index
/// order, `entry_text` the entry's exact JCS text, and `key` the audit key the
/// checkpoint must be signed by.
pub fn build_inclusion_proof(
    leaves: &[[u8; DIGEST_LEN]],
    index: u64,
    entry_text: &str,
    checkpoint: &Value,
    key: &p256::ecdsa::VerifyingKey,
) -> Result<Value, Error> {
    let claims = verify_checkpoint_value(checkpoint, key)?;
    if index >= claims.tree_size {
        return Err(Error::refused(
            "audit_proof.index",
            format!("leaf_index {index} is not below tree_size {}", claims.tree_size),
        ));
    }
    let tree_size = usize::try_from(claims.tree_size).map_err(|_| Error::io("tree_size out of range"))?;
    let covered = leaves.get(..tree_size).ok_or_else(|| Error::io("the log is shorter than the checkpoint"))?;
    let idx = usize::try_from(index).map_err(|_| Error::io("index out of range"))?;
    let path = inclusion_path(covered, idx);
    Ok(json!({
        "proof_version": "0.1",
        "proof_type": "vmr.audit-inclusion-proof",
        "checkpoint": checkpoint,
        "leaf_index": index,
        "entry": entry_text,
        "audit_path": path.iter().map(|h| format_hash(h)).collect::<Vec<_>>(),
    }))
}

/// Build a consistency proof that the log the signed `from` checkpoint covered
/// is a prefix of the log the signed `to` checkpoint covers (§8). Both
/// checkpoints must be signed by `key`.
pub fn build_consistency_proof(
    leaves: &[[u8; DIGEST_LEN]],
    from: &Value,
    to: &Value,
    key: &p256::ecdsa::VerifyingKey,
) -> Result<Value, Error> {
    let f = verify_checkpoint_value(from, key)?;
    let t = verify_checkpoint_value(to, key)?;
    if f.tree_size > t.tree_size {
        return Err(Error::refused(
            "audit_proof.order",
            format!("from tree_size {} is larger than to {}", f.tree_size, t.tree_size),
        ));
    }
    let n = usize::try_from(t.tree_size).map_err(|_| Error::io("tree_size out of range"))?;
    let m = usize::try_from(f.tree_size).map_err(|_| Error::io("tree_size out of range"))?;
    let covered = leaves.get(..n).ok_or_else(|| Error::io("the log is shorter than the checkpoint"))?;
    let path = consistency_path(m, covered);
    Ok(json!({
        "proof_version": "0.1",
        "proof_type": "vmr.audit-consistency-proof",
        "from": from,
        "to": to,
        "proof": path.iter().map(|h| format_hash(h)).collect::<Vec<_>>(),
    }))
}

/// Parse an array of at most `most` `sha256:` hashes into digests, or a
/// message. The cap is §7's and §8's `maxItems`, read before any element is
/// (QA QR-06): an over-long array is refused for its structure, not for the
/// root it fails to recompute.
fn parse_hashes(value: Option<&Value>, most: usize) -> Result<Vec<[u8; DIGEST_LEN]>, String> {
    let array = value.and_then(Value::as_array).ok_or("not an array")?;
    if array.len() > most {
        return Err(format!("{} elements, above the {most} this format allows", array.len()));
    }
    array
        .iter()
        .map(|v| v.as_str().ok_or("a path element is not a string".to_string()).and_then(|s| parse_hash(s).map_err(|e| e.to_string())))
        .collect()
}

/// Verify an inclusion proof document under the pinned audit `key`, returning
/// the proven entry (§7). No clock, no I/O, never a panic.
pub fn verify_inclusion_proof(
    bytes: &[u8],
    key: &p256::ecdsa::VerifyingKey,
    profile: &dyn EntryProfile,
) -> Result<AuditEntry, Error> {
    let refuse = |id: &'static str, m: &str| Error::refused(id, m);
    if bytes.len() > MAX_INCLUSION_PROOF_BYTES {
        return Err(refuse("audit_proof.size", "the proof is larger than the limit"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("audit_proof.syntax", "not UTF-8"))?;
    let parsed = parse_document(text).map_err(|e| Error::refused("audit_proof.syntax", e))?;
    let obj = parsed.value.as_object().ok_or_else(|| refuse("audit_proof.structure", "not an object"))?;

    if obj.get("proof_version").and_then(Value::as_str) != Some("0.1")
        || obj.get("proof_type").and_then(Value::as_str) != Some("vmr.audit-inclusion-proof")
    {
        return Err(refuse("audit_proof.version", "not a v0.1 vmr.audit-inclusion-proof"));
    }
    if parsed.repeats_at_top() {
        return Err(refuse("audit_proof.structure", "a member appears twice"));
    }
    const MEMBERS: [&str; 6] = ["proof_version", "proof_type", "checkpoint", "leaf_index", "entry", "audit_path"];
    for k in obj.keys() {
        if !MEMBERS.contains(&k.as_str()) {
            return Err(refuse("audit_proof.structure", "an unknown member"));
        }
    }
    let checkpoint = obj.get("checkpoint").ok_or_else(|| refuse("audit_proof.structure", "no checkpoint"))?;
    let claims = checkpoint_claims(checkpoint, key, parsed.repeats_inside("checkpoint"))?;
    let leaf_index = obj.get("leaf_index").and_then(Value::as_u64).ok_or_else(|| refuse("audit_proof.structure", "leaf_index is not an integer"))?;
    if leaf_index >= claims.tree_size {
        return Err(refuse("audit_proof.index", "leaf_index is not below tree_size"));
    }
    let entry_text = obj.get("entry").and_then(Value::as_str).ok_or_else(|| refuse("audit_proof.structure", "entry is not a string"))?;
    let entry_value = parse_json_bounded(entry_text).map_err(|_| refuse("audit_proof.structure", "entry is not JSON"))?;
    let entry = validate_entry(&entry_value, entry_text, profile)?;
    if entry.index != leaf_index {
        return Err(refuse("audit_proof.entry_index", "the entry's index is not leaf_index"));
    }
    let siblings = parse_hashes(obj.get("audit_path"), MAX_AUDIT_PATH_ELEMENTS).map_err(|m| Error::refused("audit_proof.structure", format!("audit_path: {m}")))?;
    let tree_size = usize::try_from(claims.tree_size).map_err(|_| refuse("audit_proof.structure", "tree_size out of range"))?;
    let index = usize::try_from(leaf_index).map_err(|_| refuse("audit_proof.structure", "leaf_index out of range"))?;
    let root = parse_hash(&claims.root_hash).map_err(|_| refuse("audit_proof.structure", "root_hash"))?;

    let proof = vmr_record::merkle::InclusionProof { index, leaf_count: tree_size, siblings };
    if vmr_record::merkle::verify_inclusion(&root, tree_size, entry_text.as_bytes(), &proof) {
        Ok(entry)
    } else {
        Err(refuse("audit_proof.path", "the entry and audit_path do not recompute the checkpoint's root"))
    }
}

/// Verify a consistency proof document under the pinned audit `key`, returning
/// `(from_size, to_size)` (§8). No clock, no I/O, never a panic.
pub fn verify_consistency_proof(bytes: &[u8], key: &p256::ecdsa::VerifyingKey) -> Result<(u64, u64), Error> {
    let refuse = |id: &'static str, m: &str| Error::refused(id, m);
    if bytes.len() > MAX_CONSISTENCY_PROOF_BYTES {
        return Err(refuse("audit_proof.size", "the proof is larger than the limit"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| refuse("audit_proof.syntax", "not UTF-8"))?;
    let parsed = parse_document(text).map_err(|e| Error::refused("audit_proof.syntax", e))?;
    let obj = parsed.value.as_object().ok_or_else(|| refuse("audit_proof.structure", "not an object"))?;

    if obj.get("proof_version").and_then(Value::as_str) != Some("0.1")
        || obj.get("proof_type").and_then(Value::as_str) != Some("vmr.audit-consistency-proof")
    {
        return Err(refuse("audit_proof.version", "not a v0.1 vmr.audit-consistency-proof"));
    }
    if parsed.repeats_at_top() {
        return Err(refuse("audit_proof.structure", "a member appears twice"));
    }
    const MEMBERS: [&str; 5] = ["proof_version", "proof_type", "from", "to", "proof"];
    for k in obj.keys() {
        if !MEMBERS.contains(&k.as_str()) {
            return Err(refuse("audit_proof.structure", "an unknown member"));
        }
    }
    let from = obj.get("from").ok_or_else(|| refuse("audit_proof.structure", "no from"))?;
    let to = obj.get("to").ok_or_else(|| refuse("audit_proof.structure", "no to"))?;
    let f = checkpoint_claims(from, key, parsed.repeats_inside("from"))?;
    let t = checkpoint_claims(to, key, parsed.repeats_inside("to"))?;
    if f.tree_size > t.tree_size {
        return Err(refuse("audit_proof.order", "from tree_size is larger than to"));
    }
    let proof = parse_hashes(obj.get("proof"), MAX_CONSISTENCY_PROOF_ELEMENTS).map_err(|m| Error::refused("audit_proof.structure", format!("proof: {m}")))?;
    let from_root = parse_hash(&f.root_hash).map_err(|_| refuse("audit_proof.structure", "from root_hash"))?;
    let to_root = parse_hash(&t.root_hash).map_err(|_| refuse("audit_proof.structure", "to root_hash"))?;
    if verify_consistency(f.tree_size, t.tree_size, &from_root, &to_root, &proof) {
        Ok((f.tree_size, t.tree_size))
    } else {
        Err(refuse("audit_proof.consistency", "the proof does not show the first tree is a prefix of the second"))
    }
}
