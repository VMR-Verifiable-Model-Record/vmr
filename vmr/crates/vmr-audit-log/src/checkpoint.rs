// ============================================================================
//  checkpoint.rs — the signed statement of a log's size and root
//  (`specs/audit-log-format-v0.1.md` §6).
//
//  The audit key signs the checkpoint, and nothing else: one key, one role.
//  A record may name a checkpoint by the registered statement format
//  `vmr-audit-checkpoint-v1` (record format §7.7), whose digest is this
//  document's signed payload.
// ============================================================================

//! The checkpoint: building a signed one, and verifying one under a pinned
//! audit key (§6).

use crate::entry::is_key_id_urn;
use crate::error::Error;
use crate::json::parse_document;
use crate::signing::{self, SigFail};
use crate::MAX_CHECKPOINT_BYTES;
use serde_json::{json, Value};
use vmr_record::hash::{format_hash, parse_hash, DIGEST_LEN};
use vmr_record::timestamp::Timestamp;

/// The claims a verified checkpoint makes (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointClaims {
    /// The audit key's id, which the checkpoint's `log_id` names.
    pub log_id: String,
    /// The number of entries the root covers.
    pub tree_size: u64,
    /// The root over the first `tree_size` entries.
    pub root_hash: String,
}

/// A signed checkpoint over the first `tree_size` entries of a log whose
/// `log_id` is the audit key's id (§6). An empty log has no checkpoint
/// (`checkpoint.empty_tree`).
pub fn build_signed(
    log_id: &str,
    tree_size: u64,
    root: &[u8; DIGEST_LEN],
    issued_at: Timestamp,
    audit_key: &p256::ecdsa::SigningKey,
) -> Result<Value, Error> {
    if tree_size == 0 {
        return Err(Error::refused("checkpoint.empty_tree", "an empty log has no checkpoint"));
    }
    let document = json!({
        "checkpoint_version": "0.1",
        "checkpoint_type": "vmr.audit-checkpoint",
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": format_hash(root),
        "issued_at": issued_at.to_string(),
    });
    signing::sign_document(audit_key, &document).map_err(|e| Error::io(format!("cannot sign a checkpoint: {e}")))
}

/// Verify a checkpoint document's bytes under the pinned audit `key` (§6
/// checks 1..=8): its size and syntax, a member repeated anywhere in it, then
/// the checks of [`verify_checkpoint_value`]. No clock, no I/O, never a panic.
pub fn verify_checkpoint(bytes: &[u8], key: &p256::ecdsa::VerifyingKey) -> Result<CheckpointClaims, Error> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::refused("checkpoint.size", format!("{} bytes; the cap is {MAX_CHECKPOINT_BYTES}", bytes.len())));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Error::refused("checkpoint.syntax", "not UTF-8"))?;
    let parsed = parse_document(text).map_err(|e| Error::refused("checkpoint.syntax", e))?;
    checkpoint_claims(&parsed.value, key, parsed.has_repeated_member())
}

/// Verify a checkpoint's value under `key` (§6 checks 3..=8). Size and syntax
/// (checks 1, 2) are the caller's for a standalone checkpoint; a checkpoint
/// inside a proof is checked from here (8.5). A [`Value`] cannot hold a
/// repeated member (check 4): a caller holding the checkpoint's text uses
/// [`verify_checkpoint`], and the proof verifiers pass on what they read.
pub fn verify_checkpoint_value(document: &Value, key: &p256::ecdsa::VerifyingKey) -> Result<CheckpointClaims, Error> {
    checkpoint_claims(document, key, false)
}

/// §6 checks 3..=8 over a checkpoint's value; `repeated` is whether its text
/// repeated a member (check 4).
pub(crate) fn checkpoint_claims(document: &Value, key: &p256::ecdsa::VerifyingKey, repeated: bool) -> Result<CheckpointClaims, Error> {
    let refuse = |id: &'static str, m: &str| Error::refused(id, m);
    let obj = document.as_object().ok_or_else(|| refuse("checkpoint.structure", "a checkpoint must be an object"))?;

    if obj.get("checkpoint_version").and_then(Value::as_str) != Some("0.1")
        || obj.get("checkpoint_type").and_then(Value::as_str) != Some("vmr.audit-checkpoint")
    {
        return Err(refuse("checkpoint.version", "not a v0.1 vmr.audit-checkpoint"));
    }
    if repeated {
        return Err(refuse("checkpoint.structure", "a member appears twice"));
    }
    const MEMBERS: [&str; 7] = ["checkpoint_version", "checkpoint_type", "log_id", "tree_size", "root_hash", "issued_at", "signature"];
    for k in obj.keys() {
        if !MEMBERS.contains(&k.as_str()) {
            return Err(refuse("checkpoint.structure", "an unknown member"));
        }
    }
    let log_id = obj.get("log_id").and_then(Value::as_str).filter(|s| is_key_id_urn(s)).ok_or_else(|| refuse("checkpoint.structure", "log_id is not a key id"))?;
    let tree_size = obj.get("tree_size").and_then(Value::as_u64).filter(|&n| n <= vmr_record::canonical::MAX_SAFE_INTEGER).ok_or_else(|| refuse("checkpoint.structure", "tree_size is not an integer"))?;
    let root_hash = obj.get("root_hash").and_then(Value::as_str).filter(|s| parse_hash(s).is_ok()).ok_or_else(|| refuse("checkpoint.structure", "root_hash is not a hash"))?;
    let issued_at_ok = obj.get("issued_at").and_then(Value::as_str).is_some_and(|s| Timestamp::parse(s).is_ok());
    if !issued_at_ok {
        return Err(refuse("checkpoint.structure", "issued_at is not a timestamp"));
    }
    if obj.get("signature").is_none() {
        return Err(refuse("checkpoint.signature_section", "no signature section"));
    }
    if tree_size == 0 {
        return Err(refuse("checkpoint.empty_tree", "tree_size is 0"));
    }
    if log_id != vmr_record::jwk::key_id(key) {
        return Err(refuse("checkpoint.wrong_key", "log_id is not the pinned audit key's id"));
    }
    match signing::check_signature(document, key) {
        Ok(()) => Ok(CheckpointClaims { log_id: log_id.to_string(), tree_size, root_hash: root_hash.to_string() }),
        Err(SigFail::KeyId) => Err(refuse("checkpoint.wrong_key", "signing_key_id is not the pinned audit key's id")),
        Err(SigFail::Invalid) => Err(refuse("checkpoint.signature_invalid", "the signature does not verify")),
        Err(_) => Err(refuse("checkpoint.signature_section", "the signature section is malformed")),
    }
}
