// ============================================================================
//  entry.rs — one line of the log (`specs/audit-log-format-v0.1.md` §4.1).
//
//  The core of an entry is the same for every writer: its version, its place
//  in the log, the tree head before it, when it was written, a kind and an
//  object of detail. What the kinds are, and what their detail must hold, is
//  the profile's (§5), never the core's.
// ============================================================================

//! The audit entry and its check (§4.4 refusals 1 to 5).

use crate::error::Error;
use crate::profile::EntryProfile;
use crate::{LOG_VERSION, MAX_ENTRY_BYTES};
use serde_json::Value;
use vmr_record::hash::parse_hash;
use vmr_record::timestamp::Timestamp;

/// A refusal of `audit_entry.structure`, the id every structural fault of an
/// entry carries, the profile's included (§5).
pub(crate) fn structure(message: impl Into<String>) -> Error {
    Error::refused("audit_entry.structure", message)
}

/// Whether `text` is a key id: an RFC 7638 thumbprint in RFC 9278 URN form
/// (§2 rule 9), which a checkpoint's `log_id` and a profile's key-id members
/// share.
pub(crate) fn is_key_id_urn(s: &str) -> bool {
    let prefix = vmr_record::jwk::KEY_ID_PREFIX;
    let Some(rest) = s.strip_prefix(prefix) else { return false };
    rest.len() == 43 && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `kind` is a kind the core allows (§4.1): two or more lower-case
/// labels separated by dots, each starting with a letter, at most 128 bytes.
/// A profile names the kinds it knows from among these.
pub fn is_kind(kind: &str) -> bool {
    if kind.is_empty() || kind.len() > 128 {
        return false;
    }
    let mut labels = 0usize;
    for label in kind.split('.') {
        labels += 1;
        let mut chars = label.chars();
        match chars.next() {
            Some(c) if c.is_ascii_lowercase() => {}
            _ => return false,
        }
        if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
            return false;
        }
    }
    labels >= 2
}

/// A parsed, validated audit entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// The entry's position in the log.
    pub index: u64,
    /// The root over the entries before this one.
    pub previous_root: String,
    /// When the log's writer wrote it.
    pub recorded_at: Timestamp,
    /// Its kind (§4.1's grammar; the profile names what it means).
    pub kind: String,
    /// The kind's detail.
    pub detail: Value,
    /// The exact JCS text of the entry (its leaf data, without a line feed).
    pub canonical: String,
}

/// Parse and validate an entry from one line's JSON value and its exact text
/// (§4.4 refusals 1..=5). `canonical_text` is the line without a line feed; it
/// must be the JCS form of `value`.
pub fn validate_entry(
    value: &Value,
    canonical_text: &str,
    profile: &dyn EntryProfile,
) -> Result<AuditEntry, Error> {
    if canonical_text.len() > MAX_ENTRY_BYTES {
        return Err(Error::refused("audit_entry.size", format!("{} bytes; the cap is {MAX_ENTRY_BYTES}", canonical_text.len())));
    }
    if vmr_record::canonical::jcs(value) != canonical_text {
        return Err(Error::refused("audit_entry.not_canonical", "the line is not the JCS form of its JSON"));
    }
    let obj = value.as_object().ok_or_else(|| structure("an entry must be an object"))?;

    const MEMBERS: [&str; 6] = ["log_version", "index", "previous_root", "recorded_at", "kind", "detail"];
    for key in obj.keys() {
        if !MEMBERS.contains(&key.as_str()) {
            return Err(structure(format!("unknown entry member {key:?}")));
        }
    }
    if obj.get("log_version").and_then(Value::as_str) != Some(LOG_VERSION) {
        return Err(Error::refused("audit_entry.version", "log_version is not \"0.1\""));
    }
    let index = obj.get("index").and_then(Value::as_u64).filter(|&n| n <= vmr_record::canonical::MAX_SAFE_INTEGER)
        .ok_or_else(|| structure("index is not an integer in range"))?;
    let previous_root = obj.get("previous_root").and_then(Value::as_str).filter(|s| parse_hash(s).is_ok())
        .ok_or_else(|| structure("previous_root is not a sha256 hash"))?
        .to_string();
    let recorded_at = obj.get("recorded_at").and_then(Value::as_str).and_then(|s| Timestamp::parse(s).ok())
        .ok_or_else(|| structure("recorded_at is not a timestamp"))?;
    let kind = obj.get("kind").and_then(Value::as_str)
        .ok_or_else(|| structure("kind is not a string"))?
        .to_string();
    let detail = obj.get("detail").cloned().ok_or_else(|| structure("an entry has no detail"))?;
    if !is_kind(&kind) {
        return Err(structure(format!("kind {kind:?} is not a kind of this format")));
    }
    if !detail.is_object() {
        return Err(structure("detail must be an object"));
    }
    profile.check(&kind, &detail)?;

    Ok(AuditEntry { index, previous_root, recorded_at, kind, detail, canonical: canonical_text.to_string() })
}
