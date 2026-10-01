//! What a record says about itself, and whether it is intact against the key
//! it carries — never whether it is trusted.
// ============================================================================
//  inspect.rs — `inspect(record)`
//
//  A reader sees who a record names, its key's fingerprint and its claims
//  before deciding to trust anything. `integrity_against_embedded_key`
//  checks the signature against the key the record itself carries
//  (vmr-record's `check_integrity`): it proves the record was not changed
//  after that key signed it, and nothing about who holds the key. A forger
//  signs with a key of their own and gets `matches` too; only a trust store
//  the reader built from a key they compared out of band says whose record
//  it is (`verify`).
// ============================================================================

use crate::refusal::Refusal;
use crate::safe::display_safe_value;
use serde_json::{json, Value};
use vmr_record::Record;
use vmr_verify::{display_safe, TrustStore, Verifier, VerifyOptions, MAX_RECORD_BYTES};

/// Read a record in either form under the format's strict rules, as the
/// verifier does. A record that cannot be read is refused with the id of
/// the verifier's first failing check for those bytes (`input.size`,
/// `input.form`, `json.structure`, `cose.*`, ...), and its detail.
pub fn read_record(bytes: &[u8]) -> Result<Record, Refusal> {
    let parsed = if bytes.len() > MAX_RECORD_BYTES {
        None
    } else if bytes.first() == Some(&0x84) {
        Record::from_cose(bytes).ok()
    } else {
        match bytes.iter().copied().find(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r')) {
            Some(b'{') => std::str::from_utf8(bytes).ok().and_then(|text| Record::from_json(text).ok()),
            _ => None,
        }
    };
    parsed.ok_or_else(|| unreadable(bytes))
}

/// The verifier's own account of bytes that are not a readable record: its
/// first failure, run against an empty trust store at a fixed time (no clock;
/// a record that cannot be read fails before time or trust is consulted).
fn unreadable(bytes: &[u8]) -> Refusal {
    let refusal = |id: &str, detail: &str| Refusal::new(id, "record", detail);
    let (Ok(store), Some(at)) = (
        TrustStore::from_json(br#"{"trust_store_version":"0.1","issuers":[]}"#),
        vmr_record::timestamp::Timestamp::from_unix_seconds(0),
    ) else {
        return refusal("input.form", "the record could not be read");
    };
    match Verifier::new(store).verify(bytes, &VerifyOptions::new(at)).failure {
        Some(failure) => refusal(failure.check.id(), &failure.detail),
        None => refusal("input.form", "the record could not be read"),
    }
}

/// `inspect`: the record's issuer as it names itself, its signing key id, the
/// fingerprint of the key it carries, whether its signature matches that key,
/// and its declared fields — every string through `display_safe`.
pub fn inspect(bytes: &[u8]) -> Value {
    let record = match read_record(bytes) {
        Ok(record) => record,
        Err(refusal) => return refusal.to_value(),
    };
    let integrity = match record.issuer.public_key.to_verifying_key() {
        Err(_) => "unreadable",
        Ok(key) => match record.check_integrity(&key) {
            Ok(()) => "matches",
            Err(_) => "does_not_match",
        },
    };
    let mut declared = serde_json::to_value(&record).unwrap_or(Value::Null);
    if let Value::Object(members) = &mut declared {
        // The signature section is not a declaration; the result above
        // already says what it shows.
        members.remove("signature");
    }
    json!({
        "issuer": {
            "name": display_safe(&record.issuer.issuer_name),
            "id": display_safe(&record.issuer.issuer_id),
        },
        "signing_key_id": display_safe(&record.signature.signing_key_id),
        // The key's own thumbprint, computed from the key the record
        // carries, never read from the key id it claims.
        "fingerprint": display_safe(&record.issuer.public_key.fingerprint()),
        "integrity_against_embedded_key": integrity,
        "declared": display_safe_value(declared),
    })
}
