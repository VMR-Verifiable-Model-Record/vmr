//! `storeForEmbeddedKey`: a trust store that trusts the key a record
//! carries, for the issuer the record names — the reader's decision, made
//! explicit, never a default.
// ============================================================================
//  store.rs — the entry `vmr trust-store add` writes, for a record's key
//
//  A reader decides to trust a key by giving the fingerprint the issuer
//  publishes (typed or pasted from the issuer's own site or letter, never
//  copied from the record). This writes that decision as a trust store:
//  exactly what `vmr trust-store add` writes for that key and issuer
//  (vmr-verify's `TrustStoreDocument::add_issuer_key` and
//  `TrustStore::to_file_json`, the code the CLI runs; tests/cli_agreement.rs
//  compares the bytes). It is refused (QA S4):
//
//    - when the reader's fingerprint, its spaces removed, is not the
//      fingerprint of the key the record carries (`store.fingerprint_mismatch`);
//    - when the record's signature does not match that key
//      (`store.integrity`): trusting the key would not make it verify, and
//      the issuer the record names is that key's claim only when it does.
//
//  With these choices, which the record never makes:
//
//    - the attestation level is the caller's, and `self` (the format's
//      lowest, the most conservative) when the caller names none: a record
//      cannot raise the level its own key is trusted for;
//    - the key may sign from the record's `issued_at`, with no end;
//    - the key id is the key's own thumbprint, computed here, whatever id
//      the record claims.
//
//  The store's text is a file to keep and pass back to `verify`, not text to
//  show: its issuer id and name are the record's, written as JSON.
// ============================================================================

use crate::refusal::{Refusal, ATTESTATION_LEVEL_UNKNOWN, STORE_FINGERPRINT_MISMATCH, STORE_INTEGRITY};
use vmr_record::Record;
use vmr_verify::trust_store::{
    AddIssuerKeyError, AttestationLevel, KeyDocument, TrustStoreDocument, TrustStoreErrorKind as Kind,
};
use vmr_verify::TrustStore;

/// The level used when the caller names none: the format's lowest.
pub const DEFAULT_ATTESTATION_LEVEL: AttestationLevel = AttestationLevel::SelfAttested;

/// The level named by `text`, refused when it is not one of the format's.
pub fn attestation_level(text: Option<&str>) -> Result<AttestationLevel, Refusal> {
    match text {
        None => Ok(DEFAULT_ATTESTATION_LEVEL),
        Some(text) => AttestationLevel::parse(text).ok_or_else(|| {
            Refusal::new(
                ATTESTATION_LEVEL_UNKNOWN,
                "attestation_level",
                format!("{text:?} is not an attestation level: self, software or hardware"),
            )
        }),
    }
}

/// The trust-store file trusting `record`'s key for its issuer at `level`,
/// once the reader's `expected_fingerprint` is that key's and the record's
/// signature matches it. Refused, with the loader's `trust_store.*` id, when
/// that store would not be valid (an issuer id that is not a DID, an
/// `issued_at` that is not a timestamp).
pub fn store_for_embedded_key(
    record: &Record,
    expected_fingerprint: &str,
    level: AttestationLevel,
) -> Result<String, Refusal> {
    let key = &record.issuer.public_key;
    let integrity = key.to_verifying_key().ok().map(|k| record.check_integrity(&k));
    if !matches!(integrity, Some(Ok(()))) {
        return Err(Refusal::new(
            STORE_INTEGRITY,
            "record",
            "the record's signature does not match the key it carries: trusting that key would not make this \
             record verify",
        ));
    }
    let expected: String = expected_fingerprint.chars().filter(|c| !c.is_whitespace()).collect();
    let actual: String = key.fingerprint().chars().filter(|c| !c.is_whitespace()).collect();
    if expected != actual {
        return Err(Refusal::new(
            STORE_FINGERPRINT_MISMATCH,
            "expected_fingerprint",
            // The key's own fingerprint is not repeated here: the reader's
            // must come from the issuer, never from this answer.
            "the fingerprint given is not the fingerprint of the key the record carries: compare it again with \
             the one its issuer publishes",
        ));
    }
    let entry = KeyDocument {
        key_id: key.key_id(),
        public_key: key.clone(),
        attestation_level: level,
        valid_from: record.issued_at.clone(),
        valid_until: None,
        revoked: false,
    };
    let mut document = TrustStoreDocument::empty();
    document
        .add_issuer_key(&record.issuer.issuer_id, &record.issuer.issuer_name, entry)
        // An empty store refuses neither; the arms say what each would mean.
        .map_err(|e| match e {
            AddIssuerKeyError::KeyAlreadyTrusted { .. } => {
                Refusal::new(Kind::DuplicateKey.id(), "record", "the key is already in the store")
            }
            AddIssuerKeyError::IssuerNameDiffers { .. } => Refusal::new(
                Kind::DuplicateIssuer.id(),
                "record",
                "the issuer is already in the store under another name",
            ),
        })?;
    let store = TrustStore::new(document).map_err(|e| Refusal::new(e.kind.id(), "record", e.detail))?;
    store
        .to_file_json()
        .map_err(|e| Refusal::new(Kind::Structure.id(), "record", format!("cannot write the store as JSON: {e}")))
}
