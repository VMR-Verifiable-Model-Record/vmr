//! Integrity checks with typed reasons: what `Record::verify_signature`
//! does, as a result a verifier can map to its check ids.
// ============================================================================
//  integrity.rs — the integrity checks with typed reasons (Phase 4 task 4.0b)
//
//  `Record::check_integrity` runs exactly the checks `verify_signature`
//  always ran, in the same order, and names the one that failed with an
//  `IntegrityError` instead of a message string. `verify_signature` is now
//  `check_integrity` plus a conversion into `Error`: same variants, same
//  messages, so nothing that matched its text changes.
//
//  Integrity, not trust (QA P3-07, PROBE 6): `Ok(())` means the record is
//  internally consistent and was signed by the holder of `key`. It says
//  nothing about who that is unless `key` came from a trust store — which is
//  what vmr-verify adds. Never pass the record's own `issuer.public_key`.
// ============================================================================

use crate::error::Error;
use crate::record::{JwkPublicKey, Record};
use p256::ecdsa::VerifyingKey;

const PAYLOAD_HASH: &str =
    "signature.signed_payload_hash does not match the canonical signed payload";
const KEY_NOT_ISSUER_KEY: &str = "the verifying key is not the record's issuer.public_key";
const KEY_ID_NOT_THUMBPRINT: &str =
    "issuer.key_id is not the RFC 7638 thumbprint URN of issuer.public_key";
const SIGNING_KEY_ID_MISMATCH: &str = "signature.signing_key_id differs from issuer.key_id";

/// The integrity check a record failed, in the order
/// [`Record::check_integrity`] runs them.
///
/// `Display` is the message of the [`Error`] that `verify_signature` returns
/// for the same failure (and `From<IntegrityError> for Error` produces it).
#[derive(Debug)]
pub enum IntegrityError {
    /// `signature.algorithm` is not exactly `ES256` (QA P3-05); carries the
    /// value found.
    Algorithm(String),
    /// The canonical signed payload cannot be computed: an integer above
    /// 2^53 − 1 (QA P3-10). A parsed record never gets here.
    Payload(Error),
    /// `signature.signed_payload_hash` is not the hash of the recomputed
    /// canonical payload (QA P3-05).
    PayloadHash,
    /// The verifying key is not `issuer.public_key` (QA P3-07).
    KeyNotIssuerKey,
    /// `issuer.key_id` is not the RFC 7638 thumbprint URN of
    /// `issuer.public_key` (QA P3-07).
    KeyIdNotThumbprint,
    /// `signature.signing_key_id` differs from `issuer.key_id` (QA P3-07).
    SigningKeyIdMismatch,
    /// The `signature` field is not `base64url:` + the canonical base64url of
    /// 64 raw bytes `r ‖ s` with `r`, `s` in `1 ..= n−1` (QA P3-02).
    SignatureEncoding(Error),
    /// The signature is high-s, the non-canonical twin (QA P3-04).
    HighS,
    /// The ES256 signature does not verify under the key.
    BadSignature(p256::ecdsa::Error),
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityError::Algorithm(a) => write!(f, "invalid input: {}", algorithm_message(a)),
            IntegrityError::Payload(e) | IntegrityError::SignatureEncoding(e) => write!(f, "{e}"),
            IntegrityError::PayloadHash => write!(f, "invalid input: {PAYLOAD_HASH}"),
            IntegrityError::KeyNotIssuerKey => write!(f, "invalid input: {KEY_NOT_ISSUER_KEY}"),
            IntegrityError::KeyIdNotThumbprint => {
                write!(f, "invalid input: {KEY_ID_NOT_THUMBPRINT}")
            }
            IntegrityError::SigningKeyIdMismatch => {
                write!(f, "invalid input: {SIGNING_KEY_ID_MISMATCH}")
            }
            IntegrityError::HighS => write!(f, "invalid input: {}", crate::sign::HIGH_S_MESSAGE),
            // Error::Signature's message format.
            IntegrityError::BadSignature(e) => write!(f, "signature: {e}"),
        }
    }
}

impl std::error::Error for IntegrityError {}

fn algorithm_message(algorithm: &str) -> String {
    format!("signature.algorithm is {algorithm:?}; v0.1 records are ES256 only")
}

impl From<IntegrityError> for Error {
    fn from(e: IntegrityError) -> Self {
        match e {
            IntegrityError::Algorithm(a) => Error::InvalidInput(algorithm_message(&a)),
            IntegrityError::Payload(e) | IntegrityError::SignatureEncoding(e) => e,
            IntegrityError::PayloadHash => Error::InvalidInput(PAYLOAD_HASH.into()),
            IntegrityError::KeyNotIssuerKey => Error::InvalidInput(KEY_NOT_ISSUER_KEY.into()),
            IntegrityError::KeyIdNotThumbprint => Error::InvalidInput(KEY_ID_NOT_THUMBPRINT.into()),
            IntegrityError::SigningKeyIdMismatch => {
                Error::InvalidInput(SIGNING_KEY_ID_MISMATCH.into())
            }
            IntegrityError::HighS => Error::InvalidInput(crate::sign::HIGH_S_MESSAGE.into()),
            IntegrityError::BadSignature(e) => Error::Signature(e),
        }
    }
}

impl Record {
    /// Check this record's integrity against `key`, naming the first check
    /// that fails. **This proves integrity, not trust** — see
    /// [`Record::verify_signature`], which is this method plus a
    /// conversion into [`Error`].
    ///
    /// In order (the integrity part of spec §6.2 — checks 7–11 and the ECDSA
    /// step of 13 — as one call):
    ///
    /// 1. `signature.algorithm` is exactly `ES256` → [`IntegrityError::Algorithm`];
    /// 2. `signature.signed_payload_hash` is the hash of the recomputed
    ///    canonical payload → [`IntegrityError::PayloadHash`];
    /// 3. key binding: `key` is `issuer.public_key`
    ///    ([`IntegrityError::KeyNotIssuerKey`]), whose RFC 7638 thumbprint
    ///    URN is `issuer.key_id` ([`IntegrityError::KeyIdNotThumbprint`]),
    ///    which equals `signature.signing_key_id`
    ///    ([`IntegrityError::SigningKeyIdMismatch`]);
    /// 4. the `signature` field decodes to a 64-byte `r ‖ s`
    ///    ([`IntegrityError::SignatureEncoding`]) that is low-s
    ///    ([`IntegrityError::HighS`]) and verifies over the COSE
    ///    Sig_structure ([`IntegrityError::BadSignature`]).
    pub fn check_integrity(&self, key: &VerifyingKey) -> Result<(), IntegrityError> {
        if self.signature.algorithm != "ES256" {
            return Err(IntegrityError::Algorithm(self.signature.algorithm.clone()));
        }
        let recomputed = self.signed_payload_hash().map_err(IntegrityError::Payload)?;
        if self.signature.signed_payload_hash != recomputed {
            return Err(IntegrityError::PayloadHash);
        }
        let supplied = JwkPublicKey::from_verifying_key(key);
        if self.issuer.public_key != supplied {
            return Err(IntegrityError::KeyNotIssuerKey);
        }
        if self.issuer.key_id != supplied.key_id() {
            return Err(IntegrityError::KeyIdNotThumbprint);
        }
        if self.signature.signing_key_id != self.issuer.key_id {
            return Err(IntegrityError::SigningKeyIdMismatch);
        }
        let sig = self
            .signature
            .parsed_signature()
            .map_err(IntegrityError::SignatureEncoding)?;
        if crate::sign::is_high_s(&sig) {
            return Err(IntegrityError::HighS);
        }
        let tbs = self.signature_tbs().map_err(IntegrityError::Payload)?;
        crate::sign::verify_ecdsa(key, &tbs, &sig).map_err(IntegrityError::BadSignature)
    }
}
