//! The fail shape every call returns for input it cannot use.
// ============================================================================
//  refusal.rs — `{ "refusal": { "id", "input", "detail" } }`
//
//  Bad input never throws and never traps: a call that cannot use one of its
//  inputs returns this shape instead of its result. `id` is the stable id of
//  the library that refused it wherever one exists (a trust store's
//  `trust_store.*`, a pack's `policy_pack.*` or `pack_signature.*`, a record
//  the verifier cannot read by its first failing check, such as
//  `input.form`); the few ids this crate adds are the constants below.
//  `input` names the argument at fault. `detail` is the library's own words,
//  through `display_safe`.
// ============================================================================

use serde_json::{json, Value};
use vmr_verify::display_safe;

/// `at` is not a whole number of seconds inside the years 0000–9999 the
/// record format's timestamps can write.
pub const EVALUATION_TIME_RANGE: &str = "evaluation_time.range";
/// An authority store that lists issuers (the CLI's `--authority-store`
/// refusal of the same id).
pub const AUTHORITY_STORE_ISSUERS: &str = "authority_store.issuers";
/// An authority store holding a key the trust store trusts for an issuer
/// (the CLI's refusal of the same id).
pub const AUTHORITY_STORE_ISSUER_KEY: &str = "authority_store.issuer_key";
/// `checkFiles` on a record whose `model_format` names a registered profile:
/// its `model_hash` is not a named-set digest of files (spec §7.1, §7.4).
pub const CHECK_FILES_UNSUPPORTED_PROFILE: &str = "check_files.unsupported_profile";
/// A file's `sha256` that is not `sha256:` and 64 lower-case hex digits.
pub const CHECK_FILES_DIGEST: &str = "check_files.digest";
/// A file's `size` that is not a whole number from 0 to 2^53 - 1.
pub const CHECK_FILES_SIZE: &str = "check_files.size";
/// `storeForEmbeddedKey`: the fingerprint the reader gave (its spaces
/// removed) is not the fingerprint of the key the record carries.
pub const STORE_FINGERPRINT_MISMATCH: &str = "store.fingerprint_mismatch";
/// `storeForEmbeddedKey`: the record's signature does not match the key it
/// carries (`integrity_against_embedded_key` is not `matches`), so trusting
/// that key would not make this record verify.
pub const STORE_INTEGRITY: &str = "store.integrity";
/// An attestation level that is not `self`, `software` or `hardware`.
pub const ATTESTATION_LEVEL_UNKNOWN: &str = "attestation_level.unknown";
/// A request whose framing is broken: only a caller that bypasses
/// js/vmr-check.js can send one.
pub const REQUEST_MALFORMED: &str = "request.malformed";

/// An input a call cannot use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The stable id of the refusal.
    pub id: String,
    /// The argument at fault: `record`, `trust_store`, `authority_store`,
    /// `pack`, `at`, `files`, `expected_fingerprint`, `attestation_level` or
    /// `request`.
    pub input: &'static str,
    /// What is wrong, in the refusing library's words.
    pub detail: String,
}

impl Refusal {
    /// A refusal of `input` as `id`.
    pub fn new(id: impl Into<String>, input: &'static str, detail: impl Into<String>) -> Self {
        Refusal { id: id.into(), input, detail: detail.into() }
    }

    /// The fail shape, every string through `display_safe`.
    pub fn to_value(&self) -> Value {
        json!({ "refusal": {
            "id": display_safe(&self.id),
            "input": self.input,
            "detail": display_safe(&self.detail),
        }})
    }
}
