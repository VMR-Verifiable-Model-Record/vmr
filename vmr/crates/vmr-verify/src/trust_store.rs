//! The trust store: the verifier operator's local root of trust
//! (`specs/trust-store-format-v0.1.md`).
// ============================================================================
//  trust_store.rs — loader, validation, lookup, canonical identity (4.2)
//
//  A trust store maps issuer DIDs to the P-256 keys the operator trusts to
//  sign records for them. It is provisioned beforehand, out of band, and
//  never fetched: this module takes bytes (or a document built in memory)
//  and does no I/O. Loading validates every rule of the format, in the
//  order the spec fixes (§3), and reports the first failure with a stable
//  kind. A loaded store is immutable; lookups go through a BTreeMap keyed by
//  key id, so no order in the file can change a result, and the store's
//  identity is the SHA-256 of its sorted JCS form (§5).
//
//  A store may also trust POLICY AUTHORITIES (P6-14, docs/TASKS.md 6.16): a
//  `policy_authorities` list beside `issuers`, whose keys are an issuer's key
//  objects. The two are kept apart by structure, never by a flag on a key:
//  `lookup` reads only the issuers and answers for records,
//  `lookup_authority` reads only the authorities and answers for policy
//  packs, and no key may appear in both lists (§3 kind 12). This module
//  never sees a pack. It says which key a pack's signature must be checked
//  with, and whether that key may speak for the pack's authority at a given
//  time (§4.2); vmr-policy checks the signature itself.
// ============================================================================

use crate::text::{bounded, cut_then_escape, quote, serde_detail};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::JwkPublicKey;
use vmr_record::timestamp::Timestamp;
use vmr_record::validate::Pattern;

/// The largest trust store the loader reads: 16 MiB (spec §2).
pub const MAX_TRUST_STORE_BYTES: usize = 16 * 1024 * 1024;

/// The deepest a store's text may nest arrays and objects, the outermost
/// counting as the first level (spec §2). Deeper text is refused as
/// `trust_store.syntax`, before the version is read (§3 kind 2), so a loader
/// whose parser stops at a depth limit can conform. A valid store nests at
/// most six levels.
pub const MAX_NESTING_DEPTH: usize = 127;

/// The only trust-store version this loader reads.
pub const TRUST_STORE_VERSION: &str = "0.1";

// ---------------------------------------------------------------------------
//  The document (a serde mirror of the file)
// ---------------------------------------------------------------------------

/// A trust-store file as written, member for member (spec §2). Build one in
/// memory and pass it to [`TrustStore::new`] to validate it, or serialize it
/// to write a store (Phase 5 `key export`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStoreDocument {
    /// `"0.1"`.
    pub trust_store_version: String,
    /// The trusted issuers; may be empty.
    pub issuers: Vec<IssuerDocument>,
    /// The trusted policy authorities (P6-14); may be empty. Absent in the
    /// file means empty, and an empty list is not written: a store without
    /// authorities has the identity it had before the member existed.
    /// `null` is refused (a `Vec` does not read one).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_authorities: Vec<AuthorityDocument>,
}

/// One trusted issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerDocument {
    /// The issuer's DID, compared with a record's `issuer.issuer_id` by
    /// exact string equality.
    pub issuer_id: String,
    /// The name a verifier shows for this issuer (the record's own
    /// `issuer_name` is only a claim).
    pub issuer_name: String,
    /// The keys trusted to sign for this issuer; at least one.
    pub keys: Vec<KeyDocument>,
}

/// One trusted policy authority (P6-14): the names a pack's own `authority`
/// member uses, and keys shaped as an issuer's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDocument {
    /// The authority's identifier, compared with a pack's
    /// `authority.authority_id` by exact string equality; not empty.
    pub authority_id: String,
    /// The name a verifier shows for this authority (the pack's own
    /// `authority_name` is only a claim).
    pub authority_name: String,
    /// The keys trusted to sign packs for this authority; at least one. Their
    /// `attestation_level` is part of the shared key object and is not read
    /// for a pack, which declares no level.
    pub keys: Vec<KeyDocument>,
}

/// One trusted key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDocument {
    /// The RFC 7638 thumbprint URN of `public_key`; unique in the store.
    pub key_id: String,
    /// The key, as a JWK exactly as in a record.
    pub public_key: JwkPublicKey,
    /// The highest attestation level a record signed by this key may
    /// declare.
    pub attestation_level: AttestationLevel,
    /// The first second at which the key may sign.
    pub valid_from: String,
    /// The key may sign strictly before this; `None` = no end.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_string"
    )]
    pub valid_until: Option<String>,
    /// Whether the key is revoked (then every record it signed fails).
    pub revoked: bool,
}

/// Absent → `None` (with `#[serde(default)]`); `null` → an error: optional
/// members are omitted, never `null`, as in records.
fn present_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

/// An attestation level, ordered `SelfAttested < Software < Hardware`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AttestationLevel {
    /// `"self"`: the issuer vouches for its own key.
    #[serde(rename = "self")]
    SelfAttested,
    /// `"software"`: a software-held key.
    #[serde(rename = "software")]
    Software,
    /// `"hardware"`: a hardware-held key.
    #[serde(rename = "hardware")]
    Hardware,
}

impl AttestationLevel {
    /// The level named by `text` (`self`, `software`, `hardware`).
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "self" => Some(AttestationLevel::SelfAttested),
            "software" => Some(AttestationLevel::Software),
            "hardware" => Some(AttestationLevel::Hardware),
            _ => None,
        }
    }

    /// The level's name in records and trust stores.
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationLevel::SelfAttested => "self",
            AttestationLevel::Software => "software",
            AttestationLevel::Hardware => "hardware",
        }
    }
}

// ---------------------------------------------------------------------------
//  Errors
// ---------------------------------------------------------------------------

/// Which loader rule a store broke (spec §3), in the order they are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustStoreErrorKind {
    /// Larger than [`MAX_TRUST_STORE_BYTES`].
    Size,
    /// Not UTF-8, not JSON, data after the top-level value, or nested more
    /// than [`MAX_NESTING_DEPTH`] levels.
    Syntax,
    /// A `trust_store_version` other than `"0.1"`.
    Version,
    /// Not exactly the format's members and JSON types at every level.
    Structure,
    /// An `issuer_id` that is not a DID.
    IssuerId,
    /// An empty `authority_id`.
    AuthorityId,
    /// A `valid_from` / `valid_until` that is not a profile timestamp.
    Timestamp,
    /// A `public_key` that is not a P-256 point.
    InvalidKey,
    /// A `key_id` that is not its key's thumbprint URN.
    KeyIdMismatch,
    /// Two issuers with one `issuer_id`.
    DuplicateIssuer,
    /// Two policy authorities with one `authority_id`.
    DuplicateAuthority,
    /// One `key_id` twice in the store, in either list or in both.
    DuplicateKey,
    /// A `valid_until` not after its `valid_from`.
    ValidityWindow,
}

impl TrustStoreErrorKind {
    /// The stable id the loader vectors use, e.g. `trust_store.size`.
    pub fn id(self) -> &'static str {
        match self {
            TrustStoreErrorKind::Size => "trust_store.size",
            TrustStoreErrorKind::Syntax => "trust_store.syntax",
            TrustStoreErrorKind::Version => "trust_store.version",
            TrustStoreErrorKind::Structure => "trust_store.structure",
            TrustStoreErrorKind::IssuerId => "trust_store.issuer_id",
            TrustStoreErrorKind::AuthorityId => "trust_store.authority_id",
            TrustStoreErrorKind::Timestamp => "trust_store.timestamp",
            TrustStoreErrorKind::InvalidKey => "trust_store.invalid_key",
            TrustStoreErrorKind::KeyIdMismatch => "trust_store.key_id_mismatch",
            TrustStoreErrorKind::DuplicateIssuer => "trust_store.duplicate_issuer",
            TrustStoreErrorKind::DuplicateAuthority => "trust_store.duplicate_authority",
            TrustStoreErrorKind::DuplicateKey => "trust_store.duplicate_key",
            TrustStoreErrorKind::ValidityWindow => "trust_store.validity_window",
        }
    }
}

/// The most characters of a loader error's detail, before its escaping.
const DETAIL_MAX_CHARS: usize = 4096;

/// A trust store that cannot be used: an operator error, never a
/// verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStoreError {
    /// The rule broken.
    pub kind: TrustStoreErrorKind,
    /// Where and how. A store is untrusted input when it reaches the wrong
    /// person, and this text reaches a terminal, so every detail the loader
    /// returns is terminal-safe — every character [`crate::display_safe`]
    /// escapes is escaped ([`crate::escape_controls`]) — and bounded: a value
    /// the loader names is quoted with at most 64 of its characters, a JSON
    /// parser's message (which may quote a member name or a value) is cut to
    /// 320, and no detail exceeds 4 096 characters before its escaping.
    pub detail: String,
}

impl TrustStoreError {
    /// Every loader error is made here: its detail cut to
    /// [`DETAIL_MAX_CHARS`] characters, then escaped — whatever built it.
    fn new(kind: TrustStoreErrorKind, detail: impl Into<String>) -> Self {
        TrustStoreError { kind, detail: cut_then_escape(detail.into(), DETAIL_MAX_CHARS) }
    }
}

impl std::fmt::Display for TrustStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind.id(), self.detail)
    }
}

impl std::error::Error for TrustStoreError {}

// ---------------------------------------------------------------------------
//  The schema's rules, and the loader stage that enforces each
// ---------------------------------------------------------------------------

/// One rule of `specs/trust-store-schema/v0.1.json` and the loader kind that
/// rejects a store breaking it. `tests/trust_store.rs` checks this table
/// against the schema in both directions (`schema_sync`) and breaks every
/// rule once to see its kind, so the schema cannot grow a rule the loader
/// does not enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRule {
    /// Instance JSON pointer; `*` stands for any array element.
    pub pointer: &'static str,
    /// The JSON Schema keyword.
    pub keyword: &'static str,
    /// The keyword's value, as compact JSON text.
    pub value: &'static str,
    /// The loader kind a violation is reported as.
    pub enforced_by: TrustStoreErrorKind,
}

const fn rule(
    pointer: &'static str,
    keyword: &'static str,
    value: &'static str,
    enforced_by: TrustStoreErrorKind,
) -> SchemaRule {
    SchemaRule { pointer, keyword, value, enforced_by }
}

use TrustStoreErrorKind as K;

const TIMESTAMP_RE: &str = "\"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$\"";
const COORD_RE: &str = "\"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$\"";
const KEY_ID_RE: &str = "\"^urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$\"";
const KEY_REQUIRED: &str = "[\"key_id\",\"public_key\",\"attestation_level\",\"valid_from\",\"revoked\"]";
const JWK_REQUIRED: &str = "[\"kty\",\"crv\",\"x\",\"y\"]";
const LEVELS: &str = "[\"hardware\",\"software\",\"self\"]";

/// Every rule of the trust-store schema (73: 39 for the store and its
/// issuers, 34 for its policy authorities), with its enforcing kind. An
/// authority's key rules are an issuer's, under another pointer.
pub const SCHEMA_RULES: &[SchemaRule] = &[
    rule("", "type", "\"object\"", K::Structure),
    rule("", "required", "[\"trust_store_version\",\"issuers\"]", K::Structure),
    rule("", "additionalProperties", "false", K::Structure),
    rule("/trust_store_version", "type", "\"string\"", K::Structure),
    rule("/trust_store_version", "const", "\"0.1\"", K::Version),
    rule("/issuers", "type", "\"array\"", K::Structure),
    rule("/issuers/*", "type", "\"object\"", K::Structure),
    rule("/issuers/*", "required", "[\"issuer_id\",\"issuer_name\",\"keys\"]", K::Structure),
    rule("/issuers/*", "additionalProperties", "false", K::Structure),
    rule("/issuers/*/issuer_id", "type", "\"string\"", K::Structure),
    rule(
        "/issuers/*/issuer_id",
        "pattern",
        "\"^did:[a-z0-9]+:([A-Za-z0-9._:-]|%[0-9A-Fa-f]{2})*([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})$\"",
        K::IssuerId,
    ),
    rule("/issuers/*/issuer_name", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys", "type", "\"array\"", K::Structure),
    rule("/issuers/*/keys", "minItems", "1", K::Structure),
    rule("/issuers/*/keys/*", "type", "\"object\"", K::Structure),
    rule("/issuers/*/keys/*", "required", KEY_REQUIRED, K::Structure),
    rule("/issuers/*/keys/*", "additionalProperties", "false", K::Structure),
    rule("/issuers/*/keys/*/key_id", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/key_id", "pattern", KEY_ID_RE, K::KeyIdMismatch),
    rule("/issuers/*/keys/*/public_key", "type", "\"object\"", K::Structure),
    rule("/issuers/*/keys/*/public_key", "required", JWK_REQUIRED, K::Structure),
    rule("/issuers/*/keys/*/public_key", "additionalProperties", "false", K::Structure),
    rule("/issuers/*/keys/*/public_key/kty", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/public_key/kty", "const", "\"EC\"", K::InvalidKey),
    rule("/issuers/*/keys/*/public_key/crv", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/public_key/crv", "const", "\"P-256\"", K::InvalidKey),
    rule("/issuers/*/keys/*/public_key/x", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/public_key/x", "pattern", COORD_RE, K::InvalidKey),
    rule("/issuers/*/keys/*/public_key/y", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/public_key/y", "pattern", COORD_RE, K::InvalidKey),
    rule("/issuers/*/keys/*/attestation_level", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/attestation_level", "enum", LEVELS, K::Structure),
    rule("/issuers/*/keys/*/valid_from", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/valid_from", "format", "\"date-time\"", K::Timestamp),
    rule("/issuers/*/keys/*/valid_from", "pattern", TIMESTAMP_RE, K::Timestamp),
    rule("/issuers/*/keys/*/valid_until", "type", "\"string\"", K::Structure),
    rule("/issuers/*/keys/*/valid_until", "format", "\"date-time\"", K::Timestamp),
    rule("/issuers/*/keys/*/valid_until", "pattern", TIMESTAMP_RE, K::Timestamp),
    rule("/issuers/*/keys/*/revoked", "type", "\"boolean\"", K::Structure),
    rule("/policy_authorities", "type", "\"array\"", K::Structure),
    rule("/policy_authorities/*", "type", "\"object\"", K::Structure),
    rule("/policy_authorities/*", "required", "[\"authority_id\",\"authority_name\",\"keys\"]", K::Structure),
    rule("/policy_authorities/*", "additionalProperties", "false", K::Structure),
    rule("/policy_authorities/*/authority_id", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/authority_id", "minLength", "1", K::AuthorityId),
    rule("/policy_authorities/*/authority_name", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys", "type", "\"array\"", K::Structure),
    rule("/policy_authorities/*/keys", "minItems", "1", K::Structure),
    rule("/policy_authorities/*/keys/*", "type", "\"object\"", K::Structure),
    rule("/policy_authorities/*/keys/*", "required", KEY_REQUIRED, K::Structure),
    rule("/policy_authorities/*/keys/*", "additionalProperties", "false", K::Structure),
    rule("/policy_authorities/*/keys/*/key_id", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/key_id", "pattern", KEY_ID_RE, K::KeyIdMismatch),
    rule("/policy_authorities/*/keys/*/public_key", "type", "\"object\"", K::Structure),
    rule("/policy_authorities/*/keys/*/public_key", "required", JWK_REQUIRED, K::Structure),
    rule("/policy_authorities/*/keys/*/public_key", "additionalProperties", "false", K::Structure),
    rule("/policy_authorities/*/keys/*/public_key/kty", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/public_key/kty", "const", "\"EC\"", K::InvalidKey),
    rule("/policy_authorities/*/keys/*/public_key/crv", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/public_key/crv", "const", "\"P-256\"", K::InvalidKey),
    rule("/policy_authorities/*/keys/*/public_key/x", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/public_key/x", "pattern", COORD_RE, K::InvalidKey),
    rule("/policy_authorities/*/keys/*/public_key/y", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/public_key/y", "pattern", COORD_RE, K::InvalidKey),
    rule("/policy_authorities/*/keys/*/attestation_level", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/attestation_level", "enum", LEVELS, K::Structure),
    rule("/policy_authorities/*/keys/*/valid_from", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/valid_from", "format", "\"date-time\"", K::Timestamp),
    rule("/policy_authorities/*/keys/*/valid_from", "pattern", TIMESTAMP_RE, K::Timestamp),
    rule("/policy_authorities/*/keys/*/valid_until", "type", "\"string\"", K::Structure),
    rule("/policy_authorities/*/keys/*/valid_until", "format", "\"date-time\"", K::Timestamp),
    rule("/policy_authorities/*/keys/*/valid_until", "pattern", TIMESTAMP_RE, K::Timestamp),
    rule("/policy_authorities/*/keys/*/revoked", "type", "\"boolean\"", K::Structure),
];

// ---------------------------------------------------------------------------
//  The validated store
// ---------------------------------------------------------------------------

/// A key the store trusts, with everything the verifier judges by.
#[derive(Debug, Clone, Copy)]
pub struct TrustedKey<'a> {
    /// The DID this key may sign for.
    pub issuer_id: &'a str,
    /// The operator's name for that issuer.
    pub issuer_name: &'a str,
    /// The key id (RFC 7638 thumbprint URN).
    pub key_id: &'a str,
    /// The key as a JWK.
    pub public_key: &'a JwkPublicKey,
    /// The key, parsed: the one a signature is verified with.
    pub verifying_key: &'a VerifyingKey,
    /// The highest attestation level a record may declare.
    pub attestation_level: AttestationLevel,
    /// The first second the key may sign.
    pub valid_from: Timestamp,
    /// The key may sign strictly before this; `None` = no end.
    pub valid_until: Option<Timestamp>,
    /// Whether the key is revoked.
    pub revoked: bool,
}

/// A key the store trusts for a policy authority (spec §4.2): the key a
/// pack's signature is checked with, and what decides whether it may speak
/// for the pack.
#[derive(Debug, Clone, Copy)]
pub struct TrustedAuthorityKey<'a> {
    /// The authority this key may sign packs for.
    pub authority_id: &'a str,
    /// The operator's name for that authority.
    pub authority_name: &'a str,
    /// The key id (RFC 7638 thumbprint URN).
    pub key_id: &'a str,
    /// The key as a JWK.
    pub public_key: &'a JwkPublicKey,
    /// The key, parsed: the one a pack's signature is verified with.
    pub verifying_key: &'a VerifyingKey,
    /// The key entry's level; not read for a pack, which declares none.
    pub attestation_level: AttestationLevel,
    /// The first second the key may sign.
    pub valid_from: Timestamp,
    /// The key may sign strictly before this; `None` = no end.
    pub valid_until: Option<Timestamp>,
    /// Whether the key is revoked.
    pub revoked: bool,
}

/// Why a key the store trusts for a policy authority may not speak for a
/// pack whose signature verified under it (spec §4.2). A caller refuses such
/// a pack: the signature does not count as the authority's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityKeyRefusal {
    /// The pack names another authority than the one the key is trusted for.
    OtherAuthority {
        /// The key.
        key_id: String,
        /// The authority the store trusts the key for.
        trusted_for: String,
        /// The authority the pack names (raw pack text).
        named: String,
    },
    /// The key is revoked: nothing it signed is believed.
    Revoked {
        /// The key.
        key_id: String,
    },
    /// The evaluation time is outside the key's window. A pack carries no
    /// signed time, so the window is judged at the time of use.
    OutsideValidity {
        /// The key.
        key_id: String,
        /// Its first second.
        valid_from: Timestamp,
        /// Its end, exclusive; `None` = no end.
        valid_until: Option<Timestamp>,
        /// The evaluation time.
        at: Timestamp,
    },
}

impl std::fmt::Display for AuthorityKeyRefusal {
    /// Terminal-safe: an authority id is quoted (at most 64 characters,
    /// escaped); a key id of a loaded store matches its pattern, and a
    /// timestamp is a profile timestamp.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityKeyRefusal::OtherAuthority { key_id, trusted_for, named } => write!(
                f,
                "the pack names policy authority {}, but its signing key {key_id} is trusted for policy \
                 authority {}: a key trusted for one authority does not speak for another",
                quote(named),
                quote(trusted_for)
            ),
            AuthorityKeyRefusal::Revoked { key_id } => {
                write!(f, "its signing key {key_id} is revoked: nothing it signed is believed")
            }
            AuthorityKeyRefusal::OutsideValidity { key_id, valid_from, valid_until: Some(until), at } => write!(
                f,
                "its signing key {key_id} may sign from {valid_from} until {until} (exclusive), and the \
                 evaluation time {at} is outside that window"
            ),
            AuthorityKeyRefusal::OutsideValidity { key_id, valid_from, valid_until: None, at } => write!(
                f,
                "its signing key {key_id} may sign from {valid_from}, and the evaluation time {at} is before that"
            ),
        }
    }
}

impl std::error::Error for AuthorityKeyRefusal {}

impl AuthorityKeyRefusal {
    /// The refusal's stable id, which a pack-signature vector and a refusal
    /// message name (docs/dev/task-6.16.md A16-22).
    pub fn id(&self) -> &'static str {
        match self {
            AuthorityKeyRefusal::OtherAuthority { .. } => "pack_signature.other_authority",
            AuthorityKeyRefusal::Revoked { .. } => "pack_signature.revoked",
            AuthorityKeyRefusal::OutsideValidity { .. } => "pack_signature.outside_validity",
        }
    }
}

impl TrustedAuthorityKey<'_> {
    /// Whether this key may speak for a pack that names `authority_id`, used
    /// at `at` (spec §4.2, after the pack's signature verified under it): the
    /// key is trusted for that very authority (exact string equality), it is
    /// not revoked, and `valid_from ≤ at < valid_until`. Checked in that
    /// order.
    pub fn may_sign_for(&self, authority_id: &str, at: Timestamp) -> Result<(), AuthorityKeyRefusal> {
        if self.authority_id != authority_id {
            return Err(AuthorityKeyRefusal::OtherAuthority {
                key_id: self.key_id.to_string(),
                trusted_for: self.authority_id.to_string(),
                named: authority_id.to_string(),
            });
        }
        if self.revoked {
            return Err(AuthorityKeyRefusal::Revoked { key_id: self.key_id.to_string() });
        }
        let before_end = self.valid_until.is_none_or(|until| at < until);
        if at < self.valid_from || !before_end {
            return Err(AuthorityKeyRefusal::OutsideValidity {
                key_id: self.key_id.to_string(),
                valid_from: self.valid_from,
                valid_until: self.valid_until,
                at,
            });
        }
        Ok(())
    }
}

/// Where a key lives in the canonical document (its entry in its list, and
/// its place among that entry's keys), and its parsed values.
#[derive(Debug, Clone)]
struct KeySlot {
    entry: usize,
    key: usize,
    parsed: ParsedKey,
}

/// A validated trust store. Immutable; build with [`TrustStore::from_json`]
/// or [`TrustStore::new`].
#[derive(Debug, Clone)]
pub struct TrustStore {
    /// The document in canonical order (issuers and authorities by id, keys
    /// by id).
    document: TrustStoreDocument,
    /// key_id → where the issuer key is.
    keys: BTreeMap<String, KeySlot>,
    /// key_id → where the policy authority key is.
    authority_keys: BTreeMap<String, KeySlot>,
    /// `sha256:<hex>` of the canonical JCS form.
    sha256: String,
}

impl TrustStore {
    /// Load a trust-store file. Checks, in order (spec §3): size, UTF-8, JSON
    /// syntax and nesting depth, version, structure, then
    /// [`TrustStore::new`]'s rules.
    pub fn from_json(bytes: &[u8]) -> Result<Self, TrustStoreError> {
        if bytes.len() > MAX_TRUST_STORE_BYTES {
            return Err(TrustStoreError::new(
                K::Size,
                format!(
                    "the store is {} bytes; the limit is {MAX_TRUST_STORE_BYTES} (16 MiB)",
                    bytes.len()
                ),
            ));
        }
        let text = std::str::from_utf8(bytes).map_err(|e| {
            TrustStoreError::new(K::Syntax, format!("not UTF-8: {e}"))
        })?;
        serde_json::from_str::<serde::de::IgnoredAny>(text)
            .map_err(|e| TrustStoreError::new(K::Syntax, format!("not JSON: {}", serde_detail(&e))))?;
        // The depth bound belongs to the syntax stage (spec §2, A16-5): it
        // comes before the version, so a loader whose parser stops at a depth
        // limit never needs to read past it.
        if let Some(offset) = nesting_past(text.as_bytes(), MAX_NESTING_DEPTH) {
            return Err(TrustStoreError::new(
                K::Syntax,
                format!(
                    "the store nests arrays and objects more than {MAX_NESTING_DEPTH} levels deep (level {} \
                     opens at byte {offset}); a trust store nests at most six",
                    MAX_NESTING_DEPTH + 1
                ),
            ));
        }

        // The version first: a later store should be reported as such, not
        // as a pile of members this reader does not know.
        if let Some(v) = peek_version(text) {
            check_version(&v)?;
        }

        // The text is valid JSON (checked above), so whatever the typed parse
        // rejects is structure - whatever category serde_json files it under
        // (it reports e.g. a number where an enum string belongs as a
        // "syntax" error). That includes a \u escape of an unpaired
        // surrogate, valid RFC 8259 syntax but not a Unicode scalar value
        // (spec §2, QA P4-03). serde_json's message quotes an unknown member
        // name or value whole, as the file has it: serde_detail cuts what it
        // quotes and escapes it. The parse is strict (QA QT-01): an object
        // written as the array of its values, which serde's derive would read
        // as the struct, is structure too (vmr_record::strict_json).
        let document: TrustStoreDocument = vmr_record::strict_json::from_str(text)
            .map_err(|e| TrustStoreError::new(K::Structure, serde_detail(&e)))?;
        Self::new(document)
    }

    /// Validate a document (spec §3, rules 3-13: version, keys present,
    /// issuer DIDs, authority ids, timestamps, keys, key ids, uniqueness,
    /// validity windows), each rule over the whole document - its issuers,
    /// then its policy authorities - before the next.
    pub fn new(document: TrustStoreDocument) -> Result<Self, TrustStoreError> {
        check_version(&document.trust_store_version)?;
        for issuer in &document.issuers {
            if issuer.keys.is_empty() {
                return Err(TrustStoreError::new(
                    K::Structure,
                    format!("issuer {} has no keys (at least one is required)", quote(&issuer.issuer_id)),
                ));
            }
        }
        for authority in &document.policy_authorities {
            if authority.keys.is_empty() {
                return Err(TrustStoreError::new(
                    K::Structure,
                    format!(
                        "policy authority {} has no keys (at least one is required)",
                        quote(&authority.authority_id)
                    ),
                ));
            }
        }
        for issuer in &document.issuers {
            if !Pattern::Did.matches(&issuer.issuer_id) {
                return Err(TrustStoreError::new(
                    K::IssuerId,
                    format!("issuer_id {} is not a DID (W3C DID Core, ASCII)", quote(&issuer.issuer_id)),
                ));
            }
        }
        if document.policy_authorities.iter().any(|a| a.authority_id.is_empty()) {
            return Err(TrustStoreError::new(
                K::AuthorityId,
                "a policy authority's authority_id is empty (it is a non-empty string, as a policy pack's is)",
            ));
        }
        // Every key of the store: the issuers' first, then the authorities'.
        let each_key = || {
            document
                .issuers
                .iter()
                .flat_map(|i| i.keys.iter())
                .chain(document.policy_authorities.iter().flat_map(|a| a.keys.iter()))
        };
        let parse_time = |key: &KeyDocument, field: &str, text: &str| {
            Timestamp::parse(text).map_err(|e| {
                TrustStoreError::new(K::Timestamp, format!("key {}: {field}: {}", quote(&key.key_id), e.detail))
            })
        };
        let mut times = Vec::new();
        for key in each_key() {
            let from = parse_time(key, "valid_from", &key.valid_from)?;
            let until = match &key.valid_until {
                Some(t) => Some(parse_time(key, "valid_until", t)?),
                None => None,
            };
            times.push((from, until));
        }
        let mut verifying_keys = Vec::new();
        for key in each_key() {
            let jwk = &key.public_key;
            let vk = jwk.to_verifying_key().map_err(|e| {
                // The JWK's own message repeats kty and crv whole; name them
                // quoted instead. Its other messages quote nothing.
                let why = if jwk.kty != "EC" || jwk.crv != "P-256" {
                    format!(
                        "public_key has kty {} and crv {}; a trusted key is kty \"EC\", crv \"P-256\"",
                        quote(&jwk.kty),
                        quote(&jwk.crv)
                    )
                } else {
                    bounded(&e.to_string())
                };
                TrustStoreError::new(K::InvalidKey, format!("key {}: {why}", quote(&key.key_id)))
            })?;
            verifying_keys.push(vk);
        }
        for key in each_key() {
            let derived = key.public_key.key_id();
            if key.key_id != derived {
                return Err(TrustStoreError::new(
                    K::KeyIdMismatch,
                    format!(
                        "key_id {} is not the RFC 7638 thumbprint URN of its public_key ({})",
                        quote(&key.key_id),
                        quote(&derived)
                    ),
                ));
            }
        }
        let mut issuer_ids = BTreeSet::new();
        for issuer in &document.issuers {
            if !issuer_ids.insert(issuer.issuer_id.as_str()) {
                return Err(TrustStoreError::new(
                    K::DuplicateIssuer,
                    format!("issuer_id {} appears twice", quote(&issuer.issuer_id)),
                ));
            }
        }
        let mut authority_ids = BTreeSet::new();
        for authority in &document.policy_authorities {
            if !authority_ids.insert(authority.authority_id.as_str()) {
                return Err(TrustStoreError::new(
                    K::DuplicateAuthority,
                    format!("policy authority {} appears twice", quote(&authority.authority_id)),
                ));
            }
        }
        let mut key_ids = BTreeSet::new();
        for key in each_key() {
            if !key_ids.insert(key.key_id.as_str()) {
                return Err(TrustStoreError::new(
                    K::DuplicateKey,
                    format!(
                        "key_id {} appears twice (a key is trusted once in the whole store: for one issuer \
                         or for one policy authority)",
                        quote(&key.key_id)
                    ),
                ));
            }
        }
        for (key, (from, until)) in each_key().zip(&times) {
            if let Some(until) = until {
                if until <= from {
                    return Err(TrustStoreError::new(
                        K::ValidityWindow,
                        format!(
                            "key {}: valid_until {until} is not after valid_from {from}",
                            quote(&key.key_id)
                        ),
                    ));
                }
            }
        }

        // Every rule holds. Pair each key with its parsed values (all three
        // lists are in the order each_key walks), then put each list in
        // canonical order - entries by id, their keys by key_id, all unique
        // now, so the order is total - carrying the parsed values along.
        let mut parsed = verifying_keys
            .into_iter()
            .zip(times)
            .map(|(verifying_key, (valid_from, valid_until))| ParsedKey { verifying_key, valid_from, valid_until });
        let TrustStoreDocument { trust_store_version, issuers, policy_authorities } = document;
        let (issuers, keys) =
            canonical_entries(issuers, &mut parsed, |i| i.issuer_id.as_str(), |i| &mut i.keys);
        let (policy_authorities, authority_keys) =
            canonical_entries(policy_authorities, &mut parsed, |a| a.authority_id.as_str(), |a| &mut a.keys);
        let canonical = TrustStoreDocument { trust_store_version, issuers, policy_authorities };

        let value = serde_json::to_value(&canonical)
            .map_err(|e| TrustStoreError::new(K::Structure, format!("cannot canonicalize: {e}")))?;
        let sha256 = format_hash(&sha256(vmr_record::canonical::jcs(&value).as_bytes()));
        Ok(TrustStore { document: canonical, keys, authority_keys, sha256 })
    }

    /// The store's identity: `sha256:<hex>` of its canonical form (spec §5)
    /// — the same for every formatting and order of the file.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The trusted ISSUER key with this key id (exact string match), if any:
    /// the key a record's signature is checked with. A policy authority's
    /// key is never found here.
    pub fn lookup(&self, key_id: &str) -> Option<TrustedKey<'_>> {
        let slot = self.keys.get(key_id)?;
        let issuer = self.document.issuers.get(slot.entry)?;
        let key = issuer.keys.get(slot.key)?;
        Some(TrustedKey {
            issuer_id: &issuer.issuer_id,
            issuer_name: &issuer.issuer_name,
            key_id: &key.key_id,
            public_key: &key.public_key,
            verifying_key: &slot.parsed.verifying_key,
            attestation_level: key.attestation_level,
            valid_from: slot.parsed.valid_from,
            valid_until: slot.parsed.valid_until,
            revoked: key.revoked,
        })
    }

    /// The trusted POLICY AUTHORITY key with this key id (exact string
    /// match), if any: the key a pack's signature is checked with (spec
    /// §4.2). An issuer's key is never found here.
    pub fn lookup_authority(&self, key_id: &str) -> Option<TrustedAuthorityKey<'_>> {
        let slot = self.authority_keys.get(key_id)?;
        let authority = self.document.policy_authorities.get(slot.entry)?;
        let key = authority.keys.get(slot.key)?;
        Some(TrustedAuthorityKey {
            authority_id: &authority.authority_id,
            authority_name: &authority.authority_name,
            key_id: &key.key_id,
            public_key: &key.public_key,
            verifying_key: &slot.parsed.verifying_key,
            attestation_level: key.attestation_level,
            valid_from: slot.parsed.valid_from,
            valid_until: slot.parsed.valid_until,
            revoked: key.revoked,
        })
    }

    /// How many issuers the store trusts.
    pub fn issuer_count(&self) -> usize {
        self.document.issuers.len()
    }

    /// How many issuer keys the store trusts, over all issuers.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// How many policy authorities the store trusts.
    pub fn authority_count(&self) -> usize {
        self.document.policy_authorities.len()
    }

    /// How many policy authority keys the store trusts, over all authorities.
    pub fn authority_key_count(&self) -> usize {
        self.authority_keys.len()
    }

    /// The store as a document, in canonical order (issuers by `issuer_id`,
    /// policy authorities by `authority_id`, keys by `key_id`).
    pub fn to_document(&self) -> TrustStoreDocument {
        self.document.clone()
    }
}

/// The values of a key entry the loader parsed while validating it.
#[derive(Debug, Clone)]
struct ParsedKey {
    verifying_key: VerifyingKey,
    valid_from: Timestamp,
    valid_until: Option<Timestamp>,
}

/// One list of the store (issuers, or policy authorities) in canonical order,
/// and the index of its keys. Each entry's keys are paired with the next
/// parsed values in document order, the entries are sorted by `id` (code-point
/// order: `str`'s byte order is UTF-8's), and each entry's keys by `key_id`.
fn canonical_entries<E>(
    entries: Vec<E>,
    parsed: &mut impl Iterator<Item = ParsedKey>,
    id: fn(&E) -> &str,
    keys: fn(&mut E) -> &mut Vec<KeyDocument>,
) -> (Vec<E>, BTreeMap<String, KeySlot>) {
    let mut paired: Vec<(E, Vec<(KeyDocument, ParsedKey)>)> = entries
        .into_iter()
        .map(|mut entry| {
            let entry_keys = std::mem::take(keys(&mut entry)).into_iter().zip(parsed.by_ref()).collect();
            (entry, entry_keys)
        })
        .collect();
    paired.sort_by(|a, b| id(&a.0).cmp(id(&b.0)));
    let mut sorted = Vec::with_capacity(paired.len());
    let mut index = BTreeMap::new();
    for (entry_pos, (mut entry, mut entry_keys)) in paired.into_iter().enumerate() {
        entry_keys.sort_by(|a, b| a.0.key_id.cmp(&b.0.key_id));
        for (key_pos, (key, parsed)) in entry_keys.into_iter().enumerate() {
            index.insert(key.key_id.clone(), KeySlot { entry: entry_pos, key: key_pos, parsed });
            keys(&mut entry).push(key);
        }
        sorted.push(entry);
    }
    (sorted, index)
}

/// The byte offset at which `json` — text already known to be RFC 8259 JSON —
/// opens its `max + 1`-th level of arrays and objects, if it does. One pass,
/// no recursion however deep the text: outside strings `[` and `{` open a
/// level and `]` and `}` close one; inside a string a backslash escapes the
/// byte after it. UTF-8 continuation bytes never equal these ASCII bytes.
fn nesting_past(json: &[u8], max: usize) -> Option<usize> {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for (offset, &byte) in json.iter().enumerate() {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return Some(offset);
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

/// The top-level `trust_store_version`, when the document is an object with
/// exactly one such member and its value is a string of Unicode scalar
/// values; `None` otherwise (the structure check then says what is wrong).
///
/// Only that one value is decoded. Member names are read as raw bytes and
/// every other value is skipped unread, so no structure failure elsewhere -
/// an unknown member, or a `\u` escape of an unpaired surrogate in a value or
/// in a member name - can hide a store's later version: spec §3 checks
/// kind 3 (version) over the whole document before kind 4 (structure).
/// (A derived struct would read each top-level member name as a string, and
/// serde_json refuses a name holding an unpaired surrogate.)
fn peek_version(text: &str) -> Option<String> {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    /// A member name: is it `trust_store_version`?
    struct IsVersion(bool);
    impl<'de> Deserialize<'de> for IsVersion {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Name;
            impl Visitor<'_> for Name {
                type Value = IsVersion;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a member name")
                }
                fn visit_bytes<E>(self, name: &[u8]) -> Result<IsVersion, E> {
                    Ok(IsVersion(name == b"trust_store_version"))
                }
                fn visit_str<E>(self, name: &str) -> Result<IsVersion, E> {
                    Ok(IsVersion(name == "trust_store_version"))
                }
            }
            d.deserialize_bytes(Name)
        }
    }

    /// The version member's value: `Some` for a string, `None` for any other
    /// value (consumed unread).
    struct VersionValue(Option<String>);
    impl<'de> Deserialize<'de> for VersionValue {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Any;
            impl<'de> Visitor<'de> for Any {
                type Value = VersionValue;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("any JSON value")
                }
                fn visit_str<E>(self, v: &str) -> Result<VersionValue, E> {
                    Ok(VersionValue(Some(v.to_string())))
                }
                fn visit_bool<E>(self, _: bool) -> Result<VersionValue, E> {
                    Ok(VersionValue(None))
                }
                fn visit_i64<E>(self, _: i64) -> Result<VersionValue, E> {
                    Ok(VersionValue(None))
                }
                fn visit_u64<E>(self, _: u64) -> Result<VersionValue, E> {
                    Ok(VersionValue(None))
                }
                fn visit_f64<E>(self, _: f64) -> Result<VersionValue, E> {
                    Ok(VersionValue(None))
                }
                fn visit_unit<E>(self) -> Result<VersionValue, E> {
                    Ok(VersionValue(None))
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<VersionValue, A::Error> {
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                    Ok(VersionValue(None))
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<VersionValue, A::Error> {
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                    Ok(VersionValue(None))
                }
            }
            d.deserialize_any(Any)
        }
    }

    /// The top-level object: the version value, if its member appears once.
    struct Top(Option<String>);
    impl<'de> Deserialize<'de> for Top {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Object;
            impl<'de> Visitor<'de> for Object {
                type Value = Top;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a JSON object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top, A::Error> {
                    let (mut version, mut seen) = (None, 0usize);
                    while let Some(IsVersion(is_version)) = map.next_key()? {
                        if is_version {
                            seen += 1;
                            version = map.next_value::<VersionValue>()?.0;
                        } else {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                    // A duplicated version member is a structure failure.
                    Ok(Top(if seen == 1 { version } else { None }))
                }
            }
            d.deserialize_map(Object)
        }
    }

    serde_json::from_str::<Top>(text).ok().and_then(|top| top.0)
}

fn check_version(version: &str) -> Result<(), TrustStoreError> {
    if version == TRUST_STORE_VERSION {
        Ok(())
    } else {
        Err(TrustStoreError::new(
            K::Version,
            format!(
                "trust_store_version {} is not supported (this verifier reads {TRUST_STORE_VERSION:?})",
                quote(version)
            ),
        ))
    }
}
