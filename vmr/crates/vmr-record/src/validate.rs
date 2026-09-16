//! The schema's rules as code: hand-written matchers (no regex engine), the
//! rule table, `Record::validate_format`, `Record::check_consistency`
//! and `Record::check_lineage_consistency`.
// ============================================================================
//  validate.rs — schema string rules (Phase 4, decisions D3 and D4)
//
//  There is no JSON Schema crate in Cargo.lock, and the verifier would not
//  want one on its path (D3). Each `pattern` of specs/record-schema/v0.1.json
//  is therefore a small hand-written matcher here, working on bytes, linear
//  in the input, with no allocation. `Pattern::regex()` returns the schema's
//  exact pattern text; tests/validate_tests.rs checks every matcher against
//  the `regex` crate on a deterministic corpus (pattern_differential), so a
//  matcher cannot silently drift from the schema text it implements.
// ============================================================================

use crate::hash::{format_hash, parse_hash};
use crate::named_set::{ascends, validate_name, NamedSetDigest};
use crate::record::Record;

/// The registered profile identifier of the KHALM engine's learned state
/// (spec §7.1, §7.4). It is the only profile of `record_version` `"0.1"`: a
/// later profile comes with a new `record_version`.
pub const KHALM_ENGINE_PROFILE: &str = "snn-compact-v1";

/// The registered formats of `model_identity.statement_references` (spec
/// §7.7; task 10.11e, D11e-3): a `format` without `.` must be one of these.
/// Fixed per `record_version`: v0.1 registers OpenSSF Model Signing's
/// bundle, named by its DSSE payload's SHA-256 (D11e-4), and an audit-log
/// checkpoint, named by the SHA-256 of its signed payload (task 10.11cd, the
/// owner's answer to Phase 8's Q9(b)). A format with `.` is the issuer's own,
/// and never collides with a later registration.
pub const REGISTERED_STATEMENT_FORMATS: &[&str] = &["oms-v1", "vmr-audit-checkpoint-v1"];

/// Which rules a record's `model_identity` follows (spec §7.1), selected by
/// comparing `model_format` with the registered identifiers as exact strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelDescription {
    /// `model_format` is `snn-compact-v1`: the KHALM engine profile (§7.4).
    KhalmEngineProfile,
    /// Any other `model_format`: the general description (§7.3).
    General,
}

/// A violated format rule: where (a JSON pointer into the document, `""`
/// for a bare value), which rule, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatViolation {
    /// JSON pointer (RFC 6901) to the offending value; `""` for a value that
    /// is not part of a document (e.g. an evaluation time).
    pub pointer: String,
    /// The rule: `timestamp`, a schema keyword (`pattern`, `enum`, …),
    /// `consistency` (spec §7) or `lineage` (spec §6.5).
    pub rule: &'static str,
    /// What was wrong, quoting at most 64 characters of the value.
    pub detail: String,
}

impl FormatViolation {
    /// A violation of `rule` at `pointer`.
    pub fn new(pointer: impl Into<String>, rule: &'static str, detail: impl Into<String>) -> Self {
        FormatViolation { pointer: pointer.into(), rule, detail: detail.into() }
    }
}

impl std::fmt::Display for FormatViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.pointer.is_empty() {
            write!(f, "{}: {}", self.rule, self.detail)
        } else {
            write!(f, "{}: {}: {}", self.pointer, self.rule, self.detail)
        }
    }
}

impl std::error::Error for FormatViolation {}

/// `value` for an error message: at most 64 characters, as a Rust-escaped
/// string literal (control and non-printing characters escaped), with `…`
/// when cut.
pub(crate) fn quote(value: &str) -> String {
    const MAX: usize = 64;
    let mut cut: String = value.chars().take(MAX).collect();
    if cut.len() < value.len() {
        cut.push('…');
    }
    format!("{cut:?}")
}

/// The string patterns of the record schema. Each has the schema's exact
/// regular-expression text ([`Pattern::regex`]) and a hand-written matcher
/// ([`Pattern::matches`]); the verifier only ever runs the matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pattern {
    /// The UTC-seconds profile (spec §2 rule 7). The matcher also checks the
    /// calendar, which the regular expression cannot.
    Timestamp,
    /// A canonical lower-case UUID URN (rule 8).
    UuidUrn,
    /// `sha256:` + 64 lower-case hex digits (rule 5).
    Hash,
    /// A hash string or `""` (rule 9).
    OptionalHash,
    /// A DID in W3C DID Core syntax, ASCII only (rule 10).
    Did,
    /// A JWK P-256 coordinate: canonical base64url of 32 bytes (§5).
    JwkCoordinate,
    /// A key id: the RFC 9278 URN of an RFC 7638 SHA-256 thumbprint (§5).
    KeyId,
    /// The JSON `signature` field: `base64url:` + canonical base64url of
    /// 64 bytes (§4.3).
    Signature,
    /// Two upper-case ASCII letters (`data_residency`, each of
    /// `data_residency_countries`).
    CountryCode,
    /// A statement format (spec §7.7; task 10.11e): one or more segments of
    /// lower-case ASCII letters, digits and `-`, each starting with a letter or
    /// a digit, joined by `.`.
    StatementFormat,
}

impl Pattern {
    /// Every pattern.
    pub const ALL: [Pattern; 10] = [
        Pattern::Timestamp,
        Pattern::UuidUrn,
        Pattern::Hash,
        Pattern::OptionalHash,
        Pattern::Did,
        Pattern::JwkCoordinate,
        Pattern::KeyId,
        Pattern::Signature,
        Pattern::CountryCode,
        Pattern::StatementFormat,
    ];

    /// The pattern's text exactly as the schema writes it (ECMA-262).
    pub fn regex(self) -> &'static str {
        match self {
            Pattern::Timestamp => {
                "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
            }
            Pattern::UuidUrn => {
                "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            }
            Pattern::Hash => "^sha256:[0-9a-f]{64}$",
            Pattern::OptionalHash => "^(sha256:[0-9a-f]{64})?$",
            Pattern::Did => {
                "^did:[a-z0-9]+:([A-Za-z0-9._:-]|%[0-9A-Fa-f]{2})*([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})$"
            }
            Pattern::JwkCoordinate => "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
            Pattern::KeyId => {
                "^urn:ietf:params:oauth:jwk-thumbprint:sha-256:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
            }
            Pattern::Signature => "^base64url:[A-Za-z0-9_-]{85}[AQgw]$",
            Pattern::CountryCode => "^[A-Z]{2}$",
            Pattern::StatementFormat => r"^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$",
        }
    }

    /// Whether `s` matches, as a whole string.
    pub fn matches(self, s: &str) -> bool {
        let b = s.as_bytes();
        match self {
            Pattern::Timestamp => crate::timestamp::Timestamp::parse(s).is_ok(),
            Pattern::UuidUrn => b.strip_prefix(b"urn:uuid:").is_some_and(|rest| {
                rest.len() == 36
                    && rest.iter().enumerate().all(|(i, &c)| match i {
                        8 | 13 | 18 | 23 => c == b'-',
                        _ => is_lower_hex(c),
                    })
            }),
            Pattern::Hash => is_hash(b),
            Pattern::OptionalHash => b.is_empty() || is_hash(b),
            Pattern::Did => is_did(b),
            Pattern::JwkCoordinate => is_b64url_with_zero_tail(b, 43, b"AEIMQUYcgkosw048"),
            Pattern::KeyId => b
                .strip_prefix(b"urn:ietf:params:oauth:jwk-thumbprint:sha-256:")
                .is_some_and(|rest| is_b64url_with_zero_tail(rest, 43, b"AEIMQUYcgkosw048")),
            Pattern::Signature => b
                .strip_prefix(b"base64url:")
                .is_some_and(|rest| is_b64url_with_zero_tail(rest, 86, b"AQgw")),
            Pattern::CountryCode => b.len() == 2 && b.iter().all(u8::is_ascii_uppercase),
            Pattern::StatementFormat => b.split(|&c| c == b'.').all(|segment| {
                segment.first().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && segment.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }),
        }
    }
}

fn is_lower_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

fn is_hash(b: &[u8]) -> bool {
    b.strip_prefix(b"sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.iter().all(|&c| is_lower_hex(c)))
}

fn is_b64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// `len` base64url characters whose last one leaves zero trailing bits:
/// canonical base64url of 32 bytes (43 characters; last in
/// `AEIMQUYcgkosw048`) or of 64 bytes (86 characters; last in `AQgw`).
fn is_b64url_with_zero_tail(b: &[u8], len: usize, last: &[u8]) -> bool {
    match b.split_last() {
        Some((tail, head)) => {
            b.len() == len && head.iter().all(|&c| is_b64url(c)) && last.contains(tail)
        }
        None => false,
    }
}

/// W3C DID Core, ASCII: `did:` method-name `:` method-specific-id, where
/// method-name = 1*(a-z / 0-9) and method-specific-id is a non-empty run of
/// idchars (`A-Z a-z 0-9 . - _` or `%HH`) and `:` that does not end in `:`.
fn is_did(b: &[u8]) -> bool {
    let Some(rest) = b.strip_prefix(b"did:") else {
        return false;
    };
    let method_len = rest
        .iter()
        .take_while(|&&c| c.is_ascii_lowercase() || c.is_ascii_digit())
        .count();
    if method_len == 0 {
        return false;
    }
    let Some(id) = rest.get(method_len..).and_then(|r| r.strip_prefix(b":")) else {
        return false;
    };
    let (mut i, mut last_was_colon, mut tokens) = (0usize, false, 0usize);
    while let Some(&c) = id.get(i) {
        if c == b'%' {
            let hex_ok = id
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit));
            if !hex_ok {
                return false;
            }
            i += 3;
            last_was_colon = false;
        } else if c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_') {
            i += 1;
            last_was_colon = false;
        } else if c == b':' {
            i += 1;
            last_was_colon = true;
        } else {
            return false;
        }
        tokens += 1;
    }
    tokens > 0 && !last_was_colon
}

// ---------------------------------------------------------------------------
//  The rule table: every rule of specs/record-schema/v0.1.json
// ---------------------------------------------------------------------------

/// One JSON Schema rule, as code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// `type`: enforced by the parser (the typed structs).
    Type(&'static str),
    /// `required`: enforced by the parser.
    Required(&'static [&'static str]),
    /// `additionalProperties: false`: enforced by the parser
    /// (`deny_unknown_fields`).
    Closed,
    /// `const`.
    Const(&'static str),
    /// `enum`.
    Enum(&'static [&'static str]),
    /// `pattern`, with its hand-written matcher.
    Pattern(Pattern),
    /// `format` (`date-time`: the UTC-seconds profile, calendar-checked).
    Format(&'static str),
    /// `minimum`.
    Minimum(u64),
    /// `maximum`.
    Maximum(u64),
    /// `minItems`.
    MinItems(u64),
    /// `maxItems`.
    MaxItems(u64),
    /// `minLength`: a string of at least that many Unicode scalar values
    /// (task 10.11b).
    MinLength(u64),
}

impl RuleKind {
    /// The JSON Schema keyword.
    pub fn keyword(&self) -> &'static str {
        match self {
            RuleKind::Type(_) => "type",
            RuleKind::Required(_) => "required",
            RuleKind::Closed => "additionalProperties",
            RuleKind::Const(_) => "const",
            RuleKind::Enum(_) => "enum",
            RuleKind::Pattern(_) => "pattern",
            RuleKind::Format(_) => "format",
            RuleKind::Minimum(_) => "minimum",
            RuleKind::Maximum(_) => "maximum",
            RuleKind::MinItems(_) => "minItems",
            RuleKind::MaxItems(_) => "maxItems",
            RuleKind::MinLength(_) => "minLength",
        }
    }

    /// The keyword's value, as it appears in the schema.
    pub fn value(&self) -> serde_json::Value {
        use serde_json::Value;
        let strings = |items: &[&str]| Value::Array(items.iter().map(|s| Value::from(*s)).collect());
        match self {
            RuleKind::Type(t) | RuleKind::Const(t) | RuleKind::Format(t) => Value::from(*t),
            RuleKind::Required(items) | RuleKind::Enum(items) => strings(items),
            RuleKind::Closed => Value::Bool(false),
            RuleKind::Pattern(p) => Value::from(p.regex()),
            RuleKind::Minimum(n)
            | RuleKind::Maximum(n)
            | RuleKind::MinItems(n)
            | RuleKind::MaxItems(n)
            | RuleKind::MinLength(n) => Value::from(*n),
        }
    }

    /// Whether the record parser enforces this rule (`type`, `required`,
    /// `additionalProperties`): a parsed or constructed `Record` satisfies
    /// it by its Rust types. [`Record::validate_format`] checks the rest.
    pub fn enforced_by_parser(&self) -> bool {
        matches!(self, RuleKind::Type(_) | RuleKind::Required(_) | RuleKind::Closed)
    }
}

/// A schema rule at a JSON pointer (`*` = every element of an array).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// Where, in the instance: `/issuer/key_id`,
    /// `/policy_compliance/results/*/status`, `""` for the root.
    pub pointer: &'static str,
    /// What.
    pub kind: RuleKind,
}

const fn r(pointer: &'static str, kind: RuleKind) -> Rule {
    Rule { pointer, kind }
}

use Pattern as P;
use RuleKind::{Closed, Enum, Format, Maximum, MinItems, MinLength, Minimum, Required, Type, Const};

/// Every rule of `specs/record-schema/v0.1.json`, in the schema's order.
/// `tests/validate_tests.rs::schema_sync` checks this table against the
/// schema in both directions and fails on any keyword the table cannot
/// express, so the schema cannot grow a rule the code lacks; every value
/// rule is broken once there to see [`Record::validate_format`] catch it.
pub const RULES: &[Rule] = &[
    r("", Type("object")),
    r("", Required(&["record_version", "record_id", "issued_at", "issuer", "model_identity", "learning_provenance", "policy_compliance", "lineage", "signature"])),
    r("/record_version", Type("string")),
    r("/record_version", Const("0.1")),
    r("/record_id", Type("string")),
    r("/record_id", RuleKind::Pattern(P::UuidUrn)),
    r("/issued_at", Type("string")),
    r("/issued_at", Format("date-time")),
    r("/issued_at", RuleKind::Pattern(P::Timestamp)),
    r("/issuer", Type("object")),
    r("/issuer", Required(&["issuer_id", "issuer_name", "public_key", "key_id", "attestation_level"])),
    r("/issuer/issuer_id", Type("string")),
    r("/issuer/issuer_id", RuleKind::Pattern(P::Did)),
    r("/issuer/issuer_name", Type("string")),
    r("/issuer/public_key", Type("object")),
    r("/issuer/public_key", Required(&["kty", "crv", "x", "y"])),
    r("/issuer/public_key/kty", Type("string")),
    r("/issuer/public_key/kty", Const("EC")),
    r("/issuer/public_key/crv", Type("string")),
    r("/issuer/public_key/crv", Const("P-256")),
    r("/issuer/public_key/x", Type("string")),
    r("/issuer/public_key/x", RuleKind::Pattern(P::JwkCoordinate)),
    r("/issuer/public_key/y", Type("string")),
    r("/issuer/public_key/y", RuleKind::Pattern(P::JwkCoordinate)),
    r("/issuer/public_key", Closed),
    r("/issuer/key_id", Type("string")),
    r("/issuer/key_id", RuleKind::Pattern(P::KeyId)),
    r("/issuer/attestation_level", Type("string")),
    r("/issuer/attestation_level", Enum(&["hardware", "software", "self"])),
    r("/issuer", Closed),
    r("/model_identity", Type("object")),
    r("/model_identity", Required(&["model_hash", "model_format", "architecture", "learned_state_hash", "learned_state_components"])),
    r("/model_identity/model_hash", Type("string")),
    r("/model_identity/model_hash", RuleKind::Pattern(P::Hash)),
    r("/model_identity/model_format", Type("string")),
    r("/model_identity/parameter_count", Type("integer")),
    r("/model_identity/parameter_count", Minimum(0)),
    r("/model_identity/parameter_count", Maximum(9_007_199_254_740_991)),
    r("/model_identity/architecture", Type("object")),
    r("/model_identity/architecture", Required(&["type", "topology", "precision"])),
    r("/model_identity/architecture/type", Type("string")),
    r("/model_identity/architecture/topology", Type("string")),
    r("/model_identity/architecture/precision", Type("string")),
    r("/model_identity/architecture", Closed),
    r("/model_identity/learned_state_hash", Type("string")),
    r("/model_identity/learned_state_hash", RuleKind::Pattern(P::Hash)),
    r("/model_identity/learned_state_components", Type("array")),
    r("/model_identity/learned_state_components", MinItems(1)),
    r("/model_identity/learned_state_components/*", Type("object")),
    r("/model_identity/learned_state_components/*", Required(&["name", "hash", "size_bytes"])),
    r("/model_identity/learned_state_components/*/name", Type("string")),
    r("/model_identity/learned_state_components/*/hash", Type("string")),
    r("/model_identity/learned_state_components/*/hash", RuleKind::Pattern(P::Hash)),
    r("/model_identity/learned_state_components/*/size_bytes", Type("integer")),
    r("/model_identity/learned_state_components/*/size_bytes", Minimum(0)),
    r("/model_identity/learned_state_components/*/size_bytes", Maximum(9_007_199_254_740_991)),
    r("/model_identity/learned_state_components/*", Closed),
    r("/model_identity/derived_from", Type("array")),
    r("/model_identity/derived_from", MinItems(1)),
    r("/model_identity/derived_from/*", Type("object")),
    r("/model_identity/derived_from/*", Required(&["model_hash", "name", "relation"])),
    r("/model_identity/derived_from/*/model_hash", Type("string")),
    r("/model_identity/derived_from/*/model_hash", RuleKind::Pattern(P::Hash)),
    r("/model_identity/derived_from/*/name", Type("string")),
    r("/model_identity/derived_from/*/relation", Type("string")),
    r("/model_identity/derived_from/*/relation", Enum(&["fine-tune", "adapter", "merge", "quantization", "distillation", "other"])),
    r("/model_identity/derived_from/*", Closed),
    r("/model_identity/statement_references", Type("array")),
    r("/model_identity/statement_references", MinItems(1)),
    r("/model_identity/statement_references/*", Type("object")),
    r("/model_identity/statement_references/*", Required(&["format", "digest"])),
    r("/model_identity/statement_references/*/format", Type("string")),
    r("/model_identity/statement_references/*/format", RuleKind::Pattern(P::StatementFormat)),
    r("/model_identity/statement_references/*/digest", Type("string")),
    r("/model_identity/statement_references/*/digest", RuleKind::Pattern(P::Hash)),
    r("/model_identity/statement_references/*", Closed),
    r("/model_identity", Closed),
    r("/learning_provenance", Type("object")),
    r("/learning_provenance", Required(&["training_input_digest", "training_input_merkle_root", "training_input_count", "training_environment", "training_input_provenance"])),
    r("/learning_provenance/training_input_digest", Type("string")),
    r("/learning_provenance/training_input_digest", RuleKind::Pattern(P::OptionalHash)),
    r("/learning_provenance/training_input_merkle_root", Type("string")),
    r("/learning_provenance/training_input_merkle_root", RuleKind::Pattern(P::OptionalHash)),
    r("/learning_provenance/training_input_count", Type("integer")),
    r("/learning_provenance/training_input_count", Minimum(0)),
    r("/learning_provenance/training_input_count", Maximum(9_007_199_254_740_991)),
    r("/learning_provenance/training_epochs", Type("integer")),
    r("/learning_provenance/training_epochs", Minimum(0)),
    r("/learning_provenance/training_epochs", Maximum(9_007_199_254_740_991)),
    r("/learning_provenance/training_started_at", Type("string")),
    r("/learning_provenance/training_started_at", Format("date-time")),
    r("/learning_provenance/training_started_at", RuleKind::Pattern(P::Timestamp)),
    r("/learning_provenance/training_ended_at", Type("string")),
    r("/learning_provenance/training_ended_at", Format("date-time")),
    r("/learning_provenance/training_ended_at", RuleKind::Pattern(P::Timestamp)),
    r("/learning_provenance/training_environment", Type("object")),
    r("/learning_provenance/training_environment", Required(&["hardware_id", "tee_measurement", "software_hash", "training_software"])),
    r("/learning_provenance/training_environment/hardware_id", Type("string")),
    r("/learning_provenance/training_environment/hardware_id", RuleKind::Pattern(P::OptionalHash)),
    r("/learning_provenance/training_environment/tee_measurement", Type("string")),
    r("/learning_provenance/training_environment/tee_measurement", RuleKind::Pattern(P::OptionalHash)),
    r("/learning_provenance/training_environment/software_hash", Type("string")),
    r("/learning_provenance/training_environment/software_hash", RuleKind::Pattern(P::OptionalHash)),
    r("/learning_provenance/training_environment/accelerator_software", Type("string")),
    r("/learning_provenance/training_environment/accelerator_software", MinLength(1)),
    r("/learning_provenance/training_environment/training_software", Type("string")),
    r("/learning_provenance/training_environment/accelerator", Type("string")),
    r("/learning_provenance/training_environment/accelerator", MinLength(1)),
    r("/learning_provenance/training_environment", Closed),
    r("/learning_provenance/training_input_provenance", Type("object")),
    r("/learning_provenance/training_input_provenance", Required(&["source_type", "source_description"])),
    r("/learning_provenance/training_input_provenance/source_type", Type("string")),
    r("/learning_provenance/training_input_provenance/source_description", Type("string")),
    r("/learning_provenance/training_input_provenance/data_residency", Type("string")),
    r("/learning_provenance/training_input_provenance/data_residency", RuleKind::Pattern(P::CountryCode)),
    r("/learning_provenance/training_input_provenance/collection_period", Type("object")),
    r("/learning_provenance/training_input_provenance/collection_period", Required(&["start", "end"])),
    r("/learning_provenance/training_input_provenance/collection_period/start", Type("string")),
    r("/learning_provenance/training_input_provenance/collection_period/start", Format("date-time")),
    r("/learning_provenance/training_input_provenance/collection_period/start", RuleKind::Pattern(P::Timestamp)),
    r("/learning_provenance/training_input_provenance/collection_period/end", Type("string")),
    r("/learning_provenance/training_input_provenance/collection_period/end", Format("date-time")),
    r("/learning_provenance/training_input_provenance/collection_period/end", RuleKind::Pattern(P::Timestamp)),
    r("/learning_provenance/training_input_provenance/collection_period", Closed),
    r("/learning_provenance/training_input_provenance/data_residency_countries", Type("array")),
    r("/learning_provenance/training_input_provenance/data_residency_countries", MinItems(2)),
    r("/learning_provenance/training_input_provenance/data_residency_countries/*", Type("string")),
    r("/learning_provenance/training_input_provenance/data_residency_countries/*", RuleKind::Pattern(P::CountryCode)),
    r("/learning_provenance/training_input_provenance", Closed),
    r("/learning_provenance/training_input_format", Type("string")),
    r("/learning_provenance/training_input_format", MinLength(1)),
    r("/learning_provenance/training_input_disclosure", Type("string")),
    r("/learning_provenance/training_input_disclosure", Enum(&["not-disclosed", "not-held"])),
    r("/learning_provenance", Closed),
    r("/deployment_context", Type("object")),
    r("/deployment_context", Required(&["deployment_id", "deployed_at", "deployed_by", "hardware_id", "tee_measurement", "software_hash", "inference_boundary", "policy_pack_id"])),
    r("/deployment_context/deployment_id", Type("string")),
    r("/deployment_context/deployment_id", RuleKind::Pattern(P::UuidUrn)),
    r("/deployment_context/deployed_at", Type("string")),
    r("/deployment_context/deployed_at", Format("date-time")),
    r("/deployment_context/deployed_at", RuleKind::Pattern(P::Timestamp)),
    r("/deployment_context/deployed_by", Type("string")),
    r("/deployment_context/deployed_by", RuleKind::Pattern(P::Did)),
    r("/deployment_context/hardware_id", Type("string")),
    r("/deployment_context/hardware_id", RuleKind::Pattern(P::OptionalHash)),
    r("/deployment_context/tee_measurement", Type("string")),
    r("/deployment_context/tee_measurement", RuleKind::Pattern(P::OptionalHash)),
    r("/deployment_context/software_hash", Type("string")),
    r("/deployment_context/software_hash", RuleKind::Pattern(P::OptionalHash)),
    r("/deployment_context/inference_boundary", Type("object")),
    r("/deployment_context/inference_boundary", Required(&["type", "egress_allowed", "allowed_egress_destinations"])),
    r("/deployment_context/inference_boundary/type", Type("string")),
    r("/deployment_context/inference_boundary/egress_allowed", Type("boolean")),
    r("/deployment_context/inference_boundary/allowed_egress_destinations", Type("array")),
    r("/deployment_context/inference_boundary/allowed_egress_destinations/*", Type("string")),
    r("/deployment_context/inference_boundary", Closed),
    r("/deployment_context/policy_pack_id", Type("string")),
    r("/deployment_context", Closed),
    r("/policy_compliance", Type("object")),
    r("/policy_compliance", Required(&["policy_pack_id", "evaluated_at", "results", "overall_status"])),
    r("/policy_compliance/policy_pack_id", Type("string")),
    r("/policy_compliance/evaluated_at", Type("string")),
    r("/policy_compliance/evaluated_at", Format("date-time")),
    r("/policy_compliance/evaluated_at", RuleKind::Pattern(P::Timestamp)),
    r("/policy_compliance/results", Type("array")),
    r("/policy_compliance/results/*", Type("object")),
    r("/policy_compliance/results/*", Required(&["rule_id", "status", "evidence_hash"])),
    r("/policy_compliance/results/*/rule_id", Type("string")),
    r("/policy_compliance/results/*/status", Type("string")),
    r("/policy_compliance/results/*/status", Enum(&["pass", "fail"])),
    r("/policy_compliance/results/*/evidence_hash", Type("string")),
    r("/policy_compliance/results/*/evidence_hash", RuleKind::Pattern(P::Hash)),
    r("/policy_compliance/results/*", Closed),
    r("/policy_compliance/overall_status", Type("string")),
    r("/policy_compliance/overall_status", Enum(&["compliant", "non-compliant", "indeterminate"])),
    r("/policy_compliance", Closed),
    r("/lineage", Type("object")),
    r("/lineage", Required(&["lineage_chain_length", "root_record_id", "lineage_type"])),
    r("/lineage/previous_record_id", Type("string")),
    r("/lineage/previous_record_id", RuleKind::Pattern(P::UuidUrn)),
    r("/lineage/previous_record_hash", Type("string")),
    r("/lineage/previous_record_hash", RuleKind::Pattern(P::Hash)),
    r("/lineage/lineage_chain_length", Type("integer")),
    r("/lineage/lineage_chain_length", Minimum(1)),
    r("/lineage/lineage_chain_length", Maximum(9_007_199_254_740_991)),
    r("/lineage/root_record_id", Type("string")),
    r("/lineage/root_record_id", RuleKind::Pattern(P::UuidUrn)),
    r("/lineage/lineage_type", Type("string")),
    r("/lineage/lineage_type", Enum(&["initial", "training-update", "fine-tune", "quantization", "deployment", "policy-change"])),
    r("/lineage", Closed),
    r("/data_governance", Type("object")),
    r("/data_governance", Required(&["documentation_hash"])),
    r("/data_governance/documentation_hash", Type("string")),
    r("/data_governance/documentation_hash", RuleKind::Pattern(P::Hash)),
    r("/data_governance", Closed),
    r("/human_oversight", Type("object")),
    r("/human_oversight", Required(&["documentation_hash"])),
    r("/human_oversight/documentation_hash", Type("string")),
    r("/human_oversight/documentation_hash", RuleKind::Pattern(P::Hash)),
    r("/human_oversight", Closed),
    r("/signature", Type("object")),
    r("/signature", Required(&["algorithm", "signature", "signed_payload_hash", "signing_key_id"])),
    r("/signature/algorithm", Type("string")),
    r("/signature/algorithm", Const("ES256")),
    r("/signature/signature", Type("string")),
    r("/signature/signature", RuleKind::Pattern(P::Signature)),
    r("/signature/signed_payload_hash", Type("string")),
    r("/signature/signed_payload_hash", RuleKind::Pattern(P::Hash)),
    r("/signature/signing_key_id", Type("string")),
    r("/signature/signing_key_id", RuleKind::Pattern(P::KeyId)),
    r("/signature", Closed),
    r("", Closed),
];

// ---------------------------------------------------------------------------
//  validate_format, check_consistency and check_lineage_consistency
// ---------------------------------------------------------------------------

impl Record {
    /// Check every value rule of the schema outside the `signature` section
    /// (spec §2 rule 11; the verifier's check `format.schema`): consts,
    /// enums, patterns (timestamps calendar-checked), integer ranges and
    /// array sizes. The `type` / `required` / `additionalProperties` rules
    /// hold by construction (the parser enforces them); the `signature`
    /// section is judged by the signature checks. Reports the first
    /// violation, in the order of [`RULES`].
    pub fn validate_format(&self) -> Result<(), FormatViolation> {
        let doc = serde_json::to_value(self).map_err(|e| {
            FormatViolation::new("", "structure", format!("cannot be represented as JSON: {e}"))
        })?;
        for rule in RULES {
            if rule.kind.enforced_by_parser() || rule.pointer.starts_with("/signature") {
                continue;
            }
            let mut found = Vec::new();
            resolve(&doc, rule.pointer, String::new(), &mut found);
            for (pointer, value) in found {
                check_rule(&rule.kind, &pointer, value)?;
            }
        }
        Ok(())
    }

    /// Which rules this record's `model_identity` follows (spec §7.1).
    pub fn model_description(&self) -> ModelDescription {
        if self.model_identity.model_format == KHALM_ENGINE_PROFILE {
            ModelDescription::KhalmEngineProfile
        } else {
            ModelDescription::General
        }
    }

    /// Check the rules that relate a record's members to each other (the
    /// verifier's check `format.consistency`; spec §6.2 row 6; task 10.11b,
    /// plan §4.3), in this order, reporting the first violation with rule
    /// `consistency`:
    ///
    /// 1. the model rules [`Record::model_description`] selects: the
    ///    profile's (§7.4) or the general description's (§7.3);
    /// 2. `derived_from` ascends, and names no entry that is the model itself
    ///    (§7.5);
    /// 3. `statement_references` name registered or issuer formats and ascend
    ///    by digest (§7.7; task 10.11e);
    /// 4. the training commitment (§8.2, §8.4);
    /// 5. the residency countries (§8.5).
    pub fn check_consistency(&self) -> Result<(), FormatViolation> {
        match self.model_description() {
            ModelDescription::KhalmEngineProfile => self.check_profile_model()?,
            ModelDescription::General => self.check_general_model()?,
        }
        self.check_derived_from()?;
        self.check_statement_references()?;
        self.check_commitment()?;
        self.check_residency()
    }

    /// The references to other signed statements (spec §7.7; task 10.11e,
    /// D11e-2 and D11e-3): a `format` without `.` is one of
    /// [`REGISTERED_STATEMENT_FORMATS`], and the entries ascend by `digest`,
    /// none repeated (lower-case hex, so string order is byte order). Only
    /// their form: nothing here reads, fetches or checks a statement.
    fn check_statement_references(&self) -> Result<(), FormatViolation> {
        const REFERENCES: &str = "/model_identity/statement_references";
        let Some(references) = &self.model_identity.statement_references else {
            return Ok(());
        };
        let mut previous: Option<&str> = None;
        for (i, reference) in references.iter().enumerate() {
            if !reference.format.contains('.') && !REGISTERED_STATEMENT_FORMATS.contains(&reference.format.as_str()) {
                return Err(FormatViolation::new(
                    format!("{REFERENCES}/{i}/format"),
                    "consistency",
                    format!(
                        "{} is not a registered statement format ({}); a format of the issuer's own contains a \
                         '.' (spec §7.7)",
                        quote(&reference.format),
                        REGISTERED_STATEMENT_FORMATS.join(", ")
                    ),
                ));
            }
            if previous.is_some_and(|p| p >= reference.digest.as_str()) {
                return Err(FormatViolation::new(
                    format!("{REFERENCES}/{i}/digest"),
                    "consistency",
                    "statement_references ascend by digest, none repeated (spec §7.7)",
                ));
            }
            previous = Some(&reference.digest);
        }
        Ok(())
    }

    /// The general description (spec §7.3): every component's name follows
    /// §7.2, the names ascend with none repeated, and `learned_state_hash` is
    /// the components' named-set digest.
    fn check_general_model(&self) -> Result<(), FormatViolation> {
        const COMPONENTS: &str = "/model_identity/learned_state_components";
        let bad = |pointer: String, detail: String| Err(FormatViolation::new(pointer, "consistency", detail));
        let m = &self.model_identity;
        if m.learned_state_components.is_empty() {
            return bad(COMPONENTS.into(), "at least one component is required (spec §7.3)".into());
        }
        let mut digest = NamedSetDigest::new();
        let mut previous: Option<&str> = None;
        for (i, c) in m.learned_state_components.iter().enumerate() {
            if let Err(e) = validate_name(&c.name) {
                return bad(
                    format!("{COMPONENTS}/{i}/name"),
                    format!("{} is not a name of spec §7.2: {}", quote(&c.name), e.reason()),
                );
            }
            if previous.is_some_and(|p| !ascends(p, &c.name)) {
                return bad(
                    format!("{COMPONENTS}/{i}/name"),
                    format!(
                        "{} does not come after the name before it: names ascend by Unicode scalar value, \
                         none repeated (spec §7.2)",
                        quote(&c.name)
                    ),
                );
            }
            let Ok(hash) = parse_hash(&c.hash) else {
                return bad(format!("{COMPONENTS}/{i}/hash"), format!("{} is not a hash string", quote(&c.hash)));
            };
            if let Err(e) = digest.push(&c.name, &hash) {
                return bad(format!("{COMPONENTS}/{i}/name"), e.reason().into());
            }
            previous = Some(&c.name);
        }
        if m.learned_state_hash != format_hash(&digest.finish()) {
            return bad(
                "/model_identity/learned_state_hash".into(),
                "learned_state_hash is not the named-set digest of the components (spec §7.3)".into(),
            );
        }
        Ok(())
    }

    /// `derived_from`'s entries ascend by `model_hash`, none repeated, and none
    /// is the model's own `model_hash` (spec §7.5; the last since QA QB-08).
    /// Lower-case hex, so string order is byte order. Each entry is checked in
    /// turn, and a failure is reported at that entry.
    fn check_derived_from(&self) -> Result<(), FormatViolation> {
        let Some(bases) = &self.model_identity.derived_from else {
            return Ok(());
        };
        let mut previous: Option<&str> = None;
        for (i, base) in bases.iter().enumerate() {
            let at = || format!("/model_identity/derived_from/{i}/model_hash");
            if previous.is_some_and(|p| p >= base.model_hash.as_str()) {
                return Err(FormatViolation::new(
                    at(),
                    "consistency",
                    "derived_from's entries ascend by model_hash, none repeated (spec §7.5)",
                ));
            }
            if base.model_hash == self.model_identity.model_hash {
                return Err(FormatViolation::new(
                    at(),
                    "consistency",
                    "a model is not made from itself: this derived_from entry is the model's own model_hash (spec §7.5)",
                ));
            }
            previous = Some(&base.model_hash);
        }
        Ok(())
    }

    /// The training commitment (spec §8.2, §8.4). With
    /// `training_input_disclosure`: `training_input_digest` and
    /// `training_input_merkle_root` are `""`, `training_input_count` is 0 and
    /// `training_input_format` is absent. Without it: both are hash strings,
    /// and a general record names its records' format.
    fn check_commitment(&self) -> Result<(), FormatViolation> {
        let l = &self.learning_provenance;
        let bad = |member: &str, detail: String| {
            Err(FormatViolation::new(format!("/learning_provenance/{member}"), "consistency", detail))
        };
        match &l.training_input_disclosure {
            Some(state) => {
                let why = format!("training_input_disclosure is {}, so the record commits to no records", quote(state));
                if !l.training_input_digest.is_empty() {
                    return bad("training_input_digest", format!("{why}: training_input_digest must be \"\" (spec §8.4)"));
                }
                if !l.training_input_merkle_root.is_empty() {
                    return bad(
                        "training_input_merkle_root",
                        format!("{why}: training_input_merkle_root must be \"\" (spec §8.4)"),
                    );
                }
                if l.training_input_count != 0 {
                    return bad("training_input_count", format!("{why}: training_input_count must be 0 (spec §8.4)"));
                }
                if l.training_input_format.is_some() {
                    return bad("training_input_format", format!("{why}: training_input_format must be absent (spec §8.4)"));
                }
            }
            None => {
                let why = "without training_input_disclosure the record commits its records";
                if l.training_input_digest.is_empty() {
                    return bad("training_input_digest", format!("{why}: training_input_digest must be a hash, not \"\" (spec §8.4)"));
                }
                if l.training_input_merkle_root.is_empty() {
                    return bad(
                        "training_input_merkle_root",
                        format!("{why}: training_input_merkle_root must be a hash, not \"\" (spec §8.4)"),
                    );
                }
                if self.model_description() == ModelDescription::General && l.training_input_format.is_none() {
                    return bad(
                        "training_input_format",
                        "a general record that commits records names their format in training_input_format (spec §8.2)"
                            .into(),
                    );
                }
            }
        }
        Ok(())
    }

    /// The residency countries (spec §8.5): when `data_residency_countries`
    /// is present, `data_residency` is absent and the codes ascend, none
    /// repeated.
    fn check_residency(&self) -> Result<(), FormatViolation> {
        const PROVENANCE: &str = "/learning_provenance/training_input_provenance";
        let p = &self.learning_provenance.training_input_provenance;
        let Some(countries) = &p.data_residency_countries else {
            return Ok(());
        };
        if p.data_residency.is_some() {
            return Err(FormatViolation::new(
                format!("{PROVENANCE}/data_residency"),
                "consistency",
                "data_residency is absent when data_residency_countries names the countries (spec §8.5)",
            ));
        }
        for (i, (earlier, later)) in countries.iter().zip(countries.iter().skip(1)).enumerate() {
            if earlier >= later {
                return Err(FormatViolation::new(
                    format!("{PROVENANCE}/data_residency_countries/{}", i + 1),
                    "consistency",
                    "data_residency_countries ascends, none repeated (spec §8.5)",
                ));
            }
        }
        Ok(())
    }

    /// The KHALM engine profile, `snn-compact-v1` (spec §7.4; D4 (e)):
    /// exactly the components `afferent_H`, `recurrent_H`, `thresholds`, in
    /// that order; `thresholds` = 4·H bytes with H ≥ 1; `recurrent_H` = H·H;
    /// `afferent_H` = I·H for some I; `parameter_count` present (optional only
    /// in the general description, QA QB-09) and = I·H + H·H + H;
    /// `model_hash` = `learned_state_hash`; and no `training_input_format`
    /// (its records are its frames, §8.2).
    fn check_profile_model(&self) -> Result<(), FormatViolation> {
        const COMPONENTS: &str = "/model_identity/learned_state_components";
        let bad = |pointer: &str, detail: String| {
            Err(FormatViolation::new(pointer, "consistency", detail))
        };
        let m = &self.model_identity;
        let names: Vec<String> = m.learned_state_components.iter().map(|c| quote(&c.name)).collect();
        let [aff, rec, thr] = m.learned_state_components.as_slice() else {
            return bad(
                COMPONENTS,
                format!("exactly three components are required, found {}", names.len()),
            );
        };
        let order = [aff.name.as_str(), rec.name.as_str(), thr.name.as_str()];
        if order != ["afferent_H", "recurrent_H", "thresholds"] {
            return bad(
                COMPONENTS,
                format!(
                    "the components must be afferent_H, recurrent_H, thresholds in this order; \
                     found {}",
                    names.join(", ")
                ),
            );
        }
        let h = thr.size_bytes / 4;
        if thr.size_bytes % 4 != 0 || h == 0 {
            return bad(
                &format!("{COMPONENTS}/2/size_bytes"),
                format!("thresholds is {} bytes, not 4·H for some H >= 1", thr.size_bytes),
            );
        }
        if h.checked_mul(h) != Some(rec.size_bytes) {
            return bad(
                &format!("{COMPONENTS}/1/size_bytes"),
                format!("recurrent_H is {} bytes, not H·H = {h}·{h}", rec.size_bytes),
            );
        }
        if aff.size_bytes % h != 0 {
            return bad(
                &format!("{COMPONENTS}/0/size_bytes"),
                format!("afferent_H is {} bytes, not a multiple of H = {h}", aff.size_bytes),
            );
        }
        let i = aff.size_bytes / h;
        // I·H + H·H + H: the three sizes' parameters (thresholds count once
        // per neuron). Every term is at most 2^53 - 1 here, so the sum fits,
        // but it is checked anyway.
        let expected = aff.size_bytes.checked_add(rec.size_bytes).and_then(|n| n.checked_add(h));
        // Optional in the general description, required here (QA QB-09).
        let Some(parameter_count) = m.parameter_count else {
            return bad(
                "/model_identity/parameter_count",
                "the snn-compact-v1 profile requires parameter_count (spec §7.4)".into(),
            );
        };
        if expected != Some(parameter_count) {
            return bad(
                "/model_identity/parameter_count",
                format!("parameter_count is {parameter_count}, not I·H + H·H + H with I = {i}, H = {h}"),
            );
        }
        if m.model_hash != m.learned_state_hash {
            return bad(
                "/model_identity/model_hash",
                "model_hash differs from learned_state_hash (they are equal in v0.1)".into(),
            );
        }
        if self.learning_provenance.training_input_format.is_some() {
            return bad(
                "/learning_provenance/training_input_format",
                "the snn-compact-v1 profile's records are its frames: training_input_format must be absent \
                 (spec §8.2)"
                    .into(),
            );
        }
        Ok(())
    }

    /// Check the lineage section's own consistency (spec §6.5; the
    /// verifier's check `lineage.consistency`): `previous_record_id` and
    /// `previous_record_hash` both present or both absent; `initial`
    /// with both absent, `lineage_chain_length` 1 and `root_record_id` =
    /// `record_id`; every other type with both present,
    /// `lineage_chain_length` ≥ 2, `root_record_id` ≠ `record_id` and
    /// `previous_record_id` ≠ `record_id`. Reports the first rule
    /// broken, at the member that breaks it, with rule `lineage`.
    ///
    /// The rule's one home: the verifier runs it at check 19 and the
    /// builder before it signs, so no record is signed that a verifier
    /// must reject for it. The links to predecessors (`lineage.chain`) need
    /// the predecessors and are the verifier's alone.
    pub fn check_lineage_consistency(&self) -> Result<(), FormatViolation> {
        let l = &self.lineage;
        let bad = |member: &str, detail: String| {
            Err(FormatViolation::new(format!("/lineage/{member}"), "lineage", detail))
        };
        match (&l.previous_record_id, &l.previous_record_hash) {
            (Some(_), None) | (None, Some(_)) => {
                let absent = if l.previous_record_id.is_some() {
                    "previous_record_hash"
                } else {
                    "previous_record_id"
                };
                return bad(
                    absent,
                    "previous_record_id and previous_record_hash must be both present or both absent"
                        .into(),
                );
            }
            _ => {}
        }
        if l.lineage_type == "initial" {
            if l.previous_record_id.is_some() {
                return bad("previous_record_id", "an initial record names no predecessor".into());
            }
            if l.lineage_chain_length != 1 {
                return bad(
                    "lineage_chain_length",
                    format!("an initial record has lineage_chain_length 1, not {}", l.lineage_chain_length),
                );
            }
            if l.root_record_id != self.record_id {
                return bad(
                    "root_record_id",
                    "an initial record is its own root: root_record_id must be its record_id".into(),
                );
            }
            return Ok(());
        }
        let Some(previous) = &l.previous_record_id else {
            return bad(
                "previous_record_id",
                format!("a {} record must name its predecessor", quote(&l.lineage_type)),
            );
        };
        if l.lineage_chain_length < 2 {
            return bad(
                "lineage_chain_length",
                format!(
                    "a {} record has a predecessor, so lineage_chain_length >= 2, not {}",
                    quote(&l.lineage_type),
                    l.lineage_chain_length
                ),
            );
        }
        if l.root_record_id == self.record_id {
            return bad("root_record_id", "only an initial record is its own root".into());
        }
        if *previous == self.record_id {
            return bad("previous_record_id", "a record cannot be its own predecessor".into());
        }
        Ok(())
    }
}

/// Every value at `pointer` (with `*` = every array element), with its
/// concrete JSON pointer, in document order. An absent member (an optional
/// one) yields nothing.
fn resolve<'v>(
    value: &'v serde_json::Value,
    pointer: &str,
    at: String,
    out: &mut Vec<(String, &'v serde_json::Value)>,
) {
    let Some(rest) = pointer.strip_prefix('/') else {
        out.push((at, value));
        return;
    };
    let (segment, tail) = match rest.split_once('/') {
        Some((segment, _)) => (segment, &rest[segment.len()..]),
        None => (rest, ""),
    };
    if segment == "*" {
        if let Some(items) = value.as_array() {
            for (i, item) in items.iter().enumerate() {
                resolve(item, tail, format!("{at}/{i}"), out);
            }
        }
    } else if let Some(child) = value.get(segment) {
        resolve(child, tail, format!("{at}/{segment}"), out);
    }
}

/// Check one value rule on one value.
fn check_rule(
    kind: &RuleKind,
    pointer: &str,
    value: &serde_json::Value,
) -> Result<(), FormatViolation> {
    let violation = |detail: String| Err(FormatViolation::new(pointer, kind.keyword(), detail));
    let shown = || value.as_str().map(quote).unwrap_or_else(|| value.to_string());
    let items = || value.as_array().map_or(0, Vec::len) as u64;
    match kind {
        RuleKind::Const(c) if value.as_str() != Some(c) => {
            violation(format!("{} is not {c:?}", shown()))
        }
        RuleKind::Enum(allowed) if !value.as_str().is_some_and(|s| allowed.contains(&s)) => {
            violation(format!("{} is not one of {}", shown(), allowed.join(", ")))
        }
        RuleKind::Pattern(p) if !value.as_str().is_some_and(|s| p.matches(s)) => {
            violation(format!("{} does not match {}", shown(), p.regex()))
        }
        RuleKind::Format(f) if !value.as_str().is_some_and(|s| Pattern::Timestamp.matches(s)) => {
            violation(format!("{} is not a {f} in the UTC-seconds profile", shown()))
        }
        RuleKind::Minimum(n) if value.as_u64().is_none_or(|v| v < *n) => {
            violation(format!("{} is below the minimum {n}", shown()))
        }
        RuleKind::Maximum(n) if value.as_u64().is_none_or(|v| v > *n) => {
            violation(format!("{} is above the maximum {n}", shown()))
        }
        RuleKind::MinItems(n) if items() < *n => {
            violation(format!("{} items; at least {n} are required", items()))
        }
        RuleKind::MaxItems(n) if items() > *n => {
            violation(format!("{} items; at most {n} are allowed", items()))
        }
        RuleKind::MinLength(n) if value.as_str().is_none_or(|s| (s.chars().count() as u64) < *n) => {
            violation(format!("{} is shorter than {n} character(s)", shown()))
        }
        _ => Ok(()),
    }
}
