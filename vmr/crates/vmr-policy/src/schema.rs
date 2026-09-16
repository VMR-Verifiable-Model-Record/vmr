//! `specs/policy-pack-schema/v0.1.json` as code: patterns, the rule table.
// ============================================================================
//  schema.rs — the pack schema's rules, hand-written (P6-10, Phase 4's D3)
//
//  There is no JSON Schema crate in Cargo.lock and P6-10 forbids adding one
//  (every dependency has to be vendored for the offline Linux runs), so the
//  schema is expressed here the way `vmr_record::validate` expresses the
//  record schema: one table of rules, hand-written matchers for the
//  `pattern`s, and a test that keeps the table and the JSON file equal in
//  both directions (`tests/pack_schema.rs`).
//
//  `type`, `required` and `additionalProperties` are enforced by the parser
//  (the typed structs, all `deny_unknown_fields`); the value rules - `const`,
//  `enum`, `pattern`, `minLength`, `minItems`, `maximum` - are enforced by
//  [`validate_values`]. The one `minimum`, 0 on `minimum_chain_length`, needs
//  no check there: the member is a `u64`, so the parser refuses a negative
//  number, and with it every other spelling of an integer (`1.0`, `1e0`,
//  `-0`).
// ============================================================================

use crate::error::Error;
use crate::pack::{PolicyPack, Rule};
use vmr_record::canonical::MAX_SAFE_INTEGER;
use vmr_record::validate::{FormatViolation, Pattern as RecordPattern};

/// The string patterns of the pack schema. Four of the five are the
/// record's own, taken from `vmr_record` rather than written again
/// (P6-7): a pack's signature, hash and key id are a record's, and an
/// allowed jurisdiction is spelled as a record's `data_residency` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pattern {
    /// `pack_version`: three dot-separated decimal numbers, none with a
    /// leading zero, so one version has one spelling.
    PackVersion,
    /// `sha256:` + 64 lower-case hex digits.
    Hash,
    /// `base64url:` + the canonical base64url of 64 bytes.
    Signature,
    /// The RFC 9278 URN of an RFC 7638 SHA-256 thumbprint.
    KeyId,
    /// An `allowed_jurisdictions` entry: two upper-case ASCII letters, the
    /// record's `data_residency` pattern. Any other entry could match no
    /// record (QA Q6-09).
    CountryCode,
}

impl Pattern {
    /// The schema's exact `pattern` text for this rule.
    pub fn regex(self) -> &'static str {
        match self {
            Pattern::PackVersion => r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$",
            Pattern::Hash => RecordPattern::Hash.regex(),
            Pattern::Signature => RecordPattern::Signature.regex(),
            Pattern::KeyId => RecordPattern::KeyId.regex(),
            Pattern::CountryCode => RecordPattern::CountryCode.regex(),
        }
    }

    /// Whether `s` matches, by the hand-written matcher.
    pub fn matches(self, s: &str) -> bool {
        match self {
            Pattern::PackVersion => is_dotted_triple(s),
            Pattern::Hash => RecordPattern::Hash.matches(s),
            Pattern::Signature => RecordPattern::Signature.matches(s),
            Pattern::KeyId => RecordPattern::KeyId.matches(s),
            Pattern::CountryCode => RecordPattern::CountryCode.matches(s),
        }
    }
}

/// `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`: three non-empty
/// runs of ASCII digits, separated by two dots, nothing else, and no run
/// longer than one digit starting with `0`.
fn is_dotted_triple(s: &str) -> bool {
    let mut parts = 0usize;
    for part in s.split('.') {
        parts += 1;
        let leading_zero = part.len() > 1 && part.starts_with('0');
        if parts > 3 || part.is_empty() || leading_zero || !part.bytes().all(|b| b.is_ascii_digit())
        {
            return false;
        }
    }
    parts == 3
}

/// One JSON Schema rule, as code. The spelling mirrors
/// `vmr_record::validate::RuleKind` so a reader moving between the two
/// schemas reads one vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `type`: enforced by the parser (the typed structs).
    Type(&'static str),
    /// `required`: enforced by the parser.
    Required(&'static [&'static str]),
    /// `additionalProperties: false`: enforced by the parser.
    Closed,
    /// `const`.
    Const(&'static str),
    /// `enum`.
    Enum(&'static [&'static str]),
    /// `pattern`, with its hand-written matcher.
    Pattern(Pattern),
    /// `minLength`.
    MinLength(u64),
    /// `minItems`.
    MinItems(u64),
    /// `minimum`, for an integer.
    Minimum(u64),
    /// `maximum`, for an integer.
    Maximum(u64),
}

impl Kind {
    /// The JSON Schema keyword.
    pub fn keyword(self) -> &'static str {
        match self {
            Kind::Type(_) => "type",
            Kind::Required(_) => "required",
            Kind::Closed => "additionalProperties",
            Kind::Const(_) => "const",
            Kind::Enum(_) => "enum",
            Kind::Pattern(_) => "pattern",
            Kind::MinLength(_) => "minLength",
            Kind::MinItems(_) => "minItems",
            Kind::Minimum(_) => "minimum",
            Kind::Maximum(_) => "maximum",
        }
    }

    /// The keyword's value, as it appears in the schema.
    pub fn value(self) -> serde_json::Value {
        use serde_json::Value;
        let strings =
            |items: &[&str]| Value::Array(items.iter().map(|s| Value::from(*s)).collect());
        match self {
            Kind::Type(t) | Kind::Const(t) => Value::from(t),
            Kind::Required(items) | Kind::Enum(items) => strings(items),
            Kind::Closed => Value::Bool(false),
            Kind::Pattern(p) => Value::from(p.regex()),
            Kind::MinLength(n) | Kind::MinItems(n) | Kind::Minimum(n) | Kind::Maximum(n) => {
                Value::from(n)
            }
        }
    }

    /// Whether the parser enforces this rule, so [`validate_values`] need
    /// not: `type`, `required`, `additionalProperties`.
    pub fn enforced_by_parser(self) -> bool {
        matches!(self, Kind::Type(_) | Kind::Required(_) | Kind::Closed)
    }
}

/// Where in the document a rule applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The pack document itself; the pointer is from its root.
    Pack,
    /// Every rule object, whatever its `type`; the pointer is from the rule
    /// object (`""` is the object). The schema repeats these in each of the
    /// seven `$defs`, because a closed object cannot be assembled from `allOf`
    /// branches without each branch rejecting the others' members.
    EveryRule,
    /// Only rule objects with this `type`; the pointer is from the object.
    Rule(&'static str),
}

/// A schema rule at a scope and a JSON pointer (`*` = every array element).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaRule {
    /// Which objects it applies to.
    pub scope: Scope,
    /// Where in them.
    pub pointer: &'static str,
    /// What it says.
    pub kind: Kind,
}

const fn r(scope: Scope, pointer: &'static str, kind: Kind) -> SchemaRule {
    SchemaRule { scope, pointer, kind }
}

use Kind::{Closed, Const, Enum, Maximum, MinItems, MinLength, Minimum, Required, Type};
use Scope::{EveryRule, Pack};

const SEVERITIES: &[&str] = &["mandatory", "recommended", "informational"];
const LEVELS: &[&str] = &["self", "software", "hardware"];
/// What `audit_integrity`'s `withheld` may say (QA QR-04).
const WITHHELD: &[&str] = &["fail", "indeterminate"];
/// What `execution_integrity`'s `compare` may name (QA QR-05).
const COMPARED: &[&str] = &["model_hash", "learned_state_hash"];
/// The documents a `documentation_declared` rule may name, as the schema's
/// `enum` writes them: the record's two optional documentation members
/// (task 10.11a).
pub const DOCUMENTS: &[&str] = &["data_governance", "human_oversight"];
const COMMON_REQUIRED: [&str; 5] = ["type", "rule_id", "description", "severity", "reference"];

/// Every rule of `specs/policy-pack-schema/v0.1.json`, in the schema's order.
/// `tests/pack_schema.rs` checks this table against the file in both
/// directions and fails on any keyword the table cannot express, so the
/// schema cannot grow a rule the code lacks.
pub const SCHEMA_RULES: &[SchemaRule] = &[
    r(Pack, "", Type("object")),
    r(
        Pack,
        "",
        Required(&[
            "version",
            "pack_id",
            "pack_version",
            "jurisdiction",
            "description",
            "disclaimer",
            "authority",
            "rules",
        ]),
    ),
    r(Pack, "", Closed),
    r(Pack, "/version", Type("string")),
    r(Pack, "/version", Const("0.1")),
    r(Pack, "/pack_id", Type("string")),
    r(Pack, "/pack_id", MinLength(1)),
    r(Pack, "/pack_version", Type("string")),
    r(Pack, "/pack_version", Kind::Pattern(Pattern::PackVersion)),
    r(Pack, "/jurisdiction", Type("string")),
    r(Pack, "/jurisdiction", MinLength(1)),
    r(Pack, "/description", Type("string")),
    r(Pack, "/description", MinLength(1)),
    r(Pack, "/disclaimer", Type("string")),
    r(Pack, "/disclaimer", MinLength(1)),
    r(Pack, "/authority", Type("object")),
    r(Pack, "/authority", Required(&["authority_id", "authority_name"])),
    r(Pack, "/authority", Closed),
    r(Pack, "/authority/authority_id", Type("string")),
    r(Pack, "/authority/authority_id", MinLength(1)),
    r(Pack, "/authority/authority_name", Type("string")),
    r(Pack, "/authority/authority_name", MinLength(1)),
    r(Pack, "/rules", Type("array")),
    r(Pack, "/rules", MinItems(1)),
    r(Pack, "/signature", Type("object")),
    r(
        Pack,
        "/signature",
        Required(&["algorithm", "signature", "signed_payload_hash", "signing_key_id"]),
    ),
    r(Pack, "/signature", Closed),
    r(Pack, "/signature/algorithm", Type("string")),
    r(Pack, "/signature/algorithm", Const("ES256")),
    r(Pack, "/signature/signature", Type("string")),
    r(Pack, "/signature/signature", Kind::Pattern(Pattern::Signature)),
    r(Pack, "/signature/signed_payload_hash", Type("string")),
    r(Pack, "/signature/signed_payload_hash", Kind::Pattern(Pattern::Hash)),
    r(Pack, "/signature/signing_key_id", Type("string")),
    r(Pack, "/signature/signing_key_id", Kind::Pattern(Pattern::KeyId)),
    // Every rule object, in each of the seven $defs.
    r(EveryRule, "", Type("object")),
    r(EveryRule, "", Closed),
    r(EveryRule, "/type", Type("string")),
    r(EveryRule, "/rule_id", Type("string")),
    r(EveryRule, "/rule_id", MinLength(1)),
    r(EveryRule, "/description", Type("string")),
    r(EveryRule, "/description", MinLength(1)),
    r(EveryRule, "/severity", Type("string")),
    r(EveryRule, "/severity", Enum(SEVERITIES)),
    r(EveryRule, "/reference", Type("string")),
    r(EveryRule, "/reference", MinLength(1)),
    // data_residency
    r(
        Scope::Rule("data_residency"),
        "",
        Required(&[
            "type",
            "rule_id",
            "description",
            "severity",
            "reference",
            "allowed_jurisdictions",
        ]),
    ),
    r(Scope::Rule("data_residency"), "/type", Const("data_residency")),
    r(Scope::Rule("data_residency"), "/allowed_jurisdictions", Type("array")),
    r(Scope::Rule("data_residency"), "/allowed_jurisdictions", MinItems(1)),
    r(Scope::Rule("data_residency"), "/allowed_jurisdictions/*", Type("string")),
    r(Scope::Rule("data_residency"), "/allowed_jurisdictions/*", MinLength(1)),
    r(
        Scope::Rule("data_residency"),
        "/allowed_jurisdictions/*",
        Kind::Pattern(Pattern::CountryCode),
    ),
    // source_screening
    r(
        Scope::Rule("source_screening"),
        "",
        Required(&["type", "rule_id", "description", "severity", "reference", "restricted_list"]),
    ),
    r(Scope::Rule("source_screening"), "/type", Const("source_screening")),
    r(Scope::Rule("source_screening"), "/restricted_list", Type("array")),
    r(Scope::Rule("source_screening"), "/restricted_list", MinItems(1)),
    r(Scope::Rule("source_screening"), "/restricted_list/*", Type("string")),
    r(Scope::Rule("source_screening"), "/restricted_list/*", MinLength(1)),
    // export_control
    r(Scope::Rule("export_control"), "", Required(&COMMON_REQUIRED)),
    r(Scope::Rule("export_control"), "/type", Const("export_control")),
    r(Scope::Rule("export_control"), "/require_air_gapped", Type("boolean")),
    r(Scope::Rule("export_control"), "/require_egress_denied", Type("boolean")),
    // audit_integrity
    r(Scope::Rule("audit_integrity"), "", Required(&COMMON_REQUIRED)),
    r(Scope::Rule("audit_integrity"), "/type", Const("audit_integrity")),
    r(Scope::Rule("audit_integrity"), "/minimum_chain_length", Type("integer")),
    r(Scope::Rule("audit_integrity"), "/minimum_chain_length", Minimum(0)),
    r(Scope::Rule("audit_integrity"), "/minimum_chain_length", Maximum(MAX_SAFE_INTEGER)),
    r(Scope::Rule("audit_integrity"), "/require_tamper_evident", Type("boolean")),
    r(Scope::Rule("audit_integrity"), "/require_input_committed", Type("boolean")),
    r(Scope::Rule("audit_integrity"), "/require_ordered_record", Type("boolean")),
    r(Scope::Rule("audit_integrity"), "/require_verified_lineage", Type("boolean")),
    r(Scope::Rule("audit_integrity"), "/withheld", Type("string")),
    r(Scope::Rule("audit_integrity"), "/withheld", Enum(WITHHELD)),
    // execution_integrity
    r(Scope::Rule("execution_integrity"), "", Required(&COMMON_REQUIRED)),
    r(Scope::Rule("execution_integrity"), "/type", Const("execution_integrity")),
    r(
        Scope::Rule("execution_integrity"),
        "/require_learned_state_components",
        Type("boolean"),
    ),
    r(Scope::Rule("execution_integrity"), "/require_environment_pinned", Type("boolean")),
    r(Scope::Rule("execution_integrity"), "/require_tee", Type("boolean")),
    r(Scope::Rule("execution_integrity"), "/require_state_kept", Type("boolean")),
    r(Scope::Rule("execution_integrity"), "/compare", Type("string")),
    r(Scope::Rule("execution_integrity"), "/compare", Enum(COMPARED)),
    // attestation_level
    r(
        Scope::Rule("attestation_level"),
        "",
        Required(&["type", "rule_id", "description", "severity", "reference", "minimum_level"]),
    ),
    r(Scope::Rule("attestation_level"), "/type", Const("attestation_level")),
    r(Scope::Rule("attestation_level"), "/minimum_level", Type("string")),
    r(Scope::Rule("attestation_level"), "/minimum_level", Enum(LEVELS)),
    // documentation_declared (task 10.11a, D11-4)
    r(
        Scope::Rule("documentation_declared"),
        "",
        Required(&["type", "rule_id", "description", "severity", "reference", "document"]),
    ),
    r(Scope::Rule("documentation_declared"), "/type", Const("documentation_declared")),
    r(Scope::Rule("documentation_declared"), "/document", Type("string")),
    r(Scope::Rule("documentation_declared"), "/document", Enum(DOCUMENTS)),
];

/// The attestation levels, weakest first, as the schema's `enum` writes them.
pub const ATTESTATION_LEVELS: &[&str] = LEVELS;

/// Check every value rule of the schema against a parsed pack. The parser
/// has already enforced the `type`, `required` and `additionalProperties`
/// rules (and `minimum` 0, on a `u64`), so what is left is `const`, `enum`,
/// `pattern`, `minLength`, `minItems` and `maximum`. The first violation is
/// returned, naming its JSON pointer.
pub fn validate_values(pack: &PolicyPack) -> Result<(), Error> {
    let non_empty = |pointer: String, value: &str| -> Result<(), FormatViolation> {
        if value.is_empty() {
            Err(FormatViolation::new(pointer, "minLength", "must not be empty".to_string()))
        } else {
            Ok(())
        }
    };
    let pattern = |pointer: String, p: Pattern, value: &str| -> Result<(), FormatViolation> {
        if p.matches(value) {
            Ok(())
        } else {
            Err(FormatViolation::new(
                pointer,
                "pattern",
                format!("{} does not match {}", quote(value), p.regex()),
            ))
        }
    };

    if pack.version != crate::PACK_FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(pack.version.clone()));
    }
    non_empty("/pack_id".into(), &pack.pack_id)?;
    pattern("/pack_version".into(), Pattern::PackVersion, &pack.pack_version)?;
    non_empty("/jurisdiction".into(), &pack.jurisdiction)?;
    non_empty("/description".into(), &pack.description)?;
    non_empty("/disclaimer".into(), &pack.disclaimer)?;
    non_empty("/authority/authority_id".into(), &pack.authority.authority_id)?;
    non_empty("/authority/authority_name".into(), &pack.authority.authority_name)?;

    if pack.rules.is_empty() {
        return Err(Error::PackEmpty);
    }
    for (i, rule) in pack.rules.iter().enumerate() {
        let at = |member: &str| format!("/rules/{i}{member}");
        let c = rule.common();
        non_empty(at("/rule_id"), c.rule_id)?;
        non_empty(at("/description"), c.description)?;
        non_empty(at("/reference"), c.reference)?;
        match rule {
            Rule::DataResidency(v) => {
                if v.allowed_jurisdictions.is_empty() {
                    return Err(items_needed(&at("/allowed_jurisdictions")));
                }
                for (j, s) in v.allowed_jurisdictions.iter().enumerate() {
                    let pointer = at(&format!("/allowed_jurisdictions/{j}"));
                    non_empty(pointer.clone(), s)?;
                    pattern(pointer, Pattern::CountryCode, s)?;
                }
            }
            Rule::SourceScreening(v) => {
                if v.restricted_list.is_empty() {
                    return Err(items_needed(&at("/restricted_list")));
                }
                for (j, s) in v.restricted_list.iter().enumerate() {
                    non_empty(at(&format!("/restricted_list/{j}")), s)?;
                }
            }
            Rule::AttestationLevel(v) => {
                if !ATTESTATION_LEVELS.contains(&v.minimum_level.as_str()) {
                    return Err(FormatViolation::new(
                        at("/minimum_level"),
                        "enum",
                        format!(
                            "{} is not one of {:?}",
                            quote(&v.minimum_level),
                            ATTESTATION_LEVELS
                        ),
                    )
                    .into());
                }
            }
            Rule::AuditIntegrity(v) => {
                // A pack is signed over its JCS form, which writes a number
                // as the double it denotes: above 2^53 - 1 two different
                // packs would share one signed payload (QA Q6-03).
                if v.minimum_chain_length > MAX_SAFE_INTEGER {
                    return Err(FormatViolation::new(
                        at("/minimum_chain_length"),
                        "maximum",
                        format!(
                            "{} is above {MAX_SAFE_INTEGER} (2^53 - 1), the largest integer a \
                             signed pack writes exactly",
                            v.minimum_chain_length
                        ),
                    )
                    .into());
                }
            }
            Rule::DocumentationDeclared(v) => {
                if !DOCUMENTS.contains(&v.document.as_str()) {
                    return Err(FormatViolation::new(
                        at("/document"),
                        "enum",
                        format!("{} is not one of {:?}", quote(&v.document), DOCUMENTS),
                    )
                    .into());
                }
            }
            Rule::ExportControl(_) | Rule::ExecutionIntegrity(_) => {}
        }
    }

    if let Some(s) = &pack.signature {
        pattern("/signature/signature".into(), Pattern::Signature, &s.signature)?;
        pattern("/signature/signed_payload_hash".into(), Pattern::Hash, &s.signed_payload_hash)?;
        pattern("/signature/signing_key_id".into(), Pattern::KeyId, &s.signing_key_id)?;
        if s.algorithm != "ES256" {
            return Err(FormatViolation::new(
                "/signature/algorithm",
                "const",
                format!("{} is not \"ES256\"", quote(&s.algorithm)),
            )
            .into());
        }
    }
    Ok(())
}

fn items_needed(pointer: &str) -> Error {
    FormatViolation::new(pointer.to_string(), "minItems", "must list at least one entry".to_string())
        .into()
}

/// `value` for an error message or a rule's detail: at most 64 characters,
/// Rust-escaped, and with nothing a terminal acts on or hides left raw
/// ([`crate::error::quoted`], QA Q6-10).
pub(crate) fn quote(value: &str) -> String {
    const MAX: usize = 64;
    let mut cut: String = value.chars().take(MAX).collect();
    if cut.len() < value.len() {
        cut.push('…');
    }
    crate::error::quoted(&cut)
}
