//! The policy-pack types: the header, the authority, the seven rule kinds.
// ============================================================================
//  pack.rs — the policy pack format v0.1
//
//  A pack is a JSON document with a header, an authority, a disclaimer, a
//  list of rules and an optional signature. Any authority - a regulator, a
//  standards body, an enterprise, an industry consortium - authors one by
//  writing JSON. No code generation, no plugin system, no external tooling.
//
//  Strictness (P6-9): every struct is `deny_unknown_fields`, so a constraint
//  this build does not understand is refused instead of ignored; an unknown
//  `type` fails when the rule is read, for the same reason. A rule is read
//  without a buffer (QA QT-01; `Rule`'s `Deserialize`), so the loader's strict
//  reader (vmr_record::strict_json) refuses an object written as the array
//  of its values at every level, a rule included. The common rule
//  members are repeated in each rule struct rather than `#[serde(flatten)]`ed
//  into a shared one, because serde cannot combine `flatten` with
//  `deny_unknown_fields`, and strictness is the point (a departure from the
//  §5 sketch, recorded in the Phase 6 handoff). `RuleCommon` survives as the
//  borrowed view `Rule::common` returns.
//
//  The normative structure is `specs/policy-pack-schema/v0.1.json`;
//  `crate::schema::SCHEMA_RULES` is that schema as code, and
//  `tests/pack_schema.rs` keeps the two equal in both directions.
// ============================================================================

use serde::Deserialize;

/// Deserialize an optional member that, when present, must have its type:
/// absent → `None` (with `#[serde(default)]`), `null` → an error. Optional
/// members are omitted, never `null` — the record's rule (spec §2.3).
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// A policy pack, as parsed. The document it was parsed from is what an
/// authority signs, so a loaded pack keeps both ([`crate::LoadedPack`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPack {
    /// The pack FORMAT version; `"0.1"` in this revision.
    pub version: String,
    /// The pack's identifier, e.g. `khalm-reading-eu-ai-act-2026`. It is what a record's
    /// `deployment_context.policy_pack_id` and `policy_compliance` name.
    pub pack_id: String,
    /// The pack's own semantic version, e.g. `1.0.0`.
    pub pack_version: String,
    /// The regime this pack encodes, free-form: `eu`, `us-nist`,
    /// `iso-42001`, `c2pa`, `trace`, `enterprise:acme-corp`.
    pub jurisdiction: String,
    /// What the pack is, in one human-readable line.
    pub description: String,
    /// What the pack is NOT (P6-4): a reference pack is a reference
    /// implementation of this format, not legal advice.
    pub disclaimer: String,
    /// Who authored it.
    pub authority: Authority,
    /// The rules, at least one, with distinct `rule_id`s.
    pub rules: Vec<Rule>,
    /// The authority's signature over the document (P6-8). Optional in v0.1:
    /// an unsigned pack loads and evaluates, and a caller that requires a
    /// signature asks for one (`crate::signing::verify_pack_signature`).
    #[serde(default, deserialize_with = "present")]
    pub signature: Option<PackSignature>,
}

/// The authority that authored a pack.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    /// The authority's identifier: a DID or an organization slug.
    pub authority_id: String,
    /// Its human-readable name.
    pub authority_name: String,
}

/// How much a failure of a rule weighs on the pack's overall status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A failure makes the whole evaluation fail; an indeterminate result
    /// makes it indeterminate.
    Mandatory,
    /// Reported, but it does not move the overall status.
    Recommended,
    /// Reported for the record only.
    Informational,
}

/// What a declared `training_input_disclosure` (record format §8.4) does to
/// `audit_integrity`'s two commitment requirements (QA QR-04, the owner,
/// 2026-09-16).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Withheld {
    /// The requirement fails: withholding is a signed statement that nothing
    /// is committed (task 10.12a, D12a-5). The default, and what the five
    /// reference packs ask for.
    #[default]
    Fail,
    /// The requirement is indeterminate: the record said it withholds, and a
    /// pack that tolerates withholding does not read that as a wrong answer.
    Indeterminate,
}

impl Withheld {
    /// The word used in a pack.
    pub fn id(self) -> &'static str {
        match self {
            Withheld::Fail => "fail",
            Withheld::Indeterminate => "indeterminate",
        }
    }
}

/// Which member of `model_identity` `require_state_kept` compares across a
/// lineage step (QA QR-05, the owner, 2026-09-16).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateComparison {
    /// `/model_identity/model_hash`, the model's identity (record format
    /// §7.3): the default.
    #[default]
    ModelHash,
    /// `/model_identity/learned_state_hash`, the named-set digest of the
    /// components, which a holder of the components can recompute (record
    /// format §7.3). It follows each issuer's choice of components, so two
    /// issuers describing one model can differ in it.
    LearnedStateHash,
}

impl StateComparison {
    /// The word used in a pack.
    pub fn id(self) -> &'static str {
        match self {
            StateComparison::ModelHash => "model_hash",
            StateComparison::LearnedStateHash => "learned_state_hash",
        }
    }

    /// The JSON pointer the comparison reads, in the record and in the
    /// verified immediate predecessor.
    pub fn pointer(self) -> &'static str {
        match self {
            StateComparison::ModelHash => crate::evidence::pointer::MODEL_HASH,
            StateComparison::LearnedStateHash => crate::evidence::pointer::LEARNED_STATE_HASH,
        }
    }
}

impl Severity {
    /// The word used in the pack and in an evaluation.
    pub fn id(self) -> &'static str {
        match self {
            Severity::Mandatory => "mandatory",
            Severity::Recommended => "recommended",
            Severity::Informational => "informational",
        }
    }

    /// Every severity, in the schema's order.
    pub const ALL: [Severity; 3] =
        [Severity::Mandatory, Severity::Recommended, Severity::Informational];
}

/// The members every rule carries, borrowed from whichever rule it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleCommon<'a> {
    /// The rule's identifier, unique within its pack.
    pub rule_id: &'a str,
    /// What the rule asks, in one human-readable line.
    pub description: &'a str,
    /// How a failure weighs.
    pub severity: Severity,
    /// The clause this rule encodes, e.g. `EU AI Act Art. 12(1)` (P6-4). A
    /// rule that cannot name a clause does not belong in a reference pack.
    pub reference: &'a str,
}

/// A policy rule. The JSON member `type` selects the kind.
///
/// Read member by member, with no buffer (QA QT-01). serde's derive for an
/// internally tagged enum buffers the rule through `deserialize_any` and reads
/// the variant's struct from that buffer, which also takes a rule written as
/// an array, its tag first. The loader's strict reader
/// (`vmr_record::strict_json`) refuses any array read that way, so with the
/// derive every pack holding a list would be refused. Every rule type's
/// member names are distinct, so one closed struct of all of them
/// (`RuleMembers`) reads the object, and only then is the `type` looked up
/// and every member checked against it. It accepts and refuses the texts the
/// derive did, except an array, which it refuses under the strict reader, and
/// a refused text keeps the derive's refusal id (the format document's §3).
/// Its errors are serde's `unknown_variant`, `unknown_field` and
/// `missing_field`, but not always in the derive's words or at the derive's
/// position: a rule that breaks more than one rule of the format may be
/// refused naming another member. Wording is not part of v0.1 (§3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// The declared training-input residency is in an allowed set.
    DataResidency(DataResidencyRule),
    /// Neither declared training-input origin is on a restricted list.
    SourceScreening(SourceScreeningRule),
    /// The declared inference boundary satisfies an export requirement.
    ExportControl(ExportControlRule),
    /// The audit trail is long enough and tamper-evident.
    AuditIntegrity(AuditIntegrityRule),
    /// What ran is pinned: learned state, environment, TEE.
    ExecutionIntegrity(ExecutionIntegrityRule),
    /// The issuer attests at least at a given level.
    AttestationLevel(AttestationLevelRule),
    /// The record pins, by hash, the document the rule names (task
    /// 10.11a).
    DocumentationDeclared(DocumentationDeclaredRule),
}

/// Every rule type's `type` string, in the schema's order.
pub const RULE_TYPES: [&str; 7] = [
    "data_residency",
    "source_screening",
    "export_control",
    "audit_integrity",
    "execution_integrity",
    "attestation_level",
    "documentation_declared",
];

macro_rules! common_view {
    ($r:expr) => {
        RuleCommon {
            rule_id: &$r.rule_id,
            description: &$r.description,
            severity: $r.severity,
            reference: &$r.reference,
        }
    };
}

impl Rule {
    /// The members every rule carries.
    pub fn common(&self) -> RuleCommon<'_> {
        match self {
            Rule::DataResidency(r) => common_view!(r),
            Rule::SourceScreening(r) => common_view!(r),
            Rule::ExportControl(r) => common_view!(r),
            Rule::AuditIntegrity(r) => common_view!(r),
            Rule::ExecutionIntegrity(r) => common_view!(r),
            Rule::AttestationLevel(r) => common_view!(r),
            Rule::DocumentationDeclared(r) => common_view!(r),
        }
    }

    /// This rule's `type` string, one of [`RULE_TYPES`].
    pub fn rule_type(&self) -> &'static str {
        match self {
            Rule::DataResidency(_) => "data_residency",
            Rule::SourceScreening(_) => "source_screening",
            Rule::ExportControl(_) => "export_control",
            Rule::AuditIntegrity(_) => "audit_integrity",
            Rule::ExecutionIntegrity(_) => "execution_integrity",
            Rule::AttestationLevel(_) => "attestation_level",
            Rule::DocumentationDeclared(_) => "documentation_declared",
        }
    }

    /// The rule's identifier (shorthand for `common().rule_id`).
    pub fn rule_id(&self) -> &str {
        self.common().rule_id
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        RuleMembers::deserialize(deserializer)?.into_rule()
    }
}

/// Every member any rule type has, each optional but `type`: what a rule object
/// may hold before its `type` says which members it has. A closed struct, so
/// an unknown or duplicate member, or a `null`, is refused as it is read. The
/// four common members come first, then each type's own, in the schema's
/// order.
#[derive(Deserialize)]
#[serde(rename = "Rule", deny_unknown_fields)]
struct RuleMembers {
    #[serde(rename = "type")]
    rule_type: String,
    #[serde(default, deserialize_with = "present")]
    rule_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    description: Option<String>,
    #[serde(default, deserialize_with = "present")]
    severity: Option<Severity>,
    #[serde(default, deserialize_with = "present")]
    reference: Option<String>,
    #[serde(default, deserialize_with = "present")]
    allowed_jurisdictions: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    restricted_list: Option<Vec<String>>,
    #[serde(default, deserialize_with = "present")]
    require_air_gapped: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_egress_denied: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    minimum_chain_length: Option<u64>,
    #[serde(default, deserialize_with = "present")]
    require_tamper_evident: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_input_committed: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_ordered_record: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_verified_lineage: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    withheld: Option<Withheld>,
    #[serde(default, deserialize_with = "present")]
    require_learned_state_components: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_environment_pinned: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_tee: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    require_state_kept: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    compare: Option<StateComparison>,
    #[serde(default, deserialize_with = "present")]
    minimum_level: Option<String>,
    #[serde(default, deserialize_with = "present")]
    document: Option<String>,
}

/// A member a rule type requires: present, or serde's own `missing field`.
fn required<T, E: serde::de::Error>(value: Option<T>, name: &'static str) -> Result<T, E> {
    value.ok_or_else(|| E::missing_field(name))
}

impl RuleMembers {
    /// The rule `type` names, holding exactly its type's members. In the order
    /// the derive of each rule struct reports: an unknown `type`; a member of
    /// another type, as an unknown field of this one; a missing member, the
    /// common four first.
    fn into_rule<E: serde::de::Error>(self) -> Result<Rule, E> {
        // Each type's members in its struct's declaration order: the list
        // serde's derive names in an `unknown field` message.
        let fields: &'static [&'static str] = match self.rule_type.as_str() {
            "data_residency" => &["rule_id", "description", "severity", "reference", "allowed_jurisdictions"],
            "source_screening" => &["rule_id", "description", "severity", "reference", "restricted_list"],
            "export_control" => {
                &["rule_id", "description", "severity", "reference", "require_air_gapped", "require_egress_denied"]
            }
            "audit_integrity" => &[
                "rule_id",
                "description",
                "severity",
                "reference",
                "minimum_chain_length",
                "require_tamper_evident",
                "require_input_committed",
                "require_ordered_record",
                "require_verified_lineage",
                "withheld",
            ],
            "execution_integrity" => &[
                "rule_id",
                "description",
                "severity",
                "reference",
                "require_learned_state_components",
                "require_environment_pinned",
                "require_tee",
                "require_state_kept",
                "compare",
            ],
            "attestation_level" => &["rule_id", "description", "severity", "reference", "minimum_level"],
            "documentation_declared" => &["rule_id", "description", "severity", "reference", "document"],
            other => return Err(E::unknown_variant(other, &RULE_TYPES)),
        };
        let present = [
            ("allowed_jurisdictions", self.allowed_jurisdictions.is_some()),
            ("restricted_list", self.restricted_list.is_some()),
            ("require_air_gapped", self.require_air_gapped.is_some()),
            ("require_egress_denied", self.require_egress_denied.is_some()),
            ("minimum_chain_length", self.minimum_chain_length.is_some()),
            ("require_tamper_evident", self.require_tamper_evident.is_some()),
            ("require_input_committed", self.require_input_committed.is_some()),
            ("require_ordered_record", self.require_ordered_record.is_some()),
            ("require_verified_lineage", self.require_verified_lineage.is_some()),
            ("withheld", self.withheld.is_some()),
            ("require_learned_state_components", self.require_learned_state_components.is_some()),
            ("require_environment_pinned", self.require_environment_pinned.is_some()),
            ("require_tee", self.require_tee.is_some()),
            ("require_state_kept", self.require_state_kept.is_some()),
            ("compare", self.compare.is_some()),
            ("minimum_level", self.minimum_level.is_some()),
            ("document", self.document.is_some()),
        ];
        if let Some((foreign, _)) = present.iter().find(|(name, is_present)| *is_present && !fields.contains(name)) {
            return Err(E::unknown_field(foreign, fields));
        }
        let rule_id = required(self.rule_id, "rule_id")?;
        let description = required(self.description, "description")?;
        let severity = required(self.severity, "severity")?;
        let reference = required(self.reference, "reference")?;
        Ok(match self.rule_type.as_str() {
            "data_residency" => Rule::DataResidency(DataResidencyRule {
                rule_id,
                description,
                severity,
                reference,
                allowed_jurisdictions: required(self.allowed_jurisdictions, "allowed_jurisdictions")?,
            }),
            "source_screening" => Rule::SourceScreening(SourceScreeningRule {
                rule_id,
                description,
                severity,
                reference,
                restricted_list: required(self.restricted_list, "restricted_list")?,
            }),
            "export_control" => Rule::ExportControl(ExportControlRule {
                rule_id,
                description,
                severity,
                reference,
                require_air_gapped: self.require_air_gapped.unwrap_or_default(),
                require_egress_denied: self.require_egress_denied.unwrap_or_default(),
            }),
            "audit_integrity" => Rule::AuditIntegrity(AuditIntegrityRule {
                rule_id,
                description,
                severity,
                reference,
                minimum_chain_length: self.minimum_chain_length.unwrap_or_default(),
                require_tamper_evident: self.require_tamper_evident.unwrap_or_default(),
                require_input_committed: self.require_input_committed.unwrap_or_default(),
                require_ordered_record: self.require_ordered_record.unwrap_or_default(),
                require_verified_lineage: self.require_verified_lineage.unwrap_or_default(),
                withheld: self.withheld.unwrap_or_default(),
            }),
            "execution_integrity" => Rule::ExecutionIntegrity(ExecutionIntegrityRule {
                rule_id,
                description,
                severity,
                reference,
                require_learned_state_components: self.require_learned_state_components.unwrap_or_default(),
                require_environment_pinned: self.require_environment_pinned.unwrap_or_default(),
                require_tee: self.require_tee.unwrap_or_default(),
                require_state_kept: self.require_state_kept.unwrap_or_default(),
                compare: self.compare.unwrap_or_default(),
            }),
            "attestation_level" => Rule::AttestationLevel(AttestationLevelRule {
                rule_id,
                description,
                severity,
                reference,
                minimum_level: required(self.minimum_level, "minimum_level")?,
            }),
            "documentation_declared" => Rule::DocumentationDeclared(DocumentationDeclaredRule {
                rule_id,
                description,
                severity,
                reference,
                document: required(self.document, "document")?,
            }),
            other => return Err(E::unknown_variant(other, &RULE_TYPES)),
        })
    }
}

/// Training data must come from one of `allowed_jurisdictions`.
///
/// Reads `/learning_provenance/training_input_provenance/data_residency`
/// (P6-3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataResidencyRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// The country codes the declaration may name. At least one, and each
    /// two upper-case ASCII letters, as a record's `data_residency` is
    /// (the schema's pattern): an entry of any other shape could match no
    /// record.
    pub allowed_jurisdictions: Vec<String>,
}

/// Neither declared origin of the training data may be restricted.
///
/// Reads `/learning_provenance/training_input_provenance/source_type` and
/// `.../data_residency` (P6-3). `source_description` is free text and is
/// never matched.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceScreeningRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// The source types and country codes that are not acceptable. At least
    /// one: a rule restricting nothing could never fail. An entry matches
    /// only when it equals the declared value exactly, case included: `cn`
    /// never matches a record's `CN`.
    pub restricted_list: Vec<String>,
}

/// The deployment boundary must satisfy an export requirement.
///
/// Reads `/deployment_context/inference_boundary/type`, `.../egress_allowed`
/// and `.../allowed_egress_destinations` (P6-3). `require_key_gated_egress`
/// of the §5 sketch is deleted: the record describes the boundary, not the
/// key that gates it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportControlRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// The boundary `type` must be `air-gapped`.
    #[serde(default)]
    pub require_air_gapped: bool,
    /// `egress_allowed` must be `false` AND `allowed_egress_destinations`
    /// must be empty: a denial with an exception list is not a denial.
    #[serde(default)]
    pub require_egress_denied: bool,
}

/// The audit trail must be long enough, tamper-evident, committed, ordered
/// and verified.
///
/// Reads `/lineage/lineage_chain_length`, `/lineage/previous_record_hash`
/// and `/learning_provenance/training_input_merkle_root` (P6-3), and
/// `training_input_count`, the training and collection times and
/// `/issued_at`, plus the verified lineage when there is context (P6-17),
/// and `training_input_disclosure` (task 10.12a).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditIntegrityRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// `lineage.lineage_chain_length` must be at least this. At most
    /// 2^53 − 1 (`vmr_record::canonical::MAX_SAFE_INTEGER`, the schema's
    /// `maximum`): a pack is signed over its JCS form, which writes a larger
    /// integer rounded, and no record's chain is longer.
    #[serde(default)]
    pub minimum_chain_length: u64,
    /// The training input must be committed by a parseable Merkle root, and
    /// a record with predecessors must carry a parseable
    /// `previous_record_hash` (P6-3). A declared `training_input_disclosure`
    /// fails it (task 10.12a).
    #[serde(default)]
    pub require_tamper_evident: bool,
    /// The training input must be committed to something: a
    /// `training_input_count` of at least 1, over a Merkle root that is not
    /// the empty tree's (P6-17). A declared `training_input_disclosure`
    /// fails it (task 10.12a).
    #[serde(default)]
    pub require_input_committed: bool,
    /// The record's own times must be in order: training ends after it
    /// starts and not after `issued_at`; the collection period ends after it
    /// starts (P6-17; the reference builder's QA P5-08 checks).
    #[serde(default)]
    pub require_ordered_record: bool,
    /// Verification must have reached the record's initial record:
    /// Indeterminate otherwise, and never a failure, so a rule needs another
    /// requirement beside it (P6-17).
    #[serde(default)]
    pub require_verified_lineage: bool,
    /// What a declared `training_input_disclosure` (record format §8.4) does
    /// to `require_tamper_evident` and `require_input_committed`: `fail` by
    /// default, today's behaviour and the five reference packs'; a pack that
    /// tolerates withholding asks for `indeterminate` (QA QR-04, the owner,
    /// 2026-09-16). It moves neither the lineage-linkage check nor any other
    /// step.
    #[serde(default)]
    pub withheld: Withheld,
}

/// What ran must be pinned by hashes the reader can check.
///
/// Reads `/model_identity/learned_state_hash`,
/// `/model_identity/learned_state_components` and
/// `/learning_provenance/training_environment/training_software`,
/// `.../software_hash`, `.../tee_measurement` (P6-3), `/lineage/lineage_type`
/// (P6-17) and `/model_identity/model_hash` (task 10.12a).
/// `minimum_test_vectors` and `require_reference_suite` of the §5 sketch are
/// deleted: the record carries no test-vector count.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionIntegrityRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// `learned_state_hash` and every declared component must carry a
    /// parseable `sha256:` hash, and every component a positive size.
    #[serde(default)]
    pub require_learned_state_components: bool,
    /// `training_software` and `software_hash` must both be declared and
    /// non-empty; an empty one is a declared absence and fails (P6-17, E2).
    #[serde(default)]
    pub require_environment_pinned: bool,
    /// `tee_measurement` must be declared and non-empty; an empty one fails
    /// (P6-17, E2).
    #[serde(default)]
    pub require_tee: bool,
    /// A `deployment` or `policy-change` record must keep the model of its
    /// verified immediate predecessor: the same `model_hash` (P6-17; task
    /// 10.12a).
    #[serde(default)]
    pub require_state_kept: bool,
    /// Which member `require_state_kept` compares: `model_hash`, the model's
    /// identity, by default, or `learned_state_hash`, which a holder of the
    /// components recomputes (QA QR-05, the owner, 2026-09-16). It is read
    /// only when `require_state_kept` is true.
    #[serde(default)]
    pub compare: StateComparison,
}

/// The issuer must attest at least at `minimum_level`.
///
/// Reads `/issuer/attestation_level` (P6-3), ordered `self`, `software`,
/// `hardware` from weakest to strongest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationLevelRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// One of `self`, `software`, `hardware`.
    pub minimum_level: String,
}

/// The record must pin, by hash, the document `document` names (task
/// 10.11a, `docs/dev/task-10.11a.md` D11-4).
///
/// Reads `/data_governance` and `/human_oversight`, both of them whichever
/// `document` names (a rule type's read list is fixed, P6-2). Unlike every
/// other type, an absent member fails: the two members are optional, so
/// absence is how a record declares that it pins no such document. A pass
/// shows which document the issuer relied on, not that it exists or is
/// adequate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationDeclaredRule {
    /// See [`RuleCommon::rule_id`].
    pub rule_id: String,
    /// See [`RuleCommon::description`].
    pub description: String,
    /// See [`RuleCommon::severity`].
    pub severity: Severity,
    /// See [`RuleCommon::reference`].
    pub reference: String,
    /// `data_governance` or `human_oversight` (the schema's enum,
    /// [`crate::schema::DOCUMENTS`]).
    pub document: String,
}

/// An authority's signature over a pack document (P6-8).
///
/// The algorithm, the encoding and the key id are the record's
/// (`specs/record-format-v0.1.md` §4, §5), so one key management serves
/// both. What is signed differs: a pack has no COSE envelope, so the signed
/// bytes are the JCS form of the document with `/signature` removed
/// (`crate::signing`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSignature {
    /// `ES256`.
    pub algorithm: String,
    /// `base64url:` + the 64-byte `r ‖ s`, low-s, as the record writes it.
    pub signature: String,
    /// The SHA-256 of the signed bytes, `sha256:<hex>`.
    pub signed_payload_hash: String,
    /// The RFC 7638 thumbprint URN of the signing key.
    pub signing_key_id: String,
}
