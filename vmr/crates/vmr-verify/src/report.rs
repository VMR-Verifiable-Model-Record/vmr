//! The verification report: every check, in order, and the verdict.
// ============================================================================
//  report.rs — VerificationReport (docs/dev/phase4.md §3.4)
//
//  The report is the whole answer; a CLI prints nothing it does not contain.
//  Deterministic by construction: serde derive, fields in declaration order,
//  Vecs in check order, no maps, no floats — the same inputs give the same
//  JSON bytes on every machine (Law 1). Record-derived text appears in two
//  places only: the `record` section (the claims, verbatim, as JSON
//  strings) and `detail` strings, which quote at most 64 characters of any
//  value, through `display_safe`.
// ============================================================================

use serde::Serialize;

/// The version of the report layout.
pub const REPORT_VERSION: &str = "0.1";

/// The stable check vocabulary (`specs/record-format-v0.1.md` §6.2). The
/// verification vectors name the first failing check by these ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum CheckId {
    /// 1: the input is at most 1 MiB.
    #[serde(rename = "input.size")]
    InputSize,
    /// 2: the input is in the form it is verified as.
    #[serde(rename = "input.form")]
    InputForm,
    /// 3j: UTF-8, RFC 8259 JSON, nothing after the value.
    #[serde(rename = "json.syntax")]
    JsonSyntax,
    /// 4j: exactly the schema's members and JSON types.
    #[serde(rename = "json.structure")]
    JsonStructure,
    /// 3c: one CBOR COSE_Sign1 array, nothing after it.
    #[serde(rename = "cose.structure")]
    CoseStructure,
    /// 4c: protected header exactly `{1: -7, 4: kid}`.
    #[serde(rename = "cose.protected_header")]
    CoseProtectedHeader,
    /// 5c: the empty unprotected header.
    #[serde(rename = "cose.unprotected_header")]
    CoseUnprotectedHeader,
    /// 6c: a 64-byte `r ‖ s` signature.
    #[serde(rename = "cose.signature_encoding")]
    CoseSignatureEncoding,
    /// 7c: the payload is the canonical signed payload of a record.
    #[serde(rename = "cose.payload")]
    CosePayload,
    /// 8c: the envelope is the canonical envelope.
    #[serde(rename = "cose.canonical")]
    CoseCanonical,
    /// 5: every value rule of the schema outside `/signature`.
    #[serde(rename = "format.schema")]
    FormatSchema,
    /// 6: the learned-state consistency rules (spec §7).
    #[serde(rename = "format.consistency")]
    FormatConsistency,
    /// 7: `signature.algorithm` is `ES256`.
    #[serde(rename = "signature.algorithm")]
    SignatureAlgorithm,
    /// 8: the `signature` field's encoding.
    #[serde(rename = "signature.encoding")]
    SignatureEncoding,
    /// 9: the signature is low-s.
    #[serde(rename = "signature.low_s")]
    SignatureLowS,
    /// 10: `signed_payload_hash` is the recomputed hash.
    #[serde(rename = "signature.payload_hash")]
    SignaturePayloadHash,
    /// 11: the record is self-consistent about its key.
    #[serde(rename = "key.binding")]
    KeyBinding,
    /// 12: the trust store knows the signing key.
    #[serde(rename = "trust.key_known")]
    TrustKeyKnown,
    /// 13: the signature verifies under the trusted key.
    #[serde(rename = "signature.valid")]
    SignatureValid,
    /// 14: the trusted key speaks for this issuer.
    #[serde(rename = "trust.issuer")]
    TrustIssuer,
    /// 15: the trusted key is not revoked.
    #[serde(rename = "trust.key_not_revoked")]
    TrustKeyNotRevoked,
    /// 16: `issued_at` is in the key's signing window.
    #[serde(rename = "trust.key_validity")]
    TrustKeyValidity,
    /// 17: the declared attestation level is at most the key's.
    #[serde(rename = "trust.attestation")]
    TrustAttestation,
    /// 18: `issued_at` is not after the evaluation time.
    #[serde(rename = "time.not_future")]
    TimeNotFuture,
    /// 19: `policy_compliance.evaluated_at` is not after `issued_at` (P6-6).
    #[serde(rename = "time.policy_not_after_issued")]
    TimePolicyNotAfterIssued,
    /// 20: the record's own lineage members are consistent.
    #[serde(rename = "lineage.consistency")]
    LineageConsistency,
    /// 21: the supplied predecessors verify and link.
    #[serde(rename = "lineage.chain")]
    LineageChain,
}

impl CheckId {
    /// Every check id, in the order of spec §6.2 (the JSON decode checks
    /// before the COSE ones).
    pub const ALL: [CheckId; 27] = [
        CheckId::InputSize,
        CheckId::InputForm,
        CheckId::JsonSyntax,
        CheckId::JsonStructure,
        CheckId::CoseStructure,
        CheckId::CoseProtectedHeader,
        CheckId::CoseUnprotectedHeader,
        CheckId::CoseSignatureEncoding,
        CheckId::CosePayload,
        CheckId::CoseCanonical,
        CheckId::FormatSchema,
        CheckId::FormatConsistency,
        CheckId::SignatureAlgorithm,
        CheckId::SignatureEncoding,
        CheckId::SignatureLowS,
        CheckId::SignaturePayloadHash,
        CheckId::KeyBinding,
        CheckId::TrustKeyKnown,
        CheckId::SignatureValid,
        CheckId::TrustIssuer,
        CheckId::TrustKeyNotRevoked,
        CheckId::TrustKeyValidity,
        CheckId::TrustAttestation,
        CheckId::TimeNotFuture,
        CheckId::TimePolicyNotAfterIssued,
        CheckId::LineageConsistency,
        CheckId::LineageChain,
    ];

    /// The stable id, e.g. `trust.key_known`.
    pub fn id(self) -> &'static str {
        match self {
            CheckId::InputSize => "input.size",
            CheckId::InputForm => "input.form",
            CheckId::JsonSyntax => "json.syntax",
            CheckId::JsonStructure => "json.structure",
            CheckId::CoseStructure => "cose.structure",
            CheckId::CoseProtectedHeader => "cose.protected_header",
            CheckId::CoseUnprotectedHeader => "cose.unprotected_header",
            CheckId::CoseSignatureEncoding => "cose.signature_encoding",
            CheckId::CosePayload => "cose.payload",
            CheckId::CoseCanonical => "cose.canonical",
            CheckId::FormatSchema => "format.schema",
            CheckId::FormatConsistency => "format.consistency",
            CheckId::SignatureAlgorithm => "signature.algorithm",
            CheckId::SignatureEncoding => "signature.encoding",
            CheckId::SignatureLowS => "signature.low_s",
            CheckId::SignaturePayloadHash => "signature.payload_hash",
            CheckId::KeyBinding => "key.binding",
            CheckId::TrustKeyKnown => "trust.key_known",
            CheckId::SignatureValid => "signature.valid",
            CheckId::TrustIssuer => "trust.issuer",
            CheckId::TrustKeyNotRevoked => "trust.key_not_revoked",
            CheckId::TrustKeyValidity => "trust.key_validity",
            CheckId::TrustAttestation => "trust.attestation",
            CheckId::TimeNotFuture => "time.not_future",
            CheckId::TimePolicyNotAfterIssued => "time.policy_not_after_issued",
            CheckId::LineageConsistency => "lineage.consistency",
            CheckId::LineageChain => "lineage.chain",
        }
    }
}

impl std::fmt::Display for CheckId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// What happened to one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The check ran and passed.
    Pass,
    /// The check ran and failed; the run ended here.
    Fail,
    /// An earlier check failed, so this one did not run.
    Skipped,
    /// The check ran but had nothing to decide (lineage without the
    /// predecessors it names); allowed in a passing report only where the
    /// spec says so.
    NotEvaluated,
}

/// One check of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckResult {
    /// Which check.
    pub id: CheckId,
    /// What happened.
    pub outcome: Outcome,
    /// Why, in English; deterministic; quotes at most 64 characters of any
    /// record-derived value.
    pub detail: String,
}

/// The verdict: is this record authentic under the trust store?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every check passed (spec §6.2).
    Pass,
    /// A check failed; `failure` names the first.
    Fail,
}

/// The first failing check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    /// Which check.
    pub check: CheckId,
    /// Why.
    pub detail: String,
}

/// The form the input was verified as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputForm {
    /// The JSON document (spec §2).
    Json,
    /// The COSE_Sign1 envelope (spec §4.4).
    Cose,
    /// A `Record` value already in memory ([`crate::Verifier::verify_record`]):
    /// the input bytes are its compact JSON serialization.
    InMemory,
    /// [`crate::Verifier::verify`] could not tell: the input starts with
    /// neither `{` (after whitespace) nor `0x84`.
    Unknown,
}

/// What was verified: enough to reproduce the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InputSummary {
    /// The form it was verified as.
    pub form: InputForm,
    /// Its length in bytes.
    pub byte_length: u64,
    /// `sha256:<hex>` of the exact input bytes.
    pub sha256: String,
}

/// Which trust store was trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustStoreSummary {
    /// The store's canonical identity (`trust-store-format-v0.1.md` §5).
    pub sha256: String,
    /// Trusted issuers.
    pub issuer_count: u64,
    /// Trusted keys.
    pub key_count: u64,
}

/// What the record says about itself — **claims**, authenticated only
/// when the verdict is `pass`. A renderer must present them as unverified
/// otherwise, and pass every string through [`crate::display_safe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordSummary {
    /// `record_id`.
    pub record_id: String,
    /// `issued_at`.
    pub issued_at: String,
    /// The signed payload's hash, recomputed by the verifier (never read from
    /// the signature section); `None` only if it cannot be computed.
    pub signed_payload_hash: Option<String>,
    /// `model_identity.model_hash`: the model's identity under both model
    /// descriptions (spec §7.3, §7.4).
    pub model_hash: String,
    /// `model_identity.model_format`, which selects the description (spec
    /// §7.1).
    pub model_format: String,
    /// `model_identity.learned_state_hash`: in the general description the
    /// digest of the components the issuer chose, in the engine profile the
    /// state's hash.
    pub learned_state_hash: String,
    /// `learning_provenance.training_input_digest`.
    pub training_input_digest: String,
    /// `issuer.issuer_id`, as declared.
    pub issuer_id: String,
    /// `issuer.issuer_name`, as declared.
    pub issuer_name: String,
    /// `issuer.attestation_level`, as declared.
    pub attestation_level: String,
    /// `lineage.lineage_type`.
    pub lineage_type: String,
}

impl RecordSummary {
    pub(crate) fn of(p: &vmr_record::Record) -> Self {
        RecordSummary {
            record_id: p.record_id.clone(),
            issued_at: p.issued_at.clone(),
            signed_payload_hash: p.signed_payload_hash().ok(),
            model_hash: p.model_identity.model_hash.clone(),
            model_format: p.model_identity.model_format.clone(),
            learned_state_hash: p.model_identity.learned_state_hash.clone(),
            training_input_digest: p.learning_provenance.training_input_digest.clone(),
            issuer_id: p.issuer.issuer_id.clone(),
            issuer_name: p.issuer.issuer_name.clone(),
            attestation_level: p.issuer.attestation_level.clone(),
            lineage_type: p.lineage.lineage_type.clone(),
        }
    }
}

/// The issuer as the **trust store** knows it — the authoritative view.
///
/// Present only once `signature.valid` **and** `trust.issuer` passed: the
/// trusted key really signed this record and speaks for the issuer the
/// record names. A report that failed earlier has none — key ids are
/// public, so a forgery can cite a trusted key, and its report must not
/// carry that key's genuine issuer (QA P4-05). A report that fails later
/// (revocation, the key's window, attestation, time, lineage) keeps it: the
/// name is truthful, the verdict is still `fail`. Only a `pass` makes the
/// record this issuer's; a renderer shows "Issuer:" on a pass alone.
///
/// Every string is raw text from the operator's trust store, which is
/// untrusted input too when handed to the wrong person: a renderer must pass
/// each through [`crate::display_safe`], as for [`RecordSummary`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IssuerSummary {
    /// The DID the store trusts this key for.
    pub issuer_id: String,
    /// The store's name for that issuer.
    pub issuer_name: String,
    /// The signing key's id.
    pub key_id: String,
    /// The highest attestation level the store grants the key.
    pub attestation_level: String,
}

impl IssuerSummary {
    pub(crate) fn of(k: &crate::trust_store::TrustedKey<'_>) -> Self {
        IssuerSummary {
            issuer_id: k.issuer_id.to_string(),
            issuer_name: k.issuer_name.to_string(),
            key_id: k.key_id.to_string(),
            attestation_level: k.attestation_level.as_str().to_string(),
        }
    }
}

/// How far the record's lineage was verified (spec §6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageStatus {
    /// An initial record, and no predecessor was supplied.
    Initial,
    /// Every supplied link verified, back to an initial record.
    Complete,
    /// Every supplied link verified, but the walk ends at a non-initial
    /// record.
    Partial,
    /// A non-initial record, and no predecessor was supplied.
    NotChecked,
    /// A lineage rule failed.
    Broken,
}

/// One verified predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkSummary {
    /// The predecessor's `record_id`.
    pub record_id: String,
    /// Its signed payload hash, recomputed by the verifier: the value its
    /// successor's `previous_record_hash` matched.
    pub signed_payload_hash: String,
    /// Its `lineage_type`.
    pub lineage_type: String,
    /// Its `lineage_chain_length`.
    pub lineage_chain_length: u64,
    /// Its `issued_at`.
    pub issued_at: String,
}

/// The lineage section: what the record declares, and how much of it was
/// verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineageReport {
    /// The record's `lineage_type`.
    pub lineage_type: String,
    /// The record's `lineage_chain_length`: how many records the chain
    /// declares, this one included.
    pub declared_chain_length: u64,
    /// How far the chain was verified.
    pub status: LineageStatus,
    /// The predecessors whose link verified, immediate predecessor first.
    pub verified_links: Vec<LinkSummary>,
}

/// What happened to the policy evaluation (never merged with the record's
/// own declaration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvaluationState {
    /// No evaluator was given.
    NotRequested,
    /// An evaluator was given, but the verdict is `fail`: an unverified
    /// record is never evaluated.
    Skipped {
        /// Why.
        reason: String,
    },
    /// The evaluator ran.
    Evaluated {
        /// The pack it applied.
        policy_pack_id: String,
        /// That pack's own version: the id alone does not say which text
        /// was applied (P6-13).
        policy_pack_version: String,
        /// That pack's payload hash, signed or not: what a gate pins (P6-16).
        policy_pack_payload_hash: String,
        /// Whether that pack carried an authority signature, and what
        /// checking it found (P6-13, P6-16).
        pack_signature: crate::policy::PackSignatureState,
        /// The authority store the signature was checked against, when it is
        /// not the trust store (P6-16); absent otherwise. Boxed, so this
        /// variant stays near the others' size (clippy's large_enum_variant).
        #[serde(skip_serializing_if = "Option::is_none")]
        authority_store: Option<Box<crate::policy::AuthorityStoreSummary>>,
        /// Its overall result.
        status: crate::policy::PolicyStatus,
        /// Its rule results.
        rules: Vec<crate::policy::PolicyRuleResult>,
        /// A note, e.g. that the record declared a different pack.
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    /// The evaluator panicked; the panic was contained. Not accepted.
    EvaluatorPanicked {
        /// The pack it was to apply.
        policy_pack_id: String,
    },
}

/// The policy section: the record's declaration and, separately, any
/// evaluation (spec §6.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyReport {
    /// The record's `policy_compliance`, verbatim — the issuer's claim,
    /// never an evaluation. `None` if the record did not parse.
    pub declared: Option<vmr_record::record::PolicyCompliance>,
    /// The evaluation, if one was requested.
    pub evaluation: EvaluationState,
}

/// The whole answer to one verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    /// [`REPORT_VERSION`].
    pub report_version: &'static str,
    /// Pass or fail.
    pub verdict: Verdict,
    /// The first failing check, or `None` on a pass.
    pub failure: Option<Failure>,
    /// The verdict is `pass` and, if a policy evaluator was given, it
    /// evaluated the record `compliant`.
    pub accepted: bool,
    /// The evaluation time the caller passed.
    pub evaluation_time: String,
    /// The input.
    pub input: InputSummary,
    /// The trust store.
    pub trust_store: TrustStoreSummary,
    /// `sha256:<hex>` of each supplied predecessor's exact bytes, in the
    /// order supplied (immediate predecessor first).
    pub previous: Vec<String>,
    /// Whether the caller required a complete lineage.
    pub require_complete_lineage: bool,
    /// The record's claims, once it parsed.
    pub record: Option<RecordSummary>,
    /// The trust store's view of the issuer: present only once
    /// `signature.valid` and `trust.issuer` passed (see [`IssuerSummary`]);
    /// raw store text, for [`crate::display_safe`] before display.
    pub issuer: Option<IssuerSummary>,
    /// Every check of the form's sequence, in order.
    pub checks: Vec<CheckResult>,
    /// The lineage, once the lineage checks ran.
    pub lineage: Option<LineageReport>,
    /// The declared policy and any evaluation of it.
    pub policy: PolicyReport,
}

impl VerificationReport {
    /// The report as pretty-printed JSON: deterministic bytes for identical
    /// inputs (the golden reports and the two-process Gate 4 test compare
    /// them byte for byte).
    ///
    /// The JSON reaches terminals (`vmr record verify --json` prints it
    /// byte for byte), and the claims in it are a record's raw text, so it
    /// carries no character a terminal acts on or hides: every character
    /// [`crate::display_safe`] escapes that serde_json would write raw (DEL,
    /// C1 controls, bidi controls, invisible characters, noncharacters) is
    /// written as a JSON `\u` escape. A JSON parser reads back exactly the
    /// values of the report; only their spelling differs.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self).map(crate::text::json_escape_unsafe)
    }

    /// The process exit code a CLI should use: 0 accepted, 3 verdict fail,
    /// 4 verdict pass but not accepted (`docs/TLM_LAYER.md` §8.2; 1, a usage
    /// or trust-store error, is the CLI's own).
    pub fn exit_code(&self) -> i32 {
        match (self.verdict, self.accepted) {
            (_, true) => 0,
            (Verdict::Fail, false) => 3,
            (Verdict::Pass, false) => 4,
        }
    }
}

/// The verdict of a finished run (spec §6.2): `pass` only when every check
/// passed — `lineage.chain` alone may be not evaluated — **and**
/// `signature.valid` is among them. Whatever else the sequence holds, no
/// report says `pass` about a signature that was not verified under a
/// trust-store key, and no check that did not run counts as passed: if a
/// pipeline ever reached its end that way, the report fails on it.
pub(crate) fn verdict_of(checks: &[CheckResult]) -> (Verdict, Option<Failure>) {
    let first_bad = checks.iter().find(|c| match c.outcome {
        Outcome::Pass => false,
        Outcome::NotEvaluated => c.id != CheckId::LineageChain,
        Outcome::Fail | Outcome::Skipped => true,
    });
    if let Some(c) = first_bad {
        let detail = match c.outcome {
            Outcome::Fail => c.detail.clone(),
            _ => format!("{} did not run to a result", c.id),
        };
        return (Verdict::Fail, Some(Failure { check: c.id, detail }));
    }
    let verified = checks
        .iter()
        .any(|c| c.id == CheckId::SignatureValid && c.outcome == Outcome::Pass);
    if verified {
        (Verdict::Pass, None)
    } else {
        (
            Verdict::Fail,
            Some(Failure {
                check: CheckId::SignatureValid,
                detail: "the signature was not verified under a trust-store key".into(),
            }),
        )
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn check(id: CheckId, outcome: Outcome) -> CheckResult {
        CheckResult { id, outcome, detail: String::new() }
    }

    #[test]
    fn a_run_without_signature_valid_never_passes() {
        let all_pass: Vec<CheckResult> = CheckId::ALL
            .iter()
            .filter(|&&c| c != CheckId::SignatureValid)
            .map(|&c| check(c, Outcome::Pass))
            .collect();
        let (verdict, failure) = verdict_of(&all_pass);
        assert_eq!(verdict, Verdict::Fail);
        assert_eq!(failure.map(|f| f.check), Some(CheckId::SignatureValid));

        let skipped_sig = vec![
            check(CheckId::InputSize, Outcome::Pass),
            check(CheckId::SignatureValid, Outcome::Skipped),
        ];
        assert_eq!(verdict_of(&skipped_sig).0, Verdict::Fail);
    }

    #[test]
    fn a_check_that_did_not_run_is_never_a_pass() {
        // A skipped check without a failure before it, or a check other
        // than lineage.chain left not evaluated, fails the report on it.
        for (id, outcome) in [
            (CheckId::TimeNotFuture, Outcome::Skipped),
            (CheckId::TrustKeyNotRevoked, Outcome::NotEvaluated),
        ] {
            let checks = vec![
                check(CheckId::SignatureValid, Outcome::Pass),
                check(id, outcome),
            ];
            let (verdict, failure) = verdict_of(&checks);
            assert_eq!(verdict, Verdict::Fail);
            assert_eq!(failure.map(|f| f.check), Some(id));
        }
    }

    #[test]
    fn the_first_failure_decides() {
        let checks = vec![
            check(CheckId::InputSize, Outcome::Pass),
            check(CheckId::InputForm, Outcome::Fail),
            check(CheckId::SignatureValid, Outcome::Pass),
            check(CheckId::TrustIssuer, Outcome::Fail),
        ];
        let (verdict, failure) = verdict_of(&checks);
        assert_eq!(verdict, Verdict::Fail);
        assert_eq!(failure.map(|f| f.check), Some(CheckId::InputForm));
    }

    #[test]
    fn signature_valid_and_no_failure_is_a_pass() {
        let checks = vec![
            check(CheckId::SignatureValid, Outcome::Pass),
            check(CheckId::LineageChain, Outcome::NotEvaluated),
        ];
        assert_eq!(verdict_of(&checks), (Verdict::Pass, None));
    }
}
