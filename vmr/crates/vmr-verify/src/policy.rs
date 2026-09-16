//! The policy hook: how a policy evaluator (KHALM-VMR Phase 6) plugs into
//! verification without ever judging an unverified record.
// ============================================================================
//  policy.rs — PolicyEvaluator, VerifiedRecord (4.5)
//
//  Declared vs evaluated (plan §5.7, spec §6.6): a record's own
//  `policy_compliance` is the issuer's statement, reported verbatim as
//  `declared`. An evaluator's result is a separate `evaluation`, never
//  merged with the declaration and never part of the verdict: the verdict
//  says whether the record is authentic; `accepted` additionally says
//  whether the evaluated policy is compliant.
//
//  The evaluator receives a `VerifiedRecord`, which only this crate can
//  construct and only after a `pass` verdict — "policy evaluated an
//  unverified record" cannot be written. A panicking evaluator is
//  contained (catch_unwind, as vmr-ffi contains a panicking step hook, QA
//  F-16) and reported as `evaluator_panicked`: not accepted. It is the only
//  panic containment in the verifier (plan §5.8).
// ============================================================================

use crate::report::{IssuerSummary, LineageReport};
use serde::Serialize;
use vmr_record::timestamp::Timestamp;
use vmr_record::Record;

/// A policy result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PolicyStatus {
    /// No mandatory rule failed or was indeterminate. Recommended and
    /// informational rules do not decide, so a pack with no mandatory rule
    /// is compliant whatever its rules found.
    #[serde(rename = "compliant")]
    Compliant,
    /// A mandatory rule failed.
    #[serde(rename = "non-compliant")]
    NonCompliant,
    /// A mandatory rule was indeterminate, and none failed.
    #[serde(rename = "indeterminate")]
    Indeterminate,
}

/// One RULE's result: the three words a record's own
/// `policy_compliance.results[]` uses (`pass`, `fail`), plus the
/// `indeterminate` a v0.1 record cannot carry but an evaluator must be
/// able to say (P6-1, P6-3).
///
/// A rule passes or fails; a PACK is compliant or not ([`PolicyStatus`]).
/// Keeping the two vocabularies apart is what lets a reader put a declared
/// result and an evaluated one side by side (P6-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleStatus {
    /// The record satisfies the rule.
    Pass,
    /// The record declares something the rule forbids.
    Fail,
    /// The record does not say enough to decide. Never a failure.
    Indeterminate,
}

/// What is known about the policy pack's OWN authority signature (P6-13,
/// P6-16).
///
/// A pack may carry a signature by the authority that wrote it
/// (`vmr_policy::verify_pack_signature`). It is checked against the policy
/// authorities the operator trusts (`specs/trust-store-format-v0.1.md` §4.2):
/// those of the trust store, or of a separate authority store. The report
/// never lets "signed" be read as "checked". A signature whose key no trusted
/// authority holds is `not_checked`. Only a signature that verified under a
/// trusted authority's key, bound to the authority the pack names, unrevoked
/// and inside its window, is `valid`. A signature that fails any of those is
/// no state at all: the caller refuses the pack before verification, and no
/// report is produced (P6-16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PackSignatureState {
    /// The pack carries no `signature` section: there is nothing to check.
    Unsigned,
    /// The pack carries a signature, and no policy authority the operator
    /// trusts holds the key it names, so it was not checked.
    NotChecked {
        /// The key id the pack names as its signer, as the pack states it
        /// (raw pack text: [`crate::display_safe`] it before display).
        signing_key_id: String,
    },
    /// The signature verified under a key a trusted policy authority holds,
    /// and that key may speak for the authority the pack names at the
    /// evaluation time.
    Valid {
        /// The signing key's id.
        signing_key_id: String,
        /// The authority the store trusts the key for, which is the pack's
        /// own `authority.authority_id` (raw text: [`crate::display_safe`] it
        /// before display).
        authority_id: String,
        /// The store's name for that authority: the operator's, not the
        /// pack's claim (raw text: [`crate::display_safe`] it before display).
        authority_name: String,
    },
}

/// The authority store a pack's signature was checked against, when it is
/// not the trust store (P6-16, `--authority-store`): its identity and size,
/// reported as the trust store's are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorityStoreSummary {
    /// The store's canonical identity (`trust-store-format-v0.1.md` §5).
    pub sha256: String,
    /// Trusted policy authorities.
    pub authority_count: u64,
    /// Their keys.
    pub key_count: u64,
}

impl AuthorityStoreSummary {
    /// The summary of `store`: its identity, its policy authorities and
    /// their keys.
    pub fn of(store: &crate::TrustStore) -> Self {
        AuthorityStoreSummary {
            sha256: store.sha256().to_string(),
            authority_count: store.authority_count() as u64,
            key_count: store.authority_key_count() as u64,
        }
    }
}

/// One rule's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRuleResult {
    /// The rule's id in its policy pack.
    pub rule_id: String,
    /// Its result.
    pub status: PolicyRuleStatus,
    /// How the pack weighs a failure of this rule (`mandatory`,
    /// `recommended`, `informational`): why the overall status is what it
    /// is. Raw pack text.
    pub severity: String,
    /// The clause this rule encodes, in the pack's words (P6-4), so a
    /// result can be read without the pack beside it. Raw pack text.
    pub reference: String,
    /// `sha256:` + the hex of the hash of what the rule read (P6-2) — the
    /// same value, with the same meaning, as a record's own
    /// `policy_compliance.results[].evidence_hash`, so a third party can
    /// check the same evidence.
    pub evidence_hash: String,
    /// Why, in the evaluator's words.
    pub detail: String,
}

/// What an evaluator returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyEvaluation {
    /// The overall result.
    pub status: PolicyStatus,
    /// The pack's own version (`pack_version`), as the pack states it: the
    /// pack id alone does not say which text was applied. Raw pack text.
    pub pack_version: String,
    /// The pack's payload hash (`policy-pack-format-v0.1.md` §4): `sha256:`
    /// and the hex of the SHA-256 of its signed payload, the same whether the
    /// pack is signed or not, so a gate can pin the content (P6-16).
    pub pack_payload_hash: String,
    /// What is known about the pack's authority signature.
    pub pack_signature: PackSignatureState,
    /// The authority store the signature was checked against, when the
    /// operator named one; `None` when the trust store's authorities were.
    pub authority_store: Option<AuthorityStoreSummary>,
    /// Every rule evaluated, in the pack's order.
    pub rules: Vec<PolicyRuleResult>,
}

/// A record that passed verification, with the trust store's view of its
/// issuer and what verification established about its lineage. Only the
/// verifier constructs one, and only after a `pass` verdict.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedRecord<'a> {
    record: &'a Record,
    issuer: &'a IssuerSummary,
    lineage: &'a LineageReport,
    predecessors: &'a [Record],
}

impl<'a> VerifiedRecord<'a> {
    pub(crate) fn new(
        record: &'a Record,
        issuer: &'a IssuerSummary,
        lineage: &'a LineageReport,
        predecessors: &'a [Record],
    ) -> Self {
        VerifiedRecord { record, issuer, lineage, predecessors }
    }

    /// What verification established about the lineage (spec §6.5): its
    /// outcome (`initial`, `complete`, `partial` or `not_checked`; a broken
    /// lineage fails verification and never reaches an evaluator) and the
    /// links that verified. It is the lineage section the report carries
    /// (P6-17).
    pub fn lineage(&self) -> &'a LineageReport {
        self.lineage
    }

    /// The predecessors whose links verified, decoded, immediate predecessor
    /// first: exactly the records [`LineageReport::verified_links`] lists,
    /// and nothing that did not verify. Empty when none were supplied.
    pub fn verified_predecessors(&self) -> &'a [Record] {
        self.predecessors
    }

    /// The record. Its content is authenticated as the issuer's
    /// statements; it is still the issuer's word, not a fact.
    pub fn record(&self) -> &'a Record {
        self.record
    }

    /// The DID the trust store trusts the signing key for.
    pub fn trusted_issuer_id(&self) -> &'a str {
        &self.issuer.issuer_id
    }

    /// The trust store's view of the issuer.
    pub fn trusted_issuer(&self) -> &'a IssuerSummary {
        self.issuer
    }
}

/// A policy evaluator (implemented by KHALM-VMR Phase 6's `vmr-policy`
/// adapter). Deterministic implementations only: the result must depend on
/// the record, the evaluation time and the evaluator's own configuration,
/// nothing else.
pub trait PolicyEvaluator {
    /// The id of the policy pack this evaluator applies.
    fn policy_pack_id(&self) -> &str;

    /// Evaluate a verified record at `evaluation_time`.
    fn evaluate(&self, record: &VerifiedRecord<'_>, evaluation_time: Timestamp) -> PolicyEvaluation;
}
