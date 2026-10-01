//! A policy pack, loaded, its own signature decided, as the verifier's
//! policy hook sees it.
// ============================================================================
//  pack.rs — vmr-policy behind vmr-verify's PolicyEvaluator
//
//  The browser's counterpart of vmr-cli's `policy_pack.rs`, with the files
//  taken out: the same order and the same decisions, so that a pack gives
//  the same evaluation here as under `vmr record verify --policy-pack`
//  (tests/cli_agreement.rs compares the two reports byte for byte over every
//  published policy and pack-signature vector). It cannot be one shared
//  module: vmr-policy depends on no verifier (P6-10) and vmr-verify on no
//  policy crate (G4-5), so the adapter between them lives in each tool.
//
//    1. load: vmr-policy's loader (size, depth, UTF-8, structure, schema);
//    2. the key-free half of a signature check: the payload hash a
//       signature section states must be the pack's own (QA Q6-05);
//    3. the pack's own signature against the policy authorities the caller
//       trusts, at the caller's time (P6-16): unsigned, not checked, or
//       valid; a signature that fails is refused; `require_signed` refuses
//       unsigned and not checked too;
//    4. the evaluation of a VERIFIED record only (vmr-verify decides that),
//       at the caller's time, in the lineage verification established.
// ============================================================================

use crate::refusal::Refusal;
use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, LoadedPack, Status, VerifiedPredecessor};
use vmr_record::timestamp::Timestamp;
use vmr_verify::policy::{
    AuthorityStoreSummary, PackSignatureState, PolicyEvaluation, PolicyEvaluator, PolicyRuleResult,
    PolicyRuleStatus, PolicyStatus, VerifiedRecord,
};
use vmr_verify::report::LineageStatus;
use vmr_verify::TrustStore;

/// Refusing an unsigned pack when a signature is required (the CLI's
/// `--require-signed-pack` refusal of the same id).
pub const UNSIGNED_REFUSED: &str = "pack_signature.unsigned_refused";

/// Refusing a pack whose key no trusted policy authority holds when a
/// signature is required (the CLI's refusal of the same id).
pub const NOT_CHECKED_REFUSED: &str = "pack_signature.not_checked_refused";

/// Where a pack's policy authorities come from (P6-16): the trust store, or
/// a separate authority store — never both.
#[derive(Debug, Clone, Copy)]
pub enum Authorities<'a> {
    /// The trust store's `policy_authorities`.
    TrustStore(&'a TrustStore),
    /// An authority store's.
    AuthorityStore(&'a TrustStore),
}

impl<'a> Authorities<'a> {
    fn store(self) -> &'a TrustStore {
        match self {
            Authorities::TrustStore(store) | Authorities::AuthorityStore(store) => store,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Authorities::TrustStore(_) => "trust store",
            Authorities::AuthorityStore(_) => "authority store",
        }
    }

    /// The report names an authority store only; the trust store is the
    /// report's own already.
    fn summary(self) -> Option<AuthorityStoreSummary> {
        match self {
            Authorities::TrustStore(_) => None,
            Authorities::AuthorityStore(store) => Some(AuthorityStoreSummary::of(store)),
        }
    }
}

/// A loaded pack and what is known about its own signature.
#[derive(Debug)]
pub struct PackEvaluator {
    pack: LoadedPack,
    signature: PackSignatureState,
    authority_store: Option<AuthorityStoreSummary>,
}

impl PackEvaluator {
    /// Steps 1 and 2: load the pack's bytes and check the payload hash its
    /// signature section states. Refused as `vmr-policy` names it.
    pub fn load(bytes: &[u8]) -> Result<Self, Refusal> {
        let pack = vmr_policy::load_pack_bytes(bytes)
            .map_err(|e| Refusal::new(e.refusal_id(), "pack", e.to_string()))?;
        if let (Err(e), Some(section)) = (pack.check_payload_hash(), &pack.pack().signature) {
            return Err(Refusal::new(
                e.refusal_id(),
                "pack",
                format!(
                    "its signature section states signed_payload_hash {}, but the pack as received hashes to {}: \
                     the pack was changed after it was signed, or the section belongs to another pack",
                    section.signed_payload_hash,
                    pack.payload_hash()
                ),
            ));
        }
        let signature = match &pack.pack().signature {
            None => PackSignatureState::Unsigned,
            Some(section) => PackSignatureState::NotChecked { signing_key_id: section.signing_key_id.clone() },
        };
        Ok(PackEvaluator { pack, signature, authority_store: None })
    }

    /// Step 3: decide the pack's own signature against `authorities` at `at`.
    pub fn check_signature(
        mut self,
        authorities: Authorities<'_>,
        at: Timestamp,
        require_signed: bool,
    ) -> Result<Self, Refusal> {
        let store = authorities.name();
        self.authority_store = authorities.summary();
        let Some(key_id) = self.pack.pack().signature.as_ref().map(|s| s.signing_key_id.clone()) else {
            if require_signed {
                return Err(Refusal::new(
                    UNSIGNED_REFUSED,
                    "pack",
                    format!(
                        "it carries no authority signature, and requireSignedPack accepts only a pack signed by a \
                         policy authority the {store} trusts"
                    ),
                ));
            }
            self.signature = PackSignatureState::Unsigned;
            return Ok(self);
        };
        let Some(key) = authorities.store().lookup_authority(&key_id) else {
            if require_signed {
                return Err(Refusal::new(
                    NOT_CHECKED_REFUSED,
                    "pack",
                    format!(
                        "it names {key_id} as its signer, but no policy authority in the {store} holds that key, and \
                         requireSignedPack accepts only a pack signed by a policy authority the {store} trusts"
                    ),
                ));
            }
            self.signature = PackSignatureState::NotChecked { signing_key_id: key_id };
            return Ok(self);
        };
        if let Err(e) = self.pack.verify_signature(key.verifying_key) {
            return Err(Refusal::new(
                e.refusal_id(),
                "pack",
                format!("its signature does not verify under {key_id}, a key the {store} trusts for a policy authority: {e}"),
            ));
        }
        if let Err(refusal) = key.may_sign_for(&self.pack.authority.authority_id, at) {
            return Err(Refusal::new(refusal.id(), "pack", refusal.to_string()));
        }
        self.signature = PackSignatureState::Valid {
            signing_key_id: key_id,
            authority_id: key.authority_id.to_string(),
            authority_name: key.authority_name.to_string(),
        };
        Ok(self)
    }

    /// What is known about the pack's own signature.
    pub fn signature_state(&self) -> &PackSignatureState {
        &self.signature
    }
}

impl PolicyEvaluator for PackEvaluator {
    fn policy_pack_id(&self) -> &str {
        &self.pack.pack_id
    }

    fn evaluate(&self, record: &VerifiedRecord<'_>, evaluation_time: Timestamp) -> PolicyEvaluation {
        // A record that does not serialise cannot happen (the verifier parsed
        // it); were it to, every rule would read Indeterminate, never pass.
        let value = serde_json::to_value(record.record()).unwrap_or(serde_json::Value::Null);
        let evaluation = self.pack.evaluate_in_context(&value, &lineage_context(record), evaluation_time);
        PolicyEvaluation {
            status: overall(evaluation.overall),
            pack_version: evaluation.pack_version,
            pack_payload_hash: self.pack.payload_hash().to_string(),
            pack_signature: self.signature.clone(),
            authority_store: self.authority_store.clone(),
            rules: evaluation
                .results
                .into_iter()
                .map(|r| PolicyRuleResult {
                    rule_id: r.rule_id,
                    status: rule(r.status),
                    severity: r.severity.id().to_string(),
                    reference: r.reference,
                    evidence_hash: r.evidence_hash,
                    detail: r.detail,
                })
                .collect(),
        }
    }
}

/// What verification established about the lineage, in vmr-policy's words
/// (P6-17): the outcome, and each predecessor whose link verified, immediate
/// predecessor first.
fn lineage_context(record: &VerifiedRecord<'_>) -> EvaluationContext {
    let lineage = record.lineage();
    let predecessors = lineage
        .verified_links
        .iter()
        .zip(record.verified_predecessors())
        .map(|(link, predecessor)| VerifiedPredecessor {
            signed_payload_hash: link.signed_payload_hash.clone(),
            record: serde_json::to_value(predecessor).unwrap_or(serde_json::Value::Null),
        })
        .collect();
    EvaluationContext { lineage: LineageContext { outcome: outcome(lineage.status), predecessors } }
}

fn outcome(status: LineageStatus) -> LineageOutcome {
    match status {
        LineageStatus::Initial => LineageOutcome::Initial,
        LineageStatus::Complete => LineageOutcome::Complete,
        LineageStatus::Partial => LineageOutcome::Partial,
        LineageStatus::NotChecked | LineageStatus::Broken => LineageOutcome::NotChecked,
    }
}

fn overall(status: Status) -> PolicyStatus {
    match status {
        Status::Pass => PolicyStatus::Compliant,
        Status::Fail => PolicyStatus::NonCompliant,
        Status::Indeterminate => PolicyStatus::Indeterminate,
    }
}

fn rule(status: Status) -> PolicyRuleStatus {
    match status {
        Status::Pass => PolicyRuleStatus::Pass,
        Status::Fail => PolicyRuleStatus::Fail,
        Status::Indeterminate => PolicyRuleStatus::Indeterminate,
    }
}
