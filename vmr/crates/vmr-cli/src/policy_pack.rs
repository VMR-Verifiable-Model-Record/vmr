//! `--policy-pack`: the evaluator `record verify` hands to `vmr-verify`
//! (P6-13, which reverses Phase 5's C6), and the check of the pack's own
//! authority signature (P6-14, P6-16).
// ============================================================================
//  policy_pack.rs — load a pack file, check its signature, adapt vmr-policy
//  to the verifier's hook
//
//  C6 refused a `--policy-pack` flag in Phase 5 because nothing in the tree
//  could perform the evaluation its name promised, and a flag that promises
//  one is worse than no flag. Phase 6's `vmr-policy` can, so the flag exists
//  and does exactly what it says.
//
//  This module is orchestration, like the rest of the CLI: it reads a file
//  (bounded, MAX_PACK_BYTES), asks vmr-policy to parse and validate it, and
//  wraps the result in the `PolicyEvaluator` the verifier already defines.
//  It decides nothing. In particular:
//
//    * The EVALUATION TIME is the verifier's, not the record's: the hook
//      is handed `opts.evaluation_time`, which is `--at` or the clock, the
//      same value `time.not_future` uses. It is never compared with the
//      record's `issued_at`. P6-6 (check 19) governs the evaluation the
//      ISSUER embedded and signed; an evaluation run here happens after
//      issuance by definition, and that is normal.
//    * The LINEAGE the evaluation sees is what verification established
//      (P6-17): the outcome, and the predecessors whose links verified,
//      `--previous` included, immediate predecessor first. vmr-policy
//      depends on no verifier (P6-10), so this module maps one crate's view
//      onto the other's. A rule that needs a predecessor that was not
//      supplied is Indeterminate, and its reason names `--previous`.
//    * The PACK'S OWN TRUST is checked against the policy authorities the
//      operator trusts (P6-14, P6-16; specs/trust-store-format-v0.1.md
//      §4.2): those of --authority-store when it is given, else those of the
//      trust store, never both. The trust decision is vmr-verify's
//      (`TrustStore::lookup_authority`, `TrustedAuthorityKey::may_sign_for`),
//      and the signature is vmr-policy's (`LoadedPack::verify_signature`).
//      vmr-policy depends on no verifier (P6-10), so this module hands the
//      one's key to the other. An unsigned pack, or one whose key no trusted
//      authority holds, is evaluated and labelled; --require-signed-pack
//      refuses both. A signature that does not verify, or whose key may not
//      speak for the pack's authority at the evaluation time, is refused.
//      The key-free part stays at load (QA Q6-05): the `signed_payload_hash`
//      the signature section states must be the hash of the pack as
//      received, so a pack changed after it was signed is refused even
//      without a key.
//    * A pack file that cannot be used, or whose signature is refused, is the
//      OPERATOR's error (exit 1), never a verification result — a bad pack
//      is a bad trust store, not a bad record — and it is decided before
//      the record is verified.
// ============================================================================

use crate::error::CliError;
use crate::files::{self, shown, ReadError};
use crate::names::TOOL;
use std::path::Path;
use vmr_record::timestamp::Timestamp;
use vmr_policy::{
    EvaluationContext, LineageContext, LineageOutcome, LoadedPack, Refusal, Status, VerifiedPredecessor,
};
use vmr_verify::policy::{
    AuthorityStoreSummary, PackSignatureState, PolicyEvaluation, PolicyEvaluator, PolicyRuleResult,
    PolicyRuleStatus, PolicyStatus, VerifiedRecord,
};
use vmr_verify::report::LineageStatus;
use vmr_verify::TrustStore;

/// The stable id of `--require-signed-pack` refusing an unsigned pack
/// (docs/dev/task-6.16.md A16-22).
pub const UNSIGNED_REFUSED: &str = "pack_signature.unsigned_refused";

/// The stable id of `--require-signed-pack` refusing a pack whose key no
/// trusted policy authority holds (A16-22).
pub const NOT_CHECKED_REFUSED: &str = "pack_signature.not_checked_refused";

/// Where a pack's policy authorities come from (P6-16): the trust store, or
/// an authority store the operator names — never both.
#[derive(Debug, Clone, Copy)]
pub enum Authorities<'a> {
    /// The `policy_authorities` of the trust store `--trust-store` names.
    TrustStore(&'a TrustStore),
    /// The authority store `--authority-store` names.
    AuthorityStore(&'a TrustStore),
}

impl<'a> Authorities<'a> {
    /// The store the authorities are looked up in.
    fn store(self) -> &'a TrustStore {
        match self {
            Authorities::TrustStore(store) | Authorities::AuthorityStore(store) => store,
        }
    }

    /// How a message and the rendering name that store.
    fn name(self) -> &'static str {
        match self {
            Authorities::TrustStore(_) => "trust store",
            Authorities::AuthorityStore(_) => "authority store",
        }
    }

    /// What the evaluation says about the store. The trust store is the
    /// report's own already, so only an authority store is named.
    fn summary(self) -> Option<AuthorityStoreSummary> {
        match self {
            Authorities::TrustStore(_) => None,
            Authorities::AuthorityStore(store) => Some(AuthorityStoreSummary::of(store)),
        }
    }
}

/// A loaded policy pack, as the verifier's hook sees it.
#[derive(Debug)]
pub struct PackEvaluator {
    pack: LoadedPack,
    /// The pack's path, as refusals show it.
    shown: String,
    /// What is known about the pack's own signature: unsigned or not checked
    /// until [`PackEvaluator::check_signature`] decides it.
    signature: PackSignatureState,
    /// The authority store the signature was checked against, if one was.
    authority_store: Option<AuthorityStoreSummary>,
}

/// Read and validate the pack at `path`. Every failure is the operator's
/// (exit 1), named by `vmr-policy`'s own typed refusal (P6-9), which says
/// which member of the pack is at fault.
pub fn load(path: &Path) -> Result<PackEvaluator, CliError> {
    let limit = vmr_policy::MAX_PACK_BYTES as u64;
    let bytes = match files::read_bounded(path, limit) {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge(size)) => {
            return Err(CliError::input(format!(
                "policy pack {} cannot be used: {}: it is {size} bytes; {TOOL} reads at most {limit} bytes \
                 (1 MiB) from a policy pack, and did not read it",
                shown(path),
                Refusal::Size.id()
            )))
        }
        Err(ReadError::Io(e)) => {
            return Err(CliError::input(format!("cannot read policy pack {}: {e}", shown(path))))
        }
    };
    let unusable = |why: String| {
        CliError::input(format!("policy pack {} cannot be used: {why}", shown(path))).with_hint(
            "a policy pack is an authority's rules in JSON (specs/policy-pack-schema/v0.1.json); \
             the five reference packs under specs/policy-packs/ are working examples",
        )
    };
    // vmr-policy decides which refusal the bytes are, in the order of
    // specs/policy-pack-format-v0.1.md §3: the size, then the depth counted
    // over the bytes whatever else they break, then bytes that are not UTF-8,
    // then the rest (QA16-02). Every refusal names its stable id
    // (docs/dev/task-6.16.md A16-20, A16-22). A BOM or UTF-16 is refused like
    // every other JSON input of this tool, as refusal 2, but says why (QA
    // P5-07): the parser's own message points at bytes the operator cannot see.
    let pack = vmr_policy::load_pack_bytes(&bytes).map_err(|e| match (e.refusal(), files::byte_order_mark(&bytes)) {
        (Some(Refusal::Structure), Some(bom)) => {
            unusable(format!("{}: {bom}, which a policy pack may not have", e.refusal_id()))
                .with_hint(files::SAVE_WITHOUT_BOM)
        }
        _ => unusable(format!("{}: {e}", e.refusal_id())),
    })?;
    // The key-free half of a signature check (QA Q6-05, P6-16): the payload
    // hash the section states must be the pack's own. Both strings are
    // schema-checked `sha256:` hashes, so quoting them is safe.
    if let (Err(e), Some(section)) = (pack.check_payload_hash(), &pack.pack().signature) {
        return Err(unusable(format!(
            "{}: its signature section states signed_payload_hash {}, but the pack as received hashes to \
             {}: the pack was changed after it was signed, or the section belongs to another pack",
            e.refusal_id(),
            section.signed_payload_hash,
            pack.payload_hash()
        ))
        .with_hint(
            "get the pack again from the authority that signed it; to evaluate this text anyway, remove \
             its signature section, and it is reported as an unsigned pack",
        ));
    }
    let signature = match &pack.pack().signature {
        None => PackSignatureState::Unsigned,
        Some(section) => PackSignatureState::NotChecked { signing_key_id: section.signing_key_id.clone() },
    };
    Ok(PackEvaluator { pack, shown: shown(path), signature, authority_store: None })
}

impl PackEvaluator {
    /// Decide the pack's own signature against `authorities`, at the
    /// evaluation time `at` (P6-16; specs/trust-store-format-v0.1.md §4.2).
    /// In order:
    ///
    /// 1. no signature section: `unsigned`;
    /// 2. no key with the id the pack names among the authorities:
    ///    `not_checked`;
    /// 3. the signature verifies under that key (vmr-policy's six steps);
    /// 4. the key may speak for the authority the pack names at `at`: trusted
    ///    for it, unrevoked, inside its window (vmr-verify) — then `valid`.
    ///
    /// A failure at step 3 or 4 is refused. With `require_signed`, so are
    /// `unsigned` and `not_checked`. Every refusal is exit 1.
    pub fn check_signature(
        mut self,
        authorities: Authorities<'_>,
        at: Timestamp,
        require_signed: bool,
    ) -> Result<Self, CliError> {
        let store = authorities.name();
        self.authority_store = authorities.summary();
        // The key id passed the pack schema's pattern (an RFC 7638 thumbprint
        // URN), so it is safe to print whole.
        let Some(key_id) = self.pack.pack().signature.as_ref().map(|s| s.signing_key_id.clone()) else {
            if require_signed {
                return Err(self.not_accepted(
                    UNSIGNED_REFUSED,
                    format!(
                        "it carries no authority signature, and --require-signed-pack accepts only a pack signed \
                         by a policy authority the {store} trusts"
                    ),
                ));
            }
            self.signature = PackSignatureState::Unsigned;
            return Ok(self);
        };
        let Some(key) = authorities.store().lookup_authority(&key_id) else {
            if require_signed {
                return Err(self.not_accepted(
                    NOT_CHECKED_REFUSED,
                    format!(
                        "it names {key_id} as its signer, but no policy authority in the {store} holds that key, \
                         and --require-signed-pack accepts only a pack signed by a policy authority the {store} \
                         trusts"
                    ),
                ));
            }
            self.signature = PackSignatureState::NotChecked { signing_key_id: key_id };
            return Ok(self);
        };
        // Step 3 names the key and no authority: key ids are public, and a
        // forgery may cite a trusted one (as QA P4-05 settled for records).
        if let Err(e) = self.pack.verify_signature(key.verifying_key) {
            return Err(self.refused(
                e.refusal_id(),
                format!("its signature does not verify under {key_id}, a key the {store} trusts for a policy authority: {e}"),
            ));
        }
        if let Err(refusal) = key.may_sign_for(&self.pack.authority.authority_id, at) {
            return Err(self.refused(refusal.id(), refusal.to_string()));
        }
        self.signature = PackSignatureState::Valid {
            signing_key_id: key_id,
            authority_id: key.authority_id.to_string(),
            authority_name: key.authority_name.to_string(),
        };
        Ok(self)
    }

    /// A pack whose signature does not count as its authority's, refused as
    /// `id`.
    fn refused(&self, id: &str, why: String) -> CliError {
        CliError::input(format!("policy pack {} cannot be used: {id}: {why}", self.shown)).with_hint(
            "a pack whose signature does not count as its authority's is not evaluated: get the pack again from \
             its authority, or check the policy_authorities you trust for it (specs/trust-store-format-v0.1.md §4.2)",
        )
    }

    /// A pack `--require-signed-pack` does not accept, refused as `id`.
    fn not_accepted(&self, id: &str, why: String) -> CliError {
        CliError::input(format!("policy pack {} cannot be used: {id}: {why}", self.shown)).with_hint(
            "trust the authority's key in the policy_authorities of the trust store, or of --authority-store \
             (specs/trust-store-format-v0.1.md §4.2); without --require-signed-pack such a pack is evaluated, and \
             the output says it is unsigned or not checked",
        )
    }
}

impl PolicyEvaluator for PackEvaluator {
    fn policy_pack_id(&self) -> &str {
        &self.pack.pack_id
    }

    fn evaluate(&self, record: &VerifiedRecord<'_>, evaluation_time: Timestamp) -> PolicyEvaluation {
        // The record as JSON is what the rules' pointers address (P6-3).
        // A record that does not serialise cannot happen — it was parsed
        // from JSON or CBOR by the verifier — and if it ever did, an empty
        // document leaves every rule Indeterminate, which is the honest
        // answer and never a false pass.
        let value = serde_json::to_value(record.record()).unwrap_or(serde_json::Value::Null);
        let evaluation =
            self.pack.evaluate_in_context(&value, &lineage_context(record), evaluation_time);
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

/// What verification established about the record's lineage, in
/// vmr-policy's words (P6-17): the outcome, and each predecessor whose link
/// verified with the signed payload hash the verifier recomputed for it,
/// immediate predecessor first. The verifier lists a link and its decoded
/// predecessor in the same order, one for one.
fn lineage_context(record: &VerifiedRecord<'_>) -> EvaluationContext {
    let lineage = record.lineage();
    let predecessors = lineage
        .verified_links
        .iter()
        .zip(record.verified_predecessors())
        .map(|(link, predecessor)| VerifiedPredecessor {
            signed_payload_hash: link.signed_payload_hash.clone(),
            // As for the record itself: a predecessor that does not
            // serialise leaves the rules that read it Indeterminate.
            record: serde_json::to_value(predecessor).unwrap_or(serde_json::Value::Null),
        })
        .collect();
    EvaluationContext { lineage: LineageContext { outcome: outcome(lineage.status), predecessors } }
}

/// A lineage status in vmr-policy's words. A broken lineage fails
/// verification and is never evaluated; were one handed over, it would read
/// as not checked, which no lineage rule passes.
fn outcome(status: LineageStatus) -> LineageOutcome {
    match status {
        LineageStatus::Initial => LineageOutcome::Initial,
        LineageStatus::Complete => LineageOutcome::Complete,
        LineageStatus::Partial => LineageOutcome::Partial,
        LineageStatus::NotChecked | LineageStatus::Broken => LineageOutcome::NotChecked,
    }
}

/// A pack's overall status in the hook's words (P6-1's mapping).
fn overall(status: Status) -> PolicyStatus {
    match status {
        Status::Pass => PolicyStatus::Compliant,
        Status::Fail => PolicyStatus::NonCompliant,
        Status::Indeterminate => PolicyStatus::Indeterminate,
    }
}

/// One rule's status in the hook's words: a rule passes or fails, as the
/// record's own `policy_compliance.results[]` does.
fn rule(status: Status) -> PolicyRuleStatus {
    match status {
        Status::Pass => PolicyRuleStatus::Pass,
        Status::Fail => PolicyRuleStatus::Fail,
        Status::Indeterminate => PolicyRuleStatus::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed EU AI Act reference pack.
    fn eu_pack_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../specs/policy-packs/khalm-reading-eu-ai-act-2026.json")
    }

    #[test]
    fn a_committed_reference_pack_loads_and_names_itself() {
        let e = load(&eu_pack_path()).expect("the committed pack loads");
        assert_eq!(e.policy_pack_id(), "khalm-reading-eu-ai-act-2026");
        assert_eq!(e.pack.pack_version, "1.0.0");
        assert!(e.pack.pack().signature.is_none(), "the reference packs are unsigned");
        assert_eq!(e.signature, PackSignatureState::Unsigned);
    }

    #[test]
    fn a_json_document_that_is_not_a_pack_is_an_input_error_with_a_hint() {
        // The published schema is JSON, and is not a pack: every refusal of
        // a pack file is the operator's error (exit 1) with vmr-policy's own
        // message. The refusals through the binary, a byte order mark
        // included, are tests/cli_verify_policy.rs.
        let schema = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../specs/policy-pack-schema/v0.1.json");
        let e = load(&schema).expect_err("a JSON Schema is not a policy pack");
        assert_eq!(e.code, crate::error::EXIT_INPUT);
        assert!(e.message.contains("cannot be used"), "{}", e.message);
        assert!(e.hint.is_some(), "a refusal says where working examples are");
    }

    #[test]
    fn a_pack_file_that_is_not_there_is_an_input_error() {
        let missing = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("no-such-pack.json");
        let e = load(&missing).expect_err("there is no such file");
        assert_eq!(e.code, crate::error::EXIT_INPUT);
        assert!(e.message.starts_with("cannot read policy pack "), "{}", e.message);
    }

    #[test]
    fn only_an_authority_store_is_named_in_the_evaluation() {
        // P6-16: the trust store is the report's own; an authority store is
        // reported with the evaluation it served, as the trust store is.
        let store = TrustStore::from_json(br#"{"trust_store_version":"0.1","issuers":[]}"#).unwrap();
        assert_eq!(Authorities::TrustStore(&store).name(), "trust store");
        assert_eq!(Authorities::AuthorityStore(&store).name(), "authority store");
        assert_eq!(Authorities::TrustStore(&store).summary(), None);
        assert_eq!(Authorities::AuthorityStore(&store).summary(), Some(AuthorityStoreSummary::of(&store)));
    }

    #[test]
    fn an_unsigned_pack_is_unsigned_whatever_the_authorities_and_refused_only_when_a_signature_is_required() {
        let store = TrustStore::from_json(br#"{"trust_store_version":"0.1","issuers":[]}"#).unwrap();
        let at = Timestamp::parse("2026-09-11T00:00:00Z").unwrap();
        let e = load(&eu_pack_path()).unwrap().check_signature(Authorities::TrustStore(&store), at, false).unwrap();
        assert_eq!((e.signature.clone(), e.authority_store.clone()), (PackSignatureState::Unsigned, None));
        let e = load(&eu_pack_path()).unwrap().check_signature(Authorities::AuthorityStore(&store), at, false).unwrap();
        assert_eq!(e.authority_store, Some(AuthorityStoreSummary::of(&store)));
        let refused =
            load(&eu_pack_path()).unwrap().check_signature(Authorities::TrustStore(&store), at, true).unwrap_err();
        assert_eq!(refused.code, crate::error::EXIT_INPUT);
        assert!(refused.message.contains("--require-signed-pack"), "{}", refused.message);
        assert!(refused.message.contains(&format!("cannot be used: {UNSIGNED_REFUSED}: ")), "{}", refused.message);
    }

    #[test]
    fn the_three_statuses_map_to_the_hooks_two_vocabularies() {
        assert_eq!(overall(Status::Pass), PolicyStatus::Compliant);
        assert_eq!(overall(Status::Fail), PolicyStatus::NonCompliant);
        assert_eq!(overall(Status::Indeterminate), PolicyStatus::Indeterminate);
        assert_eq!(rule(Status::Pass), PolicyRuleStatus::Pass);
        assert_eq!(rule(Status::Fail), PolicyRuleStatus::Fail);
        assert_eq!(rule(Status::Indeterminate), PolicyRuleStatus::Indeterminate);
    }

    #[test]
    fn every_lineage_status_maps_and_a_broken_one_reads_as_not_checked() {
        assert_eq!(outcome(LineageStatus::Initial).id(), "initial");
        assert_eq!(outcome(LineageStatus::Complete).id(), "complete");
        assert_eq!(outcome(LineageStatus::Partial).id(), "partial");
        assert_eq!(outcome(LineageStatus::NotChecked).id(), "not_checked");
        assert_eq!(outcome(LineageStatus::Broken).id(), "not_checked");
    }
}
