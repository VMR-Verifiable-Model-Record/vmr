// tests/verify_policy.rs — the policy hook (Phase 4 task 4.5; TASKS
// "test_verify_policy"). The verifier ships only the trait (vmr-policy is
// Phase 6): an evaluator runs only on a verified record, its result is
// reported next to the record's own declaration - never merged with it -
// and it never changes the verdict.

mod common;

use common::*;
use std::cell::Cell;
use vmr_record::timestamp::Timestamp;
use vmr_verify::policy::{
    AuthorityStoreSummary, PackSignatureState, PolicyEvaluation, PolicyEvaluator, PolicyRuleResult,
    PolicyRuleStatus, PolicyStatus, VerifiedRecord,
};

/// The payload hash the stub reports for its pack.
const PAYLOAD_HASH: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
use vmr_verify::report::{CheckId, EvaluationState, Verdict};
use vmr_verify::{TrustStore, Verifier, VerificationReport, VerifyOptions};

/// A stub evaluator: returns `status`, counts its calls, remembers what it
/// was shown.
struct Stub {
    pack: &'static str,
    version: &'static str,
    signature: PackSignatureState,
    authority_store: Option<AuthorityStoreSummary>,
    status: PolicyStatus,
    rule_status: PolicyRuleStatus,
    panics: bool,
    calls: Cell<u32>,
    saw: std::cell::RefCell<Option<(String, String, String)>>,
}

impl Stub {
    fn new(status: PolicyStatus) -> Self {
        Stub {
            pack: "example-policy-pack-v1",
            version: "1.0.0",
            signature: PackSignatureState::Unsigned,
            authority_store: None,
            status,
            rule_status: match status {
                PolicyStatus::Compliant => PolicyRuleStatus::Pass,
                PolicyStatus::NonCompliant => PolicyRuleStatus::Fail,
                PolicyStatus::Indeterminate => PolicyRuleStatus::Indeterminate,
            },
            panics: false,
            calls: Cell::new(0),
            saw: std::cell::RefCell::new(None),
        }
    }
}

impl PolicyEvaluator for Stub {
    fn policy_pack_id(&self) -> &str {
        self.pack
    }

    fn evaluate(&self, record: &VerifiedRecord<'_>, evaluation_time: Timestamp) -> PolicyEvaluation {
        self.calls.set(self.calls.get() + 1);
        *self.saw.borrow_mut() = Some((
            record.record().record_id.clone(),
            record.trusted_issuer_id().to_string(),
            evaluation_time.to_string(),
        ));
        if self.panics {
            panic!("a policy evaluator bug");
        }
        PolicyEvaluation {
            status: self.status,
            pack_version: self.version.into(),
            pack_payload_hash: PAYLOAD_HASH.into(),
            pack_signature: self.signature.clone(),
            authority_store: self.authority_store.clone(),
            rules: vec![PolicyRuleResult {
                rule_id: "example-data-residency".into(),
                status: self.rule_status,
                severity: "mandatory".into(),
                reference: "Example Act Art. 1".into(),
                evidence_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
                detail: "stub".into(),
            }],
        }
    }
}

fn verify_with_policy(p: &vmr_record::record::Record, evaluator: &dyn PolicyEvaluator) -> VerificationReport {
    let opts = VerifyOptions::new(Timestamp::parse(T).unwrap()).with_policy(evaluator);
    Verifier::new(basic_store()).verify_json(&json_of(p), &opts)
}

#[test]
fn without_an_evaluator_the_declaration_is_shown_and_nothing_is_evaluated() {
    let report = verify_basic(&vector());
    assert_passes(&report);
    let policy = &report.policy;
    assert_eq!(policy.declared.as_ref(), Some(&vector().policy_compliance), "verbatim");
    assert_eq!(policy.evaluation, EvaluationState::NotRequested);
    assert!(report.accepted);
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn a_compliant_evaluation_is_accepted() {
    let stub = Stub::new(PolicyStatus::Compliant);
    let report = verify_with_policy(&vector(), &stub);
    assert_passes(&report);
    match &report.policy.evaluation {
        EvaluationState::Evaluated { policy_pack_id, status, rules, .. } => {
            assert_eq!(policy_pack_id, "example-policy-pack-v1");
            assert_eq!(*status, PolicyStatus::Compliant);
            assert_eq!(rules.len(), 1);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(stub.calls.get(), 1);
}

#[test]
fn non_compliant_and_indeterminate_pass_the_verdict_but_are_not_accepted() {
    for status in [PolicyStatus::NonCompliant, PolicyStatus::Indeterminate] {
        let report = verify_with_policy(&vector(), &Stub::new(status));
        assert_eq!(report.verdict, Verdict::Pass, "the verdict is about authenticity");
        assert!(report.failure.is_none());
        assert!(!report.accepted);
        assert_eq!(report.exit_code(), 4);
    }
}

#[test]
fn the_evaluator_is_never_called_for_a_failing_record() {
    let mut forged = vector();
    reissue_with(&mut forged, KEY_F);
    let stub = Stub::new(PolicyStatus::Compliant);
    let report = verify_with_policy(&forged, &stub);
    assert_fails_at(&report, CheckId::TrustKeyKnown);
    assert_eq!(stub.calls.get(), 0, "an unverified record never reaches a policy");
    assert!(matches!(report.policy.evaluation, EvaluationState::Skipped { .. }));
}

#[test]
fn a_panicking_evaluator_is_contained_and_not_accepted() {
    let mut stub = Stub::new(PolicyStatus::Compliant);
    stub.panics = true;
    let report = verify_with_policy(&vector(), &stub);
    assert_eq!(report.verdict, Verdict::Pass);
    assert!(!report.accepted);
    assert_eq!(report.exit_code(), 4);
    assert!(matches!(
        report.policy.evaluation,
        EvaluationState::EvaluatorPanicked { ref policy_pack_id } if policy_pack_id == "example-policy-pack-v1"
    ));
}

#[test]
fn a_declared_non_compliance_still_verifies_and_is_shown_as_declared() {
    let p = vector_edited(|p| p.policy_compliance.overall_status = "non-compliant".into());
    let report = verify_basic(&p);
    assert_passes(&report);
    let policy = report.policy;
    assert_eq!(policy.declared.unwrap().overall_status, "non-compliant");
    assert_eq!(policy.evaluation, EvaluationState::NotRequested);
}

#[test]
fn an_unevaluated_report_contains_no_evaluated_status() {
    let json: serde_json::Value = serde_json::from_str(&verify_basic(&vector()).to_json().unwrap()).unwrap();
    assert_eq!(json["policy"]["evaluation"], serde_json::json!({"state": "not_requested"}));
    // The declaration is under `declared`, never presented as an evaluation.
    assert_eq!(json["policy"]["declared"]["overall_status"], "compliant");
}

#[test]
fn a_pack_mismatch_is_noted_not_failed() {
    let mut stub = Stub::new(PolicyStatus::Compliant);
    stub.pack = "another-pack-v2";
    let report = verify_with_policy(&vector(), &stub);
    assert!(report.accepted);
    match report.policy.evaluation {
        EvaluationState::Evaluated { detail, .. } => {
            let d = detail.expect("a note");
            assert!(d.contains("example-policy-pack-v1") && d.contains("another-pack-v2"), "{d}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_evaluator_sees_the_verified_record_the_trusted_issuer_and_t() {
    let stub = Stub::new(PolicyStatus::Compliant);
    verify_with_policy(&vector(), &stub);
    let saw = stub.saw.borrow().clone().unwrap();
    assert_eq!(saw, (vector().record_id, VECTOR_ISSUER.to_string(), T.to_string()));
}

#[test]
fn predecessors_are_verified_without_the_policy() {
    // A chain's predecessors are verified in full, but a policy judges only
    // the record asked about: one call.
    let prev = vector();
    let mut head = prev.clone();
    head.record_id = "urn:uuid:00000000-0000-4000-8000-0000000000b2".into();
    head.issued_at = "2026-09-10T12:00:00Z".into();
    head.lineage.previous_record_id = Some(prev.record_id.clone());
    head.lineage.previous_record_hash = Some(prev.signed_payload_hash().unwrap());
    head.lineage.lineage_chain_length = 2;
    head.lineage.lineage_type = "training-update".into();
    reissue_with(&mut head, KEY_A);
    let stub = Stub::new(PolicyStatus::Compliant);
    let prev_bytes = json_of(&prev);
    let previous: [&[u8]; 1] = [&prev_bytes];
    let opts = VerifyOptions::new(Timestamp::parse(T).unwrap()).with_previous(&previous).with_policy(&stub);
    let report = Verifier::new(basic_store()).verify_json(&json_of(&head), &opts);
    assert_passes(&report);
    assert_eq!(stub.calls.get(), 1);
}

/// What [`LineageProbe`] saw: the outcome, the ids of the links the report
/// lists, and the ids of the decoded predecessors.
type SeenLineage = (vmr_verify::report::LineageStatus, Vec<String>, Vec<String>);

/// One lineage case: what it is, the record, the predecessors supplied,
/// and the outcome and predecessor ids the evaluator must see.
type LineageCase<'a> =
    (&'a str, &'a vmr_record::record::Record, Vec<&'a [u8]>, vmr_verify::report::LineageStatus, Vec<String>);

/// An evaluator that records the lineage it was shown.
struct LineageProbe {
    saw: std::cell::RefCell<Option<SeenLineage>>,
}

impl PolicyEvaluator for LineageProbe {
    fn policy_pack_id(&self) -> &str {
        "example-policy-pack-v1"
    }

    fn evaluate(&self, record: &VerifiedRecord<'_>, _t: Timestamp) -> PolicyEvaluation {
        let lineage = record.lineage();
        *self.saw.borrow_mut() = Some((
            lineage.status,
            lineage.verified_links.iter().map(|l| l.record_id.clone()).collect(),
            record.verified_predecessors().iter().map(|p| p.record_id.clone()).collect(),
        ));
        PolicyEvaluation {
            status: PolicyStatus::Compliant,
            pack_version: "1.0.0".into(),
            pack_payload_hash: PAYLOAD_HASH.into(),
            pack_signature: PackSignatureState::Unsigned,
            authority_store: None,
            rules: Vec::new(),
        }
    }
}

/// A successor of `prev`, signed with key A and linked by its payload hash.
fn successor_of(prev: &vmr_record::record::Record, id: &str, issued_at: &str) -> vmr_record::record::Record {
    let mut next = prev.clone();
    next.record_id = id.into();
    next.issued_at = issued_at.into();
    next.lineage.previous_record_id = Some(prev.record_id.clone());
    next.lineage.previous_record_hash = Some(prev.signed_payload_hash().unwrap());
    next.lineage.lineage_chain_length = prev.lineage.lineage_chain_length + 1;
    next.lineage.lineage_type = "training-update".into();
    reissue_with(&mut next, KEY_A);
    next
}

#[test]
fn the_evaluator_sees_the_verified_lineage_for_every_outcome() {
    // P6-17 (QA Q6-01): a rule may need what verification established about
    // the lineage, not only what the record says. The evaluator is shown
    // the outcome and exactly the predecessors whose links verified,
    // immediate predecessor first. The report JSON does not change.
    use vmr_verify::report::LineageStatus;
    let p1 = vector();
    let p2 = successor_of(&p1, "urn:uuid:00000000-0000-4000-8000-0000000000b2", "2026-09-10T06:00:00Z");
    let p3 = successor_of(&p2, "urn:uuid:00000000-0000-4000-8000-0000000000b3", "2026-09-10T12:00:00Z");
    let (b1, b2) = (json_of(&p1), json_of(&p2));
    let id = |p: &vmr_record::record::Record| p.record_id.clone();

    let cases: [LineageCase; 5] = [
        ("an initial record", &p1, vec![], LineageStatus::Initial, vec![]),
        ("a successor, no predecessor supplied", &p2, vec![], LineageStatus::NotChecked, vec![]),
        ("a successor with its initial predecessor", &p2, vec![&b1], LineageStatus::Complete, vec![id(&p1)]),
        ("a third record with only its immediate predecessor", &p3, vec![&b2], LineageStatus::Partial, vec![id(&p2)]),
        ("a third record with both", &p3, vec![&b2, &b1], LineageStatus::Complete, vec![id(&p2), id(&p1)]),
    ];
    for (what, head, previous, status, ids) in cases {
        let probe = LineageProbe { saw: std::cell::RefCell::new(None) };
        let opts = VerifyOptions::new(Timestamp::parse(T).unwrap()).with_previous(&previous).with_policy(&probe);
        let report = Verifier::new(basic_store()).verify_json(&json_of(head), &opts);
        assert_passes(&report);
        let (seen_status, links, predecessors) = probe.saw.borrow().clone().expect(what);
        assert!(seen_status == status, "{what}: {seen_status:?}");
        assert_eq!(links, ids, "{what}: the links the report lists");
        assert_eq!(predecessors, ids, "{what}: the decoded predecessors are exactly the verified links");
        assert_eq!(report.lineage.as_ref().map(|l| l.status), Some(status), "{what}");
    }
}

#[test]
fn an_evaluated_report_names_the_pack_its_version_its_signature_state_and_each_rules_evidence() {
    // P6-13: a reader of the JSON must be able to tell WHICH pack, at which
    // pack version, decided this, whether that pack's own authority
    // signature was checked, and what each rule looked at (`evidence_hash`),
    // without the declaration being touched.
    let stub = Stub::new(PolicyStatus::NonCompliant);
    let report = verify_with_policy(&vector(), &stub);
    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let e = &json["policy"]["evaluation"];
    assert_eq!(e["state"], "evaluated");
    assert_eq!(e["policy_pack_id"], "example-policy-pack-v1");
    assert_eq!(e["policy_pack_version"], "1.0.0");
    assert_eq!(e["pack_signature"], serde_json::json!({"state": "unsigned"}));
    assert_eq!(e["status"], "non-compliant", "the overall keeps the pack's three words");
    let rule = &e["rules"][0];
    assert_eq!(rule["rule_id"], "example-data-residency");
    assert_eq!(rule["status"], "fail", "a RULE passes or fails, as policy_compliance.results[] does");
    assert_eq!(rule["severity"], "mandatory");
    assert_eq!(rule["reference"], "Example Act Art. 1");
    assert_eq!(
        rule["evidence_hash"],
        "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    );
    // The issuer's declaration is untouched by any of it.
    assert_eq!(json["policy"]["declared"]["overall_status"], "compliant");
    assert_eq!(json["policy"]["declared"]["policy_pack_id"], "example-policy-pack-v1");
}

#[test]
fn a_signed_pack_is_reported_as_signed_and_as_unchecked() {
    // The smallest honest v0.1 statement (P6-13): the report says a pack
    // carries a signature and says it was NOT checked. "Signed" must never
    // be readable as "checked".
    let mut stub = Stub::new(PolicyStatus::Compliant);
    stub.signature = PackSignatureState::NotChecked { signing_key_id: "urn:example:authority-key".into() };
    let report = verify_with_policy(&vector(), &stub);
    match &report.policy.evaluation {
        EvaluationState::Evaluated { pack_signature, policy_pack_version, .. } => {
            assert_eq!(policy_pack_version, "1.0.0");
            assert_eq!(
                *pack_signature,
                PackSignatureState::NotChecked { signing_key_id: "urn:example:authority-key".into() }
            );
        }
        other => panic!("{other:?}"),
    }
    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    assert_eq!(
        json["policy"]["evaluation"]["pack_signature"],
        serde_json::json!({"state": "not_checked", "signing_key_id": "urn:example:authority-key"})
    );
}

#[test]
fn an_evaluated_report_carries_the_pack_payload_hash_a_valid_signature_and_the_authority_store() {
    // P6-16 (docs/TASKS.md 6.16, docs/dev/task-6.16.md A16-12 to A16-14): a
    // signature checked against a trusted authority is `valid` and names the
    // authority as the store does; the pack's payload hash is always there;
    // the authority store's identity is there when one was given, and absent
    // when the trust store held the authorities.
    let mut stub = Stub::new(PolicyStatus::Compliant);
    stub.signature = PackSignatureState::Valid {
        signing_key_id: "urn:example:authority-key".into(),
        authority_id: "example-authority".into(),
        authority_name: "Example Authority".into(),
    };
    let store = TrustStore::from_json(
        br#"{"trust_store_version":"0.1","issuers":[],"policy_authorities":[]}"#,
    )
    .unwrap();
    stub.authority_store = Some(AuthorityStoreSummary::of(&store));
    assert_eq!(
        stub.authority_store,
        Some(AuthorityStoreSummary { sha256: store.sha256().to_string(), authority_count: 0, key_count: 0 })
    );
    let report = verify_with_policy(&vector(), &stub);
    match &report.policy.evaluation {
        EvaluationState::Evaluated { policy_pack_payload_hash, authority_store, .. } => {
            assert_eq!(policy_pack_payload_hash, PAYLOAD_HASH);
            assert_eq!(authority_store.as_deref(), stub.authority_store.as_ref());
        }
        other => panic!("{other:?}"),
    }
    let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let e = &json["policy"]["evaluation"];
    assert_eq!(e["policy_pack_payload_hash"], PAYLOAD_HASH);
    assert_eq!(
        e["pack_signature"],
        serde_json::json!({
            "state": "valid", "signing_key_id": "urn:example:authority-key",
            "authority_id": "example-authority", "authority_name": "Example Authority"
        })
    );
    assert_eq!(
        e["authority_store"],
        serde_json::json!({"sha256": store.sha256(), "authority_count": 0, "key_count": 0})
    );

    let plain = verify_with_policy(&vector(), &Stub::new(PolicyStatus::Compliant));
    let json: serde_json::Value = serde_json::from_str(&plain.to_json().unwrap()).unwrap();
    assert!(json["policy"]["evaluation"].get("authority_store").is_none(), "{json}");
    assert_eq!(json["policy"]["evaluation"]["policy_pack_payload_hash"], PAYLOAD_HASH);
}
