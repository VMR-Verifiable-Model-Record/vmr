// tests/verify_chain.rs — lineage (Phase 4 task 4.4, decision D6; TASKS
// "test_verify_chain"): lineage.consistency and lineage.chain over
// caller-supplied predecessors. Chains are built from the vector by
// re-signing templates with the derived test keys.

mod common;

use common::*;
use vmr_record::record::Record;
use vmr_verify::report::{CheckId, LineageStatus, Outcome, VerificationReport};
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

const U2: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b2";
const U3: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b3";
const U9: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b9";

/// A successor of `prev`: a new id and issued_at, lineage pointing at
/// `prev` by its RECOMPUTED signed payload hash, signed with `key_label`.
fn successor(prev: &Record, id: &str, issued_at: &str, kind: &str, key_label: &str) -> Record {
    let mut p = prev.clone();
    p.record_id = id.into();
    p.issued_at = issued_at.into();
    p.lineage.previous_record_id = Some(prev.record_id.clone());
    p.lineage.previous_record_hash = Some(prev.signed_payload_hash().unwrap());
    p.lineage.lineage_chain_length = prev.lineage.lineage_chain_length + 1;
    p.lineage.root_record_id = prev.lineage.root_record_id.clone();
    p.lineage.lineage_type = kind.into();
    reissue_with(&mut p, key_label);
    p
}

/// P1 (the vector, initial) <- P2 (training-update) <- P3 (fine-tune).
fn chain() -> (Record, Record, Record) {
    let p1 = vector();
    let p2 = successor(&p1, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
    let p3 = successor(&p2, U3, "2026-09-10T18:00:00Z", "fine-tune", KEY_A);
    (p1, p2, p3)
}

fn verify_with(store: TrustStore, head: &[u8], previous: &[&[u8]], complete: bool) -> VerificationReport {
    let opts = VerifyOptions::new(vmr_record::timestamp::Timestamp::parse(T).unwrap())
        .with_previous(previous)
        .require_complete_lineage(complete);
    Verifier::new(store).verify(head, &opts)
}

fn verify_chain(head: &Record, previous: &[&Record], complete: bool) -> VerificationReport {
    let bytes: Vec<Vec<u8>> = previous.iter().map(|p| json_of(p)).collect();
    let refs: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    verify_with(basic_store(), &json_of(head), &refs, complete)
}

fn status(r: &VerificationReport) -> LineageStatus {
    r.lineage.as_ref().expect("lineage section").status
}

fn chain_outcome(r: &VerificationReport) -> Outcome {
    r.checks.iter().find(|c| c.id == CheckId::LineageChain).unwrap().outcome
}

#[test]
fn an_initial_record_is_initial() {
    let r = verify_chain(&vector(), &[], false);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::Initial);
    assert_eq!(chain_outcome(&r), Outcome::Pass);
    let l = r.lineage.unwrap();
    assert_eq!((l.lineage_type.as_str(), l.declared_chain_length), ("initial", 1));
    assert!(l.verified_links.is_empty());
}

#[test]
fn two_and_three_link_chains_are_complete() {
    let (p1, p2, p3) = chain();
    let r = verify_chain(&p2, &[&p1], false);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::Complete);
    let links = &r.lineage.as_ref().unwrap().verified_links;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].record_id, p1.record_id);
    assert_eq!(links[0].signed_payload_hash, p1.signed_payload_hash().unwrap());

    let r = verify_chain(&p3, &[&p2, &p1], true);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::Complete);
    let ids: Vec<&str> = r.lineage.as_ref().unwrap().verified_links.iter().map(|l| l.record_id.as_str()).collect();
    assert_eq!(ids, [U2, p1.record_id.as_str()]);
}

#[test]
fn a_head_without_predecessors_is_not_checked() {
    let (_, p2, _) = chain();
    let r = verify_chain(&p2, &[], false);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::NotChecked);
    assert_eq!(chain_outcome(&r), Outcome::NotEvaluated);
    // ... unless the caller requires a complete lineage.
    let r = verify_chain(&p2, &[], true);
    assert_fails_at(&r, CheckId::LineageChain);
    assert_eq!(status(&r), LineageStatus::NotChecked);
}

#[test]
fn only_the_immediate_predecessor_is_partial() {
    let (_, p2, p3) = chain();
    let r = verify_chain(&p3, &[&p2], false);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::Partial);
    assert_eq!(chain_outcome(&r), Outcome::NotEvaluated);
    assert_eq!(r.lineage.as_ref().unwrap().verified_links.len(), 1);
    let r = verify_chain(&p3, &[&p2], true);
    assert_fails_at(&r, CheckId::LineageChain);
    assert_eq!(status(&r), LineageStatus::Partial);
}

#[test]
fn each_link_rule_broken_once_breaks_the_chain() {
    let (p1, p2, _) = chain();
    type Edit = fn(&mut Record);
    let cases: [(&str, Edit); 5] = [
        ("hash", |p| p.lineage.previous_record_hash = Some(format!("sha256:{}", "ab".repeat(32)))),
        ("id", |p| p.lineage.previous_record_id = Some(U9.into())),
        ("root", |p| p.lineage.root_record_id = U9.into()),
        ("length", |p| p.lineage.lineage_chain_length = 3),
        // The policy evaluation moves with issued_at, so this case breaks
        // the link rule alone and not time.policy_not_after_issued (P6-6).
        ("issued_at order", |p| {
            p.issued_at = "2026-09-09T00:00:00Z".into();
            p.policy_compliance.evaluated_at = "2026-09-09T00:00:00Z".into();
        }),
    ];
    for (what, edit) in cases {
        let mut bad = p2.clone();
        edit(&mut bad);
        sign_as(&mut bad, KEY_A);
        let r = verify_chain(&bad, &[&p1], false);
        assert_fails_at(&r, CheckId::LineageChain);
        assert_eq!(status(&r), LineageStatus::Broken, "{what}");
    }
}

#[test]
fn a_predecessor_that_does_not_verify_breaks_the_chain() {
    // Signed by a key the store does not know.
    let mut unknown = vector();
    reissue_with(&mut unknown, KEY_F);
    let head = successor(&unknown, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
    let r = verify_chain(&head, &[&unknown], false);
    assert_fails_at(&r, CheckId::LineageChain);
    assert!(r.failure.unwrap().detail.contains("trust.key_known"));

    // Signed by a revoked key (A2), while the head's key (A) is fine.
    let mut by_a2 = vector();
    reissue_with(&mut by_a2, KEY_A2);
    let head = successor(&by_a2, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
    let mut revoked = Entry::new(VECTOR_ISSUER, KEY_A2);
    revoked.revoked = true;
    let store = store(&[Entry::new(VECTOR_ISSUER, KEY_A), revoked]);
    let r = verify_with(store, &json_of(&head), &[&json_of(&by_a2)], false);
    assert_fails_at(&r, CheckId::LineageChain);
    assert!(r.failure.unwrap().detail.contains("trust.key_not_revoked"));

    // Its signature section lies about its payload hash: the head names the
    // real (recomputed) hash, and the predecessor fails its own verification.
    let (p1, p2, _) = chain();
    let mut lying = p1.clone();
    lying.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
    let r = verify_chain(&p2, &[&lying], false);
    assert_fails_at(&r, CheckId::LineageChain);
    assert!(r.failure.unwrap().detail.contains("signature.payload_hash"));
}

#[test]
fn a_predecessor_nested_deeper_than_a_record_breaks_the_chain() {
    // Spec §2 rule 13 binds every predecessor too, which verifies in full on
    // its own (§6.5): nested deeper than a record, its JSON form fails
    // json.structure and its COSE payload cose.payload, at every depth, and
    // an envelope nested past 16 CBOR levels (§4.4) fails cose.structure.
    // The head's lineage is broken, and the reason names the predecessor's
    // check.
    let (p1, p2, _) = chain();
    let compact = serde_json::to_string(&p1).unwrap();
    let payload = String::from_utf8(p1.signed_payload().unwrap()).unwrap();
    let mut deep: Vec<(String, Vec<u8>, &str)> = Vec::new();
    for levels in [5usize, 128, 100_000] {
        let json = nested_at_issuer_name(&compact, levels).into_bytes();
        deep.push((format!("JSON, {levels} levels"), json, "json.structure"));
        let cose = cose_with_payload(&p1, nested_at_issuer_name(&payload, levels).into_bytes());
        deep.push((format!("COSE payload, {levels} levels"), cose, "cose.payload"));
    }
    let envelope = cose_with_unprotected(&p1, &unprotected_nested(257));
    deep.push(("COSE envelope, 257 CBOR levels".into(), envelope, "cose.structure"));
    for (what, bytes, check) in deep {
        let r = verify_with(basic_store(), &json_of(&p2), &[&bytes], false);
        assert_fails_at(&r, CheckId::LineageChain);
        assert_eq!(status(&r), LineageStatus::Broken, "{what}");
        let detail = r.failure.unwrap().detail;
        let reason = format!("predecessor 1 does not verify on its own: {check}: ");
        assert!(detail.starts_with(&reason), "{what}: {detail}");
    }
}

#[test]
fn predecessors_out_of_order_break_the_chain() {
    let (p1, p2, p3) = chain();
    let r = verify_chain(&p3, &[&p1, &p2], false);
    assert_fails_at(&r, CheckId::LineageChain);
    assert_eq!(status(&r), LineageStatus::Broken);
}

#[test]
fn predecessors_for_an_initial_record_break_the_chain() {
    let (p1, p2, _) = chain();
    let r = verify_chain(&p1, &[&p1], false);
    assert_fails_at(&r, CheckId::LineageChain);
    // More predecessors after the initial one.
    let r = verify_chain(&p2, &[&p1, &p1], false);
    assert_fails_at(&r, CheckId::LineageChain);
    assert_eq!(status(&r), LineageStatus::Broken);
}

#[test]
fn more_than_1024_predecessors_break_the_chain() {
    let (p1, p2, _) = chain();
    let one = json_of(&p1);
    let many: Vec<&[u8]> = std::iter::repeat_n(one.as_slice(), 1025).collect();
    let r = verify_with(basic_store(), &json_of(&p2), &many, false);
    assert_fails_at(&r, CheckId::LineageChain);
    assert!(r.failure.unwrap().detail.contains("1024"));
}

#[test]
fn json_and_cose_mix_in_one_chain() {
    let (p1, p2, p3) = chain();
    let prev = [json_of(&p2), p1.to_cose().unwrap()];
    let refs: Vec<&[u8]> = prev.iter().map(Vec::as_slice).collect();
    let r = verify_with(basic_store(), &p3.to_cose().unwrap(), &refs, true);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::Complete);
}

#[test]
fn the_link_hash_is_the_predecessors_recomputed_payload_hash() {
    // Pretty and compact JSON, and COSE, of the same predecessor: one hash.
    let (p1, p2, _) = chain();
    let compact = serde_json::to_vec(&p1).unwrap();
    for bytes in [json_of(&p1), compact, p1.to_cose().unwrap()] {
        let r = verify_with(basic_store(), &json_of(&p2), &[&bytes], false);
        assert_passes(&r);
    }
}

#[test]
fn key_rotation_never_breaks_an_old_link() {
    // P1 signed by A inside A's window, P2 by A2 after A's window ended.
    let (p1, _, _) = chain();
    let p2 = successor(&p1, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A2);
    let mut a = Entry::new(VECTOR_ISSUER, KEY_A);
    a.valid_until = Some("2026-09-10T06:00:00Z");
    let mut a2 = Entry::new(VECTOR_ISSUER, KEY_A2);
    a2.valid_from = "2026-09-10T06:00:00Z";
    let r = verify_with(store(&[a, a2]), &json_of(&p2), &[&json_of(&p1)], true);
    assert_passes(&r);
    assert_eq!(status(&r), LineageStatus::Complete);
}

#[test]
fn the_records_own_lineage_members_must_agree() {
    // lineage.consistency, each rule broken once (re-signed, so only the
    // lineage members are wrong).
    let (_, p2, _) = chain();
    type Edit = fn(&mut Record);
    let cases: [(&str, Record, Edit); 6] = [
        ("initial naming a predecessor", vector(), |p| {
            p.lineage.previous_record_id = Some(U9.into());
            p.lineage.previous_record_hash = Some(format!("sha256:{}", "ab".repeat(32)));
        }),
        ("initial with length 2", vector(), |p| p.lineage.lineage_chain_length = 2),
        ("initial not its own root", vector(), |p| p.lineage.root_record_id = U9.into()),
        ("non-initial without predecessor", p2.clone(), |p| {
            p.lineage.previous_record_id = None;
            p.lineage.previous_record_hash = None;
        }),
        ("non-initial with length 1", p2.clone(), |p| p.lineage.lineage_chain_length = 1),
        ("only one of the two members", p2.clone(), |p| p.lineage.previous_record_hash = None),
    ];
    for (what, base, edit) in cases {
        let mut p = base;
        edit(&mut p);
        sign_as(&mut p, KEY_A);
        let r = verify_chain(&p, &[], false);
        assert_fails_at(&r, CheckId::LineageConsistency);
        assert_eq!(status(&r), LineageStatus::Broken, "{what}");
    }
    // A non-initial record that names itself as root, or as predecessor.
    let mut own_root = p2.clone();
    own_root.lineage.root_record_id = own_root.record_id.clone();
    sign_as(&mut own_root, KEY_A);
    assert_fails_at(&verify_chain(&own_root, &[], false), CheckId::LineageConsistency);
    let mut own_prev = p2.clone();
    own_prev.lineage.previous_record_id = Some(own_prev.record_id.clone());
    sign_as(&mut own_prev, KEY_A);
    assert_fails_at(&verify_chain(&own_prev, &[], false), CheckId::LineageConsistency);
}

#[test]
fn lineage_consistency_details_name_the_rule_broken() {
    // What each lineage.consistency failure says, and the two pass details.
    // The rule itself lives in vmr-record (Record::check_lineage_consistency,
    // which the builder runs before signing too); moving it there changed
    // no verdict, no check id and no detail.
    let (_, p2, _) = chain();
    type Edit = fn(&mut Record);
    let cases: [(Record, Edit, &str); 8] = [
        (vector(), |p| {
            p.lineage.previous_record_id = Some(U9.into());
            p.lineage.previous_record_hash = Some(format!("sha256:{}", "ab".repeat(32)));
        }, "an initial record names no predecessor"),
        (vector(), |p| p.lineage.lineage_chain_length = 2, "an initial record has lineage_chain_length 1, not 2"),
        (vector(), |p| p.lineage.root_record_id = U9.into(), "an initial record is its own root: root_record_id must be its record_id"),
        (p2.clone(), |p| {
            p.lineage.previous_record_id = None;
            p.lineage.previous_record_hash = None;
        }, "a \"training-update\" record must name its predecessor"),
        (p2.clone(), |p| p.lineage.lineage_chain_length = 1, "a \"training-update\" record has a predecessor, so lineage_chain_length >= 2, not 1"),
        (p2.clone(), |p| p.lineage.previous_record_hash = None, "previous_record_id and previous_record_hash must be both present or both absent"),
        (p2.clone(), |p| p.lineage.root_record_id = p.record_id.clone(), "only an initial record is its own root"),
        (p2.clone(), |p| p.lineage.previous_record_id = Some(p.record_id.clone()), "a record cannot be its own predecessor"),
    ];
    for (base, edit, detail) in cases {
        let mut p = base;
        edit(&mut p);
        sign_as(&mut p, KEY_A);
        let r = verify_chain(&p, &[], false);
        assert_fails_at(&r, CheckId::LineageConsistency);
        assert_eq!(r.failure.unwrap().detail, detail);
    }
    let detail_of = |r: &VerificationReport| {
        r.checks.iter().find(|c| c.id == CheckId::LineageConsistency).unwrap().detail.clone()
    };
    assert_eq!(detail_of(&verify_chain(&vector(), &[], false)), "initial: no predecessor, chain length 1, its own root");
    assert_eq!(
        detail_of(&verify_chain(&p2, &[], false)),
        "\"training-update\": names its predecessor, chain length 2, a root other than itself"
    );
}

#[test]
fn the_report_records_the_predecessors_it_was_given() {
    let (p1, p2, _) = chain();
    let bytes = json_of(&p1);
    let r = verify_with(basic_store(), &json_of(&p2), &[&bytes], true);
    assert_eq!(r.previous, [vmr_record::hash::format_hash(&vmr_record::hash::sha256(&bytes))]);
    assert!(r.require_complete_lineage);
    let r = verify_chain(&vector(), &[], false);
    assert!(r.previous.is_empty() && !r.require_complete_lineage);
}

#[test]
fn a_failure_before_the_lineage_checks_leaves_no_lineage_section() {
    let mut forged = vector();
    reissue_with(&mut forged, KEY_F);
    let r = verify_chain(&forged, &[], false);
    assert_fails_at(&r, CheckId::TrustKeyKnown);
    assert!(r.lineage.is_none());
}
