// tests/evaluate_full.rs — the whole-pack result: how severities aggregate
// into the overall status (P6-1), and the one boundary where the crate's
// three-valued result becomes the record's two-valued `policy_compliance`.
//
// The conversion has to produce a section the record schema accepts, or
// the builder would have to invent its own shape later; that is asserted
// here by putting the converted section into the committed conformance
// record and running the record's own `validate_format`.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_policy::vmr_record::record::Record;
use vmr_policy::Status::{Fail, Indeterminate, Pass};

fn rule(rule_id: &str, severity: &str, minimum_level: &str) -> Value {
    json!({
        "type": "attestation_level",
        "rule_id": rule_id,
        "description": "The issuer attests.",
        "severity": severity,
        "reference": "vmr-policy tests, evaluate_full.rs",
        "minimum_level": minimum_level
    })
}

fn pack_of(rules: Vec<Value>) -> vmr_policy::LoadedPack {
    vmr_policy::load_pack(&pack_document(json!(rules)).to_string()).expect("fixture pack")
}

fn issuer(level: &str) -> Value {
    json!({"issuer": {"attestation_level": level}})
}

#[test]
fn the_overall_status_comes_from_the_mandatory_rules_only() {
    let record = issuer("software");
    // A recommended rule that fails does not move the overall status.
    let pack = pack_of(vec![
        rule("ok", "mandatory", "software"),
        rule("advisory", "recommended", "hardware"),
        rule("noted", "informational", "hardware"),
    ]);
    let evaluation = pack.evaluate(&record, now());
    assert_eq!(evaluation.result("advisory").unwrap().status, Fail);
    assert_eq!(evaluation.result("noted").unwrap().status, Fail);
    assert_eq!(evaluation.overall, Pass);

    // A mandatory failure does.
    let pack = pack_of(vec![rule("hard", "mandatory", "hardware")]);
    assert_eq!(pack.evaluate(&record, now()).overall, Fail);
}

#[test]
fn a_mandatory_failure_outweighs_a_mandatory_indeterminate() {
    let pack = pack_of(vec![
        rule("cannot-tell", "mandatory", "software"),
        rule("clearly-fails", "mandatory", "hardware"),
    ]);
    // The first is indeterminate (nothing declared), the second fails.
    let evaluation = pack.evaluate(&json!({}), now());
    assert_eq!(evaluation.result("cannot-tell").unwrap().status, Indeterminate);
    assert_eq!(evaluation.overall, Indeterminate, "nothing is declared, so nothing fails");

    let evaluation = pack.evaluate(&issuer("self"), now());
    assert_eq!(evaluation.result("clearly-fails").unwrap().status, Fail);
    assert_eq!(evaluation.overall, Fail);
}

#[test]
fn a_mandatory_indeterminate_is_not_compliance() {
    let pack = pack_of(vec![rule("cannot-tell", "mandatory", "software")]);
    let evaluation = pack.evaluate(&json!({}), now());
    assert_eq!(evaluation.overall, Indeterminate);
    assert_eq!(evaluation.indeterminate, vec!["cannot-tell".to_string()]);
    assert_eq!(evaluation.to_policy_compliance().overall_status, "indeterminate");
}

#[test]
fn the_evaluation_carries_every_rule_in_the_packs_order() {
    let pack = pack_of(vec![
        rule("one", "mandatory", "software"),
        rule("two", "recommended", "software"),
        rule("three", "informational", "hardware"),
    ]);
    let evaluation = pack.evaluate(&issuer("software"), now());
    let ids: Vec<&str> = evaluation.results.iter().map(|r| r.rule_id.as_str()).collect();
    assert_eq!(ids, ["one", "two", "three"]);
    for result in &evaluation.results {
        assert_eq!(result.rule_type, "attestation_level");
        assert!(result.evidence_hash.starts_with("sha256:"));
        assert!(!result.detail.is_empty());
        assert!(result.reference.contains("evaluate_full.rs"));
    }
    assert_eq!(evaluation.pack_id, "test-pack");
    assert_eq!(evaluation.evaluated_at.to_string(), NOW);
}

#[test]
fn an_indeterminate_rule_is_omitted_from_the_records_results() {
    // P6-1: the v0.1 schema's per-rule enum is pass | fail. An
    // indeterminate rule cannot be written there, so it is left out and its
    // id stays in the evaluation.
    let pack = pack_of(vec![
        rule("decided", "mandatory", "software"),
        rule("undecided", "mandatory", "software"),
    ]);
    let record = json!({"issuer": {"attestation_level": "self"}});
    let evaluation = pack.evaluate(&record, now());
    assert_eq!(evaluation.result("undecided").unwrap().status, Fail);

    // Now make the second one indeterminate by declaring nothing.
    let evaluation = pack.evaluate(&json!({}), now());
    assert_eq!(evaluation.results.len(), 2);
    assert_eq!(evaluation.indeterminate, vec!["decided".to_string(), "undecided".to_string()]);
    let section = evaluation.to_policy_compliance();
    assert!(section.results.is_empty(), "{:?}", section.results);
    assert_eq!(section.overall_status, "indeterminate");
}

#[test]
fn the_statuses_map_to_the_records_words() {
    let pack = pack_of(vec![
        rule("passes", "mandatory", "software"),
        rule("fails", "recommended", "hardware"),
    ]);
    let evaluation = pack.evaluate(&issuer("software"), now());
    let section = evaluation.to_policy_compliance();
    assert_eq!(section.policy_pack_id, "test-pack");
    assert_eq!(section.evaluated_at, NOW);
    assert_eq!(section.overall_status, "compliant");
    let words: Vec<(&str, &str)> =
        section.results.iter().map(|r| (r.rule_id.as_str(), r.status.as_str())).collect();
    assert_eq!(words, [("passes", "pass"), ("fails", "fail")]);
    for result in &section.results {
        assert!(result.evidence_hash.starts_with("sha256:"), "{:?}", result.evidence_hash);
        assert_eq!(result.evidence_hash.len(), "sha256:".len() + 64);
    }
}

#[test]
fn the_converted_section_validates_against_the_record_schema() {
    // The point of P6-1: whatever this crate produces must be a section the
    // record's own rules accept, so a builder cannot be forced to invent
    // one. The conformance vector is the host; only policy_compliance moves.
    let vector = conformance_record();
    let pack = eu_pack();
    for record in [vector.clone(), json!({}), json!({"issuer": {"attestation_level": "self"}})] {
        let evaluation = pack.evaluate(&record, at("2026-09-10T00:00:00Z"));
        let mut document = vector.clone();
        document["policy_compliance"] = serde_json::to_value(evaluation.to_policy_compliance())
            .expect("the section serializes");
        let text = document.to_string();
        let parsed = Record::from_json(&text)
            .unwrap_or_else(|e| panic!("the section is not a record member: {e}"));
        parsed
            .validate_format()
            .unwrap_or_else(|v| panic!("the section breaks a record rule: {v}"));
    }
}

#[test]
fn the_converted_sections_evaluated_at_is_the_evaluation_time() {
    // P6-6: a builder must be able to keep evaluated_at <= issued_at, which
    // it can only do if the section carries the time it was given.
    let pack = eu_pack();
    for t in ["2026-09-09T00:00:00Z", "2026-09-10T00:00:00Z"] {
        let section = pack.evaluate(&conformance_record(), at(t)).to_policy_compliance();
        assert_eq!(section.evaluated_at, t);
    }
}
