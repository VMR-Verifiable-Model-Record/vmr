// tests/api_surface.rs — Law 8: every public symbol has a test. The parts
// of the API the other files reach only indirectly are exercised here
// directly, so a rename or a wrong word in one of them is caught.

mod common;

use common::*;
use serde_json::json;
use vmr_policy::evaluation::RuleResult;
use vmr_policy::pack::{Rule, RULE_TYPES};
use vmr_policy::schema::{Kind, Scope, SCHEMA_RULES};
use vmr_policy::{evidence, rules, signing, Evaluation, Severity, Status};

#[test]
fn the_words_of_a_status_and_a_severity_are_the_published_ones() {
    assert_eq!(Status::Pass.id(), "pass");
    assert_eq!(Status::Fail.id(), "fail");
    assert_eq!(Status::Indeterminate.id(), "indeterminate");
    // The record's vocabulary is different, and the conversion is the one
    // place the two meet (P6-1).
    assert_eq!(Status::Pass.overall_id(), "compliant");
    assert_eq!(Status::Fail.overall_id(), "non-compliant");
    assert_eq!(Status::Indeterminate.overall_id(), "indeterminate");

    assert_eq!(Severity::ALL.map(Severity::id), ["mandatory", "recommended", "informational"]);
    assert!(Severity::Mandatory < Severity::Recommended);
}

#[test]
fn a_rules_common_members_and_type_are_readable_without_matching_on_it() {
    let pack = eu_pack();
    let rule = pack.rules.first().expect("the EU pack has rules");
    let common = rule.common();
    assert_eq!(common.rule_id, "eu-ai-act-record-keeping");
    assert_eq!(rule.rule_id(), common.rule_id);
    assert_eq!(rule.rule_type(), "audit_integrity");
    assert_eq!(common.severity, Severity::Mandatory);
    assert!(common.reference.contains("Art. 12(1)"));
    assert!(!common.description.is_empty());
    assert!(matches!(rule, Rule::AuditIntegrity(_)));
    assert!(RULE_TYPES.contains(&rule.rule_type()));
}

#[test]
fn a_loaded_pack_exposes_the_typed_pack_and_the_document_it_came_from() {
    let pack = eu_pack();
    // Deref reaches the typed pack; `pack()` names it.
    assert_eq!(pack.pack().pack_id, pack.pack_id);
    assert_eq!(pack.pack(), &pack.clone().pack().clone());
    assert_eq!(pack.document()["pack_id"], json!("khalm-reading-eu-ai-act-2026"));
    // The payload hash is the hash of the bytes an authority would sign.
    assert_eq!(pack.payload_hash(), signing::payload_hash(pack.document()));
    assert_eq!(
        pack.payload_hash(),
        vmr_policy::payload_hash(pack.document()),
        "the crate-level alias is the same function"
    );
}

#[test]
fn the_signed_payload_is_the_document_without_its_signature() {
    let document = pack_document(json!([{
        "type": "attestation_level",
        "rule_id": "attest",
        "description": "The issuer attests.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, api_surface.rs",
        "minimum_level": "self"
    }]));
    let payload = signing::signed_payload(&document);
    assert!(!payload.contains("signature"), "{payload}");
    // Adding a signature section does not change the signed bytes.
    let mut signed = document.clone();
    signed["signature"] = json!({"algorithm": "ES256"});
    assert_eq!(signing::signed_payload(&signed), payload);
    assert_eq!(vmr_policy::signed_payload(&signed), payload);
}

#[test]
fn the_evidence_value_is_the_shape_the_hash_is_taken_over() {
    let record = conformance_record();
    assert_eq!(
        evidence::value(&record, evidence::pointers_for("attestation_level")),
        json!("software")
    );
    assert_eq!(
        evidence::value(&record, evidence::pointers_for("source_screening")),
        // The conformance record keeps its data in one country: no
        // data_residency_countries (task 10.12a).
        json!(["sensor_stream", "PH", null])
    );
    assert_eq!(evidence::value(&record, &[]), json!(null));
    // pointers() and pointers_for() agree for every rule of a real pack, and
    // a rule's hash is its type's hash in context (none here).
    for rule in &eu_pack().rules {
        assert_eq!(evidence::pointers(rule), evidence::pointers_for(rule.rule_type()));
        assert_eq!(evidence::hash_for(rule, &record), evidence::hash_in_context(rule.rule_type(), &record, None));
        assert_eq!(evidence::hash_for_in_context(rule, &record, None), evidence::hash_for(rule, &record));
        let value = evidence::value_in_context(rule.rule_type(), &record, None);
        assert_eq!(
            evidence::hash_for(rule, &record),
            vmr_policy::vmr_record::hash::format_hash(&vmr_policy::vmr_record::hash::sha256(
                vmr_policy::vmr_record::canonical::jcs(&value).as_bytes()
            ))
        );
    }
}

#[test]
fn a_verification_context_reaches_the_evaluation_through_every_entry_point() {
    // P6-17: the context types, their words, and the three ways in.
    use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};
    assert_eq!(
        [LineageOutcome::Initial, LineageOutcome::Complete, LineageOutcome::Partial, LineageOutcome::NotChecked]
            .map(LineageOutcome::id),
        ["initial", "complete", "partial", "not_checked"]
    );
    let record = conformance_record();
    let context = EvaluationContext {
        lineage: LineageContext {
            outcome: LineageOutcome::Complete,
            predecessors: vec![VerifiedPredecessor {
                signed_payload_hash: "sha256:".to_string() + &"ab".repeat(32),
                record: record.clone(),
            }],
        },
    };
    let pack = eu_pack();
    let in_context = pack.evaluate_in_context(&record, &context, now());
    assert_eq!(vmr_policy::evaluate_in_context(pack.pack(), &record, &context, now()), in_context);
    for (rule, result) in pack.rules.iter().zip(in_context.results.iter()) {
        assert_eq!(&rules::evaluate_one_in_context(rule, &record, Some(&context)), result);
        assert_eq!(result.evidence_hash, evidence::hash_for_in_context(rule, &record, Some(&context)));
    }
    assert_eq!(rules::evaluate_one_in_context(&pack.rules[0], &record, None), rules::evaluate_one(&pack.rules[0], &record));

    // The conformance record is initial: the context adds nothing to it, so
    // every entry point answers as without context. On a successor it applies.
    assert!(!context.applies_to(&record));
    assert_eq!(vmr_policy::context::applicable(Some(&context), &record), None);
    assert_eq!(in_context, pack.evaluate(&record, now()));
    let mut successor = record.clone();
    successor["lineage"]["lineage_chain_length"] = json!(2);
    assert!(context.applies_to(&successor));
    assert_eq!(vmr_policy::context::applicable(Some(&context), &successor), Some(&context));
}

#[test]
fn a_value_too_deep_to_read_is_named_and_not_read() {
    assert_eq!(evidence::MAX_DEPTH, 128);
    let pointers = evidence::pointers_for("source_screening");
    let record = conformance_record();
    assert_eq!(evidence::too_deep(&record, pointers), None);

    let mut deep = json!("PH");
    for _ in 0..=evidence::MAX_DEPTH {
        deep = serde_json::Value::Array(vec![deep]);
    }
    let mut nested = record.clone();
    nested["learning_provenance"]["training_input_provenance"]["data_residency"] = deep;
    assert_eq!(
        evidence::too_deep(&nested, pointers),
        Some("/learning_provenance/training_input_provenance/data_residency")
    );
    assert_eq!(evidence::value(&nested, pointers), json!(["sensor_stream", null, null]));
}

#[test]
fn one_rule_can_be_evaluated_on_its_own() {
    let pack = eu_pack();
    let record = conformance_record();
    let whole = pack.evaluate(&record, now());
    for (rule, from_pack) in pack.rules.iter().zip(whole.results.iter()) {
        assert_eq!(&rules::evaluate_one(rule, &record), from_pack);
    }
}

#[test]
fn the_overall_status_can_be_computed_from_results_alone() {
    let result = |severity, status| RuleResult {
        rule_id: "r".into(),
        rule_type: "attestation_level".into(),
        severity,
        reference: "vmr-policy tests, api_surface.rs".into(),
        status,
        evidence_hash: "sha256:".to_string() + &"00".repeat(32),
        detail: "built by a test".into(),
    };
    assert_eq!(Evaluation::compute_overall(&[]), Status::Pass);
    assert_eq!(
        Evaluation::compute_overall(&[result(Severity::Mandatory, Status::Pass)]),
        Status::Pass
    );
    assert_eq!(
        Evaluation::compute_overall(&[result(Severity::Recommended, Status::Fail)]),
        Status::Pass
    );
    assert_eq!(
        Evaluation::compute_overall(&[result(Severity::Informational, Status::Indeterminate)]),
        Status::Pass
    );
    assert_eq!(
        Evaluation::compute_overall(&[result(Severity::Mandatory, Status::Indeterminate)]),
        Status::Indeterminate
    );
    assert_eq!(
        Evaluation::compute_overall(&[
            result(Severity::Mandatory, Status::Indeterminate),
            result(Severity::Mandatory, Status::Fail),
        ]),
        Status::Fail
    );
}

#[test]
fn the_module_level_entry_points_are_the_same_as_the_methods() {
    let pack = eu_pack();
    let record = conformance_record();
    assert_eq!(
        vmr_policy::evaluate(pack.pack(), &record, now()),
        pack.evaluate(&record, now())
    );
    vmr_policy::validate(pack.pack()).expect("a loaded pack validates");
}

#[test]
fn the_documentation_rule_type_is_reachable_by_name() {
    // Task 10.11a (D11-4): the seventh rule type's public symbols.
    use vmr_policy::DocumentationDeclaredRule;
    assert_eq!(RULE_TYPES.len(), 7);
    assert_eq!(RULE_TYPES[6], "documentation_declared");
    assert_eq!(vmr_policy::schema::DOCUMENTS, ["data_governance", "human_oversight"]);
    assert_eq!(evidence::pointer::DATA_GOVERNANCE, "/data_governance");
    assert_eq!(evidence::pointer::HUMAN_OVERSIGHT, "/human_oversight");
    assert_eq!(evidence::DOCUMENTATION_DECLARED, [evidence::pointer::DATA_GOVERNANCE, evidence::pointer::HUMAN_OVERSIGHT]);
    let pack = one_rule_pack(json!({
        "type": "documentation_declared",
        "rule_id": "oversight",
        "description": "The record pins its human oversight documentation.",
        "severity": "recommended",
        "reference": "vmr-policy tests, api_surface.rs",
        "document": "human_oversight"
    }));
    let rule = &pack.rules[0];
    let Rule::DocumentationDeclared(DocumentationDeclaredRule { document, .. }) = rule else {
        panic!("not a documentation_declared rule: {rule:?}")
    };
    assert_eq!(document, "human_oversight");
    assert_eq!(rule.rule_type(), "documentation_declared");
    assert_eq!(rule.common().severity, Severity::Recommended);
    assert_eq!(evidence::pointers(rule), evidence::DOCUMENTATION_DECLARED);
}

#[test]
fn the_schema_table_describes_itself() {
    // Kind::keyword and Kind::value are what the sync test compares; a
    // direct check keeps their meaning visible.
    assert_eq!(Kind::Closed.keyword(), "additionalProperties");
    assert_eq!(Kind::Closed.value(), json!(false));
    assert_eq!(Kind::MinItems(1).keyword(), "minItems");
    assert_eq!(Kind::MinItems(1).value(), json!(1));
    assert_eq!(Kind::Const("0.1").value(), json!("0.1"));
    assert_eq!(Kind::Required(&["a", "b"]).value(), json!(["a", "b"]));
    assert_eq!(Kind::Minimum(0).keyword(), "minimum");
    assert_eq!(Kind::Minimum(0).value(), json!(0));
    assert_eq!(Kind::Maximum(9_007_199_254_740_991).keyword(), "maximum");
    assert_eq!(Kind::Maximum(9_007_199_254_740_991).value(), json!(9_007_199_254_740_991u64));
    assert!(Kind::Type("object").enforced_by_parser());
    assert!(!Kind::MinLength(1).enforced_by_parser());
    assert!(!Kind::Maximum(1).enforced_by_parser());
    // Every scope is used by the table.
    assert!(SCHEMA_RULES.iter().any(|r| r.scope == Scope::Pack));
    assert!(SCHEMA_RULES.iter().any(|r| r.scope == Scope::EveryRule));
    for rule_type in RULE_TYPES {
        assert!(
            SCHEMA_RULES.iter().any(|r| r.scope == Scope::Rule(rule_type)),
            "{rule_type} has no rules of its own"
        );
    }
}
