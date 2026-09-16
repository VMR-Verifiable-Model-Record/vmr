// tests/evidence_hash.rs — P6-2: "two verifiers with the same record and
// the same pack then produce the same evidence_hash byte for byte; a test
// must prove that".
//
// The three properties that make the hash checkable by a third party:
//   1. it is a function of the pointer list and the record's values, not of
//      how the record's JSON was written down;
//   2. it changes when a value the rule reads changes, and only then;
//   3. it is defined even when a value is absent.
//
// The pointer list itself is pinned here against P6-3's "Reads" column, so a
// rule cannot quietly start reading somewhere else while its results keep
// citing the old evidence.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_policy::evidence;
use vmr_policy::vmr_record::canonical::jcs;
use vmr_policy::vmr_record::hash::{format_hash, sha256};

#[test]
fn the_pointer_list_of_every_rule_type_is_the_one_p6_3_states() {
    assert_eq!(
        evidence::pointers_for("data_residency"),
        [
            "/learning_provenance/training_input_provenance/data_residency",
            "/learning_provenance/training_input_provenance/data_residency_countries"
        ]
    );
    assert_eq!(
        evidence::pointers_for("source_screening"),
        [
            "/learning_provenance/training_input_provenance/source_type",
            "/learning_provenance/training_input_provenance/data_residency",
            "/learning_provenance/training_input_provenance/data_residency_countries"
        ]
    );
    assert_eq!(
        evidence::pointers_for("export_control"),
        [
            "/deployment_context/inference_boundary/type",
            "/deployment_context/inference_boundary/egress_allowed",
            "/deployment_context/inference_boundary/allowed_egress_destinations"
        ]
    );
    assert_eq!(
        evidence::pointers_for("audit_integrity"),
        [
            "/lineage/lineage_chain_length",
            "/lineage/previous_record_hash",
            "/learning_provenance/training_input_merkle_root",
            "/learning_provenance/training_input_count",
            "/learning_provenance/training_started_at",
            "/learning_provenance/training_ended_at",
            "/learning_provenance/training_input_provenance/collection_period/start",
            "/learning_provenance/training_input_provenance/collection_period/end",
            "/issued_at",
            "/learning_provenance/training_input_disclosure"
        ]
    );
    assert_eq!(
        evidence::pointers_for("execution_integrity"),
        [
            "/model_identity/learned_state_hash",
            "/model_identity/learned_state_components",
            "/learning_provenance/training_environment/training_software",
            "/learning_provenance/training_environment/software_hash",
            "/learning_provenance/training_environment/tee_measurement",
            "/lineage/lineage_type",
            "/model_identity/model_hash"
        ]
    );
    assert_eq!(evidence::pointers_for("attestation_level"), ["/issuer/attestation_level"]);
    // Task 10.11a (D11-4): both documentation members, whichever one a rule
    // names.
    assert_eq!(evidence::pointers_for("documentation_declared"), ["/data_governance", "/human_oversight"]);
}

#[test]
fn every_pointer_resolves_in_the_committed_conformance_record() {
    // A pointer with a typo would otherwise read `null` forever and every
    // result would cite the hash of `null`.
    let record = conformance_record();
    for rule_type in vmr_policy::pack::RULE_TYPES {
        for pointer in evidence::pointers_for(rule_type) {
            // previous_record_hash is genuinely absent from an initial
            // record, and the conformance record declares neither
            // optional documentation member (task 10.11a), nor its data in
            // several countries, nor its training input withheld (task
            // 10.12a); everything else must be there.
            if [
                "/lineage/previous_record_hash",
                "/data_governance",
                "/human_oversight",
                "/learning_provenance/training_input_provenance/data_residency_countries",
                "/learning_provenance/training_input_disclosure",
            ]
            .contains(pointer)
            {
                continue;
            }
            assert!(record.pointer(pointer).is_some(), "{rule_type}: {pointer} resolves to nothing");
        }
    }
}

#[test]
fn a_documentation_rule_hashes_both_documents_whatever_it_names() {
    // Task 10.11a (D11-4): a rule type's read list is fixed (P6-2), so a rule
    // naming either document hashes both members, an absent one as null, and
    // two rules naming different documents carry one evidence hash while
    // their steps look only at the document each names.
    let rule = |document: &str| {
        one_rule_pack(json!({
            "type": "documentation_declared",
            "rule_id": "documentation",
            "description": "The record pins a document.",
            "severity": "recommended",
            "reference": "vmr-policy tests, evidence_hash.rs",
            "document": document
        }))
    };
    let hash_of = |value: Value| format_hash(&sha256(jcs(&value).as_bytes()));
    let mut record = conformance_record();
    let neither = rule("data_governance").evaluate(&record, now());
    assert_eq!(neither.results[0].evidence_hash, hash_of(json!([null, null])));

    let hash = format!("sha256:{}", "cd".repeat(32));
    record["human_oversight"] = json!({ "documentation_hash": hash });
    let data = rule("data_governance").evaluate(&record, now());
    let oversight = rule("human_oversight").evaluate(&record, now());
    assert_eq!(data.results[0].evidence_hash, hash_of(json!([null, { "documentation_hash": hash }])));
    assert_eq!(data.results[0].evidence_hash, oversight.results[0].evidence_hash, "one evidence hash for both rules");
    assert_eq!((data.results[0].status, oversight.results[0].status), (vmr_policy::Status::Fail, vmr_policy::Status::Pass));
}

#[test]
fn one_pointer_hashes_its_value_and_several_hash_the_array_of_them() {
    let record = conformance_record();
    let single = evidence::pointers_for("attestation_level");
    let expected = format_hash(&sha256(jcs(&json!("software")).as_bytes()));
    assert_eq!(evidence::hash(&record, single), expected);

    // The conformance record has no data_residency_countries (task 10.12a).
    let several = evidence::pointers_for("source_screening");
    let expected = format_hash(&sha256(jcs(&json!(["sensor_stream", "PH", null])).as_bytes()));
    assert_eq!(evidence::hash(&record, several), expected);
}

#[test]
fn the_evidence_hash_is_the_rfc_8785_form_not_a_plain_serialization() {
    // QA Q7-11. A value whose RFC 8785 form differs from serde_json's plain
    // serialization in member order (UTF-16 code units: U+1F600 before
    // U+E000) and in three numbers (1.0 is 1; 9007199254740993 is the double
    // 9007199254740992; 1e21 is 1e+21). The literal is the SHA-256 of
    // {"<U+1F600>":[9007199254740992,1e+21],"<U+E000>":1} in UTF-8, computed
    // by the QA's from-spec JCS, not by this crate.
    let value = json!({"\u{e000}": 1.0, "\u{1f600}": [9_007_199_254_740_993u64, 1e21]});
    let expected = "sha256:1f631a2afaf452ece68e75ca840cba5134f62b2cbe1eac5237e85de378a86ce7";
    assert_eq!(evidence::hash(&json!({"x": value.clone()}), &["/x"]), expected, "evidence::hash");
    // attestation_level is the one rule type with a single read since task
    // 10.12a gave data_residency two.
    let record = json!({"issuer": {"attestation_level": value}});
    assert_eq!(evidence::hash_in_context("attestation_level", &record, None), expected, "hash_in_context");
}

#[test]
fn an_absent_pointer_contributes_null_and_the_hash_is_still_defined() {
    let empty = json!({});
    let single = evidence::pointers_for("attestation_level");
    assert_eq!(
        evidence::hash(&empty, single),
        format_hash(&sha256(jcs(&Value::Null).as_bytes()))
    );
    let several = evidence::pointers_for("export_control");
    assert_eq!(
        evidence::hash(&empty, several),
        format_hash(&sha256(jcs(&json!([null, null, null])).as_bytes()))
    );
}

#[test]
fn the_context_slot_follows_the_record_reads_and_is_null_without_context() {
    // P6-17: the two rule types that can read verification context hash one
    // more element after their record reads. Without context it is `null`.
    // With it, on a record with predecessors, audit_integrity's is the
    // lineage outcome followed by each verified predecessor's signed-payload
    // hash, immediate first, and execution_integrity's is the immediate
    // predecessor's model_hash (task 10.12a).
    use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};
    let mut record = conformance_record();
    record["lineage"]["lineage_chain_length"] = json!(2);
    let reads = |rule_type: &str| -> Vec<Value> {
        evidence::pointers_for(rule_type).iter().map(|p| record.pointer(p).cloned().unwrap_or(Value::Null)).collect()
    };
    let hash_of = |v: Value| format_hash(&sha256(jcs(&v).as_bytes()));
    let predecessor = |n: u64, state: &str| VerifiedPredecessor {
        signed_payload_hash: format!("sha256:{n:064x}"),
        record: json!({"model_identity": {"model_hash": state, "learned_state_hash": "sha256:not-read"}}),
    };
    let state = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let context = EvaluationContext {
        lineage: LineageContext {
            outcome: LineageOutcome::Complete,
            predecessors: vec![predecessor(1, state), predecessor(2, "sha256:not-read")],
        },
    };
    let empty = EvaluationContext { lineage: LineageContext { outcome: LineageOutcome::NotChecked, predecessors: vec![] } };

    for (rule_type, with_context, with_empty) in [
        (
            "audit_integrity",
            json!(["complete", format!("sha256:{:064x}", 1), format!("sha256:{:064x}", 2)]),
            json!(["not_checked"]),
        ),
        ("execution_integrity", json!(state), Value::Null),
    ] {
        let mut values = reads(rule_type);
        values.push(Value::Null);
        assert_eq!(evidence::hash_in_context(rule_type, &record, None), hash_of(Value::Array(values.clone())), "{rule_type}");
        *values.last_mut().unwrap() = with_context;
        assert_eq!(evidence::hash_in_context(rule_type, &record, Some(&context)), hash_of(Value::Array(values.clone())), "{rule_type}");
        *values.last_mut().unwrap() = with_empty;
        assert_eq!(evidence::hash_in_context(rule_type, &record, Some(&empty)), hash_of(Value::Array(values)), "{rule_type}");
    }
    // The other four types read no context: their hash is the record reads'.
    for rule_type in ["data_residency", "source_screening", "export_control", "attestation_level"] {
        let pointers = evidence::pointers_for(rule_type);
        assert_eq!(evidence::hash_in_context(rule_type, &record, Some(&context)), evidence::hash(&record, pointers));
        assert_eq!(evidence::hash_in_context(rule_type, &record, None), evidence::hash(&record, pointers));
    }
}

#[test]
fn an_initial_record_hashes_the_same_evidence_in_every_context() {
    // P6-17: the slot is filled only by what verification adds to the
    // record's own members - an outcome other than initial, for a record
    // whose chain is 2 or more long. An initial record hashes the same
    // evidence whatever context it is given, so an issuer, the library and a
    // verifier agree on it byte for byte; and an initial outcome adds nothing
    // to any record.
    use vmr_policy::LineageOutcome::{Complete, Initial, NotChecked, Partial};
    use vmr_policy::{EvaluationContext, LineageContext, VerifiedPredecessor};
    let initial = conformance_record();
    let mut successor = initial.clone();
    successor["lineage"]["lineage_chain_length"] = json!(2);
    let mut unsaid = initial.clone();
    unsaid["lineage"]["lineage_chain_length"] = json!("2");
    let predecessors = vec![VerifiedPredecessor {
        signed_payload_hash: format!("sha256:{:064x}", 1),
        record: initial.clone(),
    }];
    let in_context = |outcome, predecessors: &[VerifiedPredecessor]| EvaluationContext {
        lineage: LineageContext { outcome, predecessors: predecessors.to_vec() },
    };

    for rule_type in ["audit_integrity", "execution_integrity"] {
        for (what, record) in [("an initial record", &initial), ("a chain length that is not a count", &unsaid)] {
            let bare = evidence::value_in_context(rule_type, record, None);
            for outcome in [Initial, Complete, Partial, NotChecked] {
                for given in [&predecessors[..0], &predecessors[..]] {
                    let c = in_context(outcome, given);
                    assert_eq!(
                        evidence::value_in_context(rule_type, record, Some(&c)),
                        bare,
                        "{rule_type}, {what}, {}, {} predecessor(s)",
                        outcome.id(),
                        given.len()
                    );
                }
            }
        }
        // An initial outcome adds nothing to a successor either.
        assert_eq!(
            evidence::value_in_context(rule_type, &successor, Some(&in_context(Initial, &predecessors))),
            evidence::value_in_context(rule_type, &successor, None),
            "{rule_type}"
        );
    }

    // A complete lineage on a successor still fills the slot.
    let complete = in_context(Complete, &predecessors);
    let slot = |rule_type: &str| {
        evidence::value_in_context(rule_type, &successor, Some(&complete)).as_array().unwrap().last().unwrap().clone()
    };
    assert_eq!(slot("audit_integrity"), json!(["complete", format!("sha256:{:064x}", 1)]));
    assert_eq!(slot("execution_integrity"), initial["model_identity"]["learned_state_hash"]);
}

#[test]
fn the_hash_does_not_depend_on_how_the_record_was_written_down() {
    // The same record written compactly, written pretty, and with one
    // character written as a \u escape: three documents, one evidence hash.
    // JCS is what is hashed, not the text.
    let record = conformance_record();
    let compact = record.to_string();
    let pretty = serde_json::to_string_pretty(&record).unwrap();
    let escaped = compact.replace("New Clark", &format!("New {}u0043lark", '\u{5c}'));
    assert_ne!(escaped, compact);
    assert_ne!(pretty, compact);
    let written: Vec<Value> = [compact, pretty, escaped]
        .iter()
        .map(|text| serde_json::from_str(text).expect("the same record"))
        .collect();
    for rule_type in vmr_policy::pack::RULE_TYPES {
        let pointers = evidence::pointers_for(rule_type);
        let expected = evidence::hash(&record, pointers);
        for form in &written {
            assert_eq!(evidence::hash(form, pointers), expected, "{rule_type}");
        }
    }
}

#[test]
fn the_hash_changes_when_what_the_rule_read_changes_and_not_otherwise() {
    let record = conformance_record();
    let pointers = evidence::pointers_for("data_residency");
    let before = evidence::hash(&record, pointers);

    let mut elsewhere = record.clone();
    elsewhere["issuer"]["issuer_name"] = json!("Someone Else");
    assert_eq!(evidence::hash(&elsewhere, pointers), before, "a member the rule never reads");

    let mut here = record.clone();
    here["learning_provenance"]["training_input_provenance"]["data_residency"] = json!("SG");
    assert_ne!(evidence::hash(&here, pointers), before, "the member the rule reads");
}

#[test]
fn a_value_nested_deeper_than_128_levels_is_not_read() {
    // Only a library caller can build one: serde_json parses no document
    // that deep. Up to 128 levels a value is read and hashed as P6-2 says;
    // past them it is not canonicalized, it contributes `null` as an absent
    // member does, and the rule is indeterminate (QA Q6-04).
    let pack = one_rule_pack(json!({
        "type": "export_control",
        "rule_id": "egress",
        "description": "Nothing leaves the boundary.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, evidence_hash.rs",
        "require_egress_denied": true
    }));
    for (levels, read) in [(128usize, true), (129, false)] {
        let mut destinations = json!("anywhere");
        for _ in 0..levels {
            destinations = Value::Array(vec![destinations]);
        }
        let record = json!({"deployment_context": {"inference_boundary": {
            "type": "enclave",
            "egress_allowed": false,
            "allowed_egress_destinations": destinations.clone()
        }}});
        let result = pack.evaluate(&record, now()).results[0].clone();
        if read {
            assert_eq!(result.status, vmr_policy::Status::Fail, "{levels}: {}", result.detail);
            let value = json!(["enclave", false, destinations]);
            assert_eq!(result.evidence_hash, format_hash(&sha256(jcs(&value).as_bytes())), "{levels}");
        } else {
            assert_eq!(result.status, vmr_policy::Status::Indeterminate, "{levels}: {}", result.detail);
            assert!(result.detail.contains("/allowed_egress_destinations"), "{}", result.detail);
            assert!(result.detail.contains("128"), "{}", result.detail);
            let value = json!(["enclave", false, null]);
            assert_eq!(result.evidence_hash, format_hash(&sha256(jcs(&value).as_bytes())), "{levels}");
        }
    }
}

#[test]
fn no_record_serde_json_parses_reaches_the_depth_bound_so_no_hash_moved() {
    // The bound sits above anything a document can hold: serde_json refuses
    // a document nested deeper than 127 arrays and objects. At every member
    // a rule reads, the deepest nesting that still parses is read and hashed
    // exactly as P6-2 always said (QA Q6-04).
    let nested = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert!(serde_json::from_str::<Value>(&nested(127)).is_ok());
    assert!(serde_json::from_str::<Value>(&nested(128)).is_err());

    let base = conformance_record();
    for rule_type in vmr_policy::pack::RULE_TYPES {
        let pointers = evidence::pointers_for(rule_type);
        for pointer in pointers {
            let (parent, member) = pointer.rsplit_once('/').expect("a member pointer");
            let mut marked = base.clone();
            marked
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .expect("the parent object")
                .insert(member.to_string(), json!("__DEEP__"));
            let text = marked.to_string();
            let (levels, record) = (1..=evidence::MAX_DEPTH)
                .map_while(|n| {
                    serde_json::from_str::<Value>(&text.replacen("\"__DEEP__\"", &nested(n), 1))
                        .ok()
                        .map(|p| (n, p))
                })
                .last()
                .expect("one level parses");
            assert!(levels < evidence::MAX_DEPTH, "{pointer}: {levels} levels parsed");
            assert_eq!(evidence::too_deep(&record, pointers), None, "{pointer}");
            let values: Vec<Value> =
                pointers.iter().map(|p| record.pointer(p).cloned().unwrap_or(Value::Null)).collect();
            let value = if values.len() == 1 { values[0].clone() } else { Value::Array(values) };
            assert_eq!(
                evidence::hash(&record, pointers),
                format_hash(&sha256(jcs(&value).as_bytes())),
                "{rule_type} at {pointer}, {levels} levels"
            );
        }
    }
}

#[test]
fn the_same_pack_and_record_give_the_same_evidence_hash_in_every_result() {
    // The reproducibility P6-2 asks for, end to end: the hash a result
    // carries is the hash of the rule's pointer list over that record,
    // followed, for the two types that read verification context, by the
    // context slot - `null` here, where there is no context (P6-17).
    let record = conformance_record();
    for pack_id in REFERENCE_PACKS {
        let pack = reference_pack(pack_id);
        let a = pack.evaluate(&record, now());
        let b = reference_pack(pack_id).evaluate(&record, now());
        assert_eq!(a, b, "{pack_id}");
        for (rule, result) in pack.rules.iter().zip(a.results.iter()) {
            let mut values: Vec<Value> = evidence::pointers(rule)
                .iter()
                .map(|p| record.pointer(p).cloned().unwrap_or(Value::Null))
                .collect();
            if matches!(rule.rule_type(), "audit_integrity" | "execution_integrity") {
                values.push(Value::Null);
            }
            let value = if values.len() == 1 { values[0].clone() } else { Value::Array(values) };
            assert_eq!(
                result.evidence_hash,
                format_hash(&sha256(jcs(&value).as_bytes())),
                "{pack_id}/{}",
                result.rule_id
            );
        }
    }
}
