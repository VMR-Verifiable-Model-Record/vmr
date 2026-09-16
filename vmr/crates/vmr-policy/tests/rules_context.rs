// tests/rules_context.rs — P6-17: the rule settings that read what
// verification established, not only what the record says. Two of them:
// `audit_integrity`'s `require_verified_lineage` (the lineage was verified
// back to its initial record) and `execution_integrity`'s
// `require_state_kept` (a deployment or policy-change record keeps its
// verified immediate predecessor's model, by `model_hash` since task 10.12a).
//
// The rule that holds for both: missing context is indeterminate, never a
// pass and never a failure. A library caller evaluating without context, and
// `vmr record verify` run without `--previous`, both get that answer.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_policy::Status::{Fail, Indeterminate, Pass};
use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, Status, VerifiedPredecessor};

const ROOT: &str = "sha256:37d463ad29ec49c8d40ced87d9be1f290f093df4d9d845c0569363f9b008cb0b";
const PREV: &str = "sha256:2eca0dd33554f5113d03ef96bc01deb56fafd8484bbf95f04bd308ee6c075967";
const STATE: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_STATE: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn rule(rule_type: &str, extra: Value) -> Value {
    let mut v = json!({
        "type": rule_type,
        "rule_id": format!("{rule_type}-in-context"),
        "description": "Built by a test.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, rules_context.rs"
    });
    for (k, val) in extra.as_object().unwrap() {
        v.as_object_mut().unwrap().insert(k.clone(), val.clone());
    }
    v
}

/// A context with `outcome` and these predecessor payloads, immediate first.
fn context(outcome: LineageOutcome, predecessors: Vec<Value>) -> EvaluationContext {
    EvaluationContext {
        lineage: LineageContext {
            outcome,
            predecessors: predecessors
                .into_iter()
                .enumerate()
                .map(|(i, record)| VerifiedPredecessor {
                    signed_payload_hash: format!("sha256:{:064x}", i + 1),
                    record,
                })
                .collect(),
        },
    }
}

/// The single rule's status and detail, with or without a context.
fn status_in(rule: Value, record: &Value, context: Option<&EvaluationContext>) -> (Status, String) {
    let pack = one_rule_pack(rule);
    let evaluation = match context {
        Some(c) => pack.evaluate_in_context(record, c, now()),
        None => pack.evaluate(record, now()),
    };
    let result = evaluation.results.first().expect("one rule, one result").clone();
    (result.status, result.detail)
}

// ---------------------------------------------------------------------------
//  audit_integrity: require_verified_lineage
// ---------------------------------------------------------------------------

fn chain(length: u64) -> Value {
    let mut lineage = json!({"lineage_chain_length": length});
    if length > 1 {
        lineage["previous_record_hash"] = json!(PREV);
    }
    json!({"lineage": lineage, "learning_provenance": {"training_input_merkle_root": ROOT}})
}

/// `value` nested in `levels` arrays: the value itself is not an array, so
/// the result nests `levels` levels (format document §5, "Nesting").
fn nested(levels: usize, value: Value) -> Value {
    (0..levels).fold(value, |inner, _| Value::Array(vec![inner]))
}

#[test]
fn a_predecessor_value_nested_past_128_levels_is_not_read() {
    // QA Q7-13 S8. The depth rule (format document §5) covers a verified
    // predecessor's model_hash too: nested past 128 levels it is not
    // read, so the execution_integrity context slot holds null (§7) and
    // require_state_kept is indeterminate (§6.5 step 4). It covers the
    // record's own reads only for the rest of the rule: another setting on
    // the same record is still decided.
    let mut record = step("deployment", STATE);
    record["model_identity"]["learned_state_hash"] = json!(STATE);
    record["model_identity"]["learned_state_components"] =
        json!([{"name": "afferent_H", "hash": OTHER_STATE, "size_bytes": 8192}]);
    let deep = context(
        LineageOutcome::Complete,
        vec![json!({"model_identity": {"model_hash": nested(129, json!(STATE))}})],
    );

    let (status, detail) = status_in(rule("execution_integrity", json!({"require_state_kept": true})), &record, Some(&deep));
    assert_eq!(status, Indeterminate, "require_state_kept: {detail}");
    let (status, detail) =
        status_in(rule("execution_integrity", json!({"require_learned_state_components": true})), &record, Some(&deep));
    assert_eq!(status, Pass, "require_learned_state_components on the same record: {detail}");

    let value = vmr_policy::evidence::value_in_context("execution_integrity", &record, Some(&deep));
    assert_eq!(value.as_array().and_then(|v| v.last()), Some(&Value::Null), "the context slot: {value}");

    // At 128 levels the value is read, and it is not a hash.
    let shallow = context(
        LineageOutcome::Complete,
        vec![json!({"model_identity": {"model_hash": nested(127, json!(STATE))}})],
    );
    let value = vmr_policy::evidence::value_in_context("execution_integrity", &record, Some(&shallow));
    assert_eq!(value.as_array().and_then(|v| v.last()), Some(&nested(127, json!(STATE))), "128 levels are read");
}

#[test]
fn a_context_that_contradicts_its_predecessors_is_evaluated_as_given() {
    // QA Q7-13 S10 (the reviewer, 2026-09-13: documented, no behaviour
    // change). An evaluation takes a verification context as given: only a
    // context a verifier produced from the predecessors it verified carries
    // meaning, and vmr-policy does not verify it again (P6-10). No verifier
    // produces a context that contradicts its own predecessors; given one,
    // the rules answer as written. These pin that answer.
    let verified = || rule("audit_integrity", json!({"require_tamper_evident": true, "require_verified_lineage": true}));
    let kept = || rule("execution_integrity", json!({"require_state_kept": true}));

    // "complete" with no predecessor: require_verified_lineage passes, and
    // the audit_integrity slot holds the outcome alone.
    let complete_alone = context(LineageOutcome::Complete, vec![]);
    let (status, detail) = status_in(verified(), &chain(2), Some(&complete_alone));
    assert_eq!(status, Pass, "complete with no predecessor: {detail}");
    let value = vmr_policy::evidence::value_in_context("audit_integrity", &chain(2), Some(&complete_alone));
    assert_eq!(value.as_array().and_then(|v| v.last()), Some(&json!(["complete"])), "{value}");

    // The same context gives require_state_kept no predecessor to compare:
    // indeterminate, with a null slot.
    let (status, detail) = status_in(kept(), &step("deployment", STATE), Some(&complete_alone));
    assert_eq!(status, Indeterminate, "{detail}");
    let value = vmr_policy::evidence::value_in_context("execution_integrity", &step("deployment", STATE), Some(&complete_alone));
    assert_eq!(value.as_array().and_then(|v| v.last()), Some(&Value::Null), "{value}");

    // "not_checked" with predecessors: require_verified_lineage is still
    // indeterminate, and require_state_kept compares with the immediate one.
    let not_checked_with_one = context(LineageOutcome::NotChecked, vec![predecessor_with(STATE)]);
    let (status, detail) = status_in(verified(), &chain(2), Some(&not_checked_with_one));
    assert_eq!(status, Indeterminate, "{detail}");
    let (status, detail) = status_in(kept(), &step("deployment", STATE), Some(&not_checked_with_one));
    assert_eq!(status, Pass, "{detail}");
}

#[test]
fn a_verified_lineage_passes_only_when_verification_reached_the_initial_record() {
    let r = || rule("audit_integrity", json!({"require_tamper_evident": true, "require_verified_lineage": true}));
    let predecessor = json!({"lineage": {"lineage_type": "initial"}});

    // An initial record has nothing to verify, with or without context.
    assert_eq!(status_in(r(), &chain(1), None).0, Pass);
    assert_eq!(status_in(r(), &chain(1), Some(&context(LineageOutcome::Initial, vec![]))).0, Pass);
    // A successor verified back to its initial record.
    let (status, detail) =
        status_in(r(), &chain(2), Some(&context(LineageOutcome::Complete, vec![predecessor.clone()])));
    assert_eq!(status, Pass, "{detail}");

    // Missing context, or a lineage that was not shown to its origin, never
    // passes and never fails.
    let (status, detail) = status_in(r(), &chain(2), None);
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(detail.contains("lineage"), "{detail}");
    for (what, outcome, predecessors) in [
        ("no predecessor supplied", LineageOutcome::NotChecked, vec![]),
        ("predecessors that stop short", LineageOutcome::Partial, vec![json!({"lineage": {"lineage_type": "training-update"}})]),
    ] {
        let (status, detail) = status_in(r(), &chain(3), Some(&context(outcome, predecessors)));
        assert_eq!(status, Indeterminate, "{what}: {detail}");
        assert!(detail.contains("--previous"), "{what}: the detail says how to supply them: {detail}");
    }
}

// ---------------------------------------------------------------------------
//  execution_integrity: require_state_kept
// ---------------------------------------------------------------------------

/// A record recording a `lineage_type` step with predecessors (a chain of
/// 2, as check 20 requires of every type but initial).
fn step(lineage_type: &str, model_hash: &str) -> Value {
    json!({
        "lineage": {"lineage_type": lineage_type, "lineage_chain_length": 2},
        "model_identity": {"model_hash": model_hash}
    })
}

fn predecessor_with(model_hash: &str) -> Value {
    json!({"model_identity": {"model_hash": model_hash}})
}

#[test]
fn a_kept_model_is_the_same_model_hash_whatever_components_each_record_lists() {
    // Task 10.12a (D12a-3, QA QC-02): model_hash is the model's identity, and
    // learned_state_hash follows each issuer's choice of components (record
    // format §7.3). A deployer that lists other components of the same model
    // keeps it; a record that names another model does not, whatever its
    // components' digest.
    let r = || rule("execution_integrity", json!({"require_state_kept": true}));
    let complete = |preds: Vec<Value>| context(LineageOutcome::Complete, preds);
    let record = |model_hash: &str, learned_state_hash: &str| {
        json!({
            "lineage": {"lineage_type": "deployment", "lineage_chain_length": 2},
            "model_identity": {"model_hash": model_hash, "learned_state_hash": learned_state_hash}
        })
    };
    let predecessor = json!({"model_identity": {"model_hash": STATE, "learned_state_hash": STATE}});

    let (status, detail) = status_in(r(), &record(STATE, OTHER_STATE), Some(&complete(vec![predecessor.clone()])));
    assert_eq!(status, Pass, "the same model, other components: {detail}");
    assert!(!detail.contains("learned state"), "{detail}");

    let (status, detail) = status_in(r(), &record(OTHER_STATE, STATE), Some(&complete(vec![predecessor.clone()])));
    assert_eq!(status, Fail, "another model, the same components' digest: {detail}");
    // A detail shortens a long value (schema::quote), so the hash is matched
    // by its start.
    assert!(detail.contains("model_hash") && detail.contains("sha256:2222"), "{detail}");

    // The context slot holds the predecessor's model_hash.
    let value = vmr_policy::evidence::value_in_context("execution_integrity", &record(STATE, OTHER_STATE), Some(&complete(vec![predecessor])));
    assert_eq!(value.as_array().and_then(|v| v.last()), Some(&json!(STATE)), "{value}");

    // A predecessor that names its components' digest but no model_hash
    // said nothing about the model.
    let (status, detail) =
        status_in(r(), &record(STATE, STATE), Some(&complete(vec![json!({"model_identity": {"learned_state_hash": STATE}})])));
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(detail.contains("model_hash"), "{detail}");
}

#[test]
fn a_state_keeping_step_is_compared_with_its_verified_immediate_predecessor() {
    let r = || rule("execution_integrity", json!({"require_state_kept": true}));
    let complete = |preds: Vec<Value>| context(LineageOutcome::Complete, preds);

    // Steps that may change the learned state pass whatever it is.
    for lineage_type in ["initial", "training-update", "fine-tune", "quantization"] {
        let (status, detail) =
            status_in(r(), &step(lineage_type, STATE), Some(&complete(vec![predecessor_with(OTHER_STATE)])));
        assert_eq!(status, Pass, "{lineage_type}: {detail}");
    }

    // deployment and policy-change keep it (the owner, 2026-09-13).
    for lineage_type in ["deployment", "policy-change"] {
        let (status, detail) =
            status_in(r(), &step(lineage_type, STATE), Some(&complete(vec![predecessor_with(STATE)])));
        assert_eq!(status, Pass, "{lineage_type}, kept: {detail}");

        let (status, detail) =
            status_in(r(), &step(lineage_type, STATE), Some(&complete(vec![predecessor_with(OTHER_STATE)])));
        assert_eq!(status, Fail, "{lineage_type}, changed: {detail}");
        assert!(detail.contains("model_hash"), "{detail}");

        // Only the immediate predecessor counts.
        let (status, detail) = status_in(
            r(),
            &step(lineage_type, STATE),
            Some(&context(LineageOutcome::Partial, vec![predecessor_with(STATE), predecessor_with(OTHER_STATE)])),
        );
        assert_eq!(status, Pass, "{lineage_type}, immediate first: {detail}");
    }

    // Missing context never passes and never fails.
    let (status, detail) = status_in(r(), &step("deployment", STATE), None);
    assert_eq!(status, Indeterminate, "{detail}");
    let (status, detail) = status_in(r(), &step("deployment", STATE), Some(&context(LineageOutcome::NotChecked, vec![])));
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(detail.contains("--previous"), "{detail}");

    // What the step reads, absent or of another type, said nothing.
    for (what, record, preds) in [
        ("no lineage_type", json!({"model_identity": {"model_hash": STATE}}), vec![predecessor_with(STATE)]),
        (
            "no model_hash",
            json!({"lineage": {"lineage_type": "deployment", "lineage_chain_length": 2}}),
            vec![predecessor_with(STATE)],
        ),
        ("a predecessor without one", step("deployment", STATE), vec![json!({"model_identity": {}})]),
        ("a predecessor that is not an object", step("deployment", STATE), vec![json!(7)]),
    ] {
        let (status, detail) = status_in(r(), &record, Some(&complete(preds)));
        assert_eq!(status, Indeterminate, "{what}: {detail}");
    }
}

#[test]
fn a_context_that_adds_nothing_to_the_record_is_not_read() {
    // P6-17 (made normative 2026-09-13): an initial outcome says nothing a
    // record's own members do not, and neither does any outcome for a chain
    // of 1 - on every verified record a chain of 1 is exactly an initial
    // record (spec §6.5, check 20). Such a context is neither hashed nor
    // read: the evaluation is the one without context, with the same status,
    // reason and evidence hash.
    let verified = || rule("audit_integrity", json!({"require_tamper_evident": true, "require_verified_lineage": true}));
    let kept = || rule("execution_integrity", json!({"require_state_kept": true}));
    let mut deployment_of_one = step("deployment", STATE);
    deployment_of_one["lineage"]["lineage_chain_length"] = json!(1);
    // QA Q7-05 S2 (the owner, 2026-09-13): 2^53 is not a count, so it is not
    // "a count of 2 or more" either.
    let mut deployment_past_2_53 = step("deployment", STATE);
    deployment_past_2_53["lineage"]["lineage_chain_length"] = json!(9_007_199_254_740_992u64);
    let evaluate = |r: Value, record: &Value, c: Option<&EvaluationContext>| {
        let pack = one_rule_pack(r);
        match c {
            Some(c) => pack.evaluate_in_context(record, c, now()),
            None => pack.evaluate(record, now()),
        }
    };

    for (what, r, record) in [
        ("an initial record, require_verified_lineage", verified(), chain(1)),
        ("a deployment with a chain of 1, require_state_kept", kept(), deployment_of_one),
        ("a deployment whose chain length 2^53 is not a count, require_state_kept", kept(), deployment_past_2_53),
    ] {
        let without = evaluate(r.clone(), &record, None);
        for outcome in [LineageOutcome::Initial, LineageOutcome::Complete, LineageOutcome::Partial, LineageOutcome::NotChecked] {
            let c = context(outcome, vec![predecessor_with(OTHER_STATE)]);
            assert_eq!(evaluate(r.clone(), &record, Some(&c)), without, "{what}, {}", outcome.id());
        }
    }

    // An initial outcome on a record with predecessors is not read either.
    for (what, r, record) in [("verified lineage", verified(), chain(2)), ("state kept", kept(), step("deployment", STATE))] {
        let c = context(LineageOutcome::Initial, vec![predecessor_with(STATE)]);
        assert_eq!(evaluate(r.clone(), &record, Some(&c)), evaluate(r, &record, None), "{what}");
    }

    // A complete lineage on a successor is read, and hashed.
    let c = context(LineageOutcome::Complete, vec![predecessor_with(STATE)]);
    for (what, r, record) in [("verified lineage", verified(), chain(2)), ("state kept", kept(), step("deployment", STATE))] {
        let with = evaluate(r.clone(), &record, Some(&c));
        let without = evaluate(r, &record, None);
        assert_eq!(with.results[0].status, Pass, "{what}: {}", with.results[0].detail);
        assert_ne!(with.results[0].evidence_hash, without.results[0].evidence_hash, "{what}");
    }
}

#[test]
fn a_rule_that_reads_no_context_answers_the_same_in_every_context() {
    // attestation_level, and documentation_declared (task 10.11a, D11-4),
    // on an initial record and on a successor, where a context applies.
    let mut successor = conformance_record();
    successor["lineage"]["lineage_chain_length"] = json!(2);
    successor["data_governance"] = json!({ "documentation_hash": format!("sha256:{}", "ef".repeat(32)) });
    for r in [
        rule("attestation_level", json!({"minimum_level": "software"})),
        rule("documentation_declared", json!({"document": "data_governance"})),
        rule("documentation_declared", json!({"document": "human_oversight"})),
    ] {
        let pack = one_rule_pack(r);
        for record in [conformance_record(), successor.clone()] {
            let without = pack.evaluate(&record, now());
            for outcome in [LineageOutcome::Initial, LineageOutcome::Complete, LineageOutcome::Partial, LineageOutcome::NotChecked] {
                let with = pack.evaluate_in_context(&record, &context(outcome, vec![record.clone()]), now());
                assert_eq!(with, without, "{}: {}", pack.rules[0].rule_id(), outcome.id());
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  execution_integrity: require_state_kept's `compare` (QA QR-05, the owner,
//  2026-09-16)
// ---------------------------------------------------------------------------

#[test]
fn require_state_kept_compares_the_member_the_pack_names() {
    // QR-05 (the owner, 2026-09-16): `compare` chooses the member step 4
    // compares, `model_hash` by default. A deployment whose declared learned
    // state moved while its model_hash did not keeps the model under the
    // default and fails under `learned_state_hash`, which a verifier can
    // recompute from the components (record format §7.3).
    let mut moved = step("deployment", STATE);
    moved["model_identity"]["learned_state_hash"] = json!(OTHER_STATE);
    let mut predecessor = predecessor_with(STATE);
    predecessor["model_identity"]["learned_state_hash"] = json!(STATE);
    let held = context(LineageOutcome::Complete, vec![predecessor]);

    for parameters in [
        json!({"require_state_kept": true}),
        json!({"require_state_kept": true, "compare": "model_hash"}),
    ] {
        let (status, detail) = status_in(rule("execution_integrity", parameters.clone()), &moved, Some(&held));
        assert_eq!(status, Pass, "{parameters}: {detail}");
        assert!(detail.contains("model_hash") || detail.contains("keeps"), "{detail}");
    }
    let (status, detail) = status_in(
        rule("execution_integrity", json!({"require_state_kept": true, "compare": "learned_state_hash"})),
        &moved,
        Some(&held),
    );
    assert_eq!(status, Fail, "compare learned_state_hash: {detail}");
    assert!(detail.contains("learned_state_hash"), "{detail}");

    // The other direction: a record whose learned state is kept and whose
    // model_hash moved fails the default and passes under learned_state_hash.
    let mut relisted = step("deployment", OTHER_STATE);
    relisted["model_identity"]["learned_state_hash"] = json!(STATE);
    assert_eq!(
        status_in(rule("execution_integrity", json!({"require_state_kept": true})), &relisted, Some(&held)).0,
        Fail
    );
    assert_eq!(
        status_in(
            rule("execution_integrity", json!({"require_state_kept": true, "compare": "learned_state_hash"})),
            &relisted,
            Some(&held)
        )
        .0,
        Pass
    );
}

#[test]
fn compare_reads_the_named_member_of_the_predecessor_too() {
    // A predecessor that declares no learned_state_hash says nothing about
    // the state, so the comparison is indeterminate, never a pass.
    let mut moved = step("deployment", STATE);
    moved["model_identity"]["learned_state_hash"] = json!(STATE);
    let silent = context(LineageOutcome::Complete, vec![predecessor_with(STATE)]);
    let (status, detail) = status_in(
        rule("execution_integrity", json!({"require_state_kept": true, "compare": "learned_state_hash"})),
        &moved,
        Some(&silent),
    );
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(detail.contains("learned_state_hash"), "{detail}");
}
