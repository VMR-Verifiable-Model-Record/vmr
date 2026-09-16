// tests/rules_pos_neg.rs — Gate 6's "every rule type has at least one
// positive and one negative test", and the third answer the other two
// hide: Indeterminate. One section per rule type; each asserts a Pass, a
// Fail and at least one Indeterminate, and each Indeterminate names the
// pointer that was missing, so a rule that silently reads the wrong member
// cannot pass this file.
//
// The packs are built inline: a rule type belongs in a reference pack only
// when a real clause asks for it (P6-4), and two of the seven - data_residency
// and source_screening - are in no reference pack for exactly that reason.

mod common;

use common::*;
use serde_json::json;
use vmr_policy::Status::{Fail, Indeterminate, Pass};

fn rule(rule_type: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut v = json!({
        "type": rule_type,
        "rule_id": format!("{rule_type}-under-test"),
        "description": "Built by a test.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, rules_pos_neg.rs"
    });
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in e {
            o.insert(k.clone(), val.clone());
        }
    }
    v
}

fn residency(value: serde_json::Value) -> serde_json::Value {
    json!({"learning_provenance": {"training_input_provenance": {"data_residency": value}}})
}

/// A record whose data resides in several countries (record format §8.5).
fn countries(value: serde_json::Value) -> serde_json::Value {
    json!({"learning_provenance": {"training_input_provenance": {"data_residency_countries": value}}})
}

// ---------------------------------------------------------------------------
//  documentation_declared (task 10.11a, docs/dev/task-10.11a.md D11-4)
// ---------------------------------------------------------------------------

/// A record payload holding only `value` at the top-level `member`.
fn documented(member: &str, value: serde_json::Value) -> serde_json::Value {
    let mut record = json!({});
    record[member] = value;
    record
}

#[test]
fn documentation_declared_passes_fails_and_abstains() {
    let hash = format!("sha256:{}", "ab".repeat(32));
    for (document, other) in [("data_governance", "human_oversight"), ("human_oversight", "data_governance")] {
        let r = || rule("documentation_declared", json!({ "document": document }));
        let pointer = format!("/{document}");
        let hash_pointer = format!("/{document}/documentation_hash");

        // Pass: the named member pins a document by a hash, whose hex digits
        // may be in either case, and mixed in one hash (the format document's
        // §5, "A hash"). Step 3 reads no member of the object but
        // documentation_hash, so another member leaves a pass: the closed
        // object is verification's rule. Asserted by status (QA QT-03), so a
        // rule that requires the closed object fails here (mutation M10).
        for member in [
            json!({ "documentation_hash": hash }),
            json!({ "documentation_hash": format!("sha256:{}", "AB".repeat(32)) }),
            json!({ "documentation_hash": format!("sha256:{}", "aB".repeat(32)) }),
            json!({ "documentation_hash": hash, "title": "x" }),
        ] {
            let (status, detail) = status_of(r(), &documented(document, member.clone()));
            assert_eq!(status, Pass, "{document} = {member}: {detail}");
            assert!(detail.contains(&hash_pointer), "{detail}");
        }

        // Fail: a record object without the member, even when the other
        // document is declared. For an optional member, absence is the
        // record's only signed way to say that it pins no such document.
        for record in [json!({}), documented(other, json!({ "documentation_hash": hash }))] {
            let (status, detail) = status_of(r(), &record);
            assert_eq!(status, Fail, "{document} in {record}: {detail}");
            assert!(detail.contains(&pointer), "{detail}");
            assert!(!detail.contains("is not declared"), "an absent optional member is a declaration here: {detail}");
        }
        // Fail: a declared string that is not a hash. A hash is `sha256:` and
        // exactly 64 ASCII hex digits, with nothing around it (QA QT-03: a
        // rule that trims white space, mutation M12, or takes any number of
        // hex digits, mutation M13, fails here).
        let hex = "ab".repeat(32);
        for bad in [
            "sha256:not-hex".to_string(),
            "none".to_string(),
            "sha256:".to_string(),
            format!("SHA256:{hex}"),
            format!("sha256:{}", &hex[..62]),
            format!("sha256:{}", &hex[..63]),
            format!("sha256:{hex}a"),
            format!("sha256:{hex}ab"),
            format!("sha256:{hex}\n"),
            format!(" sha256:{hex}"),
            format!("sha256:{hex} "),
            format!("\tsha256:{hex}"),
            format!("sha256:{}", "\u{ff11}".repeat(64)),
            format!("sha256:{}", "\u{0661}".repeat(64)),
            format!("sha256:{}_{}", &hex[..32], &hex[..31]),
        ] {
            let (status, detail) = status_of(r(), &documented(document, json!({ "documentation_hash": bad })));
            assert_eq!(status, Fail, "{document} {bad:?}: {detail}");
            assert!(detail.contains(&hash_pointer), "{detail}");
        }

        // Indeterminate: the member is present but is not an object, or its
        // documentation_hash is not a declared string.
        for value in [
            serde_json::Value::Null,
            json!(hash),
            json!([]),
            json!({}),
            json!({ "documentation_hash": "" }),
            json!({ "documentation_hash": 7 }),
            json!({ "documentation_hash": null }),
        ] {
            let (status, detail) = status_of(r(), &documented(document, value.clone()));
            assert_eq!(status, Indeterminate, "{document} = {value}: {detail}");
            assert!(detail.contains(&hash_pointer), "{detail}");
        }
        // Indeterminate: a record that is not an object declares nothing.
        for record in [serde_json::Value::Null, json!([]), json!("record")] {
            assert_eq!(status_of(r(), &record).0, Indeterminate, "{document} in {record}");
        }
    }
}

// ---------------------------------------------------------------------------
//  data_residency
// ---------------------------------------------------------------------------

#[test]
fn a_failure_detail_is_bounded_whatever_the_pack_lists() {
    // A detail travels whole in --json, and a pack may be 1 MiB: listing
    // every allowed jurisdiction made a detail larger than the pack
    // (QA Q6-10). 200 000 entries, AA to ZY over and over; the record
    // declares ZZ, which none of them is.
    let allowed: Vec<String> = (0..200_000usize)
        .map(|i| {
            let k = i % 675;
            String::from_utf8(vec![b'A' + (k / 26) as u8, b'A' + (k % 26) as u8]).unwrap()
        })
        .collect();
    let r = rule("data_residency", json!({ "allowed_jurisdictions": allowed }));
    let (status, detail) = status_of(r, &residency(json!("ZZ")));
    assert_eq!(status, Fail);
    assert!(detail.chars().count() < 1_000, "{} characters: {}…", detail.chars().count(), &detail[..200]);
    assert!(detail.contains("\"ZZ\""), "{detail}");
    assert!(detail.contains("200000"), "the detail says how many were allowed: {detail}");
}

#[test]
fn data_residency_passes_fails_and_abstains() {
    let r = || rule("data_residency", json!({"allowed_jurisdictions": ["PH", "SG"]}));

    let (status, detail) = status_of(r(), &residency(json!("PH")));
    assert_eq!(status, Pass, "{detail}");
    assert!(detail.contains("\"PH\""), "{detail}");

    let (status, detail) = status_of(r(), &residency(json!("DE")));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("\"DE\""), "{detail}");

    // Absent, empty, and the wrong JSON type are all "did not say".
    for record in [json!({}), residency(json!("")), residency(json!(7))] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains("/data_residency"), "{detail}");
    }

    // Comparison is exact and case-sensitive.
    assert_eq!(status_of(r(), &residency(json!("ph"))).0, Fail);

    // Task 10.12a (D12a-4): data kept in several countries passes when every
    // country is allowed and fails on the first that is not.
    let (status, detail) = status_of(r(), &countries(json!(["PH", "SG"])));
    assert_eq!(status, Pass, "{detail}");
    assert!(detail.contains("data_residency_countries") && detail.contains("\"SG\""), "{detail}");
    let (status, detail) = status_of(r(), &countries(json!(["DE", "PH", "US"])));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("\"DE\"") && !detail.contains("\"US\""), "the first one not allowed: {detail}");

    // A list that is empty or holds a value that is not a declared string
    // said nothing checkable: indeterminate, naming the list, even beside a
    // declared data_residency (a record a verifier refuses, §8.5).
    for record in [countries(json!([])), countries(json!(["PH", 7])), countries(json!(["PH", ""]))] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains("/data_residency_countries"), "{detail}");
    }
    let mut both = residency(json!("PH"));
    both["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = json!(["PH", 7]);
    assert_eq!(status_of(r(), &both).0, Indeterminate);
    // A list that is not an array, or null, is not declared; the one code
    // then decides alone, and without it the rule abstains.
    for value in [json!("PH"), json!(null)] {
        let mut record = residency(json!("PH"));
        record["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = value.clone();
        assert_eq!(status_of(r(), &record).0, Pass, "{value}");
        assert_eq!(status_of(r(), &countries(value.clone())).0, Indeterminate, "{value}");
    }
    // Both declared (refused by a verifier, §8.5): every code is read.
    both["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = json!(["DE", "FR"]);
    assert_eq!(status_of(r(), &both).0, Fail);
}

// ---------------------------------------------------------------------------
//  source_screening
// ---------------------------------------------------------------------------

fn origins(source_type: &str, residency: &str) -> serde_json::Value {
    json!({"learning_provenance": {"training_input_provenance": {
        "source_type": source_type,
        "data_residency": residency,
        "source_description": "scraped from a restricted place, in prose"
    }}})
}

#[test]
fn source_screening_passes_fails_and_abstains() {
    let r = || rule("source_screening", json!({"restricted_list": ["web_scrape", "XX"]}));

    let (status, detail) = status_of(r(), &origins("sensor_stream", "PH"));
    assert_eq!(status, Pass, "{detail}");

    // Either declared origin can be the one that is restricted.
    let (status, detail) = status_of(r(), &origins("web_scrape", "PH"));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("web_scrape"), "{detail}");
    let (status, detail) = status_of(r(), &origins("sensor_stream", "XX"));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("XX"), "{detail}");

    // source_description is free text and is never matched (P6-3), even
    // when it contains a restricted word.
    assert_eq!(status_of(r(), &origins("sensor_stream", "PH")).0, Pass);

    for (record, missing) in [
        (json!({}), "/source_type"),
        (origins("", "PH"), "/source_type"),
        (
            json!({"learning_provenance": {"training_input_provenance": {"source_type": "sensor_stream"}}}),
            "/data_residency",
        ),
    ] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains(missing), "{detail}");
    }

    // Task 10.12a (D12a-4): each of several countries is screened too.
    let several = |list: serde_json::Value| {
        json!({"learning_provenance": {"training_input_provenance": {
            "source_type": "sensor_stream",
            "data_residency_countries": list
        }}})
    };
    let (status, detail) = status_of(r(), &several(json!(["DE", "PH"])));
    assert_eq!(status, Pass, "{detail}");
    let (status, detail) = status_of(r(), &several(json!(["DE", "XX"])));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("\"XX\""), "{detail}");
    let (status, detail) = status_of(r(), &several(json!(["DE", 7])));
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(detail.contains("/data_residency_countries"), "{detail}");
}

// ---------------------------------------------------------------------------
//  export_control
// ---------------------------------------------------------------------------

fn boundary(kind: &str, egress: bool, destinations: serde_json::Value) -> serde_json::Value {
    json!({"deployment_context": {"inference_boundary": {
        "type": kind, "egress_allowed": egress, "allowed_egress_destinations": destinations
    }}})
}

#[test]
fn export_control_passes_fails_and_abstains() {
    let air = || rule("export_control", json!({"require_air_gapped": true}));
    let denied = || rule("export_control", json!({"require_egress_denied": true}));

    assert_eq!(status_of(air(), &boundary("air-gapped", false, json!([]))).0, Pass);
    let (status, detail) = status_of(air(), &boundary("networked", false, json!([])));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("networked"), "{detail}");

    assert_eq!(status_of(denied(), &boundary("air-gapped", false, json!([]))).0, Pass);
    let (status, detail) = status_of(denied(), &boundary("air-gapped", true, json!([])));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("egress_allowed is true"), "{detail}");

    // A denial with an exception list is not a denial (P6-3).
    let (status, detail) =
        status_of(denied(), &boundary("air-gapped", false, json!(["sink.example"])));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("exception list"), "{detail}");

    for (r, record, missing) in [
        (air(), json!({}), "/type"),
        (denied(), json!({}), "/egress_allowed"),
        (
            denied(),
            json!({"deployment_context": {"inference_boundary": {"egress_allowed": false}}}),
            "/allowed_egress_destinations",
        ),
        // egress_allowed as a string, not a boolean: nothing was declared.
        (
            denied(),
            json!({"deployment_context": {"inference_boundary": {"egress_allowed": "false"}}}),
            "/egress_allowed",
        ),
    ] {
        let (status, detail) = status_of(r, &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains(missing), "{detail}");
    }
}

// ---------------------------------------------------------------------------
//  audit_integrity
// ---------------------------------------------------------------------------

const ROOT: &str = "sha256:37d463ad29ec49c8d40ced87d9be1f290f093df4d9d845c0569363f9b008cb0b";
const PREV: &str = "sha256:2eca0dd33554f5113d03ef96bc01deb56fafd8484bbf95f04bd308ee6c075967";

#[test]
fn audit_integrity_passes_fails_and_abstains() {
    let r = || {
        rule(
            "audit_integrity",
            json!({"minimum_chain_length": 2, "require_tamper_evident": true}),
        )
    };
    let long_chain = json!({
        "lineage": {"lineage_chain_length": 2, "previous_record_hash": PREV},
        "learning_provenance": {"training_input_merkle_root": ROOT}
    });
    let (status, detail) = status_of(r(), &long_chain);
    assert_eq!(status, Pass, "{detail}");

    // Too short.
    let short = json!({
        "lineage": {"lineage_chain_length": 1},
        "learning_provenance": {"training_input_merkle_root": ROOT}
    });
    let (status, detail) = status_of(r(), &short);
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("below the required 2"), "{detail}");

    // Declared and unparseable is a failure, not an abstention: the
    // record said something checkable and it was wrong.
    let bad_root = json!({
        "lineage": {"lineage_chain_length": 2, "previous_record_hash": PREV},
        "learning_provenance": {"training_input_merkle_root": "not-a-hash"}
    });
    let (status, detail) = status_of(r(), &bad_root);
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("training_input_merkle_root"), "{detail}");

    // An initial record has no predecessor to link, and is not faulted.
    let initial = rule("audit_integrity", json!({"require_tamper_evident": true}));
    let one = json!({
        "lineage": {"lineage_chain_length": 1},
        "learning_provenance": {"training_input_merkle_root": ROOT}
    });
    let (status, detail) = status_of(initial, &one);
    assert_eq!(status, Pass, "{detail}");

    for (record, missing) in [
        (json!({}), "/lineage_chain_length"),
        (json!({"lineage": {"lineage_chain_length": 2}}), "/training_input_merkle_root"),
        (
            json!({
                "lineage": {"lineage_chain_length": 2},
                "learning_provenance": {"training_input_merkle_root": ROOT}
            }),
            "/previous_record_hash",
        ),
    ] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains(missing), "{detail}");
    }
}

// ---------------------------------------------------------------------------
//  execution_integrity
// ---------------------------------------------------------------------------

fn model(components: serde_json::Value) -> serde_json::Value {
    json!({"model_identity": {"learned_state_hash": ROOT, "learned_state_components": components}})
}

fn component(name: &str, hash: &str, size: u64) -> serde_json::Value {
    json!({"name": name, "hash": hash, "size_bytes": size})
}

#[test]
fn execution_integrity_passes_fails_and_abstains() {
    let state = || rule("execution_integrity", json!({"require_learned_state_components": true}));
    let env = || rule("execution_integrity", json!({"require_environment_pinned": true}));
    let tee = || rule("execution_integrity", json!({"require_tee": true}));

    let good = model(json!([component("afferent_H", PREV, 8192)]));
    let (status, detail) = status_of(state(), &good);
    assert_eq!(status, Pass, "{detail}");

    // A component of no bytes pins nothing.
    let zero = model(json!([component("afferent_H", PREV, 0)]));
    let (status, detail) = status_of(state(), &zero);
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("size_bytes 0"), "{detail}");

    // A declared hash that does not parse is a failure.
    let bad = model(json!([component("afferent_H", "sha1:deadbeef", 8192)]));
    assert_eq!(status_of(state(), &bad).0, Fail);

    // An empty components array pins nothing and declares nothing: the loop
    // over its elements would find no fault, so the step must say so first
    // (QA Q7-02, mutation G5).
    let (status, detail) = status_of(state(), &model(json!([])));
    assert_eq!(status, Indeterminate, "an empty learned_state_components: {detail}");
    assert!(detail.contains("/learned_state_components"), "{detail}");

    let environment = |training_software: &str, software: &str, measurement: &str| {
        json!({"learning_provenance": {"training_environment": {
            "training_software": training_software, "software_hash": software, "tee_measurement": measurement
        }}})
    };
    let (status, detail) = status_of(env(), &environment("khalm-tlm 0.1.0", PREV, ""));
    assert_eq!(status, Pass, "{detail}");
    let (status, detail) = status_of(env(), &environment("khalm-tlm 0.1.0", "nope", ""));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("software_hash"), "{detail}");

    assert_eq!(status_of(tee(), &environment("e", PREV, PREV)).0, Pass);
    assert_eq!(status_of(tee(), &environment("e", PREV, "nope")).0, Fail);

    // P6-17 (E2): the hardware/TEE/software members are "a hash or the empty
    // string", so "" is what an issuer signs to say "none" - a declared
    // absence, which fails a requirement for that member.
    let (status, detail) = status_of(env(), &environment("khalm-tlm 0.1.0", "", ""));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("software_hash"), "{detail}");
    let (status, detail) = status_of(tee(), &environment("e", PREV, ""));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("tee_measurement"), "{detail}");

    // A member that is absent, or not a string, still said nothing.
    for (r, record, missing) in [
        (state(), json!({}), "/learned_state_hash"),
        (state(), json!({"model_identity": {"learned_state_hash": ROOT}}), "/learned_state_components"),
        (env(), json!({}), "/training_software"),
    ] {
        let (status, detail) = status_of(r, &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains(missing), "{detail}");
    }

    // Task 10.12a (D12a-2): an empty training_software names no training
    // software, whatever software trained the model.
    let (status, detail) = status_of(env(), &environment("", PREV, ""));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("training_software") && !detail.contains("engine"), "{detail}");
}

#[test]
fn an_empty_environment_member_fails_but_an_absent_or_wrong_typed_one_does_not() {
    // P6-17 (E2, the owner, 2026-09-13), for every member it covers: "" is a
    // signed declaration of absence and fails the requirement; absent and
    // wrong-typed stay indeterminate (P6-3), and never pass.
    const ENVIRONMENT: &str = "/learning_provenance/training_environment";
    let env = || rule("execution_integrity", json!({"require_environment_pinned": true}));
    let tee = || rule("execution_integrity", json!({"require_tee": true}));
    let pinned = || json!({"training_software": "khalm-tlm 0.1.0", "software_hash": PREV, "tee_measurement": PREV});
    for (member, r) in [("training_software", env()), ("software_hash", env()), ("tee_measurement", tee())] {
        for (what, value, expected) in [
            ("empty", Some(json!("")), Fail),
            ("absent", None, Indeterminate),
            ("a number", Some(json!(7)), Indeterminate),
            ("null", Some(json!(null)), Indeterminate),
        ] {
            let mut environment = pinned();
            match value {
                Some(v) => environment[member] = v,
                None => {
                    environment.as_object_mut().unwrap().remove(member);
                }
            }
            let record = json!({"learning_provenance": {"training_environment": environment}});
            let (status, detail) = status_of(r.clone(), &record);
            assert_eq!(status, expected, "{member} {what}: {detail}");
            assert!(detail.contains(&format!("{ENVIRONMENT}/{member}")) || detail.contains(member), "{detail}");
        }
    }
}

// ---------------------------------------------------------------------------
//  audit_integrity: the P6-17 checks that read the record
// ---------------------------------------------------------------------------

/// A record: an initial record with its merkle root, the given training
/// times, issuance and collection period.
fn timed_record(started: &str, ended: &str, issued: &str, from: &str, to: &str) -> serde_json::Value {
    json!({
        "issued_at": issued,
        "lineage": {"lineage_chain_length": 1},
        "learning_provenance": {
            "training_input_merkle_root": ROOT,
            "training_input_count": 16,
            "training_started_at": started,
            "training_ended_at": ended,
            "training_input_provenance": {"collection_period": {"start": from, "end": to}}
        }
    })
}

#[test]
fn an_ordered_record_passes_a_contradictory_one_fails_and_a_missing_time_abstains() {
    let r = || rule("audit_integrity", json!({"require_ordered_record": true}));
    let (a, b, c, d, e) =
        ("2026-08-01T00:00:00Z", "2026-08-31T00:00:00Z", "2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-10T00:00:00Z");

    let (status, detail) = status_of(r(), &timed_record(c, d, e, a, b));
    assert_eq!(status, Pass, "{detail}");

    // The three contradictions the reference builder refuses to sign
    // (P5-08), which no verifier check covers.
    for (what, record, member) in [
        ("training ends before it starts", timed_record(d, c, e, a, b), "training_ended_at"),
        ("training ends after issuance", timed_record(c, "2026-09-11T00:00:00Z", e, a, b), "training_ended_at"),
        ("the collection period ends before it starts", timed_record(c, d, e, b, a), "collection_period"),
    ] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Fail, "{what}: {detail}");
        assert!(detail.contains(member), "{what}: {detail}");
    }

    // A time that is absent, null, or not a timestamp said nothing.
    let mut absent = timed_record(c, d, e, a, b);
    absent["learning_provenance"].as_object_mut().unwrap().remove("training_started_at");
    let mut null = timed_record(c, d, e, a, b);
    null["issued_at"] = json!(null);
    for (what, record) in [
        ("an absent start", absent),
        ("a null issuance", null),
        ("a start that is not a timestamp", timed_record("yesterday", d, e, a, b)),
    ] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{what}: {detail}");
    }
}

#[test]
fn a_committed_input_passes_and_a_commitment_to_nothing_fails() {
    let r = || rule("audit_integrity", json!({"require_input_committed": true}));
    let good = timed_record("2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-10T00:00:00Z", "2026-08-01T00:00:00Z", "2026-08-31T00:00:00Z");
    let (status, detail) = status_of(r(), &good);
    assert_eq!(status, Pass, "{detail}");

    let empty_root = vmr_policy::vmr_record::hash::format_hash(&vmr_policy::vmr_record::merkle::empty_root());
    let edited = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut p = good.clone();
        f(&mut p);
        p
    };
    for (what, record, mentions) in [
        ("no training input", edited(&|p| p["learning_provenance"]["training_input_count"] = json!(0)), "training_input_count"),
        (
            "a count over the empty tree's root",
            edited(&|p| p["learning_provenance"]["training_input_merkle_root"] = json!(empty_root.clone())),
            "empty",
        ),
        (
            "a root that is not a hash",
            edited(&|p| p["learning_provenance"]["training_input_merkle_root"] = json!("nope")),
            "training_input_merkle_root",
        ),
    ] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Fail, "{what}: {detail}");
        assert!(detail.contains(mentions), "{what}: {detail}");
    }
    for (what, record) in [
        ("an absent count", edited(&|p| {
            p["learning_provenance"].as_object_mut().unwrap().remove("training_input_count");
        })),
        ("a count written as a string", edited(&|p| p["learning_provenance"]["training_input_count"] = json!("16"))),
        ("an absent root", edited(&|p| {
            p["learning_provenance"].as_object_mut().unwrap().remove("training_input_merkle_root");
        })),
    ] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{what}: {detail}");
    }
}

#[test]
fn a_record_that_declares_its_training_input_withheld_fails_both_commitment_requirements() {
    // Task 10.12a (D12a-5): record format §8.4's training_input_disclosure is
    // a signed statement that nothing is committed, so a requirement for the
    // commitment fails on it instead of abstaining.
    let committed = || rule("audit_integrity", json!({"require_input_committed": true}));
    let tamper = || rule("audit_integrity", json!({"require_tamper_evident": true}));
    let withheld = |disclosure: serde_json::Value| {
        json!({
            "lineage": {"lineage_chain_length": 1},
            "learning_provenance": {
                "training_input_digest": "",
                "training_input_merkle_root": "",
                "training_input_count": 0,
                "training_input_disclosure": disclosure
            }
        })
    };
    for disclosure in ["not-held", "not-disclosed"] {
        for (setting, r) in [("require_input_committed", committed()), ("require_tamper_evident", tamper())] {
            let (status, detail) = status_of(r, &withheld(json!(disclosure)));
            assert_eq!(status, Fail, "{setting}, {disclosure}: {detail}");
            assert!(detail.contains("training_input_disclosure") && detail.contains(disclosure), "{detail}");
        }
    }
    // Declared first: a withholding record with a hash for a root still fails.
    let mut contradictory = withheld(json!("not-held"));
    contradictory["learning_provenance"]["training_input_merkle_root"] = json!(ROOT);
    contradictory["learning_provenance"]["training_input_count"] = json!(16);
    assert_eq!(status_of(committed(), &contradictory).0, Fail);
    assert_eq!(status_of(tamper(), &contradictory).0, Fail);
    // An empty, null or other-typed disclosure is not declared: the root and
    // the count decide, as before.
    for disclosure in [json!(""), json!(null), json!(7)] {
        for r in [committed(), tamper()] {
            let (status, detail) = status_of(r, &withheld(disclosure.clone()));
            assert_eq!(status, Indeterminate, "{disclosure}: {detail}");
            assert!(detail.contains("/training_input_merkle_root") || detail.contains("/training_input_count"), "{detail}");
        }
    }
}

#[test]
fn a_pack_chooses_what_a_withheld_training_input_means() {
    // QR-04 (the owner, 2026-09-16): `withheld` says what a declared
    // training_input_disclosure (record format §8.4) does to the two
    // commitment requirements. `fail` is the default and today's behaviour;
    // `indeterminate` is for a pack that tolerates withholding - the record
    // said it withholds, it did not say the wrong thing.
    let settings = |extra: serde_json::Value| {
        let mut v = json!({"require_input_committed": true});
        for (k, val) in extra.as_object().unwrap() {
            v.as_object_mut().unwrap().insert(k.clone(), val.clone());
        }
        rule("audit_integrity", v)
    };
    let record = json!({
        "lineage": {"lineage_chain_length": 1},
        "learning_provenance": {
            "training_input_digest": "",
            "training_input_merkle_root": "",
            "training_input_count": 0,
            "training_input_disclosure": "not-held"
        }
    });
    for (setting, expected) in
        [(json!({}), Fail), (json!({"withheld": "fail"}), Fail), (json!({"withheld": "indeterminate"}), Indeterminate)]
    {
        let (status, detail) = status_of(settings(setting.clone()), &record);
        assert_eq!(status, expected, "require_input_committed {setting}: {detail}");
        assert!(detail.contains("training_input_disclosure") && detail.contains("not-held"), "{detail}");
    }
    // The same for require_tamper_evident, and the reference packs' behaviour
    // is the default, so the five of them are unchanged.
    let tamper = |extra: serde_json::Value| {
        let mut v = json!({"require_tamper_evident": true});
        for (k, val) in extra.as_object().unwrap() {
            v.as_object_mut().unwrap().insert(k.clone(), val.clone());
        }
        rule("audit_integrity", v)
    };
    for (setting, expected) in
        [(json!({}), Fail), (json!({"withheld": "fail"}), Fail), (json!({"withheld": "indeterminate"}), Indeterminate)]
    {
        let (status, detail) = status_of(tamper(setting.clone()), &record);
        assert_eq!(status, expected, "require_tamper_evident {setting}: {detail}");
    }
}

#[test]
fn a_withheld_training_input_does_not_hide_the_broken_chain_link() {
    // QR-04's smaller point: before this round the withheld answer returned
    // from require_tamper_evident before its lineage-linkage check, so a
    // record that both withholds and breaks its chain link reported only the
    // withholding. Both reasons are reported now.
    let mut record = json!({
        "lineage": {"lineage_chain_length": 2, "previous_record_hash": "not a hash"},
        "learning_provenance": {
            "training_input_digest": "",
            "training_input_merkle_root": "",
            "training_input_count": 0,
            "training_input_disclosure": "not-held"
        }
    });
    let tamper = |withheld: &str| {
        rule("audit_integrity", json!({"require_tamper_evident": true, "withheld": withheld}))
    };
    for withheld in ["fail", "indeterminate"] {
        let (status, detail) = status_of(tamper(withheld), &record);
        assert_eq!(status, Fail, "withheld {withheld}: {detail}");
        assert!(detail.contains("training_input_disclosure"), "the withholding: {detail}");
        assert!(detail.contains("previous_record_hash"), "the broken link: {detail}");
    }
    // A linked chain reports the withholding alone, at the pack's status.
    record["lineage"]["previous_record_hash"] = json!(ROOT);
    let (status, detail) = status_of(tamper("indeterminate"), &record);
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(!detail.contains("previous_record_hash"), "{detail}");
}

#[test]
fn a_number_above_2_53_minus_1_or_not_written_as_an_integer_is_not_a_count() {
    // QA Q7-05 S1 and S2 (the owner, 2026-09-13). A count is a JSON integer
    // from 0 to 2^53 - 1, the largest integer RFC 8785 keeps exact. Above it
    // the evidence hash holds the nearest double, so 2^53 and 2^53 + 1 would
    // share one evidence hash and compare differently: such a value is not a
    // count, and a step that needs one is indeterminate, as for a member of
    // the wrong JSON type. The same holds for every count the evaluator
    // reads: lineage_chain_length, training_input_count and size_bytes.
    const MAX: u64 = 9_007_199_254_740_991;
    let from_text = |text: &str| -> serde_json::Value { serde_json::from_str(text).unwrap() };

    // lineage_chain_length, under minimum_chain_length 2.
    let chain = || rule("audit_integrity", json!({"minimum_chain_length": 2}));
    let length = |n: serde_json::Value| json!({"lineage": {"lineage_chain_length": n}});
    let (status, detail) = status_of(chain(), &length(json!(MAX)));
    assert_eq!(status, Pass, "2^53 - 1: {detail}");
    for (what, record) in [
        ("2^53", length(json!(MAX + 1))),
        ("2^53 + 1", length(json!(MAX + 2))),
        ("1e21", from_text(r#"{"lineage": {"lineage_chain_length": 1e21}}"#)),
        ("2.0", from_text(r#"{"lineage": {"lineage_chain_length": 2.0}}"#)),
        ("-0", from_text(r#"{"lineage": {"lineage_chain_length": -0}}"#)),
    ] {
        let (status, detail) = status_of(chain(), &record);
        assert_eq!(status, Indeterminate, "lineage_chain_length {what}: {detail}");
        assert!(detail.contains("/lineage_chain_length"), "{what}: {detail}");
    }

    // training_input_count, under require_input_committed.
    let committed = || rule("audit_integrity", json!({"require_input_committed": true}));
    let counted = |n: u64| {
        let mut p = timed_record("2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z", "2026-09-10T00:00:00Z", "2026-08-01T00:00:00Z", "2026-08-31T00:00:00Z");
        p["learning_provenance"]["training_input_count"] = json!(n);
        p
    };
    let (status, detail) = status_of(committed(), &counted(MAX));
    assert_eq!(status, Pass, "training_input_count 2^53 - 1: {detail}");
    let (status, detail) = status_of(committed(), &counted(MAX + 1));
    assert_eq!(status, Indeterminate, "training_input_count 2^53: {detail}");
    assert!(detail.contains("/training_input_count"), "{detail}");

    // size_bytes, under require_learned_state_components.
    let components = || rule("execution_integrity", json!({"require_learned_state_components": true}));
    let (status, detail) = status_of(components(), &model(json!([component("afferent_H", PREV, MAX)])));
    assert_eq!(status, Pass, "size_bytes 2^53 - 1: {detail}");
    let (status, detail) = status_of(components(), &model(json!([component("afferent_H", PREV, MAX + 1)])));
    assert_eq!(status, Indeterminate, "size_bytes 2^53: {detail}");
    assert!(detail.contains("size_bytes"), "{detail}");
}

// ---------------------------------------------------------------------------
//  attestation_level
// ---------------------------------------------------------------------------

fn issuer(level: serde_json::Value) -> serde_json::Value {
    json!({"issuer": {"attestation_level": level}})
}

#[test]
fn attestation_level_passes_fails_and_abstains() {
    let r = || rule("attestation_level", json!({"minimum_level": "software"}));

    assert_eq!(status_of(r(), &issuer(json!("software"))).0, Pass);
    assert_eq!(status_of(r(), &issuer(json!("hardware"))).0, Pass);
    let (status, detail) = status_of(r(), &issuer(json!("self")));
    assert_eq!(status, Fail, "{detail}");
    assert!(detail.contains("weaker"), "{detail}");

    // A level this build does not know is never read as the weakest.
    let (status, detail) = status_of(r(), &issuer(json!("quantum")));
    assert_eq!(status, Indeterminate, "{detail}");
    assert!(detail.contains("quantum"), "{detail}");

    for record in [json!({}), issuer(json!("")), issuer(json!(null))] {
        let (status, detail) = status_of(r(), &record);
        assert_eq!(status, Indeterminate, "{record}: {detail}");
        assert!(detail.contains("/attestation_level"), "{detail}");
    }
}

// ---------------------------------------------------------------------------
//  Every type is covered
// ---------------------------------------------------------------------------

#[test]
fn this_file_exercises_every_rule_type() {
    // An eighth rule type added to the format without a section here should
    // make this fail rather than ship untested. The seventh,
    // documentation_declared (task 10.11a), has its section above.
    assert_eq!(
        vmr_policy::pack::RULE_TYPES,
        [
            "data_residency",
            "source_screening",
            "export_control",
            "audit_integrity",
            "execution_integrity",
            "attestation_level",
            "documentation_declared"
        ]
    );
}
