// tests/vectors.rs — the verification and trust-store vectors (Phase 4 task
// 4.9; Doctrine Refusal 6: no format without test vectors). The committed
// files under specs/test-vectors/verify/ and specs/test-vectors/trust-store/
// are the cross-implementation contract: verdict and first failing check id
// per case, error kind (or canonical identity) per store. They are written
// only by tests/common/generate.rs:
//
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-verify --test vectors -- --ignored
//
// and verify_vectors_are_reproducible fails if the committed bytes differ
// from a fresh generation.

mod common;
#[path = "common/generate.rs"]
mod generate;

use generate::input_bytes;
use serde_json::Value;
use std::collections::BTreeSet;
use vmr_record::timestamp::Timestamp;
use vmr_verify::report::{CheckId, Verdict};
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors")
}

fn read(rel: &str) -> String {
    let path = vectors_dir().join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()))
}

fn cases(rel: &str) -> Vec<Value> {
    let doc: Value = serde_json::from_str(&read(rel)).unwrap();
    assert_eq!(doc["vector_version"], "0.1");
    doc["cases"].as_array().unwrap().clone()
}

#[test]
fn verify_vectors_are_reproducible() {
    let generated = generate::generate();
    for (rel, contents) in &generated {
        assert!(read(rel) == *contents, "{rel} differs from a fresh generation");
    }
    // Nothing else sits among the generated trust stores.
    let on_disk: BTreeSet<String> = std::fs::read_dir(vectors_dir().join("verify/trust-stores"))
        .unwrap()
        .map(|e| format!("verify/trust-stores/{}", e.unwrap().file_name().to_string_lossy()))
        .collect();
    let expected: BTreeSet<String> =
        generated.iter().map(|(rel, _)| rel.clone()).filter(|r| r.starts_with("verify/trust-stores/")).collect();
    assert_eq!(on_disk, expected);
}

fn load_store(name: &str) -> TrustStore {
    TrustStore::from_json(read(&format!("verify/trust-stores/{name}.json")).as_bytes())
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn the_verify_vectors_pin_the_general_description() {
    // Task 10.11b (docs/dev/task-10.11b.md §4.5; spec §7, §8): a record of
    // any kind of model. The general description, the profile's selection and
    // bytes fitted to it, the training commitment, residency and derived
    // models, each at the check spec §6.2 names. They are cases 161 to 203,
    // after every earlier one, and no earlier case uses the general
    // description. Later cases follow them.
    const CASES: &[(&str, &str, Option<&str>)] = &[
        ("pass-general-open-weights-not-held", "json", None),
        ("pass-general-open-weights-not-held-cose", "cose", None),
        ("pass-general-fine-tune-unrecorded-base", "json", None),
        ("pass-general-fine-tune-chain-across-issuers", "json", None),
        ("pass-general-diffusion-weights-only", "json", None),
        ("pass-general-classical-one-file-not-disclosed", "json", None),
        ("pass-vector-without-deployment-and-accelerator-software", "json", None),
        ("fail-profile-extra-component", "json", Some("format.consistency")),
        ("fail-profile-model-hash-of-files", "json", Some("format.consistency")),
        ("fail-profile-identifier-dropped", "json", Some("format.consistency")),
        ("fail-profile-identifier-added", "json", Some("format.consistency")),
        ("fail-profile-byte-fitted-under-general-format", "json", Some("format.consistency")),
        ("fail-profile-training-input-format", "json", Some("format.consistency")),
        ("fail-general-state-hash-not-digest", "json", Some("format.consistency")),
        ("fail-general-components-unordered", "json", Some("format.consistency")),
        ("fail-general-component-name-repeated", "json", Some("format.consistency")),
        ("fail-general-component-name-dot-segment", "json", Some("format.consistency")),
        ("fail-general-component-name-leading-slash", "json", Some("format.consistency")),
        ("fail-general-component-name-empty", "json", Some("format.consistency")),
        ("fail-general-component-hash-edited", "json", Some("format.consistency")),
        ("fail-general-training-format-missing", "json", Some("format.consistency")),
        ("fail-general-no-components", "json", Some("format.schema")),
        ("fail-not-held-with-digest", "json", Some("format.consistency")),
        ("fail-not-held-count-not-zero", "json", Some("format.consistency")),
        ("fail-not-held-with-format", "json", Some("format.consistency")),
        ("fail-committed-root-empty", "json", Some("format.consistency")),
        ("fail-disclosure-outside-enum", "json", Some("format.schema")),
        ("fail-disclosure-edited", "json", Some("signature.payload_hash")),
        ("fail-residency-countries-with-residency", "json", Some("format.consistency")),
        ("fail-residency-countries-unordered", "json", Some("format.consistency")),
        ("fail-residency-countries-one", "json", Some("format.schema")),
        ("fail-residency-countries-lowercase", "json", Some("format.schema")),
        ("fail-derived-from-unordered", "json", Some("format.consistency")),
        ("fail-derived-from-relation-outside-enum", "json", Some("format.schema")),
        ("fail-derived-from-empty", "json", Some("format.schema")),
        ("fail-general-training-format-empty", "json", Some("format.schema")),
        ("fail-accelerator-empty", "json", Some("format.schema")),
        ("fail-derived-from-null", "json", Some("json.structure")),
        ("fail-deployment-context-null", "json", Some("json.structure")),
        ("fail-training-epochs-null", "json", Some("json.structure")),
        ("fail-accelerator-not-a-string", "json", Some("json.structure")),
        ("fail-derived-from-entry-unknown-member", "json", Some("json.structure")),
        ("fail-derived-from-entry-as-array", "json", Some("json.structure")),
    ];
    let all = cases("verify/cases.json");
    let earlier = 160;
    assert!(all.len() >= earlier + CASES.len(), "the 160 cases before task 10.11b and its own");
    let tail: Vec<&str> = all[earlier..earlier + CASES.len()].iter().map(|c| c["id"].as_str().unwrap()).collect();
    let listed: Vec<&str> = CASES.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(tail, listed, "the task's cases, in this order, after every earlier case");
    for (id, form, check) in CASES {
        let case = all.iter().find(|c| c["id"] == *id).unwrap();
        assert_eq!(case["input"]["form"], *form, "{id}");
        assert_eq!(case["expected"]["verdict"], if check.is_some() { "fail" } else { "pass" }, "{id}");
        assert_eq!(case["expected"]["check"].as_str(), *check, "{id}");
    }
    // Every earlier record, predecessors included, names snn-compact-v1
    // wherever it names a model_format: none of them changes rules.
    let names_only_the_profile = |bytes: &[u8]| {
        let (needle, profile) = (b"model_format".as_slice(), b"snn-compact-v1".as_slice());
        let mut at = 0;
        while let Some(i) = bytes[at..].windows(needle.len()).position(|w| w == needle) {
            let start = at + i + needle.len();
            let window = &bytes[start..(start + 32).min(bytes.len())];
            if !window.windows(profile.len()).any(|w| w == profile) {
                return false;
            }
            at = start;
        }
        true
    };
    for case in &all[..earlier] {
        let id = case["id"].as_str().unwrap();
        assert!(names_only_the_profile(&input_bytes(&case["input"])), "{id}");
        for previous in case["previous"].as_array().unwrap() {
            assert!(names_only_the_profile(&input_bytes(previous)), "{id}: a predecessor");
        }
    }
}

#[test]
fn every_verify_vector_gives_its_expected_verdict_and_check() {
    let all = cases("verify/cases.json");
    assert!(all.len() >= 45, "{} cases", all.len());
    let mut ids = BTreeSet::new();
    for case in &all {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id.to_string()), "duplicate case id {id}");
        let verifier = Verifier::new(load_store(case["trust_store"].as_str().unwrap()));
        let input = input_bytes(&case["input"]);
        let previous: Vec<Vec<u8>> = case["previous"].as_array().unwrap().iter().map(input_bytes).collect();
        let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
        let t = Timestamp::parse(case["evaluation_time"].as_str().unwrap()).unwrap();
        let opts = VerifyOptions::new(t)
            .with_previous(&refs)
            .require_complete_lineage(case["require_complete_lineage"].as_bool().unwrap());
        let report = match case["input"]["form"].as_str().unwrap() {
            "json" => verifier.verify_json(&input, &opts),
            "cose" => verifier.verify_cose(&input, &opts),
            other => panic!("{id}: form {other}"),
        };
        let expected = &case["expected"];
        let verdict = match report.verdict {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
        };
        assert_eq!(verdict, expected["verdict"], "{id}: {:?}", report.failure);
        let check = report.failure.as_ref().map(|f| f.check.id());
        assert_eq!(check, expected["check"].as_str(), "{id}: {:?}", report.failure);
        if let Some(status) = expected["lineage"].as_str() {
            let got = serde_json::to_value(report.lineage.as_ref().unwrap().status).unwrap();
            assert_eq!(got, status, "{id}");
        }
        // Form detection reaches the same verdict and check.
        let auto = verifier.verify(&input, &opts);
        assert_eq!((auto.verdict, auto.failure.map(|f| f.check)), (report.verdict, report.failure.map(|f| f.check)), "{id}");
    }
}

/// Every nesting and envelope-CBOR case, with its expected first failing
/// check (spec §2 rule 13, §4.4). A verifier that misreads one of those
/// rules names another check than one of these cases expects.
const NESTING_AND_ENVELOPE_CBOR_CASES: [(&str, &str); 29] = [
    // JSON, the COSE payload and a predecessor (§2 rule 13).
    ("fail-nesting-5-levels", "json.structure"),
    ("fail-nesting-127-levels", "json.structure"),
    ("fail-nesting-128-levels", "json.structure"),
    ("fail-nesting-10000-levels", "json.structure"),
    ("fail-nesting-128-levels-unclosed", "json.syntax"),
    ("fail-cose-nesting-5-levels", "cose.payload"),
    ("fail-cose-nesting-127-levels", "cose.payload"),
    ("fail-cose-nesting-128-levels", "cose.payload"),
    ("fail-chain-predecessor-nesting-128-levels", "lineage.chain"),
    // The envelope's CBOR (§4.4).
    ("fail-cose-nesting-16-cbor-levels", "cose.unprotected_header"),
    ("fail-cose-nesting-17-cbor-levels", "cose.structure"),
    ("fail-cose-cbor-null-in-unprotected-map", "cose.unprotected_header"),
    ("fail-cose-cbor-simple-value", "cose.structure"),
    ("fail-cose-cbor-true", "cose.structure"),
    ("fail-cose-cbor-float", "cose.structure"),
    ("fail-cose-cbor-bignum", "cose.structure"),
    ("fail-cose-cbor-indefinite-length", "cose.structure"),
    ("fail-cose-cbor-8-byte-argument", "cose.structure"),
    ("fail-cose-cbor-indefinite-payload", "cose.structure"),
    // The spec-pass QA's ten (QS-01): a map key's depth, UTF-8, 4- and
    // 8-byte arguments, undefined, reserved additional information, a
    // double, and a JSON text past the depth limits parsers commonly have.
    ("fail-cose-nesting-16-cbor-levels-in-a-key", "cose.unprotected_header"),
    ("fail-cose-nesting-17-cbor-levels-in-a-key", "cose.structure"),
    ("fail-cose-cbor-text-not-utf8", "cose.structure"),
    ("fail-cose-cbor-4-byte-argument", "cose.unprotected_header"),
    ("fail-cose-non-preferred-4-byte-length", "cose.canonical"),
    ("fail-cose-cbor-8-byte-signature-length", "cose.structure"),
    ("fail-cose-cbor-undefined", "cose.structure"),
    ("fail-cose-cbor-reserved-additional-information", "cose.structure"),
    ("fail-cose-cbor-double-float", "cose.structure"),
    ("fail-nesting-100000-levels", "json.structure"),
];

#[test]
fn the_verify_vectors_pin_the_nesting_and_envelope_cbor_rules() {
    let all = cases("verify/cases.json");
    let by_id = |id: &str| all.iter().find(|c| c["id"] == id);
    let missing: Vec<&str> =
        NESTING_AND_ENVELOPE_CBOR_CASES.iter().map(|(id, _)| *id).filter(|id| by_id(id).is_none()).collect();
    assert!(missing.is_empty(), "{} nesting or envelope-CBOR cases missing: {missing:?}", missing.len());
    for (id, check) in NESTING_AND_ENVELOPE_CBOR_CASES {
        let expected = &by_id(id).unwrap()["expected"];
        assert_eq!((expected["verdict"].as_str(), expected["check"].as_str()), (Some("fail"), Some(check)), "{id}");
    }

    // Each input is what its id says. In a v0.1 envelope the unprotected map
    // is the byte at offset 97, and the payload's bstr head (59) follows it.
    let cose_input = |id: &str| {
        let input = &by_id(id).unwrap()["input"];
        assert_eq!(input["form"], "cose", "{id}");
        input_bytes(input)
    };
    // A map key 17 levels deep: the envelope's array is level 1, the map
    // level 2, and the key's fifteen arrays levels 3 to 17.
    let envelope = cose_input("fail-cose-nesting-17-cbor-levels-in-a-key");
    let map = [vec![0xa1u8], vec![0x81; 14], vec![0x80, 0x00]].concat();
    assert_eq!(&envelope[97..97 + map.len() + 1], &[&map[..], &[0x59]].concat()[..]);
    // A signature bstr whose length, 64, is an 8-byte argument.
    let envelope = cose_input("fail-cose-cbor-8-byte-signature-length");
    let head = envelope.len() - 64 - 9;
    assert_eq!(&envelope[head..head + 9], &[0x5b, 0, 0, 0, 0, 0, 0, 0, 0x40]);
    // A text string of two bytes that are not UTF-8.
    let envelope = cose_input("fail-cose-cbor-text-not-utf8");
    assert_eq!(&envelope[97..103], &[0xa1, 0x00, 0x62, 0xc3, 0x28, 0x59]);
    assert!(std::str::from_utf8(&envelope[100..102]).is_err());
    // The deepest JSON case nests 100 000 levels.
    let deepest = by_id("fail-nesting-100000-levels").unwrap()["input"]["text"].as_str().unwrap();
    assert_eq!(common::nesting_depth(deepest), 100_000);
}

#[test]
fn the_verify_vectors_exercise_every_check() {
    let failing: BTreeSet<String> = cases("verify/cases.json")
        .iter()
        .filter_map(|c| c["expected"]["check"].as_str().map(str::to_string))
        .collect();
    for id in CheckId::ALL {
        assert!(failing.contains(id.id()), "no vector fails at {id}");
    }
    let passes = cases("verify/cases.json").iter().filter(|c| c["expected"]["verdict"] == "pass").count();
    assert!(passes >= 10, "{passes} passing cases");
}

#[test]
fn the_verify_vectors_pin_the_optional_documentation_members() {
    // Task 10.11a (docs/dev/task-10.11a.md D11-1, D11-3): `data_governance`
    // and `human_oversight` are judged by existing checks only. A record
    // carrying both verifies in both forms; each malformation fails at the
    // check spec §6.2 names; the signature covers the members.
    const CASES: &[(&str, &str, Option<&str>)] = &[
        ("pass-documentation-declared", "json", None),
        ("pass-documentation-declared-cose", "cose", None),
        ("fail-documentation-hash-edited", "json", Some("signature.payload_hash")),
        ("fail-documentation-hash-uppercase", "json", Some("format.schema")),
        ("fail-documentation-hash-empty", "json", Some("format.schema")),
        ("fail-documentation-null", "json", Some("json.structure")),
        ("fail-documentation-unknown-member", "json", Some("json.structure")),
        ("fail-documentation-missing-hash", "json", Some("json.structure")),
        ("fail-documentation-not-an-object", "json", Some("json.structure")),
        // QA QT-02 (QA/QA_REPORT_TASK_10_11A.md): each case above on the
        // other member too, so a verifier that misreads §2 rule 3 for one of
        // the two members fails a case.
        ("fail-documentation-governance-hash-edited", "json", Some("signature.payload_hash")),
        ("fail-documentation-oversight-hash-uppercase", "json", Some("format.schema")),
        ("fail-documentation-governance-hash-empty", "json", Some("format.schema")),
        ("fail-documentation-oversight-null", "json", Some("json.structure")),
        ("fail-documentation-governance-unknown-member", "json", Some("json.structure")),
        ("fail-documentation-oversight-missing-hash", "json", Some("json.structure")),
        ("fail-documentation-governance-not-an-object", "json", Some("json.structure")),
        // QA QT-01: each member written as the array of its one value.
        ("fail-documentation-governance-as-array", "json", Some("json.structure")),
        ("fail-documentation-oversight-as-array", "json", Some("json.structure")),
    ];
    let all = cases("verify/cases.json");
    let mut missing = Vec::new();
    for (id, form, check) in CASES {
        let Some(case) = all.iter().find(|c| c["id"] == *id) else {
            missing.push(*id);
            continue;
        };
        assert_eq!(case["input"]["form"], *form, "{id}");
        assert_eq!(case["expected"]["verdict"], if check.is_some() { "fail" } else { "pass" }, "{id}");
        assert_eq!(case["expected"]["check"].as_str(), *check, "{id}");
    }
    assert!(missing.is_empty(), "{} of {} documentation cases have no vector: {missing:?}", missing.len(), CASES.len());
    // The passing JSON case carries both members; no case that predates them
    // declares either (the committed vector declares neither).
    let declared = all.iter().find(|c| c["id"] == "pass-documentation-declared").unwrap();
    let text = declared["input"]["text"].as_str().unwrap();
    assert!(text.contains("\"data_governance\"") && text.contains("\"human_oversight\""), "{text}");
    for case in &all {
        let id = case["id"].as_str().unwrap();
        let bytes = input_bytes(&case["input"]);
        let mentions = bytes.windows(b"documentation_hash".len()).any(|w| w == b"documentation_hash");
        if !id.contains("-documentation-") {
            assert!(!mentions, "{id} declares a documentation member");
        }
    }
}

/// Every case with one object written as the array of its values (QA QT-01):
/// its id, the pointer of that object in the record it respells (the
/// predecessor, for the chain case), and the expected first failing check.
/// The record itself so written fails check 2 first (QJ-04).
const OBJECT_AS_ARRAY_CASES: [(&str, &str, &str); 21] = [
    ("fail-issuer-as-array", "/issuer", "json.structure"),
    ("fail-public-key-as-array", "/issuer/public_key", "json.structure"),
    ("fail-model-identity-as-array", "/model_identity", "json.structure"),
    ("fail-architecture-as-array", "/model_identity/architecture", "json.structure"),
    ("fail-state-component-as-array", "/model_identity/learned_state_components/0", "json.structure"),
    ("fail-learning-provenance-as-array", "/learning_provenance", "json.structure"),
    ("fail-training-environment-as-array", "/learning_provenance/training_environment", "json.structure"),
    ("fail-training-input-provenance-as-array", "/learning_provenance/training_input_provenance", "json.structure"),
    ("fail-collection-period-as-array", "/learning_provenance/training_input_provenance/collection_period", "json.structure"),
    ("fail-deployment-context-as-array", "/deployment_context", "json.structure"),
    ("fail-inference-boundary-as-array", "/deployment_context/inference_boundary", "json.structure"),
    ("fail-policy-compliance-as-array", "/policy_compliance", "json.structure"),
    ("fail-policy-result-as-array", "/policy_compliance/results/0", "json.structure"),
    ("fail-lineage-as-array", "/lineage", "json.structure"),
    ("fail-signature-section-as-array", "/signature", "json.structure"),
    ("fail-documentation-governance-as-array", "/data_governance", "json.structure"),
    ("fail-documentation-oversight-as-array", "/human_oversight", "json.structure"),
    ("fail-chain-predecessor-public-key-as-array", "/issuer/public_key", "lineage.chain"),
    ("fail-record-as-array", "", "input.form"),
    // Task 10.11b: an entry of derived_from, a later object kind.
    ("fail-derived-from-entry-as-array", "/model_identity/derived_from/0", "json.structure"),
    // Task 10.11e: an entry of statement_references, a later object kind.
    ("fail-statement-references-entry-as-array", "/model_identity/statement_references/0", "json.structure"),
];

#[test]
fn the_verify_vectors_pin_objects_written_as_arrays() {
    // QA QT-01 (spec §2 rule 2, check 4j): one case per nested object kind of
    // a record, and a predecessor. Each input is what its id says: at that
    // pointer, an array where the record has an object.
    let all = cases("verify/cases.json");
    for (id, pointer, check) in OBJECT_AS_ARRAY_CASES {
        let case = all.iter().find(|c| c["id"] == id).unwrap_or_else(|| panic!("{id} has no vector"));
        let expected = &case["expected"];
        assert_eq!((expected["verdict"].as_str(), expected["check"].as_str()), (Some("fail"), Some(check)), "{id}");
        let respelled = if check == "lineage.chain" { &case["previous"][0] } else { &case["input"] };
        assert_eq!(respelled["form"], "json", "{id}");
        let doc: Value = serde_json::from_slice(&input_bytes(respelled)).unwrap();
        assert!(doc.pointer(pointer).is_some_and(Value::is_array), "{id}: {pointer} is not an array");
    }
    let kinds: BTreeSet<String> =
        OBJECT_AS_ARRAY_CASES.iter().filter(|c| c.2 == "json.structure").map(|c| c.1.replace("/0", "/*")).collect();
    let every_kind: BTreeSet<String> =
        common::OBJECT_FIELDS.iter().map(|(kind, _)| kind.to_string()).filter(|kind| !kind.is_empty()).collect();
    assert_eq!(kinds, every_kind, "one json.structure case per nested object kind");
}

#[test]
fn the_verify_vectors_pin_the_task_10_11b_qa_fixes_and_the_statement_references() {
    // After the task 10.11b QA (QA/QA_REPORT_TASK_10_11B.md; spec §7, §8) and
    // task 10.11e (docs/dev/task-10.11e.md; spec §7.7): cases that pin the
    // rules the QA's wrong readings passed (QB-01, QB-03, QB-05, QB-08),
    // parameter_count (QB-09) and statement_references, each at the check
    // spec §6.2 names. They are the last cases, after the 203 before them,
    // and no earlier case carries statement_references.
    const CASES: &[(&str, &str, Option<&str>)] = &[
        // QB-01
        ("pass-general-component-name-backslash", "json", None),
        ("pass-general-component-names-nfc-and-nfd", "json", None),
        ("pass-general-component-names-case-twins", "json", None),
        // QB-03
        ("fail-general-component-name-empty-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-name-dot-segment-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-name-dotdot-segment-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-name-leading-slash-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-name-trailing-slash-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-name-double-slash-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-name-repeated-digest-kept", "json", Some("format.consistency")),
        ("fail-general-components-unordered-digest-kept", "json", Some("format.consistency")),
        ("fail-general-component-names-utf16-order", "json", Some("format.consistency")),
        ("fail-general-component-names-case-insensitive-order", "json", Some("format.consistency")),
        ("fail-profile-identifier-case", "json", Some("format.consistency")),
        ("fail-not-held-with-root", "json", Some("format.consistency")),
        ("fail-committed-digest-empty", "json", Some("format.consistency")),
        ("fail-residency-countries-repeated", "json", Some("format.consistency")),
        ("fail-derived-from-repeated", "json", Some("format.consistency")),
        ("pass-general-component-names-utf8-order", "json", None),
        ("pass-general-component-names-capitals-first", "json", None),
        ("pass-general-profile-look-alike", "json", None),
        ("pass-general-profile-look-alike-fullwidth", "json", None),
        ("pass-general-empty-model-format", "json", None),
        ("pass-general-empty-file-component", "json", None),
        // QB-05
        ("pass-general-profile-shaped-components", "json", None),
        // QB-08
        ("pass-profile-not-held", "json", None),
        ("pass-profile-derived-from", "json", None),
        ("pass-general-file-and-directory-names", "json", None),
        ("pass-general-component-name-with-controls", "json", None),
        ("fail-derived-from-itself", "json", Some("format.consistency")),
        // QB-09
        ("pass-general-parameter-count-not-stated", "json", None),
        ("pass-general-parameter-count-not-stated-cose", "cose", None),
        ("fail-profile-parameter-count-absent", "json", Some("format.consistency")),
        ("fail-general-parameter-count-null", "json", Some("json.structure")),
        // Task 10.11e
        ("pass-statement-references-oms-v1", "json", None),
        ("pass-statement-references-issuer-format", "json", None),
        ("pass-statement-references-issuer-format-cose", "cose", None),
        ("fail-statement-references-dotless-unregistered", "json", Some("format.consistency")),
        ("fail-statement-references-unordered", "json", Some("format.consistency")),
        ("fail-statement-references-repeated", "json", Some("format.consistency")),
        ("fail-statement-references-empty", "json", Some("format.schema")),
        ("fail-statement-references-digest-uppercase", "json", Some("format.schema")),
        ("fail-statement-references-digest-empty", "json", Some("format.schema")),
        ("fail-statement-references-format-uppercase", "json", Some("format.schema")),
        ("fail-statement-references-format-look-alike", "json", Some("format.schema")),
        ("fail-statement-references-null", "json", Some("json.structure")),
        ("fail-statement-references-entry-member-repeated", "json", Some("json.structure")),
        ("fail-statement-references-entry-unknown-member", "json", Some("json.structure")),
        ("fail-statement-references-entry-as-array", "json", Some("json.structure")),
        ("fail-statement-references-format-not-a-string", "json", Some("json.structure")),
        // After the task 10.11e QA (QA/QA_REPORT_TASK_10_11E.md, QE-02)
        ("fail-statement-references-dotless-oms-v2", "json", Some("format.consistency")),
        ("fail-statement-references-format-fullwidth", "json", Some("format.schema")),
        ("pass-statement-references-registered-name-as-segment", "json", None),
        ("pass-statement-references-two-of-one-format", "json", None),
        ("pass-profile-statement-references", "json", None),
        ("pass-profile-statement-references-cose", "cose", None),
        ("fail-derived-from-own-model-hash-differs-from-state-hash", "json", Some("format.consistency")),
        ("pass-derived-from-learned-state-hash", "json", None),
        ("pass-general-parameter-count-zero", "json", None),
        // Task 10.11cd: vmr-audit-checkpoint-v1 (Phase 8's Q9(b))
        ("pass-statement-references-vmr-audit-checkpoint-v1", "json", None),
        ("pass-statement-references-vmr-audit-checkpoint-v1-cose", "cose", None),
        ("fail-statement-references-vmr-audit-checkpoint-v1-case-variant", "json", Some("format.schema")),
        ("fail-statement-references-vmr-audit-checkpoint-look-alike", "json", Some("format.consistency")),
        // Task 10.12a (D12a-1): accelerator_software is never empty
        ("fail-accelerator-software-empty", "json", Some("format.schema")),
    ];
    // The general-description copies (QA QR-09 / D-1.5) are appended after
    // every committed case, so this tail is the committed set's.
    let all: Vec<Value> =
        cases("verify/cases.json").into_iter().filter(|c| !c["id"].as_str().unwrap().ends_with("-general-record")).collect();
    let earlier = 203;
    assert_eq!(all.len(), earlier + CASES.len(), "the 203 cases before the QA's fixes, and these");
    let tail: Vec<&str> = all[earlier..].iter().map(|c| c["id"].as_str().unwrap()).collect();
    let listed: Vec<&str> = CASES.iter().map(|(id, _, _)| *id).collect();
    assert_eq!(tail, listed, "these cases, in this order, after every earlier case");
    for (id, form, check) in CASES {
        let case = all.iter().find(|c| c["id"] == *id).unwrap();
        assert_eq!(case["input"]["form"], *form, "{id}");
        assert_eq!(case["expected"]["verdict"], if check.is_some() { "fail" } else { "pass" }, "{id}");
        assert_eq!(case["expected"]["check"].as_str(), *check, "{id}");
    }
    let needle = b"statement_references".as_slice();
    for case in &all[..earlier] {
        let id = case["id"].as_str().unwrap();
        assert!(!input_bytes(&case["input"]).windows(needle.len()).any(|w| w == needle), "{id}");
    }
}

#[test]
fn every_trust_store_vector_gives_its_expected_result() {
    let all = cases("trust-store/cases.json");
    let mut kinds = BTreeSet::new();
    for case in &all {
        let id = case["id"].as_str().unwrap();
        let result = TrustStore::from_json(&input_bytes(&case["input"]));
        let expected = &case["expected"];
        match (expected["result"].as_str().unwrap(), result) {
            ("ok", Ok(store)) => assert_eq!(store.sha256(), expected["sha256"], "{id}"),
            ("error", Err(e)) => {
                assert_eq!(e.kind.id(), expected["kind"], "{id}: {e}");
                kinds.insert(e.kind.id().to_string());
            }
            (want, got) => panic!("{id}: expected {want}, got {:?}", got.map(|s| s.sha256().to_string())),
        }
    }
    assert_eq!(kinds.len(), 13, "one store per loader kind: {kinds:?}");
}

/// Where `text` cites work outside the published documents, matched as QA
/// QC-03's fix map matches it: `\bQA\b`, `\btask [0-9]`, `\bGate [0-9]`,
/// `docs/`, `vmr/crates`, or a finding id `\b[PQ][0-9A-Z]*-[0-9]{2}\b`. The
/// first match, with what follows it.
fn internal_citation(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let word = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_');
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    for i in 0..b.len() {
        let at_word = i == 0 || !word(i - 1);
        let rest = &b[i..];
        let finding_id = at_word && matches!(b[i], b'P' | b'Q') && {
            let mut j = i + 1;
            while b.get(j).is_some_and(|c| c.is_ascii_digit() || c.is_ascii_uppercase()) {
                j += 1;
            }
            b.get(j) == Some(&b'-') && digit(j + 1) && digit(j + 2) && !word(j + 3)
        };
        if rest.starts_with(b"docs/")
            || rest.starts_with(b"vmr/crates")
            || (at_word && rest.starts_with(b"QA") && !word(i + 2))
            || (at_word && (rest.starts_with(b"task ") || rest.starts_with(b"Gate ")) && digit(i + 5))
            || finding_id
        {
            return Some(String::from_utf8_lossy(&b[i..(i + 24).min(b.len())]).into_owned());
        }
    }
    None
}

/// Every `description` string in a vector file, with its JSON pointer.
fn descriptions(value: &Value, pointer: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (key, member) in map {
                let here = format!("{pointer}/{key}");
                if let Some(text) = member.as_str().filter(|_| key == "description") {
                    out.push((here.clone(), text.to_string()));
                }
                descriptions(member, &here, out);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                descriptions(item, &format!("{pointer}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn no_vector_description_cites_internal_work() {
    // QA QC-03 (D11cd-14): a published vector says what a case is. It cites
    // no QA probe or report, no task, no gate, no repository path and no
    // finding id, none of which a reader of the published files can resolve.
    // Every description in the two files this generator writes, each file's
    // own included.
    let mut cited = Vec::new();
    for rel in ["verify/cases.json", "trust-store/cases.json"] {
        let doc: Value = serde_json::from_str(&read(rel)).unwrap();
        let mut all = Vec::new();
        descriptions(&doc, "", &mut all);
        assert!(all.len() > 1, "{rel}: no descriptions found");
        for (pointer, text) in all {
            if let Some(hit) = internal_citation(&text) {
                cited.push(format!("{rel}{pointer}: {hit:?} in {text:?}"));
            }
        }
    }
    assert!(cited.is_empty(), "vector descriptions cite internal work:\n{}", cited.join("\n"));
}

#[test]
#[ignore = "writes specs/test-vectors/; run with VMR_WRITE_VECTORS=1 to regenerate"]
#[allow(clippy::disallowed_methods)] // reading the opt-in switch is this generator's whole job
fn write_verify_vectors() {
    if std::env::var("VMR_WRITE_VECTORS").as_deref() != Ok("1") {
        eprintln!("VMR_WRITE_VECTORS is not 1: nothing written");
        return;
    }
    for (rel, contents) in generate::generate() {
        let path = vectors_dir().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}
