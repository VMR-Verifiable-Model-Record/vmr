// tests/general.rs — task 10.13a, commits B2/B3 (docs/dev/task-10.13a.md,
// D13a-1): the general description (spec §7.3) of a model from its files,
// signed through the engine-free assembly.
//
// No engine and no file system: a model is a set of named files, each by its
// name, SHA-256 and size (the walk of B4/B5 makes them from a folder). Every
// expected digest here comes from the spec's own example (§7.2) or from the
// committed vectors (specs/test-vectors/model-hash/, example-general-v0.1.json),
// never from the code under test.

use serde_json::{json, Value};
use vmr_builder::general::{DigestSource, FileEntry, FileSet, GeneralBuilder, Training};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::*;
use vmr_record::sign::signing_key_from_secret;

fn repo_file(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

fn entry(name: &str, bytes: &[u8]) -> FileEntry {
    FileEntry { name: name.into(), digest: sha256(bytes), size_bytes: bytes.len() as u64, source: DigestSource::Read { through_link: false } }
}

fn files(members: &[(&str, &[u8])]) -> FileSet {
    FileSet::from_entries(members.iter().map(|(n, b)| entry(n, b)).collect()).unwrap()
}

/// The conformance vectors' test key (spec §9): test-only.
fn vector_key() -> p256::ecdsa::SigningKey {
    signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap()
}

fn issuer(key: &p256::ecdsa::SigningKey) -> Issuer {
    Issuer {
        issuer_id: "did:web:example.org".into(),
        issuer_name: "Example issuer".into(),
        public_key: JwkPublicKey::from_verifying_key(key.verifying_key()),
        key_id: String::new(),
        attestation_level: "software".into(),
    }
}

fn empty_environment() -> TrainingEnvironment {
    TrainingEnvironment {
        hardware_id: String::new(),
        tee_measurement: String::new(),
        software_hash: String::new(),
        accelerator_software: None,
        training_software: String::new(),
        accelerator: None,
    }
}

fn empty_provenance() -> TrainingInputProvenance {
    TrainingInputProvenance {
        source_type: String::new(),
        source_description: String::new(),
        data_residency: None,
        collection_period: None,
        data_residency_countries: None,
    }
}

const ID: &str = "urn:uuid:3f0c6a52-8d4e-4b1a-9c2f-7e5d1a0b9c8d";

/// A builder with every required statement, over `model`.
fn builder(model: FileSet) -> GeneralBuilder {
    let key = vector_key();
    GeneralBuilder::new(model)
        .record_id(ID)
        .issued_at("2026-09-14T00:00:00Z")
        .issuer(issuer(&key))
        .model_format("safetensors")
        .architecture(Architecture { kind: "transformer".into(), topology: "decoder-only".into(), precision: "bfloat16".into() })
        .training(Training::NotHeld)
        .training_environment(empty_environment())
        .training_input_provenance(empty_provenance())
        .policy_compliance(PolicyCompliance {
            policy_pack_id: "example-policy-pack-v1".into(),
            evaluated_at: "2026-09-14T00:00:00Z".into(),
            results: vec![],
            overall_status: "indeterminate".into(),
        })
        .lineage(Lineage {
            previous_record_id: None,
            previous_record_hash: None,
            lineage_chain_length: 1,
            root_record_id: ID.into(),
            lineage_type: "initial".into(),
        })
}

fn two_files() -> FileSet {
    files(&[("config.json", b"{}"), ("weights.bin", &[0u8; 4])])
}

#[test]
fn the_spec_example_is_the_model_hash_of_its_files() {
    // Spec §7.2's example: config.json ("{}") and weights.bin (four zero bytes).
    assert_eq!(
        format_hash(&two_files().named_set_digest()),
        "sha256:bcd9ed61d08e582e69d37afb23dbf37c69b14a3e26d1751a7d6ac6f12803c6d3"
    );
    let one = files(&[("weights.bin", &[0u8; 4])]);
    assert_eq!(format_hash(&one.named_set_digest()), "sha256:c32b0039edc7ed971446e62f8701b5a835f9c15b3fbac208f318e2626b9650ea");
    let p = builder(two_files()).build(&vector_key()).unwrap();
    assert_eq!(p.model_identity.model_hash, "sha256:bcd9ed61d08e582e69d37afb23dbf37c69b14a3e26d1751a7d6ac6f12803c6d3");
    assert_eq!(p.model_identity.learned_state_hash, p.model_identity.model_hash, "every file is a component");
    let names: Vec<&str> = p.model_identity.learned_state_components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["config.json", "weights.bin"]);
    assert_eq!(p.model_identity.learned_state_components[1].size_bytes, 4);
    assert_eq!(p.model_identity.learned_state_components[1].hash, format_hash(&sha256(&[0u8; 4])));
}

#[test]
fn the_general_vector_is_what_the_builder_signs_from_its_files() {
    // example-general-v0.1.json: four synthetic files, not-held training, a
    // deployment context and no declared evaluation, signed with the test key.
    let doc: Value = serde_json::from_str(&repo_file("specs/test-vectors/record/example-general-v0.1.json")).unwrap();
    let record = &doc["record"];
    let model = FileSet::from_entries(
        doc["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| entry(f["name"].as_str().unwrap(), f["text"].as_str().unwrap().as_bytes()))
            .collect(),
    )
    .unwrap();
    // A macro, not a closure: each use deserializes its own type.
    macro_rules! from {
        ($v:expr) => {
            serde_json::from_value($v.clone()).unwrap()
        };
    }
    let key = vector_key();
    let mut issuer: Issuer = from!(&record["issuer"]);
    issuer.key_id = String::new();
    let identity = &record["model_identity"];
    let p = GeneralBuilder::new(model)
        .record_id(record["record_id"].as_str().unwrap())
        .issued_at(record["issued_at"].as_str().unwrap())
        .issuer(issuer)
        .model_format(identity["model_format"].as_str().unwrap())
        .parameter_count(identity["parameter_count"].as_u64().unwrap())
        .architecture(from!(&identity["architecture"]))
        .training(Training::NotHeld)
        .training_environment(from!(&record["learning_provenance"]["training_environment"]))
        .training_input_provenance(from!(&record["learning_provenance"]["training_input_provenance"]))
        .deployment_context(from!(&record["deployment_context"]))
        .policy_compliance(from!(&record["policy_compliance"]))
        .lineage(from!(&record["lineage"]))
        .build(&key)
        .unwrap();
    assert_eq!(serde_json::to_value(&p).unwrap(), *record, "the builder signs the committed vector's record");
    assert_eq!(Value::String(p.signed_payload_hash().unwrap()), doc["expected"]["signed_payload_hash"]);
    assert_eq!(Value::String(String::from_utf8(p.signed_payload().unwrap()).unwrap()), doc["expected"]["signed_payload"]);
}

#[test]
fn the_same_inputs_give_the_same_record_byte_for_byte() {
    let a = builder(two_files()).build(&vector_key()).unwrap();
    let b = builder(two_files()).build(&vector_key()).unwrap();
    assert_eq!(a.to_cose().unwrap(), b.to_cose().unwrap());
    assert_eq!(a.to_json().unwrap(), b.to_json().unwrap());
    // One changed issuer input, another record.
    let c = builder(two_files()).issued_at("2026-09-14T00:00:01Z").build(&vector_key()).unwrap();
    assert_ne!(a.to_cose().unwrap(), c.to_cose().unwrap());
}

#[test]
fn a_file_set_orders_names_by_their_utf8_bytes_and_refuses_repeats_and_bad_names() {
    // Given out of order: sorted by UTF-8 bytes, so U+FF5E comes before U+1F600
    // (spec §7.2), and `a b` < `a-b` < `a.b` < `a/b` < `a0`.
    let set = files(&[("\u{1f600}", b"x"), ("a0", b"x"), ("a/b", b"x"), ("\u{ff5e}", b"x"), ("a.b", b"x"), ("a b", b"x"), ("a-b", b"x")]);
    let names: Vec<&str> = set.entries().iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["a b", "a-b", "a.b", "a/b", "a0", "\u{ff5e}", "\u{1f600}"]);
    for (members, expect) in [
        (vec![entry("a", b"1"), entry("a", b"2")], "twice"),
        (vec![entry("a/../b", b"1")], "a name has no .. segment"),
        (vec![entry("", b"1")], "a name is not empty"),
        (vec![entry("dir/", b"1")], "no empty segment"),
    ] {
        let err = FileSet::from_entries(members).unwrap_err().to_string();
        assert!(err.contains(expect), "expected {expect:?} in {err}");
    }
    // A backslash is a name character (spec §7.2), and names are not normalised
    // or case-folded: all four are members.
    let kept = files(&[("a\\b", b"1"), ("\u{e9}.bin", b"2"), ("e\u{301}.bin", b"3"), ("README.md", b"4"), ("readme.md", b"5")]);
    assert_eq!(kept.len(), 5);
}

#[test]
fn a_subset_of_components_names_the_learned_state_and_model_hash_still_covers_every_file() {
    let model = files(&[("config.json", b"{}"), ("model.safetensors", b"weights"), ("tokenizer.json", b"tok")]);
    let every = format_hash(&model.named_set_digest());
    let p = builder(model).components(vec!["model.safetensors".into()]).build(&vector_key()).unwrap();
    assert_eq!(p.model_identity.model_hash, every);
    let only = files(&[("model.safetensors", b"weights")]);
    assert_eq!(p.model_identity.learned_state_hash, format_hash(&only.named_set_digest()));
    assert_ne!(p.model_identity.learned_state_hash, p.model_identity.model_hash);
    assert_eq!(p.model_identity.learned_state_components.len(), 1);
}

#[test]
fn a_component_that_is_not_one_file_of_the_model_is_refused_before_signing() {
    for (components, expect) in [
        (vec!["missing.bin".to_string()], "is not a file of the model"),
        (vec!["config.json".into(), "config.json".into()], "twice"),
        (vec!["./config.json".into()], "a name has no . segment"),
        (vec![], "at least one component"),
    ] {
        let err = builder(two_files()).components(components.clone()).build(&vector_key()).unwrap_err().to_string();
        assert!(err.contains(expect), "{components:?}: expected {expect:?} in {err}");
    }
}

#[test]
fn a_registered_profile_identifier_is_never_the_format_of_a_models_files() {
    let err = builder(two_files()).model_format("snn-compact-v1").build(&vector_key()).unwrap_err().to_string();
    assert!(err.contains("snn-compact-v1") && err.contains("profile"), "{err}");
    let err = builder(two_files()).model_format("").build(&vector_key()).unwrap_err().to_string();
    assert!(err.contains("model_format"), "{err}");
}

#[test]
fn a_model_of_no_files_is_refused() {
    let err = builder(FileSet::from_entries(vec![]).unwrap()).build(&vector_key()).unwrap_err().to_string();
    assert!(err.contains("at least one file"), "{err}");
}

#[test]
fn missing_required_statements_are_refused_by_name() {
    let key = vector_key();
    let bare = || GeneralBuilder::new(two_files()).record_id(ID).issued_at("2026-09-14T00:00:00Z").issuer(issuer(&key));
    for (b, name) in [
        (bare(), "model_format"),
        (bare().model_format("gguf"), "architecture"),
        (
            bare().model_format("gguf").architecture(Architecture { kind: String::new(), topology: String::new(), precision: String::new() }),
            "training",
        ),
    ] {
        let err = b.build(&key).unwrap_err().to_string();
        assert!(err.contains(&format!("missing required field: {name}")), "{name}: {err}");
    }
}

#[test]
fn named_set_v1_records_commit_their_count_digest_and_merkle_root() {
    let doc: Value = serde_json::from_str(&repo_file("specs/test-vectors/model-hash/cases.json")).unwrap();
    let mut seen = 0;
    for case in doc["cases"].as_array().unwrap().iter().filter(|c| c["kind"] == "named-set-records") {
        let records = FileSet::from_entries(
            case["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| entry(m["name"].as_str().unwrap(), &hex_bytes(m["bytes_hex"].as_str().unwrap())))
                .collect(),
        )
        .unwrap();
        let commitment = vmr_builder::general::commit_records(&records);
        let expected = &case["expected"];
        assert_eq!(json!(commitment.count), expected["training_input_count"], "{}", case["id"]);
        assert_eq!(json!(format_hash(&commitment.digest)), expected["training_input_digest"], "{}", case["id"]);
        assert_eq!(json!(format_hash(&commitment.merkle_root)), expected["training_input_merkle_root"], "{}", case["id"]);
        seen += 1;
    }
    assert!(seen >= 9, "the vectors' named-set-records cases: {seen}");
    // In a record: the format named, the commitment carried, nothing disclosed.
    let records = files(&[("record-00000", b"record 0\n"), ("record-00001", b"record 1\n")]);
    let p = builder(two_files()).training(Training::Records(records)).build(&vector_key()).unwrap();
    let l = &p.learning_provenance;
    assert_eq!(l.training_input_format.as_deref(), Some("named-set-v1"));
    assert_eq!(l.training_input_count, 2);
    assert_eq!(l.training_input_digest, "sha256:684c832f290bc51d6fe4d77c2e4e72da586cc0254589c9ba9050bc4fa6a87614");
    assert_eq!(l.training_input_merkle_root, "sha256:85a88e16e29142cef985afc886520f170bd28c8fda2106867c6f5d5956509fd7");
    assert!(l.training_input_disclosure.is_none());
}

#[test]
fn not_held_and_not_disclosed_commit_nothing_and_state_nothing_unknown() {
    for (training, word) in [(Training::NotHeld, "not-held"), (Training::NotDisclosed, "not-disclosed")] {
        let p = builder(two_files()).training(training).build(&vector_key()).unwrap();
        let l = &p.learning_provenance;
        assert_eq!(l.training_input_disclosure.as_deref(), Some(word));
        assert_eq!((l.training_input_digest.as_str(), l.training_input_merkle_root.as_str(), l.training_input_count), ("", "", 0));
        assert!(l.training_input_format.is_none() && l.training_epochs.is_none() && l.training_started_at.is_none() && l.training_ended_at.is_none());
        // What the issuer did not state is absent, never guessed.
        assert!(p.model_identity.parameter_count.is_none());
        assert!(p.deployment_context.is_none());
        assert!(p.model_identity.derived_from.is_none() && p.model_identity.statement_references.is_none());
    }
}

#[test]
fn bases_and_statement_references_are_signed_as_stated_and_checked_as_verifiers_check_them() {
    let base = format!("sha256:{}", "0a".repeat(32));
    let later = format!("sha256:{}", "0b".repeat(32));
    let bases = vec![
        BaseModel { model_hash: base.clone(), name: "a base".into(), relation: "quantization".into() },
        BaseModel { model_hash: later, name: String::new(), relation: "adapter".into() },
    ];
    let reference = StatementReference { format: "oms-v1".into(), digest: format!("sha256:{}", "cc".repeat(32)) };
    let p = builder(two_files()).derived_from(bases.clone()).statement_references(vec![reference.clone()]).build(&vector_key()).unwrap();
    assert_eq!(p.model_identity.derived_from.as_deref(), Some(bases.as_slice()));
    assert_eq!(p.model_identity.statement_references.as_deref(), Some(std::slice::from_ref(&reference)));
    // A model is not made from itself (spec §7.5).
    let own = format_hash(&two_files().named_set_digest());
    let err = builder(two_files())
        .derived_from(vec![BaseModel { model_hash: own, name: String::new(), relation: "fine-tune".into() }])
        .build(&vector_key())
        .unwrap_err()
        .to_string();
    assert!(err.contains("not made from itself"), "{err}");
    // An unregistered format without a dot (spec §7.7).
    let err = builder(two_files())
        .statement_references(vec![StatementReference { format: "oms-v2".into(), digest: reference.digest.clone() }])
        .build(&vector_key())
        .unwrap_err()
        .to_string();
    assert!(err.contains("statement_references"), "{err}");
}

#[test]
fn a_record_signed_by_the_builder_verifies_and_round_trips() {
    let key = vector_key();
    let p = builder(two_files()).parameter_count(0).build(&key).unwrap();
    p.verify_signature(key.verifying_key()).unwrap();
    assert_eq!(p.model_identity.parameter_count, Some(0), "0 states a model with no learned parameters (spec §7.3)");
    assert_eq!(Record::from_cose(&p.to_cose().unwrap()).unwrap(), p);
    assert_eq!(Record::from_json(&p.to_json().unwrap()).unwrap(), p);
}
