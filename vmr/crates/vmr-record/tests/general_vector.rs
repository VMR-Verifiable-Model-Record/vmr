// tests/general_vector.rs — the generator and the checks of
// specs/test-vectors/record/example-general-v0.1.json (task 10.11b, plan
// §4.5; spec §9).
//
// A record in the general description (spec §7.3) of an open-weight model
// distributed as four synthetic files, issued by a party that holds the files
// and deploys the model but does not hold its training records (§8.4). It is
// signed with the conformance vector's test key (§9) and names no real model
// or vendor. No engine is needed. The file is written only by
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-record --test general_vector -- --ignored
// in its own commit; every other run checks that it is what this file writes.

use serde_json::{json, Value};
use vmr_record::canonical::jcs;
use vmr_record::hash::{format_hash, sha256};
use vmr_record::named_set::named_set_digest;
use vmr_record::record::*;
use vmr_record::sign::signing_key_from_secret;
use vmr_record::validate::ModelDescription;

/// The conformance vector's test key (spec §9): test-only.
const KEY_LABEL: &[u8] = b"khalm v0.1 test-vector signing key";
const RECORD_ID: &str = "urn:uuid:9e0c3c1a-6b2d-4f7e-8a51-3c2b1d0e9f10";
const DEPLOYMENT_ID: &str = "urn:uuid:5d2e8f41-0c7a-4b3e-9a62-8e1f0d4c7b29";
const ISSUER: &str = "did:web:factory-operator.ph";

/// The model's synthetic files, (name, contents), in name order.
const FILES: [(&str, &str); 4] = [
    ("config.json", "{\"architectures\":[\"ExampleDecoderOnly\"],\"hidden_size\":8,\"num_hidden_layers\":2}\n"),
    ("model-00001-of-00002.safetensors", "synthetic shard 1 of 2: not a real model\n"),
    ("model-00002-of-00002.safetensors", "synthetic shard 2 of 2: not a real model\n"),
    ("tokenizer.json", "{\"version\":\"1.0\",\"model\":{\"type\":\"example\"}}\n"),
];

/// The named-set digest of FILES, computed independently with Python's
/// hashlib (u64 big-endian name length, name, SHA-256, in name order).
const MODEL_HASH: &str = "sha256:06923b0375f50a7a550788b010f2a93b9852572cc2928238462822b00c0f33a7";

fn vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors/record/example-general-v0.1.json")
}

fn key() -> p256::ecdsa::SigningKey {
    signing_key_from_secret(&sha256(KEY_LABEL)).unwrap()
}

fn general_record() -> Record {
    let jwk = JwkPublicKey::from_verifying_key(key().verifying_key());
    let key_id = jwk.key_id();
    let digests: Vec<(&str, [u8; 32])> = FILES.iter().map(|(name, text)| (*name, sha256(text.as_bytes()))).collect();
    let model_hash = format_hash(&named_set_digest(&digests).unwrap());
    let empty = String::new;
    let mut p = Record {
        record_version: "0.1".into(),
        record_id: RECORD_ID.into(),
        issued_at: "2026-09-10T00:00:00Z".into(),
        issuer: Issuer {
            issuer_id: ISSUER.into(),
            issuer_name: "New Clark City Fab Operator".into(),
            public_key: jwk,
            key_id: key_id.clone(),
            attestation_level: "software".into(),
        },
        model_identity: ModelIdentity {
            model_hash: model_hash.clone(),
            model_format: "safetensors".into(),
            parameter_count: Some(64),
            architecture: Architecture {
                kind: "transformer".into(),
                topology: "decoder-only".into(),
                precision: "bfloat16".into(),
            },
            learned_state_hash: model_hash,
            learned_state_components: FILES
                .iter()
                .map(|(name, text)| StateComponent {
                    name: name.to_string(),
                    hash: format_hash(&sha256(text.as_bytes())),
                    size_bytes: text.len() as u64,
                })
                .collect(),
            derived_from: None,
            statement_references: None,
        },
        learning_provenance: LearningProvenance {
            training_input_digest: empty(),
            training_input_merkle_root: empty(),
            training_input_count: 0,
            training_epochs: None,
            training_started_at: None,
            training_ended_at: None,
            training_environment: TrainingEnvironment {
                hardware_id: empty(),
                tee_measurement: empty(),
                software_hash: empty(),
                accelerator_software: None,
                training_software: empty(),
                accelerator: None,
            },
            training_input_provenance: TrainingInputProvenance {
                source_type: empty(),
                source_description: empty(),
                data_residency: None,
                collection_period: None,
                data_residency_countries: None,
            },
            training_input_format: None,
            training_input_disclosure: Some("not-held".into()),
        },
        deployment_context: Some(DeploymentContext {
            deployment_id: DEPLOYMENT_ID.into(),
            deployed_at: "2026-09-10T00:00:00Z".into(),
            deployed_by: ISSUER.into(),
            hardware_id: empty(),
            tee_measurement: empty(),
            software_hash: empty(),
            inference_boundary: InferenceBoundary {
                kind: "air-gapped".into(),
                egress_allowed: false,
                allowed_egress_destinations: vec![],
            },
            policy_pack_id: "example-policy-pack-v1".into(),
        }),
        policy_compliance: PolicyCompliance {
            policy_pack_id: "example-policy-pack-v1".into(),
            evaluated_at: "2026-09-10T00:00:00Z".into(),
            results: vec![],
            overall_status: "indeterminate".into(),
        },
        lineage: Lineage {
            previous_record_id: None,
            previous_record_hash: None,
            lineage_chain_length: 1,
            root_record_id: RECORD_ID.into(),
            lineage_type: "initial".into(),
        },
        data_governance: None,
        human_oversight: None,
        signature: SignatureSection { signing_key_id: key_id, ..SignatureSection::default() },
    };
    let sig = vmr_record::sign::sign(&key(), &p.signature_tbs().unwrap()).unwrap();
    p.signature.algorithm = "ES256".into();
    p.signature.signature = SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
    p
}

fn file() -> Value {
    let p = general_record();
    json!({
        "description": "Conformance vector v0.1 for this format's general model description (record format v0.1, §7.3): an open-weight model distributed as four synthetic files (listed in `files`, which are not a real model), described by a party that holds the files and deploys the model, and that does not hold the model's training records (§8.4). No real model, vendor or authority is named; the policy section declares no evaluation. Written by the vmr-record crate's generator (VMR_WRITE_VECTORS=1 cargo test -p vmr-record --test general_vector -- --ignored). Signing key: secret scalar = SHA-256(\"khalm v0.1 test-vector signing key\") — test-only.",
        "files": FILES.iter().map(|(name, text)| json!({
            "name": name,
            "size_bytes": text.len(),
            "sha256": format_hash(&sha256(text.as_bytes())),
            "text": text,
        })).collect::<Vec<_>>(),
        "expected": {
            "signed_payload": String::from_utf8(p.signed_payload().unwrap()).unwrap(),
            "signed_payload_hash": p.signed_payload_hash().unwrap(),
        },
        "record": serde_json::to_value(&p).unwrap(),
    })
}

fn pretty(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap())
}

#[test]
fn general_vector_is_reproducible() {
    let committed = std::fs::read_to_string(vector_path()).expect("specs/test-vectors/record/example-general-v0.1.json");
    assert!(committed == pretty(&file()), "the committed general vector differs from what the generator writes");
}

#[test]
#[ignore = "writes specs/test-vectors/record/example-general-v0.1.json; run with VMR_WRITE_VECTORS=1 to regenerate"]
#[allow(clippy::disallowed_methods)] // reading the opt-in switch is this generator's whole job
fn write_general_vector() {
    if std::env::var("VMR_WRITE_VECTORS").as_deref() != Ok("1") {
        eprintln!("VMR_WRITE_VECTORS is not 1: nothing written");
        return;
    }
    std::fs::write(vector_path(), pretty(&file())).unwrap();
}

#[test]
fn the_general_vector_is_a_consistent_signed_general_record() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(vector_path()).unwrap()).unwrap();
    let p = Record::from_json(&serde_json::to_string(&doc["record"]).unwrap()).unwrap();
    assert_eq!(p.model_description(), ModelDescription::General);
    p.validate_format().unwrap();
    p.check_consistency().unwrap();
    p.verify_signature(key().verifying_key()).unwrap();
    // The payload is the JCS form of the record without its signature (§3).
    let mut unsigned = doc["record"].clone();
    unsigned.as_object_mut().unwrap().remove("signature");
    assert_eq!(doc["expected"]["signed_payload"], jcs(&unsigned));
    assert_eq!(doc["expected"]["signed_payload_hash"], format_hash(&sha256(jcs(&unsigned).as_bytes())));
    assert_eq!(p.signature.signed_payload_hash, doc["expected"]["signed_payload_hash"]);
    // Each file hashes to its component; the model hash is the independently
    // computed named-set digest, and the components are every file.
    let files = doc["files"].as_array().unwrap();
    assert_eq!(files.len(), p.model_identity.learned_state_components.len());
    for (file, component) in files.iter().zip(&p.model_identity.learned_state_components) {
        let text = file["text"].as_str().unwrap();
        assert_eq!(file["name"], component.name.as_str());
        assert_eq!((format_hash(&sha256(text.as_bytes())), text.len() as u64), (component.hash.clone(), component.size_bytes));
    }
    assert_eq!(p.model_identity.model_hash, MODEL_HASH);
    assert_eq!(p.model_identity.learned_state_hash, MODEL_HASH);
    // Not held (§8.4): nothing committed, and nothing unknown stated.
    let l = &p.learning_provenance;
    assert_eq!(l.training_input_disclosure.as_deref(), Some("not-held"));
    assert_eq!((l.training_input_digest.as_str(), l.training_input_merkle_root.as_str(), l.training_input_count), ("", "", 0));
    assert!(l.training_epochs.is_none() && l.training_started_at.is_none() && l.training_input_format.is_none());
    // A COSE round trip gives the same record.
    assert_eq!(Record::from_cose(&p.to_cose().unwrap()).unwrap(), p);
}
