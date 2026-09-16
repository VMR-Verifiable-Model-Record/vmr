// tests/vectors.rs — the audit-log vectors (task 10.13): the committed
// specs/test-vectors/audit-log/cases.json is the cross-implementation contract
// of specs/audit-log-format-v0.1.md. It is written only by common/generate.rs
// (statuses by hand, bytes computed), and audit_log_vectors_are_reproducible
// fails if the committed bytes differ. Every case is replayed through this
// build, and the schema is held to the validators.

mod common;

use common::generate;
use common::*;
use serde_json::Value;
use std::path::{Path, PathBuf};
use vmr_audit_log::entry::validate_entry;
use vmr_audit_log::json::parse_json_bounded;
use vmr_audit_log::profile::{EntryProfile, CORE};
use vmr_audit_log::profiles::khalm_enforcer::PROFILE;
use vmr_audit_log::{checkpoint, log, proof};

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs")
}

fn read_cases() -> Value {
    let path = specs_dir().join("test-vectors/audit-log/cases.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn cases<'a>(doc: &'a Value, key: &str) -> &'a Vec<Value> {
    doc[key].as_array().unwrap_or_else(|| panic!("no {key} array"))
}

fn expect_id(case: &Value) -> &str {
    case["expect"].as_str().unwrap()
}

/// The profile a case names, or the core (§5.1).
fn profile_of(case: &Value) -> &'static dyn EntryProfile {
    match case.get("profile").and_then(Value::as_str) {
        None => &CORE,
        Some("khalm-vmr.enforcer") => &PROFILE,
        Some(other) => panic!("a case names the profile {other:?}, which this build does not have"),
    }
}

/// A case's document bytes: its `raw` text verbatim, else its `member` value.
fn case_bytes(case: &Value, member: &str) -> Vec<u8> {
    match case.get("raw") {
        Some(raw) => raw.as_str().unwrap().as_bytes().to_vec(),
        None => serde_json::to_vec(&case[member]).unwrap(),
    }
}

// ---------------------------------------------------------------------------
//  Reproducibility (the writer is the only ignored test)
// ---------------------------------------------------------------------------

#[test]
fn audit_log_vectors_are_reproducible() {
    for (rel, contents) in generate::generate() {
        let path = specs_dir().join("test-vectors").join(&rel);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()));
        assert!(
            committed == contents,
            "{rel} differs from a fresh generation: regenerate with VMR_WRITE_VECTORS=1, in its own commit"
        );
    }
}

#[test]
#[ignore = "writes specs/test-vectors/audit-log/; run with VMR_WRITE_VECTORS=1 -- --ignored, in its own commit"]
fn write_audit_log_vectors() {
    // The crate's clippy.toml forbids env reads; this writer says why.
    #[allow(clippy::disallowed_methods)]
    let write = std::env::var("VMR_WRITE_VECTORS").is_ok();
    if !write {
        eprintln!("set VMR_WRITE_VECTORS=1 to write the vectors");
        return;
    }
    for (rel, contents) in generate::generate() {
        let path = specs_dir().join("test-vectors").join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        eprintln!("wrote {}", path.display());
    }
}

// ---------------------------------------------------------------------------
//  Replaying the cases
// ---------------------------------------------------------------------------

#[test]
fn the_environment_is_this_builds() {
    let doc = read_cases();
    let env = &doc["environment"];
    assert_eq!(env["audit_key_id"].as_str().unwrap(), key_id(AUDIT_KEY), "the audit key id");
    let (log, lines) = seeded_log();
    let committed: Vec<String> =
        env["log_lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
    assert_eq!(committed, lines, "the environment's log lines");
    let cp = checkpoint::verify_checkpoint(
        &serde_json::to_vec(&env["checkpoint"]).unwrap(),
        key(AUDIT_KEY).verifying_key(),
    )
    .expect("the environment's checkpoint verifies");
    assert_eq!(cp.tree_size, log.len());
    assert_eq!(cp.root_hash, vmr_audit_log::vmr_record::hash::format_hash(&log.root()));
}

#[test]
fn every_log_vector_gives_its_expected_result() {
    let doc = read_cases();
    for case in cases(&doc, "logs") {
        let id = case["id"].as_str().unwrap();
        let result = log::read_log(case["raw"].as_str().unwrap().as_bytes(), profile_of(case));
        match expect_id(case) {
            "accept" => {
                result.unwrap_or_else(|e| panic!("{id}: expected accept, got {}", e.id()));
            }
            want => {
                let got = result.unwrap_err();
                assert_eq!(got.id(), want, "{id}: expected {want}, got {}", got.id());
            }
        }
    }
}

#[test]
fn every_entry_vector_gives_its_expected_result() {
    let doc = read_cases();
    for case in cases(&doc, "entries") {
        let id = case["id"].as_str().unwrap();
        let text = case["raw"].as_str().unwrap();
        // One line, read as a log of one entry reads it: size, syntax, then
        // the entry's own checks under the case's profile (§4.4 rows 1 to 5).
        let result = log::read_log(format!("{text}\n").as_bytes(), profile_of(case));
        match expect_id(case) {
            "accept" => {
                let entries = result.unwrap_or_else(|e| panic!("{id}: expected accept, got {}", e.id()));
                assert_eq!(entries.len(), 1, "{id}");
            }
            want => {
                let got = result.unwrap_err();
                assert_eq!(got.id(), want, "{id}: expected {want}, got {}", got.id());
            }
        }
        // An accepted entry read on its own is the same entry.
        if expect_id(case) == "accept" {
            let value = parse_json_bounded(text).unwrap();
            validate_entry(&value, text, profile_of(case)).unwrap_or_else(|e| panic!("{id}: {}", e.id()));
        }
    }
}

#[test]
fn every_checkpoint_vector_gives_its_expected_result() {
    let doc = read_cases();
    let audit_key = *key(AUDIT_KEY).verifying_key();
    for case in cases(&doc, "checkpoints") {
        let id = case["id"].as_str().unwrap();
        let result = checkpoint::verify_checkpoint(&case_bytes(case, "checkpoint"), &audit_key);
        match expect_id(case) {
            "accept" => {
                result.unwrap_or_else(|e| panic!("{id}: expected accept, got {}", e.id()));
            }
            want => assert_eq!(result.unwrap_err().id(), want, "{id}"),
        }
    }
}

#[test]
fn every_proof_vector_gives_its_expected_result() {
    let doc = read_cases();
    let audit_key = *key(AUDIT_KEY).verifying_key();
    for case in cases(&doc, "inclusion_proofs") {
        let id = case["id"].as_str().unwrap();
        let result = proof::verify_inclusion_proof(&case_bytes(case, "proof"), &audit_key, profile_of(case));
        match expect_id(case) {
            "accept" => {
                result.unwrap_or_else(|e| panic!("{id}: expected accept, got {}", e.id()));
            }
            want => assert_eq!(result.unwrap_err().id(), want, "{id}"),
        }
    }
    for case in cases(&doc, "consistency_proofs") {
        let id = case["id"].as_str().unwrap();
        let result = proof::verify_consistency_proof(&case_bytes(case, "proof"), &audit_key);
        match expect_id(case) {
            "accept" => {
                result.unwrap_or_else(|e| panic!("{id}: expected accept, got {}", e.id()));
            }
            want => assert_eq!(result.unwrap_err().id(), want, "{id}"),
        }
    }
}

// ---------------------------------------------------------------------------
//  Schema sync: the authored schema and the validators agree on the members
// ---------------------------------------------------------------------------

#[test]
fn the_schema_and_the_validators_agree_on_the_document_members() {
    let schema_path = specs_dir().join("audit-log-schema/v0.1.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(&schema_path).unwrap()).unwrap();
    assert_eq!(
        schema["$id"].as_str().unwrap(),
        "https://verifiablemodel.org/schemas/audit-log/v0.1.json",
        "the schema's $id is the published one"
    );
    let defs = schema["$defs"].as_object().expect("$defs");

    let expected: [(&str, &[&str]); 5] = [
        ("entry", &["log_version", "index", "previous_root", "recorded_at", "kind", "detail"]),
        ("khalm_enforcer_entry", &["log_version", "index", "previous_root", "recorded_at", "kind", "detail"]),
        ("checkpoint", &["checkpoint_version", "checkpoint_type", "log_id", "tree_size", "root_hash", "issued_at", "signature"]),
        ("inclusion_proof", &["proof_version", "proof_type", "checkpoint", "leaf_index", "entry", "audit_path"]),
        ("consistency_proof", &["proof_version", "proof_type", "from", "to", "proof"]),
    ];
    for (name, members) in expected {
        let props = defs[name]["properties"].as_object().unwrap_or_else(|| panic!("$defs.{name}.properties"));
        let mut schema_members: Vec<&str> = props.keys().map(String::as_str).collect();
        schema_members.sort_unstable();
        let mut want: Vec<&str> = members.to_vec();
        want.sort_unstable();
        assert_eq!(schema_members, want, "schema $defs.{name} members differ from the validator's");
    }

    // The profile's kinds are the schema's, and the core takes any kind its
    // grammar allows (§5).
    let kinds: Vec<&str> = defs["khalm_enforcer_entry"]["properties"]["kind"]["enum"]
        .as_array()
        .expect("the profile's kind enum")
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(kinds, vmr_audit_log::profiles::khalm_enforcer::KINDS, "the profile's kinds");
    assert!(defs["entry"]["properties"]["kind"].get("enum").is_none(), "the core entry names no kinds");
}
