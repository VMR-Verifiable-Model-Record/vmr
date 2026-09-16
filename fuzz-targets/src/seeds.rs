//! Seeds for every fuzz target, decoded from `specs/test-vectors/` and the
//! worked examples. Shared by `tests/vectors.rs` (the stable "checked
//! without nightly" run over these seeds) and `src/bin/write_corpus.rs`
//! (which materializes them as files for `cargo +nightly fuzz run`'s
//! corpus directory: `tools/fuzz.ps1`, task 10.13's pre-release fuzzing
//! task). Neither `tests/` nor `src/bin/` can share code any other way
//! without a public module, so this one is `pub` though nothing outside
//! this crate has a reason to call it.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// This repository's root: `fuzz-targets/`'s parent directory.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn read(rel: &str) -> Vec<u8> {
    let path = repo_root().join(rel);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn json(rel: &str) -> Value {
    serde_json::from_slice(&read(rel)).unwrap_or_else(|e| panic!("{rel}: not JSON: {e}"))
}

/// specs/test-vectors' own input wrapper: `{"text": "..."}` (a JSON string)
/// or `{"hex": "..."}` (arbitrary bytes, COSE included). `None` for neither.
fn wrapped_bytes(v: &Value) -> Option<Vec<u8>> {
    if let Some(t) = v.get("text").and_then(Value::as_str) {
        return Some(t.as_bytes().to_vec());
    }
    if let Some(h) = v.get("hex").and_then(Value::as_str) {
        return hex::decode(h).ok();
    }
    None
}

/// Every `input` and `previous` entry of specs/test-vectors/verify/cases.json
/// whose `form` is `want_form` ("json" or "cose"), decoded to bytes.
fn verify_vector_seeds(want_form: &str) -> Vec<Vec<u8>> {
    let doc = json("specs/test-vectors/verify/cases.json");
    let mut out = Vec::new();
    for case in doc["cases"].as_array().expect("verify/cases.json: cases") {
        let empty = Vec::new();
        let previous = case["previous"].as_array().unwrap_or(&empty);
        for input in std::iter::once(&case["input"]).chain(previous.iter()) {
            if input["form"] == want_form {
                if let Some(bytes) = wrapped_bytes(input) {
                    out.push(bytes);
                }
            }
        }
    }
    out
}

/// Seeds for the `record_json` target: `vmr_record::Record::from_json`.
pub fn record_json() -> Vec<Vec<u8>> {
    let mut seeds = verify_vector_seeds("json");
    // The two conformance vectors carry the record as a JSON value (not
    // pre-serialized text): re-serialize it the way `Record::from_json`
    // would be handed equivalent bytes to parse.
    for rel in [
        "specs/test-vectors/record/example-v0.1.json",
        "specs/test-vectors/record/example-general-v0.1.json",
    ] {
        seeds.push(serde_json::to_vec(&json(rel)["record"]).unwrap());
    }
    seeds.push(read("docs/examples/phi-4-mini-instruct/record.json"));
    seeds
}

/// Seeds for the `record_cose` target: `vmr_record::Record::from_cose`.
pub fn record_cose() -> Vec<Vec<u8>> {
    let mut seeds = verify_vector_seeds("cose");
    seeds.push(read("docs/examples/phi-4-mini-instruct/record.vmr"));
    seeds
}

/// Seeds for the `trust_store` target: `vmr_verify::TrustStore::from_json`.
pub fn trust_store() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    // specs/test-vectors/trust-store/cases.json: the loader's own vectors.
    let doc = json("specs/test-vectors/trust-store/cases.json");
    for case in doc["cases"].as_array().expect("trust-store/cases.json: cases") {
        if let Some(bytes) = wrapped_bytes(&case["input"]) {
            seeds.push(bytes);
        }
    }
    // Every trust store the verify vectors evaluate against, and the worked
    // example's: real TrustStoreDocument files, not the loader's wrapper.
    let stores_dir = repo_root().join("specs/test-vectors/verify/trust-stores");
    for entry in fs::read_dir(&stores_dir).unwrap() {
        seeds.push(fs::read(entry.unwrap().path()).unwrap());
    }
    seeds.push(read("docs/examples/phi-4-mini-instruct/trust-store.json"));
    seeds
}

/// Seeds for the `policy_pack` target: `vmr_policy::load_pack_bytes`.
pub fn policy_pack() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for rel in ["specs/test-vectors/policy/pack-loader.json", "specs/test-vectors/policy/pack-signature.json"] {
        let doc = json(rel);
        for case in doc["cases"].as_array().expect("cases") {
            if let Some(bytes) = wrapped_bytes(&case["pack"]) {
                seeds.push(bytes);
            }
        }
    }
    // The five reference policy packs: real, signed-or-not pack files.
    let packs_dir = repo_root().join("specs/policy-packs");
    for entry in fs::read_dir(&packs_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            seeds.push(fs::read(path).unwrap());
        }
    }
    seeds
}

/// Seeds for the `public_key` target: `vmr_cli::keys::parse_public_key_file`.
/// No committed test vectors are this exact format (a bare `{"key_id": ...,
/// "public_key": {...}}` file): built here from real JWKs the verify trust
/// stores already carry.
pub fn public_key() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for name in ["ts-basic", "ts-two-keys", "ts-rotated"] {
        let store = json(&format!("specs/test-vectors/verify/trust-stores/{name}.json"));
        for issuer in store["issuers"].as_array().expect("issuers") {
            for key in issuer["keys"].as_array().expect("keys") {
                let file = serde_json::json!({"key_id": key["key_id"], "public_key": key["public_key"]});
                seeds.push(serde_json::to_vec(&file).unwrap());
            }
        }
    }
    // A key file whose key_id does not match its own JWK (the exact case
    // parse_public_key_file names: "the file was altered").
    if let Some(first) = seeds.first().cloned() {
        let mut tampered: Value = serde_json::from_slice(&first).unwrap();
        tampered["key_id"] = Value::from("urn:ietf:params:oauth:jwk-thumbprint:sha-256:not-the-real-thumbprint");
        seeds.push(serde_json::to_vec(&tampered).unwrap());
    }
    seeds
}

/// Seeds for the `manifest` target: `vmr_cli::manifest::parse`.
pub fn manifest() -> Vec<Vec<u8>> {
    vec![read("docs/demo/record-manifest.json"), read("docs/examples/phi-4-mini-instruct/manifest.json")]
}

/// specs/test-vectors/audit-log's own wrapper for a case that may give a
/// document's exact bytes (`raw`, already text) or only its structured value
/// (serialized here the way `vmr-audit-log/tests/vectors.rs`'s own
/// `case_bytes` reads the same file, mirrored so this crate needs no second
/// reader of it).
fn audit_case_bytes(case: &Value, member: &str) -> Vec<u8> {
    if let Some(raw) = case.get("raw").and_then(Value::as_str) {
        return raw.as_bytes().to_vec();
    }
    serde_json::to_vec(&case[member]).unwrap()
}

fn audit_log_cases(key: &str) -> Vec<Value> {
    let doc = json("specs/test-vectors/audit-log/cases.json");
    doc[key].as_array().unwrap_or_else(|| panic!("audit-log cases.json: no {key} array")).clone()
}

/// Seeds for the `audit_entry` target: `vmr_audit_log::entry::validate_entry`
/// (every `entries` case's exact line — core and `khalm-vmr.enforcer` cases
/// alike, since the profile checked against is the target's own choice, not
/// the seed's).
pub fn audit_entry() -> Vec<Vec<u8>> {
    audit_log_cases("entries").iter().map(|c| audit_case_bytes(c, "raw")).collect()
}

/// Seeds for the `audit_log` target: `vmr_audit_log::log::read_log` (every
/// `logs` case's exact file bytes).
pub fn audit_log() -> Vec<Vec<u8>> {
    audit_log_cases("logs").iter().map(|c| audit_case_bytes(c, "raw")).collect()
}

/// Seeds for the `audit_checkpoint` target:
/// `vmr_audit_log::checkpoint::verify_checkpoint`.
pub fn audit_checkpoint() -> Vec<Vec<u8>> {
    audit_log_cases("checkpoints").iter().map(|c| audit_case_bytes(c, "checkpoint")).collect()
}

/// Seeds for the `audit_inclusion_proof` target:
/// `vmr_audit_log::proof::verify_inclusion_proof`.
pub fn audit_inclusion_proof() -> Vec<Vec<u8>> {
    audit_log_cases("inclusion_proofs").iter().map(|c| audit_case_bytes(c, "proof")).collect()
}

/// Seeds for the `audit_consistency_proof` target:
/// `vmr_audit_log::proof::verify_consistency_proof`.
pub fn audit_consistency_proof() -> Vec<Vec<u8>> {
    audit_log_cases("consistency_proofs").iter().map(|c| audit_case_bytes(c, "proof")).collect()
}

/// Every target's name, exactly as `fuzz/Cargo.toml`'s `[[bin]]` entries and
/// this crate's own function names spell it.
pub const NAMES: &[&str] = &[
    "record_json",
    "record_cose",
    "trust_store",
    "policy_pack",
    "public_key",
    "manifest",
    "audit_entry",
    "audit_log",
    "audit_checkpoint",
    "audit_inclusion_proof",
    "audit_consistency_proof",
];

/// `name`'s seeds (panics on a name not in [`NAMES`]: a programming error,
/// not a fuzzing result).
pub fn by_name(name: &str) -> Vec<Vec<u8>> {
    match name {
        "record_json" => record_json(),
        "record_cose" => record_cose(),
        "trust_store" => trust_store(),
        "policy_pack" => policy_pack(),
        "public_key" => public_key(),
        "manifest" => manifest(),
        "audit_entry" => audit_entry(),
        "audit_log" => audit_log(),
        "audit_checkpoint" => audit_checkpoint(),
        "audit_inclusion_proof" => audit_inclusion_proof(),
        "audit_consistency_proof" => audit_consistency_proof(),
        other => panic!("no such fuzz target: {other} (known: {NAMES:?})"),
    }
}

/// Every target's name and seeds, in [`NAMES`]'s order.
pub fn all() -> Vec<(&'static str, Vec<Vec<u8>>)> {
    NAMES.iter().map(|&name| (name, by_name(name))).collect()
}
