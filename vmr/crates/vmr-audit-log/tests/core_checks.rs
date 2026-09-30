// tests/core_checks.rs — two rules of the core no vector pins
// (specs/audit-log-format-v0.1.md): a hash is lower case (§2 rule 7) wherever
// the format reads one, and a checkpoint's checks run in §6's order, so the
// first failing check names the refusal.
//
// The published core vectors (specs/test-vectors/audit-log/) are frozen, so
// these cases are held here, as Rust tests.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_audit_log::log::{read_log, LogBuilder};
use vmr_audit_log::profile::CORE;
use vmr_audit_log::profiles::khalm_enforcer::PROFILE;
use vmr_audit_log::vmr_record::canonical::jcs;
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::{checkpoint, entry, proof, signing, Error};

/// The refusal id of a result that must be a refusal.
fn refused<T: std::fmt::Debug>(result: Result<T, Error>) -> &'static str {
    match result {
        Err(Error::Refused { id, .. }) => id,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// `hash` with its hexadecimal digits in upper case.
fn upper(hash: &str) -> String {
    let hex = hash.strip_prefix("sha256:").unwrap();
    format!("sha256:{}", hex.to_ascii_uppercase())
}

/// `hash` with its first letter digit in upper case.
fn mixed(hash: &str) -> String {
    let hex = hash.strip_prefix("sha256:").unwrap();
    let at = hex.find(|c: char| c.is_ascii_alphabetic()).unwrap();
    format!("sha256:{}{}{}", &hex[..at], hex[at..=at].to_ascii_uppercase(), &hex[at + 1..])
}

/// A checkpoint document with these members, signed by the audit key, or by
/// the key `signer` when given.
fn signed(document: Value, signer: &str) -> Vec<u8> {
    let signed = signing::sign_document(&key(signer), &document).unwrap();
    serde_json::to_vec(&signed).unwrap()
}

fn checkpoint_of(log_id: &str, tree_size: u64, root_hash: &str) -> Value {
    json!({
        "checkpoint_version": "0.1",
        "checkpoint_type": "vmr.audit-checkpoint",
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "issued_at": "2026-09-14T10:00:00Z",
    })
}

// ---- §2 rule 7: hashes are lower case ----

#[test]
fn a_checkpoint_s_root_hash_in_upper_or_mixed_case_is_refused_for_its_structure() {
    let audit = key(AUDIT_KEY);
    let (log, _) = seeded_log();
    let root = format_hash(&log.root());
    // Lower case, signed by the audit key: accepted.
    let good = signed(checkpoint_of(&key_id(AUDIT_KEY), log.len(), &root), AUDIT_KEY);
    assert!(checkpoint::verify_checkpoint(&good, audit.verifying_key()).is_ok());
    // The same root in other case, signed by the audit key: §6 check 4.
    for spelling in [upper(&root), mixed(&root)] {
        let bytes = signed(checkpoint_of(&key_id(AUDIT_KEY), log.len(), &spelling), AUDIT_KEY);
        assert_eq!(refused(checkpoint::verify_checkpoint(&bytes, audit.verifying_key())), "checkpoint.structure", "{spelling}");
    }
}

#[test]
fn an_enforcer_detail_hash_in_upper_case_is_refused_for_its_structure() {
    let (_, lines) = seeded_log();
    let mut value: Value = serde_json::from_str(&lines[0]).unwrap();
    assert!(entry::validate_entry(&value, &lines[0], &PROFILE).is_ok());
    let model_hash = value["detail"]["model_hash"].as_str().unwrap().to_string();
    value["detail"]["model_hash"] = Value::String(upper(&model_hash));
    let text = jcs(&value);
    assert_eq!(refused(entry::validate_entry(&value, &text, &PROFILE)), "audit_entry.structure");
}

#[test]
fn an_upper_case_previous_root_is_refused_for_its_structure_before_the_chain_rows() {
    for profile in [&CORE as &dyn vmr_audit_log::profile::EntryProfile, &PROFILE] {
        let (_, lines) = seeded_log();
        let mut second: Value = serde_json::from_str(&lines[1]).unwrap();
        let previous = second["previous_root"].as_str().unwrap().to_string();
        second["previous_root"] = Value::String(upper(&previous));
        // With its index right, it would otherwise be row 7; with its index
        // wrong too, row 6. Row 5 comes first either way.
        for index in [1u64, 5] {
            second["index"] = json!(index);
            let file = file_of(&[lines[0].clone(), jcs(&second)]);
            assert_eq!(refused(read_log(file.as_bytes(), profile)), "audit_entry.structure", "index {index}");
        }
    }
}

#[test]
fn an_inclusion_proof_s_path_in_upper_case_is_refused_for_its_structure() {
    let audit = key(AUDIT_KEY);
    let mut log = LogBuilder::new(key_id(AUDIT_KEY));
    let mut texts = Vec::new();
    for i in 0..3 {
        let e = log
            .append(t("2026-09-14T09:30:00Z"), "writer.note", json!({ "n": i }), &CORE)
            .unwrap();
        texts.push(e.canonical);
    }
    let cp = checkpoint::build_signed(&key_id(AUDIT_KEY), 3, &log.root(), t("2026-09-14T10:00:00Z"), &audit).unwrap();
    let good = proof::build_inclusion_proof(log.leaves(), 0, &texts[0], &cp, audit.verifying_key()).unwrap();
    let bytes = serde_json::to_vec(&good).unwrap();
    assert!(proof::verify_inclusion_proof(&bytes, audit.verifying_key(), &CORE).is_ok());

    let mut bad = good.clone();
    let first = bad["audit_path"][0].as_str().unwrap().to_string();
    bad["audit_path"][0] = Value::String(upper(&first));
    let bytes = serde_json::to_vec(&bad).unwrap();
    assert_eq!(refused(proof::verify_inclusion_proof(&bytes, audit.verifying_key(), &CORE)), "audit_proof.structure");
}

// ---- §6: the checkpoint's checks, in order ----

#[test]
fn a_checkpoint_of_an_empty_tree_is_refused_as_empty_before_its_signature_is_read() {
    let audit = key(AUDIT_KEY);
    let root = format_hash(&sha256(b""));
    // No signature at all: check 5 before check 6.
    let unsigned = serde_json::to_vec(&checkpoint_of(&key_id(AUDIT_KEY), 0, &root)).unwrap();
    assert_eq!(refused(checkpoint::verify_checkpoint(&unsigned, audit.verifying_key())), "checkpoint.empty_tree");
    // No signature and another key's log_id: check 5 before checks 6 and 7.
    let stranger = serde_json::to_vec(&checkpoint_of(&key_id(STRANGER_KEY), 0, &root)).unwrap();
    assert_eq!(refused(checkpoint::verify_checkpoint(&stranger, audit.verifying_key())), "checkpoint.empty_tree");
}

#[test]
fn a_bad_signature_section_is_refused_before_a_wrong_key() {
    let audit = key(AUDIT_KEY);
    let (log, _) = seeded_log();
    let root = format_hash(&log.root());
    let theirs = checkpoint_of(&key_id(STRANGER_KEY), log.len(), &root);

    // Another key's log_id and no signature: check 6 before check 7.
    let unsigned = serde_json::to_vec(&theirs).unwrap();
    assert_eq!(refused(checkpoint::verify_checkpoint(&unsigned, audit.verifying_key())), "checkpoint.signature_section");

    // Another key's log_id, signed by that key, then the section broken
    // (another algorithm; a payload hash that is not the payload's).
    let good: Value = serde_json::from_slice(&signed(theirs.clone(), STRANGER_KEY)).unwrap();
    let mut algorithm = good.clone();
    algorithm["signature"]["algorithm"] = json!("ES384");
    let mut payload = good.clone();
    payload["signature"]["signed_payload_hash"] = json!(format_hash(&sha256(b"another payload")));
    for broken in [algorithm, payload] {
        let bytes = serde_json::to_vec(&broken).unwrap();
        assert_eq!(refused(checkpoint::verify_checkpoint(&bytes, audit.verifying_key())), "checkpoint.signature_section");
    }

    // Its section whole: check 7.
    let bytes = serde_json::to_vec(&good).unwrap();
    assert_eq!(refused(checkpoint::verify_checkpoint(&bytes, audit.verifying_key())), "checkpoint.wrong_key");
}

#[test]
fn a_wrong_key_is_refused_before_the_signature_is_checked() {
    let audit = key(AUDIT_KEY);
    let (log, _) = seeded_log();
    let root = format_hash(&log.root());
    // The audit key's log_id, signed by another key: check 7 (its
    // signing_key_id), not check 8.
    let bytes = signed(checkpoint_of(&key_id(AUDIT_KEY), log.len(), &root), STRANGER_KEY);
    assert_eq!(refused(checkpoint::verify_checkpoint(&bytes, audit.verifying_key())), "checkpoint.wrong_key");
    // Signed by the audit key, then a signed member changed and the payload
    // hash made the new payload's: check 8.
    let mut value: Value = serde_json::from_slice(&signed(checkpoint_of(&key_id(AUDIT_KEY), log.len(), &root), AUDIT_KEY)).unwrap();
    value["issued_at"] = json!("2026-09-14T11:00:00Z");
    let payload = signing::payload_hash(&value);
    value["signature"]["signed_payload_hash"] = json!(payload);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(refused(checkpoint::verify_checkpoint(&bytes, audit.verifying_key())), "checkpoint.signature_invalid");
}
