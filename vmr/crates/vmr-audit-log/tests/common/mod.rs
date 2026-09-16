// tests/common/mod.rs — the fixtures the audit-log vectors are built from.
//
// Every key is derived from a fixed label, for tests only, and the labels are
// the ones the sovereignty vectors used before the split (task 10.13): the
// moved cases keep every signed byte. Nothing here opens a file: a log is
// built in memory (vmr_audit_log::log::LogBuilder) and written to the vector
// file, never to disk.

#![allow(dead_code)]

use p256::ecdsa::SigningKey;
use serde_json::json;
use vmr_audit_log::log::LogBuilder;
use vmr_audit_log::profiles::khalm_enforcer::PROFILE;
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::vmr_record::timestamp::Timestamp;

/// A signing key derived from a fixed label (tests only).
pub fn key(label: &str) -> SigningKey {
    vmr_audit_log::vmr_record::sign::signing_key_from_secret(&sha256(label.as_bytes())).unwrap()
}

/// The key id of [`key`]'s key.
pub fn key_id(label: &str) -> String {
    vmr_audit_log::vmr_record::jwk::key_id(key(label).verifying_key())
}

/// A timestamp from its text.
pub fn t(s: &str) -> Timestamp {
    Timestamp::parse(s).unwrap()
}

/// Labels for the roles, as the sovereignty vectors derive them.
pub const AUDIT_KEY: &str = "khalm phase8 tests: audit key";
pub const EXPORT_KEY: &str = "khalm phase8 tests: export key (valid)";
pub const STRANGER_KEY: &str = "khalm phase8 tests: a key the bundle does not name";

/// The model the enforcer's bundle guards.
pub fn model_hash() -> String {
    format_hash(&sha256(b"the guarded model state"))
}

/// The payload hash of the sovereignty vectors' signed bundle, which the
/// seeded log's `enforcer.started` entry names. The bundle is the enforcer's
/// document, not this format's; `vmr-sovereignty`'s vectors test asserts that
/// its bundle still hashes to this, so the two vector sets cannot drift.
pub const BUNDLE_PAYLOAD_HASH: &str = "sha256:6d1a03838a1588d0752c7c0f57c575e8f339700f9d139e4d8d44ed73dcd59749";

/// The token the seeded log's `export.granted` entry spends.
pub const SPENT_TOKEN_ID: &str = "urn:uuid:55555555-5555-4555-8555-555555555555";

/// The two-entry log the vectors share: an `enforcer.started` and an
/// `export.granted` of the `khalm-vmr.enforcer` profile, built in memory.
pub fn seeded_log() -> (LogBuilder, Vec<String>) {
    let mut lines: Vec<String> = Vec::new();
    let mut log = LogBuilder::new(key_id(AUDIT_KEY));
    lines.push(log.append(
        t("2026-09-14T09:30:00Z"),
        "enforcer.started",
        json!({
            "audit_key_id": key_id(AUDIT_KEY),
            "bundle_id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "bundle_payload_hash": BUNDLE_PAYLOAD_HASH,
            "record_id": "urn:uuid:22222222-2222-4222-8222-222222222222",
            "model_hash": model_hash(),
            "mechanism": "bpf-lsm",
            "object_version": 1,
            "boot_id": "abcd",
        }),
        &PROFILE,
    )
    .unwrap().canonical);
    lines.push(log.append(
        t("2026-09-14T09:45:00Z"),
        "export.granted",
        json!({
            "token_id": SPENT_TOKEN_ID,
            "token_payload_hash": format_hash(&sha256(b"spent token")),
            "signing_key_id": key_id(EXPORT_KEY),
            "destination": { "protocol": "tcp", "address": "203.0.113.7", "port": 443 },
            "not_before": "2026-09-14T09:40:00Z",
            "not_after": "2026-09-14T09:50:00Z",
            "deadline": { "seconds": 900, "nanoseconds": 0 },
            "grant": 1,
        }),
        &PROFILE,
    )
    .unwrap().canonical);
    (log, lines)
}

/// A log's lines as one file's bytes: each line and a line feed.
pub fn file_of(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}
")).collect()
}

/// The vector generator (the writer and the reproducibility test use it).
pub mod generate;
