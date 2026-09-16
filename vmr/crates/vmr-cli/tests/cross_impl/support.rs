//! What the cross_impl modules share: the issuer they emit as, its trust
//! store and the published policy vectors.

// Each module uses part of this. vmr-cli's cross_impl target compiles only
// policy_vectors; the engine build's target takes this file by path with
// Phase 7's engine modules (task 10.13a).
#![allow(dead_code)]

use crate::common::*;
use serde_json::Value;

/// The demo manifest's issuer.
pub const ISSUER: &str = "did:web:factory-operator.ph";
/// Its name, as the demo manifest and the trust store give it.
pub const ISSUER_NAME: &str = "New Clark City Fab Operator";
/// The issued_at of every record these tests emit (the Gate 5 artifact's).
pub const ISSUED: &str = "2026-09-11T00:00:00Z";
/// The verification time: twelve hours later, as Gate 5 verifies.
pub const AT: &str = "2026-09-11T12:00:00Z";
/// The derived, test-only key these tests emit with.
pub const KEY_LABEL: &str = "khalm-vmr cross_impl issuer key (test-only)";
/// The five committed reference packs (`specs/policy-packs/`), by id.
pub const REFERENCE_PACKS: [&str; 5] =
    ["khalm-reading-eu-ai-act-2026", "khalm-reading-nist-ai-rmf-1.0", "khalm-reading-iso-42001-2023", "khalm-reading-c2pa-ai-disclosure-2.2", "khalm-reading-rats-rfc9334-v0.1"];

/// A trust store holding `label`'s key for the demo issuer, at `software`,
/// from 2026-09-01: the verifier's operator's decision, as `vmr trust-store
/// add` would write it. Validated before it is returned.
pub fn store_json(label: &str) -> String {
    use vmr_verify::trust_store::{AttestationLevel, IssuerDocument, KeyDocument, TrustStoreDocument, TRUST_STORE_VERSION};
    let jwk = vmr_record::record::JwkPublicKey::from_verifying_key(key(label).verifying_key());
    let doc = TrustStoreDocument {
        trust_store_version: TRUST_STORE_VERSION.into(),
        issuers: vec![IssuerDocument {
            issuer_id: ISSUER.into(),
            issuer_name: ISSUER_NAME.into(),
            keys: vec![KeyDocument {
                key_id: jwk.key_id(),
                public_key: jwk,
                attestation_level: AttestationLevel::Software,
                valid_from: "2026-09-01T00:00:00Z".into(),
                valid_until: None,
                revoked: false,
            }],
        }],
        policy_authorities: Vec::new(),
    };
    vmr_verify::TrustStore::new(doc.clone()).expect("a valid trust store");
    serde_json::to_string_pretty(&doc).unwrap()
}

/// The published policy vectors (`specs/test-vectors/policy/cases.json`).
pub fn policy_cases() -> Vec<Value> {
    let path = repo().join("specs/test-vectors/policy/cases.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["vector_version"], "0.1");
    doc["cases"].as_array().unwrap().clone()
}

/// A published policy vector file other than the evaluation cases
/// (`specs/test-vectors/policy/<name>`: `pack-loader.json`,
/// `pack-signature.json`), parsed.
pub fn policy_vector_file(name: &str) -> Value {
    let path = repo().join("specs/test-vectors/policy").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["vector_version"], "0.1");
    doc
}

/// The verification context a policy vector gives (the format document's §5
/// and §9), in vmr-policy's types, or `None` for a case evaluated without
/// one. Written out again from vmr-policy's `tests/vectors.rs` (`context`):
/// one crate's test code cannot use another's.
pub fn policy_context(case: &Value) -> Option<vmr_policy::EvaluationContext> {
    use vmr_policy::{EvaluationContext, LineageContext, LineageOutcome, VerifiedPredecessor};
    let c = case.get("context")?;
    let id = &case["id"];
    let outcome = match c["lineage_outcome"].as_str() {
        Some("initial") => LineageOutcome::Initial,
        Some("complete") => LineageOutcome::Complete,
        Some("partial") => LineageOutcome::Partial,
        Some("not_checked") => LineageOutcome::NotChecked,
        other => panic!("{id}: lineage_outcome {other:?}"),
    };
    let predecessors = c["predecessors"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: context.predecessors"))
        .iter()
        .map(|p| VerifiedPredecessor {
            signed_payload_hash: p["signed_payload_hash"].as_str().unwrap().to_string(),
            record: serde_json::from_str(p["text"].as_str().unwrap()).unwrap(),
        })
        .collect();
    Some(EvaluationContext { lineage: LineageContext { outcome, predecessors } })
}

/// The record's `overall_status` word for a vector's overall status
/// (specs/policy-pack-format-v0.1.md §8), which is also the report's.
pub fn overall_status(overall: &Value) -> &'static str {
    match overall.as_str() {
        Some("pass") => "compliant",
        Some("fail") => "non-compliant",
        Some("indeterminate") => "indeterminate",
        other => panic!("an overall status is pass, fail or indeterminate, not {other:?}"),
    }
}
