// tests/limits.rs — the size rows no vector carries.
//
// A document over its limit is refused before it is parsed (§2 rule 2). The
// vectors carry that case for the entry, the checkpoint and the consistency
// proof; an oversized inclusion proof would be a quarter of a megabyte of
// padding in a published file, so it is checked here instead.

mod common;

use common::*;
use serde_json::json;
use vmr_audit_log::profile::CORE;
use vmr_audit_log::{checkpoint, log, proof, MAX_AUDIT_PATH_ELEMENTS, MAX_CONSISTENCY_PROOF_ELEMENTS,
                    MAX_INCLUSION_PROOF_BYTES};

#[test]
fn an_inclusion_proof_over_its_limit_is_refused_before_it_is_parsed() {
    let key = key(AUDIT_KEY);
    // Not even valid JSON: the size is read first, so it never gets that far.
    let bytes = vec![b'{'; MAX_INCLUSION_PROOF_BYTES + 1];
    let err = proof::verify_inclusion_proof(&bytes, key.verifying_key(), &CORE).unwrap_err();
    assert_eq!(err.id(), "audit_proof.size");

    // One byte under the limit is read as a document, and refused as one.
    let mut under = serde_json::to_vec(&json!({ "proof_version": "0.1" })).unwrap();
    under.resize(MAX_INCLUSION_PROOF_BYTES, b' ');
    let err = proof::verify_inclusion_proof(&under, key.verifying_key(), &CORE).unwrap_err();
    assert_ne!(err.id(), "audit_proof.size", "a document at the limit is read, not refused for its size");
}

// The array caps of §7 and §8 (QA QR-06). Both are normative in the document
// and in the schema, and neither was enforced before this round: an over-long
// path was refused `audit_proof.path` here and `audit_proof.structure` by any
// implementation that follows the document, which is a conformance divergence
// in the reference implementation. The cap is read before the path is walked,
// so the refusal names the structure, not the arithmetic.

/// The seeded two-entry log, its latest checkpoint, and the audit key.
fn seeded() -> (log::LogBuilder, Vec<String>, serde_json::Value) {
    let (builder, lines) = seeded_log();
    let signed = checkpoint::build_signed(
        builder.log_id(),
        builder.len(),
        &builder.root(),
        t("2026-09-14T10:00:00Z"),
        &key(AUDIT_KEY),
    )
    .unwrap();
    (builder, lines, signed)
}

#[test]
fn an_audit_path_above_64_elements_is_refused() {
    let k = key(AUDIT_KEY);
    let (builder, lines, cp) = seeded();
    let good = proof::build_inclusion_proof(builder.leaves(), 0, &lines[0], &cp, k.verifying_key()).unwrap();
    proof::verify_inclusion_proof(&serde_json::to_vec(&good).unwrap(), k.verifying_key(), &CORE)
        .expect("the built proof verifies");

    let pad = format!("sha256:{}", "00".repeat(32));
    for (count, expected) in [(MAX_AUDIT_PATH_ELEMENTS, "audit_proof.path"), (MAX_AUDIT_PATH_ELEMENTS + 1, "audit_proof.structure")] {
        let mut doc = good.clone();
        doc["audit_path"] = serde_json::Value::Array(vec![serde_json::Value::String(pad.clone()); count]);
        let err = proof::verify_inclusion_proof(&serde_json::to_vec(&doc).unwrap(), k.verifying_key(), &CORE)
            .unwrap_err();
        assert_eq!(err.id(), expected, "{count} elements: {err}");
    }
}

#[test]
fn a_consistency_proof_above_128_elements_is_refused() {
    let k = key(AUDIT_KEY);
    let (builder, _lines, to) = seeded();
    let from = checkpoint::build_signed(
        builder.log_id(),
        1,
        &builder.root_at(1).unwrap(),
        t("2026-09-14T09:40:00Z"),
        &k,
    )
    .unwrap();
    let good = proof::build_consistency_proof(builder.leaves(), &from, &to, k.verifying_key()).unwrap();
    proof::verify_consistency_proof(&serde_json::to_vec(&good).unwrap(), k.verifying_key())
        .expect("the built proof verifies");

    let pad = format!("sha256:{}", "00".repeat(32));
    for (count, expected) in [
        (MAX_CONSISTENCY_PROOF_ELEMENTS, "audit_proof.consistency"),
        (MAX_CONSISTENCY_PROOF_ELEMENTS + 1, "audit_proof.structure"),
    ] {
        let mut doc = good.clone();
        doc["proof"] = serde_json::Value::Array(vec![serde_json::Value::String(pad.clone()); count]);
        let err =
            proof::verify_consistency_proof(&serde_json::to_vec(&doc).unwrap(), k.verifying_key()).unwrap_err();
        assert_eq!(err.id(), expected, "{count} elements: {err}");
    }
}
