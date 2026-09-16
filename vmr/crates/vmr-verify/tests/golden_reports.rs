// tests/golden_reports.rs — the report is a reviewed artifact (Phase 4
// tasks 4.1/4.4/4.7): the full check order of both forms is pinned, and a
// few reports are pinned byte for byte in tests/golden/. A golden change is
// reviewed like a vector change; regenerate with
//
//     VMR_WRITE_GOLDEN=1 cargo test -p vmr-verify --test golden_reports -- --ignored
//
// Only verdicts and check ids are cross-implementation contract (the
// verification vectors in specs/); these files pin THIS implementation's
// report layout and wording.

mod common;

use common::*;
use vmr_record::record::Record;
use vmr_verify::report::CheckId;
use vmr_verify::{Verifier, VerifyOptions};

#[test]
fn the_check_sequences_are_pinned() {
    let p = vector();
    let json: Vec<&str> = verify_basic(&p).checks.iter().map(|c| c.id.id()).collect();
    assert_eq!(
        json,
        [
            "input.size", "input.form", "json.syntax", "json.structure", "format.schema",
            "format.consistency", "signature.algorithm", "signature.encoding", "signature.low_s",
            "signature.payload_hash", "key.binding", "trust.key_known", "signature.valid",
            "trust.issuer", "trust.key_not_revoked", "trust.key_validity", "trust.attestation",
            "time.not_future", "time.policy_not_after_issued", "lineage.consistency",
            "lineage.chain",
        ]
    );
    let cose_report = Verifier::new(basic_store()).verify_cose(&p.to_cose().unwrap(), &at(T));
    let cose: Vec<&str> = cose_report.checks.iter().map(|c| c.id.id()).collect();
    assert_eq!(
        cose,
        [
            "input.size", "input.form", "cose.structure", "cose.protected_header",
            "cose.unprotected_header", "cose.signature_encoding", "cose.payload", "cose.canonical",
            "format.schema", "format.consistency", "signature.algorithm", "signature.encoding",
            "signature.low_s", "signature.payload_hash", "key.binding", "trust.key_known",
            "signature.valid", "trust.issuer", "trust.key_not_revoked", "trust.key_validity",
            "trust.attestation", "time.not_future", "time.policy_not_after_issued",
            "lineage.consistency", "lineage.chain",
        ]
    );
    // A failing report lists the same sequence (the rest skipped).
    let failing = Verifier::new(basic_store()).verify_json(b"", &at(T));
    assert_eq!(failing.checks.len(), 21);
    assert_eq!(failing.checks.iter().filter(|c| c.id == CheckId::InputForm).count(), 1);
}

/// A successor of the vector (training-update), linked by its recomputed
/// payload hash and signed with key A.
fn vector_successor() -> Record {
    let prev = vector();
    let mut p = prev.clone();
    p.record_id = "urn:uuid:00000000-0000-4000-8000-0000000000b2".into();
    p.issued_at = "2026-09-10T12:00:00Z".into();
    p.lineage.previous_record_id = Some(prev.record_id.clone());
    p.lineage.previous_record_hash = Some(prev.signed_payload_hash().unwrap());
    p.lineage.lineage_chain_length = 2;
    p.lineage.lineage_type = "training-update".into();
    reissue_with(&mut p, KEY_A);
    p
}

/// The golden cases: file name and the report's JSON.
fn goldens() -> Vec<(&'static str, String)> {
    let v = vector();
    let mut forged = vector();
    reissue_with(&mut forged, KEY_F);
    let verifier = Verifier::new(basic_store());
    let chain_prev = json_of(&v);
    let previous: [&[u8]; 1] = [&chain_prev];
    let t = vmr_record::timestamp::Timestamp::parse(T).unwrap();
    let chain_opts = VerifyOptions::new(t).with_previous(&previous).require_complete_lineage(true);
    vec![
        ("vector.json.report.json", verifier.verify_json(&json_of(&v), &at(T))),
        ("vector.cose.report.json", verifier.verify_cose(&v.to_cose().unwrap(), &at(T))),
        ("forged.report.json", verifier.verify_json(&json_of(&forged), &at(T))),
        ("chain-complete.report.json", verifier.verify(&json_of(&vector_successor()), &chain_opts)),
    ]
    .into_iter()
    .map(|(name, report)| (name, format!("{}\n", report.to_json().unwrap())))
    .collect()
}

fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("golden")
}

#[test]
fn golden_reports_are_byte_identical() {
    for (name, json) in goldens() {
        let path = golden_dir().join(name);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_GOLDEN=1)", path.display()));
        assert_eq!(json, committed, "{name} differs from the committed golden report");
    }
}

#[test]
#[ignore = "writes tests/golden/; run with VMR_WRITE_GOLDEN=1 to regenerate"]
#[allow(clippy::disallowed_methods)] // reading the opt-in switch is this generator's whole job
fn write_golden_reports() {
    if std::env::var("VMR_WRITE_GOLDEN").as_deref() != Ok("1") {
        eprintln!("VMR_WRITE_GOLDEN is not 1: nothing written");
        return;
    }
    std::fs::create_dir_all(golden_dir()).unwrap();
    for (name, json) in goldens() {
        std::fs::write(golden_dir().join(name), json).unwrap();
    }
}
