// tests/gate5.rs — TASKS Gate 5: "the CLI emits a record from a brain
// file, writes it to disk, and verifies it in a separate invocation"
// (acceptance criteria G5-1..G5-6: docs/dev/phase5.md §6).
//
// Every step is a separate `vmr` process. The verifier's step runs as the
// second terminal of the demo: a CLEARED environment (plus SystemRoot on
// Windows), TZ=Pacific/Kiritimati (UTC+14), and as its working directory a
// fresh directory holding ONLY the record and the trust store, named
// relatively. The issuer's directory — private key included — is deleted
// before it runs. The binary under test decides nothing about trust on its
// own: the verdicts it prints are vmr-verify's.
//
// Two builds, two test files (task 10.13a, Part A):
//   * the engine build's Gate 5 test, outside the Community workspace: the
//     whole flow — key generate, key export, trust-store add
//     on the verifier's side, record emit from
//     tests/fixtures/golden_reservoir.brain, then verify; plus the impostor,
//     tamper and wrong-store cases (G5-1..G5-4). It also re-emits the
//     committed artifact below byte for byte (C12).
//   * this file, the Community build: this binary has no engine — its
//     --version names none and `record emit` takes no --engine, asserted
//     first (task 10.13a: it emits records of a model's files, never of a
//     brain) — and it verifies the committed artifact under the same
//     isolation (G5-5).
// The isolation helpers are the shared harness's (tests/common/mod.rs).
//
// The committed artifact, tests/data/gate5/: `model.vmr`, emitted by
// `vmr record emit` (engine build) from the golden brain with the demo
// manifest and input (docs/demo/; since task 7.6 the manifest pins the
// demo's software environment and data governance documents by hash and
// declares its issuer's evaluation of khalm-reading-eu-ai-act-2026), a derived TEST-ONLY key and
// --issued-at 2026-09-11T00:00:00Z; and `trust-store.json`, built by
// `vmr key export` + `vmr trust-store add` for that key. The private key is
// never written to the repository: it is derived in the test. The engine
// build's Gate 5 test regenerates it (VMR_WRITE_GATE5=1); review a
// regeneration like a vector.

mod common;
use common::gate5::*;
use common::*;

// ---------------------------------------------------------------------------
//  G5-5: the Community build verifies the committed, CLI-emitted record in
//  isolation
// ---------------------------------------------------------------------------

#[test]
fn gate5_the_committed_cli_emitted_record_verifies_in_an_isolated_process() {
    // Which binary is this? The Community build has no engine at all: its
    // version names none, and emit takes no brain (task 10.13a).
    {
        let run = vmr(&["record", "emit", "--engine", "x", "--profile", "discrete-reservoir", "--input", "x",
            "--manifest", "x", "--key", "x", "--output", "x"]);
        run.expect_code(1);
        assert!(run.stderr.contains("unexpected argument '--engine'"), "{}", run.transcript());
        assert!(!vmr(&["--version"]).stdout.contains("engine"));
    }

    let s = Scratch::new("gate5-artifact");
    let model = std::fs::read(artifact_dir().join("model.vmr")).expect("the committed Gate 5 record");
    let store = std::fs::read(artifact_dir().join("trust-store.json")).expect("the committed Gate 5 trust store");
    assert_eq!(model.first(), Some(&0x84), "the artifact is the COSE form");

    let dir = verifier_dir(&s, "verifier", &[("model.vmr", model.clone()), ("trust-store.json", store.clone())]);
    let run = isolated_verify(&dir, "model.vmr", "trust-store.json", false);
    run.expect_code(0);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
    assert!(run.stdout.contains(&format!("  Issuer:        {ISSUER} ({NAME}, per trust store)")), "{}", run.transcript());
    assert!(run.stdout.contains(&format!("  Model state:   {}", golden_state_hash())), "{}", run.transcript());
    // The demo's declaration (task 7.6): its issuer's evaluation of the EU
    // AI Act reference pack, "compliant" - shown as declared, not evaluated.
    assert!(
        run.stdout.contains("  Policy status: \"compliant\", declared by the issuer, not evaluated (khalm-reading-eu-ai-act-2026)"),
        "{}",
        run.transcript()
    );

    let json = isolated_verify(&dir, "model.vmr", "trust-store.json", true);
    json.expect_code(0);
    let report: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert_eq!(report["verdict"], "pass");
    assert_eq!(report["record"]["learned_state_hash"], golden_state_hash().as_str(), "G5-3 on the artifact");
    assert_eq!(report["issuer"]["issuer_id"], ISSUER);
    assert_eq!(report["lineage"]["status"], "initial");
    assert_eq!(report["policy"]["evaluation"]["state"], "not_requested");
    assert_eq!(report["policy"]["declared"]["policy_pack_id"], "khalm-reading-eu-ai-act-2026");
    assert_eq!(report["policy"]["declared"]["overall_status"], "compliant");
    assert_eq!(report["policy"]["declared"]["evaluated_at"], "2026-09-11T00:00:00Z");
    assert_eq!(report["policy"]["declared"]["results"].as_array().map(Vec::len), Some(6));
    assert_eq!(report["evaluation_time"], AT);
    assert_eq!(listing(&dir), ["model.vmr", "trust-store.json"], "verify wrote nothing");

    // What the artifact pins (task 7.6): the demo's software environment and
    // data governance documents, by the SHA-256 of their committed bytes, and
    // no human oversight document.
    let record = vmr_record::Record::from_cose(&model).unwrap();
    let hash_of = |name: &str| {
        let bytes = std::fs::read(repo().join("docs/demo").join(name)).unwrap();
        vmr_record::hash::format_hash(&vmr_record::hash::sha256(&bytes))
    };
    assert_eq!(record.learning_provenance.training_environment.software_hash, hash_of("software-environment.json"));
    assert_eq!(
        record.data_governance.as_ref().map(|d| d.documentation_hash.clone()),
        Some(hash_of("data-governance.md"))
    );
    assert!(record.human_oversight.is_none());

    // In the same isolation: one changed claim, an empty store, an impostor.
    let tamper = verifier_dir(&s, "tamper", &[("model.vmr", tampered(&model)), ("trust-store.json", store.clone())]);
    let run = isolated_verify(&tamper, "model.vmr", "trust-store.json", false);
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}signature.valid: ")), "{}", run.transcript());

    let empty = br#"{"trust_store_version":"0.1","issuers":[]}"#.to_vec();
    let nobody = verifier_dir(&s, "empty-store", &[("model.vmr", model.clone()), ("trust-store.json", empty)]);
    let run = isolated_verify(&nobody, "model.vmr", "trust-store.json", false);
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}trust.key_known: ")), "{}", run.transcript());

    let mut forged = vmr_record::Record::from_cose(&model).unwrap();
    forged.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
    reissue_with(&mut forged, KEY_FORGER);
    let impostor = verifier_dir(&s, "forged", &[("model.vmr", forged.to_cose().unwrap()), ("trust-store.json", store)]);
    let run = isolated_verify(&impostor, "model.vmr", "trust-store.json", false);
    run.expect_code(3);
    assert!(headline(&run).starts_with(&format!("{NOT_VALID}trust.key_known: ")), "{}", run.transcript());
}
