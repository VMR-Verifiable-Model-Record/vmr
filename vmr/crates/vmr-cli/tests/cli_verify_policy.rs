// tests/cli_verify_policy.rs — `vmr record verify --policy-pack <FILE>`
// (P6-13), the flag that reverses Phase 5's C6.
//
// C6 refused a `--policy-pack` flag because nothing in the tree could
// perform the evaluation its name promised; Phase 6's `vmr-policy` can, so
// the flag exists and does exactly what it says. What these tests hold to:
//
//  (1) the issuer's DECLARATION and this verifier's FINDING are two
//      different statements, both shown, never merged, and a disagreement
//      between them is impossible to miss;
//  (2) the pack that decided is named with its `pack_id` AND its
//      `pack_version`, and the output says whether the pack was signed and
//      whether that signature was checked;
//  (3) exit 0 when the evaluation accepts, 4 when it does not - an
//      indeterminate overall included, with wording of its own;
//  (4) the verifier's evaluation time is the verifier's own (`--at`, else
//      the clock). It is NOT the record's `policy_compliance.evaluated_at`
//      and P6-6's rule (an embedded evaluation may not post-date issuance)
//      does not apply to it: a record issued years ago, evaluated today,
//      is normal;
//  (5) `--json` is still the report byte for byte, now carrying the
//      evaluation and every rule's `evidence_hash`;
//  (6) the pack's own authority signature is checked against the policy
//      authorities of the trust store, or of `--authority-store` (P6-14,
//      P6-16, docs/TASKS.md 6.16): valid, not checked, or refused with exit 1
//      before the record is verified; `--require-signed-pack` refuses an
//      unsigned or untrusted pack; the pack's payload hash is reported.

mod common;
use common::*;
use serde_json::Value;
use std::path::{Path, PathBuf};
use vmr_record::record::{JwkPublicKey, Record};

/// The verifier's rendering of a pass starts with this.
const VALID: &str = "✓ Record valid — signed by a key the trust store trusts for this issuer";

/// `<repo>/specs/policy-packs/<pack_id>.json`, the committed reference pack.
fn reference_pack(pack_id: &str) -> String {
    repo().join(format!("specs/policy-packs/{pack_id}.json")).to_string_lossy().into_owned()
}

fn gate5_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/gate5")
}

/// The Gate 5 artifact's derived, test-only signing key, which its trust
/// store trusts (`ARTIFACT_KEY` in tests/gate5.rs).
const GATE5_ARTIFACT_KEY: &str = "khalm-vmr gate5 artifact issuer key (test-only)";

fn verify_with_pack(record: &str, store: &str, at: &str, pack: &str) -> Run {
    vmr(&["record", "verify", "--record", record, "--trust-store", store, "--at", at, "--policy-pack", pack])
}

/// The line beginning with `  <label>:`, or "" — the rendering is one field
/// per line, so a test names the field it means.
fn line(run: &Run, label: &str) -> String {
    let want = format!("  {label}:");
    run.stdout.lines().find(|l| l.starts_with(&want)).unwrap_or("").to_string()
}

/// A pack that the conformance vector FAILS: it declares attestation level
/// `software`, and this pack demands `hardware`. Inline, because no
/// reference standard should be bent to make a test fail (P6-4).
fn strict_pack() -> String {
    strict_pack_for("test-strict-attestation")
}

/// [`strict_pack`] under another `pack_id`.
fn strict_pack_for(pack_id: &str) -> String {
    serde_json::json!({
        "version": "0.1",
        "pack_id": pack_id,
        "pack_version": "2.3.4",
        "jurisdiction": "test",
        "description": "A test pack that demands hardware attestation.",
        "disclaimer": "A fixture of the vmr-cli test suite. Not a reference pack, not legal advice.",
        "authority": {"authority_id": "khalm-vmr-tests", "authority_name": "KHALM-VMR tests"},
        "rules": [{
            "type": "attestation_level",
            "rule_id": "strict-hardware",
            "description": "The issuer attests at hardware level.",
            "severity": "mandatory",
            "reference": "Test fixture rule 1",
            "minimum_level": "hardware"
        }]
    })
    .to_string()
}

// ---------------------------------------------------------------------------
//  (1) and (2): both statements, and the pack that made one of them
// ---------------------------------------------------------------------------

#[test]
fn the_declaration_and_the_evaluation_are_both_shown_and_never_merged() {
    let s = Scratch::new("verify-pack-both");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = verify_with_pack(&record, &store, T, &reference_pack("khalm-reading-eu-ai-act-2026"));
    run.expect_code(0);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());

    // The issuer's declaration, unchanged by the evaluation: its own status,
    // its own pack, and its own evaluation time.
    assert_eq!(
        line(&run, "Policy status"),
        "  Policy status: \"compliant\" for example-policy-pack-v1 as of 2026-09-10T00:00:00Z, declared by the issuer",
        "{}",
        run.transcript()
    );
    // This verifier's finding, on its own line, naming the pack AND its
    // version.
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  compliant — evaluated here against pack khalm-reading-eu-ai-act-2026 1.0.0",
        "{}",
        run.transcript()
    );
    // The packs differ, which is a note, not a disagreement.
    assert!(
        run.stdout.contains(
            "                 note: the record declares policy pack \"example-policy-pack-v1\"; \
             the evaluator applied \"khalm-reading-eu-ai-act-2026\""
        ),
        "{}",
        run.transcript()
    );
    // The vector declares neither optional documentation member, so the EU
    // pack's two recommended documentation rules fail; the mandatory four
    // pass, and the pack is compliant (task 10.11a, D11-5).
    assert!(run.stdout.contains("                 6 rules: 4 pass, 2 fail\n"), "{}", run.transcript());
    assert!(!run.stdout.contains("DISAGREEMENT"), "the two agree:\n{}", run.transcript());
    // The declared status was never overwritten with the evaluated one.
    assert!(!run.stdout.contains("not evaluated"), "{}", run.transcript());
}

#[test]
fn the_printed_pack_payload_hash_is_the_packs_own_and_the_guide_quotes_it() {
    // QA QC-05 (the reviewer's decision B): a pack's payload hash, not its
    // pack_version, names its text. So the payload hash `vmr` prints is the
    // pack's, recomputed, and the guide's Gate 5 transcript against
    // khalm-reading-eu-ai-act-2026 (docs/CLI.md) quotes the value a run prints today.
    let s = Scratch::new("verify-pack-payload-hash");
    let record = s.write("model.vmr", std::fs::read(gate5_dir().join("model.vmr")).unwrap());
    let store = s.write("trust-store.json", std::fs::read(gate5_dir().join("trust-store.json")).unwrap());
    let pack = reference_pack("khalm-reading-eu-ai-act-2026");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&pack).unwrap()).unwrap();
    let printed = format!("                 pack payload hash: {}", vmr_policy::payload_hash(&doc));
    let run = verify_with_pack(&record, &store, "2026-09-11T12:00:00Z", &pack);
    run.expect_code(0);
    assert!(run.stdout.lines().any(|l| l == printed), "missing `{printed}`:\n{}", run.transcript());
    let guide = std::fs::read_to_string(repo().join("docs/CLI.md")).unwrap();
    assert!(guide.contains(&printed), "docs/CLI.md does not quote `{}`", printed.trim_start());
}

/// The one line a pack result carries (the owner, 2026-09-16), as
/// `vmr_cli`'s renderer spells it.
const READING_NOTE: &str =
    "the pack author's reading of the cited text — docs/POLICY_PACKS.md says what it does not mean";

#[test]
fn a_pack_result_says_once_that_it_is_the_pack_authors_reading() {
    // The owner, 2026-09-16: wherever a pack result is printed, one line
    // says what that result is — the pack author's reading of the text it
    // cites — and points at the document that says what it does not mean.
    // Once per result, not once per rule; no line at all without a pack,
    // because then there is no pack result; never in `--json`, which is the
    // report itself and is unchanged; and no exit code moves.
    let s = Scratch::new("verify-pack-reading-note");
    let record = s.write("model.vmr", std::fs::read(gate5_dir().join("model.vmr")).unwrap());
    let store = s.write("trust-store.json", std::fs::read(gate5_dir().join("trust-store.json")).unwrap());
    let pack = reference_pack("khalm-reading-eu-ai-act-2026");
    let run = verify_with_pack(&record, &store, "2026-09-11T12:00:00Z", &pack);
    run.expect_code(0);
    assert_eq!(
        run.stdout.matches(READING_NOTE).count(),
        1,
        "once, beside the pack result:\n{}",
        run.transcript()
    );
    assert!(
        run.stdout.lines().any(|l| l == format!("                 {READING_NOTE}")),
        "{}",
        run.transcript()
    );
    // No pack, no pack result, no line.
    let without =
        vmr(&["record", "verify", "--record", &record, "--trust-store", &store, "--at", "2026-09-11T12:00:00Z"]);
    without.expect_code(0);
    assert!(!without.stdout.contains("POLICY_PACKS"), "{}", without.transcript());
    // `--json` is the report, byte for byte, and carries no prose of ours.
    let json = vmr(&[
        "record",
        "verify",
        "--record",
        &record,
        "--trust-store",
        &store,
        "--at",
        "2026-09-11T12:00:00Z",
        "--policy-pack",
        &pack,
        "--json",
    ]);
    json.expect_code(0);
    assert!(!json.stdout.contains("POLICY_PACKS"), "{}", json.transcript());
    serde_json::from_str::<Value>(&json.stdout).expect("--json is a JSON report");
}

#[test]
fn the_output_says_whether_the_pack_was_signed_and_whether_it_was_checked() {
    // P6-13, as P6-16 completes it: `vmr` never claims to have checked a
    // pack's signature it could not check. ts-basic holds no policy
    // authority, so a signed pack is not checked, and the line says so.
    let s = Scratch::new("verify-pack-signature");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));

    // The committed reference packs are unsigned.
    let run = verify_with_pack(&record, &store, T, &reference_pack("khalm-reading-eu-ai-act-2026"));
    run.expect_code(0);
    assert!(
        run.stdout.contains("                 pack signature: none, the pack carries no authority signature\n"),
        "{}",
        run.transcript()
    );

    // The same pack with a signature section that names the pack's own
    // payload hash but carries a garbage signature: the payload hash is
    // checked (QA Q6-05), the signature cannot be without an authority's key,
    // so this is still not_checked, and the line says the key id is only what
    // the pack names.
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(reference_pack("khalm-reading-eu-ai-act-2026")).unwrap()).unwrap();
    const KEY_ID: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg";
    doc["signature"] = serde_json::json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", "A".repeat(86)),
        "signed_payload_hash": vmr_policy::payload_hash(&doc),
        "signing_key_id": KEY_ID,
    });
    let signed = s.write("signed-pack.json", serde_json::to_vec_pretty(&doc).unwrap());
    let run = verify_with_pack(&record, &store, T, &signed);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!(
            "                 pack signature: names {KEY_ID} as its signer — NOT checked: no policy authority in the trust store holds that key\n"
        )),
        "{}",
        run.transcript()
    );
    let json: Value = serde_json::from_str(&signed_json(&record, &store, &signed)).unwrap();
    assert_eq!(
        json["policy"]["evaluation"]["pack_signature"],
        serde_json::json!({"state": "not_checked", "signing_key_id": KEY_ID})
    );
}

/// `doc` signed, over vmr-policy's signed payload, by a key derived from a
/// fixed label (test-only, worthless elsewhere); returns it and the key id.
fn signed_by_test_authority(mut doc: Value) -> (Value, String) {
    use vmr_policy::vmr_record::{encoding::b64url_encode, hash::sha256, jwk, sign};
    if let Some(o) = doc.as_object_mut() {
        o.remove("signature");
    }
    let key = sign::signing_key_from_secret(&sha256(b"vmr-cli tests: a policy authority key")).unwrap();
    let signature = sign::sign(&key, vmr_policy::signed_payload(&doc).as_bytes()).unwrap();
    let key_id = jwk::key_id(key.verifying_key());
    doc["signature"] = serde_json::json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", b64url_encode(&signature.to_bytes())),
        "signed_payload_hash": vmr_policy::payload_hash(&doc),
        "signing_key_id": key_id,
    });
    (doc, key_id)
}

#[test]
fn a_pack_edited_after_signing_is_not_reported_like_an_intact_one() {
    // QA Q6-05 (the owner, 2026-09-13, option c: the key-free half of P6-16).
    // A pack signed by its authority and then edited no longer matches the
    // signed_payload_hash its own signature section states. That needs no
    // key to see, so it is refused before the record is verified, exit 1,
    // exactly as P6-16 orders for a signature that does not verify.
    let s = Scratch::new("verify-pack-edited");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let eu: Value =
        serde_json::from_str(&std::fs::read_to_string(reference_pack("khalm-reading-eu-ai-act-2026")).unwrap()).unwrap();
    let (intact, key_id) = signed_by_test_authority(eu);
    let mut edited = intact.clone();
    edited["rules"][0]["severity"] = Value::String("informational".into());
    let intact_path = s.write("intact.json", serde_json::to_vec_pretty(&intact).unwrap());
    let edited_path = s.write("edited.json", serde_json::to_vec_pretty(&edited).unwrap());

    let run = verify_with_pack(&record, &store, T, &edited_path);
    run.expect_code(1);
    assert!(run.stdout.is_empty(), "no verification result for an unusable pack:\n{}", run.transcript());
    assert!(run.stderr.contains("signed_payload_hash"), "{}", run.transcript());
    assert!(run.stderr.contains("changed after it was signed"), "{}", run.transcript());
    assert!(run.stderr.contains("cannot be used: pack_signature.payload_hash: "), "{}", run.transcript());

    let run = verify_with_pack(&record, &store, T, &intact_path);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!("pack signature: names {key_id} as its signer")),
        "{}",
        run.transcript()
    );
    let json: Value = serde_json::from_str(&signed_json(&record, &store, &intact_path)).unwrap();
    assert_eq!(
        json["policy"]["evaluation"]["pack_signature"],
        serde_json::json!({"state": "not_checked", "signing_key_id": key_id})
    );
}

/// `--json` for one run, as text.
fn signed_json(record: &str, store: &str, pack: &str) -> String {
    vmr(&[
        "record", "verify", "--record", record, "--trust-store", store, "--at", T,
        "--policy-pack", pack, "--json",
    ])
    .stdout
}

#[test]
fn a_disagreement_between_the_issuer_and_the_evaluation_is_impossible_to_miss() {
    // The single most interesting thing on the screen: the issuer declared
    // "compliant" for a pack; this verifier, against a pack of the same id,
    // did not agree. The declared value is still there, untouched. (A pack of
    // another id is a note, not a disagreement: QA Q6-08, tested below.)
    let s = Scratch::new("verify-pack-disagree");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let pack = s.write("strict.json", strict_pack_for("example-policy-pack-v1"));
    let run = verify_with_pack(&record, &store, T, &pack);
    run.expect_code(4);
    assert_eq!(headline(&run), VALID, "authenticity is not policy:\n{}", run.transcript());
    assert_eq!(
        line(&run, "Policy status"),
        "  Policy status: \"compliant\" for example-policy-pack-v1 as of 2026-09-10T00:00:00Z, declared by the issuer",
        "{}",
        run.transcript()
    );
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  non-compliant — evaluated here against pack example-policy-pack-v1 2.3.4",
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(
            "!! DISAGREEMENT — the issuer declared \"compliant\" (example-policy-pack-v1); \
             this evaluation found \"non-compliant\" (example-policy-pack-v1)\n"
        ),
        "{}",
        run.transcript()
    );
    assert!(!run.stdout.contains("note: the record declares"), "the packs are the same:\n{}", run.transcript());
    // The rule that decided it, with its clause and its reason.
    assert!(
        run.stdout.contains(
            "                 fail          strict-hardware (mandatory, Test fixture rule 1): "
        ),
        "{}",
        run.transcript()
    );
    assert_eq!(
        line(&run, "Accepted"),
        "  Accepted:      no: the evaluation found the record non-compliant",
        "{}",
        run.transcript()
    );
}

#[test]
fn statuses_about_different_packs_are_not_called_a_disagreement() {
    // QA Q6-08 (the owner, 2026-09-13: a DISAGREEMENT only for the same
    // pack). The Gate 5 record declares "compliant" for khalm-reading-eu-ai-act-2026
    // (task 7.6); a pack that demands hardware attestation finds it
    // "non-compliant". Those answer different questions, so the output says
    // the packs differ, and does not call the two statuses a disagreement.
    // That is the refusing half; the accepting half, on an evaluation that
    // finds "compliant", follows.
    let s = Scratch::new("verify-pack-other-pack");
    let record = s.write("model.vmr", std::fs::read(gate5_dir().join("model.vmr")).unwrap());
    let store = s.write("trust-store.json", std::fs::read(gate5_dir().join("trust-store.json")).unwrap());
    let pack = s.write("strict.json", strict_pack());
    let run = verify_with_pack(&record, &store, "2026-09-11T12:00:00Z", &pack);
    run.expect_code(4);
    assert_eq!(
        line(&run, "Policy status"),
        "  Policy status: \"compliant\" for khalm-reading-eu-ai-act-2026 as of 2026-09-11T00:00:00Z, declared by the issuer",
        "{}",
        run.transcript()
    );
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  non-compliant — evaluated here against pack test-strict-attestation 2.3.4",
        "{}",
        run.transcript()
    );
    assert!(
        !run.stdout.lines().any(|l| l.starts_with("!! DISAGREEMENT")),
        "statuses about two packs are not a disagreement:\n{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(
            "                 note: the record declares policy pack \"khalm-reading-eu-ai-act-2026\"; \
             the evaluator applied \"test-strict-attestation\""
        ),
        "{}",
        run.transcript()
    );

    // The accepting half, the case Q6-08's test was written for (QA QD-02):
    // the artifact declaring P5-09's "indeterminate" for khalm-reading-eu-ai-act-2026, with
    // no results, signed again with its own key; the C2PA pack finds it
    // "compliant". The statuses differ and the packs differ, the evaluation
    // accepts, and still no disagreement line. Against its own pack the same
    // record shows one: it is the packs that differ, not the statuses that
    // agree.
    let mut undecided = Record::from_cose(&std::fs::read(gate5_dir().join("model.vmr")).unwrap()).unwrap();
    undecided.policy_compliance.evaluated_at = "2026-09-10T00:00:00Z".into();
    undecided.policy_compliance.results.clear();
    undecided.policy_compliance.overall_status = "indeterminate".into();
    sign_as(&mut undecided, GATE5_ARTIFACT_KEY);
    let undecided = s.write("undecided.vmr", undecided.to_cose().unwrap());
    let run = verify_with_pack(&undecided, &store, "2026-09-11T12:00:00Z", &reference_pack("khalm-reading-c2pa-ai-disclosure-2.2"));
    run.expect_code(0);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
    assert_eq!(
        line(&run, "Policy status"),
        "  Policy status: \"indeterminate\" for khalm-reading-eu-ai-act-2026 as of 2026-09-10T00:00:00Z, declared by the issuer",
        "{}",
        run.transcript()
    );
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  compliant — evaluated here against pack khalm-reading-c2pa-ai-disclosure-2.2 1.0.0",
        "{}",
        run.transcript()
    );
    assert!(
        !run.stdout.lines().any(|l| l.starts_with("!! DISAGREEMENT")),
        "statuses about two packs are not a disagreement, when the evaluation accepts too:\n{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(
            "                 note: the record declares policy pack \"khalm-reading-eu-ai-act-2026\"; \
             the evaluator applied \"khalm-reading-c2pa-ai-disclosure-2.2\""
        ),
        "{}",
        run.transcript()
    );
    let own = verify_with_pack(&undecided, &store, "2026-09-11T12:00:00Z", &reference_pack("khalm-reading-eu-ai-act-2026"));
    own.expect_code(0);
    assert!(
        own.stdout.contains(
            "!! DISAGREEMENT — the issuer declared \"indeterminate\" (khalm-reading-eu-ai-act-2026); \
             this evaluation found \"compliant\" (khalm-reading-eu-ai-act-2026)\n"
        ),
        "{}",
        own.transcript()
    );
}

// ---------------------------------------------------------------------------
//  (3) exit codes, and what an indeterminate overall does
// ---------------------------------------------------------------------------

/// The verification vector `id` (specs/test-vectors/verify/cases.json):
/// its record and its predecessors, immediate first, written into `s`,
/// and its evaluation time.
fn chain_case(s: &Scratch, id: &str) -> (String, Vec<String>, String) {
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(repo().join("specs/test-vectors/verify/cases.json")).unwrap(),
    )
    .unwrap();
    let case = doc["cases"].as_array().unwrap().iter().find(|c| c["id"] == id).unwrap();
    let head = s.write(&format!("{id}.json"), vector_input_bytes(&case["input"]));
    let previous = case["previous"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, p)| s.write(&format!("{id}.previous-{i}.json"), vector_input_bytes(p)))
        .collect();
    (head, previous, case["evaluation_time"].as_str().unwrap().to_string())
}

/// A pack `pack_id` 1.0.0 holding the one mandatory `rule`. Inline, like
/// [`strict_pack`].
fn one_rule_pack(pack_id: &str, rule: Value) -> String {
    serde_json::json!({
        "version": "0.1",
        "pack_id": pack_id,
        "pack_version": "1.0.0",
        "jurisdiction": "test",
        "description": "A test pack with one rule that reads what verification established (P6-17).",
        "disclaimer": "A fixture of the vmr-cli test suite. Not a reference pack, not legal advice.",
        "authority": {"authority_id": "khalm-vmr-tests", "authority_name": "KHALM-VMR tests"},
        "rules": [rule]
    })
    .to_string()
}

/// One mandatory rule: the lineage was verified back to the initial
/// record (P6-17).
fn verified_lineage_pack() -> String {
    one_rule_pack(
        "test-verified-lineage",
        serde_json::json!({
            "type": "audit_integrity",
            "rule_id": "verified-lineage",
            "description": "The lineage was verified back to the initial record.",
            "severity": "mandatory",
            "reference": "Test fixture rule 2",
            "minimum_chain_length": 1,
            "require_verified_lineage": true
        }),
    )
}

/// One mandatory rule: a deployment or policy-change record keeps its
/// verified immediate predecessor's learned state (P6-17).
fn state_kept_pack() -> String {
    one_rule_pack(
        "test-state-kept",
        serde_json::json!({
            "type": "execution_integrity",
            "rule_id": "state-kept",
            "description": "A deployment keeps the learned state of the record before it.",
            "severity": "mandatory",
            "reference": "Test fixture rule 3",
            "require_state_kept": true
        }),
    )
}

/// [`verify_with_pack`] with `--previous` for each of `previous`, in order.
fn verify_with_previous(record: &str, previous: &[String], store: &str, at: &str, pack: &str) -> Run {
    let mut args =
        vec!["record", "verify", "--record", record, "--trust-store", store, "--at", at, "--policy-pack", pack];
    for p in previous {
        args.extend(["--previous", p.as_str()]);
    }
    vmr(&args)
}

#[test]
fn an_indeterminate_evaluation_exits_4_with_wording_of_its_own() {
    // "Could not be decided" is not acceptance (P6-13). A successor record
    // verified without its predecessors: its lineage was not checked, so a
    // rule that requires a verified lineage cannot be decided - the honest
    // answer, and not a failure of the record (P6-17).
    let s = Scratch::new("verify-pack-indeterminate");
    let (record, _, at) = chain_case(&s, "pass-chain-not-checked");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let pack = s.write("verified-lineage.json", verified_lineage_pack());
    let run = verify_with_pack(&record, &store, &at, &pack);
    run.expect_code(4);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  indeterminate — evaluated here against pack test-verified-lineage 1.0.0",
        "{}",
        run.transcript()
    );
    assert!(run.stdout.contains("                 1 rule: 1 indeterminate\n"), "{}", run.transcript());
    // The reason names the flag that would decide it.
    assert!(
        run.stdout.contains(
            "                 indeterminate verified-lineage (mandatory, Test fixture rule 2): \
             the lineage of 2 records was not verified: none of its predecessors was supplied \
             to verification (vmr record verify --previous)\n"
        ),
        "{}",
        run.transcript()
    );
    assert_eq!(
        line(&run, "Accepted"),
        "  Accepted:      no: the evaluation could not be decided — \"indeterminate\" is not acceptance",
        "{}",
        run.transcript()
    );
    // The issuer's declaration is about another pack: a note, not a
    // disagreement, and still labelled as the issuer's.
    assert!(!run.stdout.contains("DISAGREEMENT"), "{}", run.transcript());
    assert!(line(&run, "Policy status").contains("declared by the issuer"), "{}", run.transcript());
}

#[test]
fn an_empty_software_hash_the_issuer_signed_fails_and_disagrees_with_its_declaration() {
    // P6-17 (E2, the owner, 2026-09-13). A software_hash of "" is what an
    // issuer signs to say "none", so the AI Act pack's technical-documentation
    // rule fails on it. Since task 7.6 the Gate 5 artifact pins its software
    // environment, so this test signs the artifact again, with its own key,
    // after emptying that member. The record still declares "compliant" for
    // that same pack, so the two statements disagree. Before P6-17 the rule
    // was indeterminate.
    let s = Scratch::new("verify-pack-demo");
    let mut unpinned = Record::from_cose(&std::fs::read(gate5_dir().join("model.vmr")).unwrap()).unwrap();
    unpinned.learning_provenance.training_environment.software_hash = String::new();
    sign_as(&mut unpinned, GATE5_ARTIFACT_KEY);
    let record = s.write("model.vmr", unpinned.to_cose().unwrap());
    let store = s.write("trust-store.json", std::fs::read(gate5_dir().join("trust-store.json")).unwrap());
    let run = verify_with_pack(&record, &store, "2026-09-11T12:00:00Z", &reference_pack("khalm-reading-eu-ai-act-2026"));
    run.expect_code(4);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  non-compliant — evaluated here against pack khalm-reading-eu-ai-act-2026 1.0.0",
        "{}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(
            "!! DISAGREEMENT — the issuer declared \"compliant\" (khalm-reading-eu-ai-act-2026); \
             this evaluation found \"non-compliant\" (khalm-reading-eu-ai-act-2026)\n"
        ),
        "{}",
        run.transcript()
    );
    // The mandatory technical-documentation rule, and the recommended human
    // oversight rule: the demo pins no oversight document (task 7.6, D11-7).
    assert!(run.stdout.contains("                 6 rules: 4 pass, 2 fail\n"), "{}", run.transcript());
    assert!(
        run.stdout.contains(
            "                 fail          eu-ai-act-technical-documentation (mandatory, \
             Regulation (EU) 2024/1689 (AI Act) Art. 11(1) and Annex IV(1)(c)): "
        ),
        "{}",
        run.transcript()
    );
    assert!(run.stdout.contains("software_hash is empty: "), "{}", run.transcript());
    assert_eq!(
        line(&run, "Accepted"),
        "  Accepted:      no: the evaluation found the record non-compliant",
        "{}",
        run.transcript()
    );
    assert!(line(&run, "Policy status").contains("declared by the issuer"), "{}", run.transcript());
}

#[test]
fn the_previous_records_reach_the_lineage_rules() {
    // P6-17: a rule that reads the lineage reads what verification made of
    // the predecessors given with --previous.
    let s = Scratch::new("verify-pack-previous");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let pack = s.write("verified-lineage.json", verified_lineage_pack());

    // Verified back to the initial record: the rule passes, exit 0.
    let (head, previous, at) = chain_case(&s, "pass-chain-3-complete");
    let run = verify_with_previous(&head, &previous, &store, &at, &pack);
    run.expect_code(0);
    assert_eq!(
        line(&run, "Policy check"),
        "  Policy check:  compliant — evaluated here against pack test-verified-lineage 1.0.0",
        "{}",
        run.transcript()
    );
    assert!(run.stdout.contains("                 1 rule: 1 pass\n"), "{}", run.transcript());

    // Verified only in part: indeterminate, exit 4, and the reason says what
    // to supply.
    let (head, previous, at) = chain_case(&s, "pass-chain-partial");
    let run = verify_with_previous(&head, &previous, &store, &at, &pack);
    run.expect_code(4);
    assert!(
        run.stdout.contains(
            "                 indeterminate verified-lineage (mandatory, Test fixture rule 2): \
             the lineage of 3 records was verified only in part: the predecessors supplied to \
             verification stop before its initial record (supply the rest with vmr record \
             verify --previous)\n"
        ),
        "{}",
        run.transcript()
    );
}

#[test]
fn a_deployment_is_compared_with_the_learned_state_of_its_verified_predecessor() {
    // P6-17: require_state_kept on a deployment reads the immediate
    // predecessor --previous supplied. The two-record vector's successor,
    // recorded as a deployment and signed again with the vector's own key,
    // keeps its predecessor's model, the same model_hash (task 10.12a).
    let s = Scratch::new("verify-pack-state-kept");
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let pack = s.write("state-kept.json", state_kept_pack());
    let (head, previous, at) = chain_case(&s, "pass-chain-2-complete");
    let mut deployment = Record::from_json(&std::fs::read_to_string(&head).unwrap()).unwrap();
    deployment.lineage.lineage_type = "deployment".into();
    sign_as(&mut deployment, KEY_A);
    let head = s.write("deployment.json", deployment.to_json().unwrap());

    // Without its predecessor: indeterminate, exit 4, naming --previous.
    let run = verify_with_previous(&head, &[], &store, &at, &pack);
    run.expect_code(4);
    assert_eq!(headline(&run), VALID, "{}", run.transcript());
    assert!(
        run.stdout.contains(
            "                 indeterminate state-kept (mandatory, Test fixture rule 3): a \"deployment\" \
             record must keep its predecessor's model, and its immediate predecessor was not \
             supplied to verification (vmr record verify --previous)\n"
        ),
        "{}",
        run.transcript()
    );

    // With it: the model hashes are compared, and they agree.
    let run = verify_with_previous(&head, &previous, &store, &at, &pack);
    run.expect_code(0);
    assert!(run.stdout.contains("                 1 rule: 1 pass\n"), "{}", run.transcript());
}

#[test]
fn without_the_flag_nothing_changes() {
    // C6's wording survives for every run that asks for no evaluation: the
    // flag adds a capability, it does not alter the old output.
    let s = Scratch::new("verify-pack-absent");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &store, "--at", T]);
    run.expect_code(0);
    assert_eq!(
        line(&run, "Policy status"),
        "  Policy status: \"compliant\", declared by the issuer, not evaluated (example-policy-pack-v1)"
    );
    assert!(line(&run, "Policy check").is_empty(), "{}", run.transcript());
}

#[test]
fn a_record_that_does_not_verify_is_never_evaluated() {
    // A policy judges a verified record or nothing (spec §6.6): the
    // verdict comes first, and exit 3 is not overtaken by exit 4.
    let s = Scratch::new("verify-pack-forged");
    let mut forged = vector();
    reissue_with(&mut forged, KEY_FORGER);
    let record = s.write("record.json", forged.to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let run = verify_with_pack(&record, &store, T, &reference_pack("khalm-reading-eu-ai-act-2026"));
    run.expect_code(3);
    assert!(line(&run, "Policy check").is_empty(), "{}", run.transcript());
    let json: Value = serde_json::from_str(&signed_json(&record, &store, &reference_pack("khalm-reading-eu-ai-act-2026"))).unwrap();
    assert_eq!(json["policy"]["evaluation"]["state"], "skipped", "{}", run.transcript());
}

// ---------------------------------------------------------------------------
//  (4) the two times, which must not be confused
// ---------------------------------------------------------------------------

#[test]
fn a_record_issued_long_ago_and_evaluated_now_is_not_refused_for_it() {
    // P6-6 (check 19) is about the evaluation the ISSUER embedded and
    // signed: `policy_compliance.evaluated_at` may not be later than
    // `issued_at`. An evaluation this verifier runs happens long after
    // issuance by definition, is stamped with the verifier's own time, and
    // is never related to `issued_at`.
    let s = Scratch::new("verify-pack-time");
    let record = s.write("model.vmr", std::fs::read(gate5_dir().join("model.vmr")).unwrap());
    let store = s.write("trust-store.json", std::fs::read(gate5_dir().join("trust-store.json")).unwrap());
    // Five years after the record was issued (2026-09-11).
    const LATE: &str = "2031-09-11T00:00:00Z";
    let run = verify_with_pack(&record, &store, LATE, &reference_pack("khalm-reading-eu-ai-act-2026"));
    assert_eq!(headline(&run), VALID, "verification is unaffected:\n{}", run.transcript());
    run.expect_code(0); // compliant (task 7.6), exactly as at any other time
    assert_eq!(line(&run, "Checked at"), format!("  Checked at:    {LATE} (--at)"), "{}", run.transcript());

    let json: Value = serde_json::from_str(
        &vmr(&[
            "record", "verify", "--record", &record, "--trust-store", &store, "--at", LATE,
            "--policy-pack", &reference_pack("khalm-reading-eu-ai-act-2026"), "--json",
        ])
        .stdout,
    )
    .unwrap();
    // Check 19 relates two of the RECORD's claims and passed; the report's
    // evaluation time is the verifier's, and the declaration keeps its own
    // (the issuer's evaluation, at the record's issued_at: task 7.6).
    let checks = json["checks"].as_array().unwrap();
    let check19 = checks.iter().find(|c| c["id"] == "time.policy_not_after_issued").unwrap();
    assert_eq!(check19["outcome"], "pass", "{check19}");
    assert_eq!(json["evaluation_time"], LATE);
    assert_eq!(json["policy"]["declared"]["evaluated_at"], "2026-09-11T00:00:00Z");
    assert_eq!(json["policy"]["evaluation"]["state"], "evaluated");
}

// ---------------------------------------------------------------------------
//  (5) --json: still the report, now carrying the evaluation
// ---------------------------------------------------------------------------

#[test]
fn json_is_the_report_byte_for_byte_and_carries_every_rules_evidence_hash() {
    let s = Scratch::new("verify-pack-json");
    let record_bytes = vector().to_json().unwrap();
    let store_bytes = vector_store("ts-basic");
    let record = s.write("record.json", &record_bytes);
    let store = s.write("trust-store.json", &store_bytes);
    let pack_path = reference_pack("khalm-reading-eu-ai-act-2026");
    let printed = signed_json(&record, &store, &pack_path);

    // The same report, computed in this process from vmr-verify and
    // vmr-policy directly: the CLI adds no policy logic of its own.
    let pack = vmr_policy::load_pack(&std::fs::read_to_string(&pack_path).unwrap()).unwrap();
    let expected = in_process_report_with_pack(record_bytes.as_bytes(), &store_bytes, T, &[], &pack);
    assert_eq!(printed, format!("{}\n", expected.to_json().unwrap()));

    // With predecessors too: the context the CLI hands the evaluation is the
    // one built here from the verifier's own view (P6-17).
    let (head, previous, at) = chain_case(&s, "pass-chain-3-complete");
    let mut args = vec![
        "record", "verify", "--record", &head, "--trust-store", &store, "--at", &at, "--policy-pack", &pack_path,
        "--json",
    ];
    for p in &previous {
        args.extend(["--previous", p.as_str()]);
    }
    let chain_printed = vmr(&args).stdout;
    let previous_bytes: Vec<Vec<u8>> = previous.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let chain_expected =
        in_process_report_with_pack(&std::fs::read(&head).unwrap(), &store_bytes, &at, &previous_bytes, &pack);
    assert_eq!(chain_printed, format!("{}\n", chain_expected.to_json().unwrap()));
    let chain_json: Value = serde_json::from_str(&chain_printed).unwrap();
    assert_eq!(chain_json["lineage"]["status"], "complete");
    assert_eq!(chain_json["policy"]["evaluation"]["state"], "evaluated");

    let json: Value = serde_json::from_str(&printed).unwrap();
    let evaluation = &json["policy"]["evaluation"];
    assert_eq!(evaluation["state"], "evaluated");
    assert_eq!(evaluation["policy_pack_id"], "khalm-reading-eu-ai-act-2026");
    assert_eq!(evaluation["policy_pack_version"], "1.0.0");
    assert_eq!(evaluation["status"], "compliant");
    assert_ne!(evaluation["state"], "not_requested", "the flag is what stops it being not_requested");

    // Every rule of the pack, with the evidence hash vmr-policy computes for
    // it (P6-2) - the value a third party recomputes to check the same
    // evidence. The vector is an initial record, verified alone, so its
    // context says so (P6-17).
    let rules = evaluation["rules"].as_array().unwrap();
    let initial = vmr_policy::EvaluationContext {
        lineage: vmr_policy::LineageContext { outcome: vmr_policy::LineageOutcome::Initial, predecessors: vec![] },
    };
    let own = pack.evaluate_in_context(
        &serde_json::to_value(vector()).unwrap(),
        &initial,
        vmr_policy::vmr_record::timestamp::Timestamp::parse(T).unwrap(),
    );
    assert_eq!(rules.len(), own.results.len());
    for (reported, computed) in rules.iter().zip(own.results.iter()) {
        assert_eq!(reported["rule_id"], computed.rule_id);
        assert_eq!(reported["status"], computed.status.id());
        assert_eq!(reported["severity"], computed.severity.id());
        assert_eq!(reported["reference"], computed.reference);
        assert_eq!(reported["evidence_hash"], computed.evidence_hash);
        assert!(computed.evidence_hash.starts_with("sha256:"), "{computed:?}");
    }
}

#[test]
fn an_initial_record_gets_the_evidence_hashes_of_an_evaluation_without_context() {
    // P6-17 (made normative 2026-09-13): for an initial record verification
    // learns nothing its own members do not say, so the context slot is null.
    // An issuer embedding its own evaluation has no context, and neither has
    // the library's `evaluate`: the binary must give every rule of every
    // reference pack the evidence hash they give, byte for byte (P6-2).
    let s = Scratch::new("verify-pack-initial-evidence");
    let conformance = vector();
    let gate5_bytes = std::fs::read(gate5_dir().join("model.vmr")).unwrap();
    let gate5 = Record::from_cose(&gate5_bytes).unwrap();
    let cases = [
        (
            "the conformance vector",
            s.write("vector.json", conformance.to_json().unwrap()),
            s.write("ts-basic.json", vector_store("ts-basic")),
            T,
            serde_json::to_value(&conformance).unwrap(),
        ),
        (
            "the Gate 5 record",
            s.write("model.vmr", &gate5_bytes),
            s.write("gate5-store.json", std::fs::read(gate5_dir().join("trust-store.json")).unwrap()),
            "2026-09-11T12:00:00Z",
            serde_json::to_value(&gate5).unwrap(),
        ),
    ];
    let mut differ = Vec::new();
    for pack_id in ["khalm-reading-eu-ai-act-2026", "khalm-reading-iso-42001-2023", "khalm-reading-nist-ai-rmf-1.0", "khalm-reading-rats-rfc9334-v0.1", "khalm-reading-c2pa-ai-disclosure-2.2"] {
        let pack_path = reference_pack(pack_id);
        let pack = vmr_policy::load_pack(&std::fs::read_to_string(&pack_path).unwrap()).unwrap();
        for (what, record, store, at, value) in &cases {
            let run = vmr(&[
                "record", "verify", "--record", record, "--trust-store", store, "--at", at, "--policy-pack",
                &pack_path, "--json",
            ]);
            let json: Value = serde_json::from_str(&run.stdout)
                .unwrap_or_else(|e| panic!("{what} x {pack_id}: {e}\n{}", run.transcript()));
            assert_eq!(json["lineage"]["status"], "initial", "{what}");
            let reported = json["policy"]["evaluation"]["rules"].as_array().unwrap();
            let library = vmr_policy::evaluate(
                pack.pack(),
                value,
                vmr_policy::vmr_record::timestamp::Timestamp::parse(at).unwrap(),
            );
            assert_eq!(reported.len(), library.results.len(), "{what} x {pack_id}");
            for (r, l) in reported.iter().zip(&library.results) {
                if r["evidence_hash"] != l.evidence_hash.as_str() {
                    differ.push(format!("{what} x {pack_id}/{} ({})", l.rule_id, l.rule_type));
                }
            }
        }
    }
    assert!(differ.is_empty(), "the binary and the library without context disagree on: {differ:#?}");
}

/// The report `vmr-verify` computes in this process for the same inputs and
/// the same pack — what `vmr record verify --policy-pack ... --json` must
/// print byte for byte, `--previous` included. The adapter is a mapping and
/// nothing more, which is the point: the CLI orchestrates and decides
/// nothing.
fn in_process_report_with_pack(
    record: &[u8],
    store: &[u8],
    at: &str,
    previous: &[Vec<u8>],
    pack: &vmr_policy::LoadedPack,
) -> vmr_verify::VerificationReport {
    struct Adapter<'a>(&'a vmr_policy::LoadedPack);
    impl vmr_verify::policy::PolicyEvaluator for Adapter<'_> {
        fn policy_pack_id(&self) -> &str {
            &self.0.pack_id
        }

        fn evaluate(
            &self,
            record: &vmr_verify::policy::VerifiedRecord<'_>,
            evaluation_time: vmr_record::timestamp::Timestamp,
        ) -> vmr_verify::policy::PolicyEvaluation {
            use vmr_verify::report::LineageStatus;
            let value = serde_json::to_value(record.record()).unwrap();
            let lineage = record.lineage();
            let context = vmr_policy::EvaluationContext {
                lineage: vmr_policy::LineageContext {
                    outcome: match lineage.status {
                        LineageStatus::Initial => vmr_policy::LineageOutcome::Initial,
                        LineageStatus::Complete => vmr_policy::LineageOutcome::Complete,
                        LineageStatus::Partial => vmr_policy::LineageOutcome::Partial,
                        LineageStatus::NotChecked | LineageStatus::Broken => vmr_policy::LineageOutcome::NotChecked,
                    },
                    predecessors: lineage
                        .verified_links
                        .iter()
                        .zip(record.verified_predecessors())
                        .map(|(link, p)| vmr_policy::VerifiedPredecessor {
                            signed_payload_hash: link.signed_payload_hash.clone(),
                            record: serde_json::to_value(p).unwrap(),
                        })
                        .collect(),
                },
            };
            let evaluation = self.0.evaluate_in_context(&value, &context, evaluation_time);
            vmr_verify::policy::PolicyEvaluation {
                status: match evaluation.overall {
                    vmr_policy::Status::Pass => vmr_verify::policy::PolicyStatus::Compliant,
                    vmr_policy::Status::Fail => vmr_verify::policy::PolicyStatus::NonCompliant,
                    vmr_policy::Status::Indeterminate => vmr_verify::policy::PolicyStatus::Indeterminate,
                },
                pack_version: evaluation.pack_version.clone(),
                pack_payload_hash: self.0.payload_hash().to_string(),
                // The stores these reports use hold no policy authority.
                pack_signature: match &self.0.pack().signature {
                    None => vmr_verify::policy::PackSignatureState::Unsigned,
                    Some(s) => vmr_verify::policy::PackSignatureState::NotChecked {
                        signing_key_id: s.signing_key_id.clone(),
                    },
                },
                authority_store: None,
                rules: evaluation
                    .results
                    .iter()
                    .map(|r| vmr_verify::policy::PolicyRuleResult {
                        rule_id: r.rule_id.clone(),
                        status: match r.status {
                            vmr_policy::Status::Pass => vmr_verify::policy::PolicyRuleStatus::Pass,
                            vmr_policy::Status::Fail => vmr_verify::policy::PolicyRuleStatus::Fail,
                            vmr_policy::Status::Indeterminate => {
                                vmr_verify::policy::PolicyRuleStatus::Indeterminate
                            }
                        },
                        severity: r.severity.id().to_string(),
                        reference: r.reference.clone(),
                        evidence_hash: r.evidence_hash.clone(),
                        detail: r.detail.clone(),
                    })
                    .collect(),
            }
        }
    }
    let store = vmr_verify::TrustStore::from_json(store).unwrap();
    let adapter = Adapter(pack);
    let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
    let opts = vmr_verify::VerifyOptions::new(vmr_record::timestamp::Timestamp::parse(at).unwrap())
        .with_previous(&refs)
        .with_policy(&adapter);
    vmr_verify::Verifier::new(store).verify(record, &opts)
}

// ---------------------------------------------------------------------------
//  A pack file is the operator's input: every refusal is exit 1
// ---------------------------------------------------------------------------

#[test]
fn an_unusable_pack_file_is_the_operators_error_and_names_what_is_wrong() {
    let s = Scratch::new("verify-pack-bad");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let missing = s.arg("no-such-pack.json");
    let not_json = s.write("not-json.json", "{ this is not json");
    let unknown = s.write("unknown.json", {
        let mut v: Value = serde_json::from_str(&strict_pack()).unwrap();
        v["surprise"] = Value::Bool(true);
        v.to_string()
    });
    let wrong_version = s.write("wrong-version.json", {
        let mut v: Value = serde_json::from_str(&strict_pack()).unwrap();
        v["version"] = Value::String("0.2".into());
        v.to_string()
    });
    let bom = s.write("bom.json", {
        let mut bytes = vec![0xef, 0xbb, 0xbf];
        bytes.extend_from_slice(strict_pack().as_bytes());
        bytes
    });
    let cases: [(&str, &str); 5] = [
        (&missing, "cannot read policy pack"),
        (&not_json, "policy pack parse failed"),
        (&unknown, "unknown field `surprise`"),
        (&wrong_version, "unsupported policy pack version"),
        (&bom, "byte order mark"),
    ];
    for (pack, fragment) in cases {
        let run = verify_with_pack(&record, &store, T, pack);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{pack}:\n{}", run.transcript());
        assert!(run.stderr.contains(fragment), "{pack}: expected `{fragment}`:\n{}", run.transcript());
    }
    // A refused pack names the refusal's stable id (specs/policy-pack-format-v0.1.md
    // §3; docs/dev/task-6.16.md A16-20): a byte order mark is not JSON.
    for (pack, id) in [
        (&not_json, "policy_pack.structure"),
        (&unknown, "policy_pack.structure"),
        (&wrong_version, "policy_pack.version"),
        (&bom, "policy_pack.structure"),
    ] {
        let run = verify_with_pack(&record, &store, T, pack);
        assert!(run.stderr.contains(&format!("cannot be used: {id}: ")), "{pack}: expected {id}:\n{}", run.transcript());
    }
}

#[test]
fn a_pack_nested_past_127_levels_is_refused_for_its_depth_whatever_else_its_bytes_break() {
    // QA16-02 (specs/policy-pack-format-v0.1.md §3): refusal 1 is decided
    // first, then refusal 12, by a count over the bytes, before a byte order
    // mark, bytes that are not UTF-8 or a syntax error is looked at. The
    // binary names what vmr-policy's loader names for the same bytes.
    let s = Scratch::new("verify-pack-nesting-first");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let pack = strict_pack();
    let close = pack.rfind('}').unwrap();
    // 127 arrays in a member the format lacks: 128 levels with the pack object.
    let deep = format!("{},\"surprise\":{}{}}}", &pack[..close], "[".repeat(127), "]".repeat(127));
    let not_utf8 = |text: &str| {
        // One byte that is not UTF-8, inside the rule's minimum_level string,
        // well before the brackets open.
        let at = text.find("\"hardware\"").unwrap() + 2;
        let mut bytes = text.as_bytes().to_vec();
        bytes[at] = 0xff;
        bytes
    };
    let refused_as = |bytes: Vec<u8>, name: &str, id: &str| {
        let file = s.write(name, &bytes);
        let run = verify_with_pack(&record, &store, T, &file);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{name}:\n{}", run.transcript());
        assert!(run.stderr.contains(&format!("cannot be used: {id}: ")), "{name}: expected {id}:\n{}", run.transcript());
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let library = vmr_policy::load_pack(text).map(|_| ()).expect_err(name);
            assert_eq!(library.refusal_id(), id, "{name}: the library names the same refusal");
        }
    };
    refused_as([&[0xef, 0xbb, 0xbf][..], deep.as_bytes()].concat(), "bom-then-128.json", "policy_pack.nesting");
    refused_as([&[0xff, 0xfe][..], deep.as_bytes()].concat(), "utf16-bom-then-128.json", "policy_pack.nesting");
    refused_as(not_utf8(&deep), "not-utf8-then-128.json", "policy_pack.nesting");
    refused_as(deep.replacen('{', "{\"x\":tru,", 1).into_bytes(), "syntax-error-then-128.json", "policy_pack.nesting");
    refused_as(format!("{deep},]").into_bytes(), "128-then-syntax-error.json", "policy_pack.nesting");
    // Refusal 1 comes first.
    let mut big = deep.clone().into_bytes();
    big.resize(1024 * 1024 + 1, b' ');
    refused_as(big, "over-1-mib-and-128.json", "policy_pack.size");
    // Without the depth, a byte order mark and bytes that are not UTF-8 stay
    // refusal 2.
    refused_as([&[0xef, 0xbb, 0xbf][..], pack.as_bytes()].concat(), "bom.json", "policy_pack.structure");
    refused_as(not_utf8(&pack), "not-utf8.json", "policy_pack.structure");
    // Brackets inside a string open no level: 200 of them, after an escaped
    // quotation mark, in a description at depth 1. The pack loads, and the
    // conformance vector fails its rule.
    let mut doc: Value = serde_json::from_str(&pack).unwrap();
    doc["description"] = Value::from(format!("\"{}", "[".repeat(200)));
    let brackets = write_json(&s, "brackets-in-a-string.json", &doc);
    let run = verify_with_pack(&record, &store, T, &brackets);
    run.expect_code(4);
    assert!(line(&run, "Policy check").contains("non-compliant"), "{}", run.transcript());
}

#[test]
fn a_pack_larger_than_the_limit_is_not_read() {
    let s = Scratch::new("verify-pack-huge");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let pack = s.write("huge.json", vec![b' '; 1024 * 1024 + 1]);
    let run = verify_with_pack(&record, &store, T, &pack);
    run.expect_code(1);
    assert!(run.stderr.contains("1 MiB"), "{}", run.transcript());
    assert!(run.stderr.contains("cannot be used: policy_pack.size: "), "{}", run.transcript());
}

#[test]
fn verify_help_documents_the_flag_and_the_exit_code() {
    let run = vmr(&["record", "verify", "--help"]);
    run.expect_code(0);
    assert!(run.stdout.contains("--policy-pack"), "{}", run.transcript());
    assert!(run.stdout.contains("--authority-store"), "{}", run.transcript());
    assert!(run.stdout.contains("--require-signed-pack"), "{}", run.transcript());
    assert!(
        run.stdout.contains("the policy evaluation did not accept it"),
        "exit code 4 is no longer reserved:\n{}",
        run.transcript()
    );
    // QA16-05: exit 1's list names every refusal these flags add, as
    // docs/CLI.md §5 does, in `vmr --help` and in the command's own help.
    for help in [run, vmr(&["--help"])] {
        help.expect_code(0);
        for fragment in ["an unusable trust store, authority store or policy pack", "--require-signed-pack does not"] {
            assert!(help.stdout.contains(fragment), "expected `{fragment}` in the exit codes:\n{}", help.transcript());
        }
    }
}

// ---------------------------------------------------------------------------
//  (6) The pack's authority signature, checked (docs/dev/phase6.md P6-14 and
//      P6-16; docs/dev/task-6.16.md A16-6 to A16-17)
// ---------------------------------------------------------------------------

/// The label of the test policy authority's key (derived, test-only): the
/// key `signed_by_test_authority` signs with.
const AUTHORITY_LABEL: &str = "vmr-cli tests: a policy authority key";
/// Another derived key, which no store trusts.
const OTHER_AUTHORITY_LABEL: &str = "vmr-cli tests: someone else's key";
/// The reference packs' own authority (`specs/policy-packs/`).
const REFERENCE_AUTHORITY: &str = "khalm-reference-packs";
/// The operator's name for it in these tests' stores.
const REFERENCE_AUTHORITY_NAME: &str = "KHALM reference packs, per this operator";

/// The key id of `label`'s derived key.
fn key_id_of(label: &str) -> String {
    JwkPublicKey::from_verifying_key(key(label).verifying_key()).key_id()
}

/// A trust-store key object for `label`'s key: `software`, from `from`,
/// until `until` when given.
fn key_object(label: &str, from: &str, until: Option<&str>, revoked: bool) -> Value {
    let jwk = JwkPublicKey::from_verifying_key(key(label).verifying_key());
    let mut k = serde_json::json!({
        "key_id": jwk.key_id(),
        "public_key": jwk,
        "attestation_level": "software",
        "valid_from": from,
        "revoked": revoked
    });
    if let Some(until) = until {
        k["valid_until"] = Value::from(until);
    }
    k
}

/// A policy authority entry of a trust store.
fn authority_entry(id: &str, name: &str, keys: Vec<Value>) -> Value {
    serde_json::json!({"authority_id": id, "authority_name": name, "keys": keys})
}

/// The reference packs' authority, holding the test authority key from
/// 2026-01-01 until 2027-01-01 (the vectors' T is inside).
fn trusted_reference_authority() -> Value {
    authority_entry(
        REFERENCE_AUTHORITY,
        REFERENCE_AUTHORITY_NAME,
        vec![key_object(AUTHORITY_LABEL, "2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), false)],
    )
}

/// `ts-basic`, the record vector's issuers, with `authorities` added.
fn basic_store_with(authorities: Vec<Value>) -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(&vector_store("ts-basic")).unwrap();
    doc["policy_authorities"] = Value::Array(authorities);
    serde_json::to_vec_pretty(&doc).unwrap()
}

/// A store of policy authorities alone: an authority store (trust-store
/// format §4.2).
fn authority_store_of(authorities: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "trust_store_version": "0.1", "issuers": [], "policy_authorities": authorities
    }))
    .unwrap()
}

/// The EU AI Act reference pack, as a value (it is unsigned).
fn eu_pack() -> Value {
    serde_json::from_str(&std::fs::read_to_string(reference_pack("khalm-reading-eu-ai-act-2026")).unwrap()).unwrap()
}

/// `doc` signed over vmr-policy's signed payload by `label`'s key, naming it.
fn signed_by(mut doc: Value, label: &str) -> Value {
    use vmr_policy::vmr_record::{encoding::b64url_encode, sign};
    if let Some(o) = doc.as_object_mut() {
        o.remove("signature");
    }
    let signature = sign::sign(&key(label), vmr_policy::signed_payload(&doc).as_bytes()).unwrap();
    doc["signature"] = serde_json::json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", b64url_encode(&signature.to_bytes())),
        "signed_payload_hash": vmr_policy::payload_hash(&doc),
        "signing_key_id": key_id_of(label),
    });
    doc
}

/// The high-s twin of a pack's `signature` member: the same `r`, `n - s`.
fn high_s_twin(field: &str) -> String {
    use vmr_policy::vmr_record::{encoding::b64url_encode, sign};
    let low = sign::signature_from_b64url(field.strip_prefix("base64url:").unwrap()).unwrap();
    let twin = p256::ecdsa::Signature::from_scalars(*low.r(), -*low.s()).unwrap();
    format!("base64url:{}", b64url_encode(&twin.to_bytes()))
}

/// `doc` written as pretty JSON into the scratch directory.
fn write_json(s: &Scratch, name: &str, doc: &Value) -> String {
    s.write(name, serde_json::to_vec_pretty(doc).unwrap())
}

/// `record verify` of `record` against `store` with `pack` at T, and
/// `extra` flags.
fn verify_pack_with(record: &str, store: &str, pack: &str, extra: &[&str]) -> Run {
    let mut args = vec!["record", "verify", "--record", record, "--trust-store", store, "--at", T, "--policy-pack", pack];
    args.extend_from_slice(extra);
    vmr(&args)
}

#[test]
fn a_pack_signed_by_a_trusted_authority_is_valid_in_text_and_json() {
    let s = Scratch::new("verify-pack-valid");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", basic_store_with(vec![trusted_reference_authority()]));
    let doc = signed_by(eu_pack(), AUTHORITY_LABEL);
    let pack = write_json(&s, "signed.json", &doc);
    let kid = key_id_of(AUTHORITY_LABEL);
    let hash = vmr_policy::payload_hash(&doc);
    assert_eq!(hash, vmr_policy::payload_hash(&eu_pack()), "a signature does not move the payload hash");

    let run = verify_pack_with(&record, &store, &pack, &[]);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!(
            "                 pack signature: valid — signed by {kid}, a key the trust store trusts for policy authority {REFERENCE_AUTHORITY} ({REFERENCE_AUTHORITY_NAME})\n"
        )),
        "{}",
        run.transcript()
    );
    assert!(run.stdout.contains(&format!("                 pack payload hash: {hash}\n")), "{}", run.transcript());
    assert!(!run.stdout.contains("  Authorities:"), "the trust store held the authorities:\n{}", run.transcript());

    let json: Value = serde_json::from_str(&verify_pack_with(&record, &store, &pack, &["--json"]).stdout).unwrap();
    let e = &json["policy"]["evaluation"];
    assert_eq!(
        e["pack_signature"],
        serde_json::json!({
            "state": "valid", "signing_key_id": kid, "authority_id": REFERENCE_AUTHORITY,
            "authority_name": REFERENCE_AUTHORITY_NAME
        })
    );
    assert_eq!(e["policy_pack_payload_hash"], hash);
    assert!(e.get("authority_store").is_none(), "{e}");
    // A gate that demands a signed pack accepts this one.
    verify_pack_with(&record, &store, &pack, &["--require-signed-pack"]).expect_code(0);
}

#[test]
fn the_payload_hash_of_an_unsigned_pack_is_reported_too() {
    let s = Scratch::new("verify-pack-hash");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let hash = vmr_policy::payload_hash(&eu_pack());
    let run = verify_pack_with(&record, &store, &reference_pack("khalm-reading-eu-ai-act-2026"), &[]);
    run.expect_code(0);
    assert!(run.stdout.contains(&format!("                 pack payload hash: {hash}\n")), "{}", run.transcript());
    let json: Value =
        serde_json::from_str(&verify_pack_with(&record, &store, &reference_pack("khalm-reading-eu-ai-act-2026"), &["--json"]).stdout)
            .unwrap();
    assert_eq!(json["policy"]["evaluation"]["policy_pack_payload_hash"], hash);
    assert_eq!(json["policy"]["evaluation"]["pack_signature"], serde_json::json!({"state": "unsigned"}));
}

#[test]
fn a_signature_that_does_not_verify_exits_1_before_the_record_is_verified() {
    // P6-16: another key, damaged bytes, a key trusted for another authority,
    // a revoked key, a key outside its window at T (A16-10, A16-11).
    let s = Scratch::new("verify-pack-refused");
    let record = s.write("record.json", vector().to_json().unwrap());
    let kid = key_id_of(AUTHORITY_LABEL);
    let good = signed_by(eu_pack(), AUTHORITY_LABEL);
    let trusted = s.write("trusted.json", basic_store_with(vec![trusted_reference_authority()]));

    let mut by_other = signed_by(eu_pack(), OTHER_AUTHORITY_LABEL);
    by_other["signature"]["signing_key_id"] = Value::from(kid.clone());
    let mut high_s = good.clone();
    high_s["signature"]["signature"] = Value::from(high_s_twin(good["signature"]["signature"].as_str().unwrap()));
    let mut elsewhere = eu_pack();
    elsewhere["authority"]["authority_id"] = Value::from("another-authority");
    let elsewhere = signed_by(elsewhere, AUTHORITY_LABEL);
    let store_of = |name: &str, key: Value| {
        s.write(name, basic_store_with(vec![authority_entry(REFERENCE_AUTHORITY, REFERENCE_AUTHORITY_NAME, vec![key])]))
    };
    let revoked = store_of("revoked.json", key_object(AUTHORITY_LABEL, "2026-01-01T00:00:00Z", None, true));
    let not_yet =
        store_of("not-yet.json", key_object(AUTHORITY_LABEL, "2026-09-12T00:00:00Z", Some("2027-01-01T00:00:00Z"), false));
    let ended = store_of("ended.json", key_object(AUTHORITY_LABEL, "2026-01-01T00:00:00Z", Some(T), false));
    let good_path = write_json(&s, "good.json", &good);
    let by_other_path = write_json(&s, "by-other.json", &by_other);

    let cases: Vec<(&str, String, String, &str)> = vec![
        ("another key", by_other_path.clone(), trusted.clone(), "does not verify"),
        ("damaged bytes (the high-s twin)", write_json(&s, "high-s.json", &high_s), trusted.clone(), "high-s"),
        (
            "a key trusted for another authority",
            write_json(&s, "elsewhere.json", &elsewhere),
            trusted.clone(),
            "is trusted for policy authority \"khalm-reference-packs\"",
        ),
        ("a revoked key", good_path.clone(), revoked, "is revoked"),
        ("a key not yet valid at T", good_path.clone(), not_yet, "outside that window"),
        ("a key whose window ended at T", good_path, ended, "outside that window"),
    ];
    for (what, pack, store, fragment) in &cases {
        for flags in [&[][..], &["--json"][..], &["--require-signed-pack"][..]] {
            let run = verify_pack_with(&record, store, pack, flags);
            run.expect_code(1);
            assert!(run.stdout.is_empty(), "{what} {flags:?}: no report for a refused signature:\n{}", run.transcript());
            assert!(run.stderr.contains("cannot be used"), "{what}:\n{}", run.transcript());
            assert!(run.stderr.contains(fragment), "{what}: expected `{fragment}`:\n{}", run.transcript());
        }
    }
    // Each refusal names its stable id (docs/dev/task-6.16.md A16-22).
    let ids = [
        "pack_signature.invalid",
        "pack_signature.invalid",
        "pack_signature.other_authority",
        "pack_signature.revoked",
        "pack_signature.outside_validity",
        "pack_signature.outside_validity",
    ];
    for ((what, pack, store, _), id) in cases.iter().zip(ids) {
        let run = verify_pack_with(&record, store, pack, &[]);
        assert!(run.stderr.contains(&format!("cannot be used: {id}: ")), "{what}: expected {id}:\n{}", run.transcript());
    }
    // A signature that does not verify names its key, and no authority: key
    // ids are public, and a forgery may cite a trusted one (QA P4-05).
    let run = verify_pack_with(&record, &trusted, &by_other_path, &[]);
    assert!(run.stderr.contains(&kid), "{}", run.transcript());
    assert!(!run.stderr.contains(REFERENCE_AUTHORITY), "{}", run.transcript());
}

#[test]
fn a_refused_pack_signature_exits_1_whatever_the_record_would_have_given() {
    // A16-17: the pack is decided before the record is verified, so exit 1
    // comes before 3 and before 4.
    let s = Scratch::new("verify-pack-precedence");
    let mut forged = vector();
    reissue_with(&mut forged, KEY_FORGER);
    let forged = s.write("forged.json", forged.to_json().unwrap());
    let genuine = s.write("record.json", vector().to_json().unwrap());
    let trusted = s.write("trusted.json", basic_store_with(vec![trusted_reference_authority()]));
    let untrusted = s.write("ts-basic.json", vector_store("ts-basic"));
    let damage = |doc: &Value| {
        let mut d = doc.clone();
        d["signature"]["signature"] = Value::from(high_s_twin(doc["signature"]["signature"].as_str().unwrap()));
        d
    };
    let eu_signed = signed_by(eu_pack(), AUTHORITY_LABEL);
    let eu_damaged = write_json(&s, "eu-damaged.json", &damage(&eu_signed));
    // The strict pack fails the genuine record, so a usable copy exits 4.
    let mut strict: Value = serde_json::from_str(&strict_pack()).unwrap();
    strict["authority"]["authority_id"] = Value::from(REFERENCE_AUTHORITY);
    let strict_signed = signed_by(strict, AUTHORITY_LABEL);
    let strict_ok = write_json(&s, "strict.json", &strict_signed);
    let strict_damaged = write_json(&s, "strict-damaged.json", &damage(&strict_signed));
    let unsigned = reference_pack("khalm-reading-eu-ai-act-2026");

    verify_pack_with(&forged, &trusted, &unsigned, &[]).expect_code(3);
    verify_pack_with(&forged, &trusted, &eu_damaged, &[]).expect_code(1);
    verify_pack_with(&genuine, &trusted, &strict_ok, &[]).expect_code(4);
    verify_pack_with(&genuine, &trusted, &strict_damaged, &[]).expect_code(1);
    verify_pack_with(&forged, &trusted, &unsigned, &["--require-signed-pack"]).expect_code(1);
    verify_pack_with(&genuine, &untrusted, &strict_ok, &["--require-signed-pack"]).expect_code(1);
    // Without a key for its authority, the damage cannot be seen: the pack is
    // evaluated as not checked, and the record's own code stands.
    verify_pack_with(&forged, &untrusted, &eu_damaged, &[]).expect_code(3);
    verify_pack_with(&genuine, &untrusted, &strict_ok, &[]).expect_code(4);
}

#[test]
fn an_unsigned_or_untrusted_pack_is_evaluated_and_labelled_and_require_signed_pack_refuses_both() {
    let s = Scratch::new("verify-pack-require");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("ts-basic.json", vector_store("ts-basic"));
    let unsigned = reference_pack("khalm-reading-eu-ai-act-2026");
    let signed = write_json(&s, "signed.json", &signed_by(eu_pack(), AUTHORITY_LABEL));
    let kid = key_id_of(AUTHORITY_LABEL);

    let run = verify_pack_with(&record, &store, &unsigned, &[]);
    run.expect_code(0);
    assert!(
        run.stdout.contains("                 pack signature: none, the pack carries no authority signature\n"),
        "{}",
        run.transcript()
    );
    let run = verify_pack_with(&record, &store, &signed, &[]);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!(
            "                 pack signature: names {kid} as its signer — NOT checked: no policy authority in the trust store holds that key\n"
        )),
        "{}",
        run.transcript()
    );
    let json: Value = serde_json::from_str(&verify_pack_with(&record, &store, &signed, &["--json"]).stdout).unwrap();
    assert_eq!(
        json["policy"]["evaluation"]["pack_signature"],
        serde_json::json!({"state": "not_checked", "signing_key_id": kid})
    );

    for (what, pack, fragment, id) in [
        ("unsigned", &unsigned, "carries no authority signature".to_string(), "pack_signature.unsigned_refused"),
        (
            "untrusted",
            &signed,
            format!("names {kid} as its signer, but no policy authority in the trust store holds that key"),
            "pack_signature.not_checked_refused",
        ),
    ] {
        let run = verify_pack_with(&record, &store, pack, &["--require-signed-pack"]);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{what}:\n{}", run.transcript());
        assert!(run.stderr.contains(&format!("cannot be used: {id}: ")), "{what}: expected {id}:\n{}", run.transcript());
        assert!(run.stderr.contains("--require-signed-pack"), "{what}:\n{}", run.transcript());
        assert!(run.stderr.contains(&fragment), "{what}: expected `{fragment}`:\n{}", run.transcript());
        assert!(run.stderr.contains("policy_authorities"), "{what}: the hint says where trust comes from:\n{}", run.transcript());
    }
}

#[test]
fn an_issuers_key_never_vouches_for_a_pack_nor_an_authoritys_key_for_a_record() {
    // P6-14: the two lists are kept apart by structure.
    let s = Scratch::new("verify-pack-apart");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("ts-basic.json", vector_store("ts-basic"));
    // Key A signs the record vector, and ts-basic trusts it for the
    // vector's issuer: a pack it signs is still not its authority's.
    let by_key_a = write_json(&s, "by-key-a.json", &signed_by(eu_pack(), KEY_A));
    let run = verify_pack_with(&record, &store, &by_key_a, &[]);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!("pack signature: names {} as its signer — NOT checked", key_id_of(KEY_A))),
        "{}",
        run.transcript()
    );
    verify_pack_with(&record, &store, &by_key_a, &["--require-signed-pack"]).expect_code(1);
    // Key A as a policy authority's only: the record it signed is not trusted.
    let as_authority = s.write(
        "key-a-as-authority.json",
        authority_store_of(vec![authority_entry(
            REFERENCE_AUTHORITY,
            "key A, as an authority",
            vec![key_object(KEY_A, "2026-01-01T00:00:00Z", None, false)],
        )]),
    );
    let run = vmr(&["record", "verify", "--record", &record, "--trust-store", &as_authority, "--at", T]);
    run.expect_code(3);
    assert!(headline(&run).contains("trust.key_known"), "{}", run.transcript());
}

#[test]
fn authorities_come_only_from_the_authority_store_when_one_is_given() {
    // P6-16: no fallback to --trust-store, and the authority store's identity
    // is printed as the trust store's is (A16-7, A16-13).
    let s = Scratch::new("verify-pack-authority-store");
    let record = s.write("record.json", vector().to_json().unwrap());
    let signed = write_json(&s, "signed.json", &signed_by(eu_pack(), AUTHORITY_LABEL));
    let kid = key_id_of(AUTHORITY_LABEL);
    let trust_with = s.write("trust-with-authority.json", basic_store_with(vec![trusted_reference_authority()]));
    let trust_without = s.write("ts-basic.json", vector_store("ts-basic"));
    let empty_bytes = authority_store_of(vec![]);
    let empty = s.write("no-authorities.json", &empty_bytes);
    let with_bytes = authority_store_of(vec![trusted_reference_authority()]);
    let with = s.write("authorities.json", &with_bytes);
    let identity = |bytes: &[u8]| vmr_verify::TrustStore::from_json(bytes).unwrap().sha256().to_string();

    // The trust store would vouch; the authority store given does not.
    let run = verify_pack_with(&record, &trust_with, &signed, &["--authority-store", &empty]);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!(
            "                 pack signature: names {kid} as its signer — NOT checked: no policy authority in the authority store holds that key\n"
        )),
        "{}",
        run.transcript()
    );
    assert_eq!(
        line(&run, "Authorities"),
        format!("  Authorities:   {} (0 authorities, 0 keys)", identity(&empty_bytes)),
        "{}",
        run.transcript()
    );
    verify_pack_with(&record, &trust_with, &signed, &["--authority-store", &empty, "--require-signed-pack"])
        .expect_code(1);

    // The authority store vouches; the trust store holds no authority.
    let run = verify_pack_with(&record, &trust_without, &signed, &["--authority-store", &with]);
    run.expect_code(0);
    assert!(
        run.stdout.contains(&format!(
            "                 pack signature: valid — signed by {kid}, a key the authority store trusts for policy authority {REFERENCE_AUTHORITY} ({REFERENCE_AUTHORITY_NAME})\n"
        )),
        "{}",
        run.transcript()
    );
    assert_eq!(line(&run, "Authorities"), format!("  Authorities:   {} (1 authority, 1 key)", identity(&with_bytes)));
    let basic = identity(&vector_store("ts-basic"));
    assert!(line(&run, "Trust store").contains(&basic), "{}", run.transcript());
    let json: Value =
        serde_json::from_str(&verify_pack_with(&record, &trust_without, &signed, &["--authority-store", &with, "--json"]).stdout)
            .unwrap();
    assert_eq!(
        json["policy"]["evaluation"]["authority_store"],
        serde_json::json!({"sha256": identity(&with_bytes), "authority_count": 1, "key_count": 1})
    );
    assert_eq!(json["policy"]["evaluation"]["pack_signature"]["state"], "valid");
    assert_eq!(json["trust_store"]["sha256"], basic);
}

#[test]
fn an_authority_store_that_lists_issuers_or_cannot_be_read_is_refused() {
    let s = Scratch::new("verify-pack-authority-store-bad");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("ts-basic.json", vector_store("ts-basic"));
    let pack = reference_pack("khalm-reading-eu-ai-act-2026");
    let with_issuers = s.write("issuers.json", vector_store("ts-basic"));
    let not_json = s.write("not-json.json", "{ not json");
    let missing = s.arg("no-such-store.json");
    let bom = s.write("bom.json", [&[0xef, 0xbb, 0xbf][..], &authority_store_of(vec![])].concat());
    let cases: [(&str, &str); 4] = [
        (&with_issuers, "cannot be used: authority_store.issuers: it trusts 2 issuers"),
        (&not_json, "trust_store.syntax"),
        (&missing, "cannot read authority store"),
        (&bom, "byte order mark"),
    ];
    for (authorities, fragment) in cases {
        let run = verify_pack_with(&record, &store, &pack, &["--authority-store", authorities]);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{authorities}:\n{}", run.transcript());
        assert!(run.stderr.contains("authority store"), "{authorities}:\n{}", run.transcript());
        assert!(run.stderr.contains(fragment), "{authorities}: expected `{fragment}`:\n{}", run.transcript());
    }
    // The authority store is read before the pack.
    let bad_pack = s.write("bad-pack.json", "{ not a pack");
    let run = verify_pack_with(&record, &store, &bad_pack, &["--authority-store", &not_json]);
    run.expect_code(1);
    assert!(run.stderr.contains("authority store"), "{}", run.transcript());
    assert!(!run.stderr.contains("policy pack parse failed"), "{}", run.transcript());
}

#[test]
fn an_authority_store_may_not_hold_a_key_the_trust_store_trusts_for_an_issuer() {
    // QA16-01 (docs/dev/task-6.16.md A16-25): one key may not speak for
    // records in the trust store and for packs in the authority store, as
    // A16-3 already refuses inside one store. Key A is the conformance
    // record's issuer key in ts-basic.
    let s = Scratch::new("verify-pack-authority-store-issuer-key");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("trust-store.json", basic_store_with(vec![]));
    let key_a = key_object(KEY_A, "2026-01-01T00:00:00Z", None, false);
    let refused = format!("cannot be used: authority_store.issuer_key: it trusts {}", key_id_of(KEY_A));
    let expect_refused = |run: &Run, what: &str| {
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{what}:\n{}", run.transcript());
        assert!(run.stderr.contains("authority store"), "{what}:\n{}", run.transcript());
        assert!(run.stderr.contains(&refused), "{what}: expected `{refused}`:\n{}", run.transcript());
    };
    let a_as_authority = s.write(
        "a-as-authority.json",
        authority_store_of(vec![authority_entry(REFERENCE_AUTHORITY, REFERENCE_AUTHORITY_NAME, vec![key_a.clone()])]),
    );

    // The pack signed by key A would otherwise be valid: exit 0 before the fix.
    let signed_a = write_json(&s, "signed-by-a.json", &signed_by(eu_pack(), KEY_A));
    expect_refused(&verify_pack_with(&record, &store, &signed_a, &["--authority-store", &a_as_authority]), "signed by A");

    // It is the stores that are refused, whatever the pack: signed by a key
    // the authority store rightly trusts, unsigned, or not a pack at all.
    let beside = s.write(
        "a-beside-the-authority-key.json",
        authority_store_of(vec![authority_entry(
            REFERENCE_AUTHORITY,
            REFERENCE_AUTHORITY_NAME,
            vec![key_object(AUTHORITY_LABEL, "2026-01-01T00:00:00Z", None, false), key_a.clone()],
        )]),
    );
    let signed = write_json(&s, "signed.json", &signed_by(eu_pack(), AUTHORITY_LABEL));
    expect_refused(&verify_pack_with(&record, &store, &signed, &["--authority-store", &beside]), "signed by the authority key");
    let unsigned = reference_pack("khalm-reading-eu-ai-act-2026");
    expect_refused(&verify_pack_with(&record, &store, &unsigned, &["--authority-store", &a_as_authority]), "unsigned");
    let bad_pack = s.write("bad-pack.json", "{ not a pack");
    expect_refused(&verify_pack_with(&record, &store, &bad_pack, &["--authority-store", &a_as_authority]), "not a pack");

    // An authority store that also lists issuers is refused for that first.
    let with_issuers = s.write(
        "issuers-and-a.json",
        serde_json::to_vec_pretty(&serde_json::json!({
            "trust_store_version": "0.1",
            "issuers": [{
                "issuer_id": "did:web:another-issuer.example",
                "issuer_name": "Another issuer",
                "keys": [key_object(KEY_FORGER, "2026-01-01T00:00:00Z", None, false)]
            }],
            "policy_authorities": [authority_entry(REFERENCE_AUTHORITY, REFERENCE_AUTHORITY_NAME, vec![key_a])]
        }))
        .unwrap(),
    );
    let run = verify_pack_with(&record, &store, &signed_a, &["--authority-store", &with_issuers]);
    run.expect_code(1);
    assert!(run.stderr.contains("cannot be used: authority_store.issuers: "), "{}", run.transcript());

    // Without --authority-store nothing changes: key A in the trust store's
    // own authorities is one store's duplicate key, the loader's refusal.
    let one_store = s.write(
        "one-store.json",
        basic_store_with(vec![authority_entry(
            REFERENCE_AUTHORITY,
            REFERENCE_AUTHORITY_NAME,
            vec![key_object(KEY_A, "2026-01-01T00:00:00Z", None, false)],
        )]),
    );
    let run = verify_pack_with(&record, &one_store, &signed_a, &[]);
    run.expect_code(1);
    assert!(run.stderr.contains("trust_store.duplicate_key"), "{}", run.transcript());
}

#[test]
fn the_authority_flags_need_a_policy_pack() {
    let s = Scratch::new("verify-pack-flags");
    let record = s.write("record.json", vector().to_json().unwrap());
    let store = s.write("ts-basic.json", vector_store("ts-basic"));
    let authorities = s.write("authorities.json", authority_store_of(vec![]));
    for extra in [&["--authority-store", authorities.as_str()][..], &["--require-signed-pack"][..]] {
        let mut args = vec!["record", "verify", "--record", &record, "--trust-store", &store, "--at", T];
        args.extend_from_slice(extra);
        let run = vmr(&args);
        run.expect_code(1);
        assert!(run.stdout.is_empty(), "{extra:?}:\n{}", run.transcript());
        assert!(run.stderr.contains("--policy-pack"), "{extra:?}: the missing flag is named:\n{}", run.transcript());
    }
}

#[test]
fn hostile_authority_text_never_reaches_the_terminal_raw() {
    let s = Scratch::new("verify-pack-hostile-authority");
    const HOSTILE: &str = "\u{1b}[2J\u{1b}[32m\u{2713} Pack valid\u{1b}[0m\u{202e}\u{200b}\u{9b}";
    let raw = |text: &str| text.contains('\u{1b}') || text.contains('\u{202e}') || text.contains('\u{200b}') || text.contains('\u{9b}');
    let record = s.write("record.json", vector().to_json().unwrap());
    // The operator's name for the authority, shown on a valid signature.
    let store = s.write(
        "store.json",
        basic_store_with(vec![authority_entry(
            REFERENCE_AUTHORITY,
            HOSTILE,
            vec![key_object(AUTHORITY_LABEL, "2026-01-01T00:00:00Z", None, false)],
        )]),
    );
    let pack = write_json(&s, "signed.json", &signed_by(eu_pack(), AUTHORITY_LABEL));
    let run = verify_pack_with(&record, &store, &pack, &[]);
    run.expect_code(0);
    assert!(!raw(&run.stdout), "{}", run.transcript());
    assert!(run.stdout.contains("\\u{001b}[2J"), "escaped, and still legible:\n{}", run.transcript());
    assert!(!raw(&verify_pack_with(&record, &store, &pack, &["--json"]).stdout));
    // The pack's own authority id, quoted in a refusal.
    let mut hostile = eu_pack();
    hostile["authority"]["authority_id"] = Value::from(HOSTILE);
    let hostile = write_json(&s, "hostile.json", &signed_by(hostile, AUTHORITY_LABEL));
    let run = verify_pack_with(&record, &store, &hostile, &[]);
    run.expect_code(1);
    assert!(run.stderr.contains("trusted for policy authority"), "{}", run.transcript());
    assert!(!raw(&run.stderr), "{}", run.transcript());
}
