// tests/cli_pack_sign.rs — `vmr pack sign` and `vmr pack check`.
//
// The policy-pack format says any authority may publish and sign a pack, and
// the verifier checks a pack signature in full; until these commands the tool
// could check a signature it could not make, so the claim held of the format
// and not of the tooling. What these tests hold to:
//
//  (1) the signature this tool makes is THE signature the format defines.
//      ES256 with RFC 6979 is deterministic, so signing a committed vector's
//      pack with that vector's key must reproduce the vector's own signature
//      section byte for byte - a check against a file written by hand from
//      the specification, not against this code;
//  (2) what this tool signs, this tool and `record verify` accept: a pack
//      signed here is `valid` against an authority store that trusts the
//      signing key, and passes `--require-signed-pack`;
//  (3) "signed" never reads as "checked": without a store `pack check`
//      checks nothing and says so, and a key no trusted authority holds is
//      `not checked`, not valid;
//  (4) a pack changed after it was signed is refused by its payload hash,
//      with the format's own identifier;
//  (5) the file conventions every other command keeps: no output overwritten
//      without --force, no signature replaced without --replace, and a file
//      that is not a pack is an input error (exit 1).

mod common;
use common::*;
use serde_json::{json, Value};

// The vectors' key labels, from the generator that wrote
// specs/test-vectors/policy/pack-signature.json, so the label lives in one
// place: key P is the key the vectors' policy authority holds, key Q a key no
// authority holds.
#[path = "common/generate_pack_signature.rs"]
mod generate;

/// The committed pack-signature vectors.
fn vectors() -> Value {
    let text = std::fs::read_to_string(repo().join("specs/test-vectors/policy/pack-signature.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The vector case with this id.
fn vector_case(id: &str) -> Value {
    vectors()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no pack-signature vector {id}"))
        .clone()
}

/// A case's pack document.
fn case_pack(id: &str) -> Value {
    serde_json::from_str(vector_case(id)["pack"]["text"].as_str().unwrap()).unwrap()
}

/// `document` without its top-level `signature`.
fn unsigned(mut document: Value) -> Value {
    document.as_object_mut().unwrap().remove("signature");
    document
}

fn write_json(s: &Scratch, name: &str, document: &Value) -> String {
    s.write(name, format!("{}\n", serde_json::to_string_pretty(document).unwrap()))
}

/// The `signature` section of a pack file `vmr pack sign` wrote.
fn signature_of(path: &str) -> Value {
    let document: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    document["signature"].clone()
}

/// An authority store (trust-store format §4.2) trusting `labels`' keys for
/// `authority_id`, each from 2026-01-01 with no end.
fn authority_store(s: &Scratch, name: &str, authority_id: &str, labels: &[&str]) -> String {
    let keys: Vec<Value> = labels
        .iter()
        .map(|label| {
            let jwk = vmr_record::record::JwkPublicKey::from_verifying_key(key(label).verifying_key());
            json!({
                "key_id": jwk.key_id(),
                "public_key": jwk,
                "attestation_level": "software",
                "valid_from": "2026-01-01T00:00:00Z",
                "revoked": false,
            })
        })
        .collect();
    let document = json!({
        "trust_store_version": "0.1",
        "issuers": [],
        "policy_authorities": [{
            "authority_id": authority_id,
            "authority_name": "The authority, per this operator",
            "keys": keys,
        }],
    });
    write_json(s, name, &document)
}

/// The committed EU AI Act reference pack, as a path.
fn reference_pack() -> String {
    repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json").to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
//  (1) The signature is the format's, not this code's
// ---------------------------------------------------------------------------

#[test]
fn signing_a_vector_pack_reproduces_the_vectors_signature_byte_for_byte() {
    // The strongest check available: specs/test-vectors/policy/pack-signature.json
    // was written by hand from specs/policy-pack-format-v0.1.md §4, and ES256
    // with RFC 6979 is deterministic. Signing the `valid` case's pack with
    // that case's key P must therefore give that case's signature section,
    // member for member - algorithm, signature, payload hash and key id.
    // Nothing here is compared against this command's own earlier output.
    let s = Scratch::new("pack-sign-vector");
    let case = case_pack("valid");
    let expected = case["signature"].clone();
    let pack = write_json(&s, "pack.json", &unsigned(case));
    let key_file = write_test_key(&s, "p.key", generate::KEY_P);
    let out = s.arg("signed.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out]).expect_code(0);
    assert_eq!(signature_of(&out), expected, "the vector's signature section, byte for byte");
}

#[test]
fn re_signing_the_vectors_signed_pack_gives_the_same_signature_it_already_carries() {
    // A signature section is never part of what is signed (§4), so replacing
    // one covers exactly the same payload: --replace over the vector's own
    // signed pack reproduces that same section, and the payload hash is
    // unchanged. The output also says the section was replaced, not added.
    let s = Scratch::new("pack-sign-replace");
    let case = case_pack("valid");
    let expected = case["signature"].clone();
    let pack = write_json(&s, "pack.json", &case);
    let key_file = write_test_key(&s, "p.key", generate::KEY_P);
    let out = s.arg("again.json");
    let run = vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out, "--replace"]);
    run.expect_code(0);
    assert_eq!(signature_of(&out), expected, "{}", run.transcript());
    assert!(run.stdout.contains("signature section replaced"), "{}", run.transcript());
}

#[test]
fn signing_changes_nothing_but_the_signature_and_never_the_payload_hash() {
    // The pack an author publishes is the pack they wrote: every other member
    // keeps its value, and the payload hash the section states is the hash the
    // unsigned pack already had (§4: a signed pack and the same pack without
    // its signature share a payload hash).
    let s = Scratch::new("pack-sign-untouched");
    let before: Value = serde_json::from_str(&std::fs::read_to_string(reference_pack()).unwrap()).unwrap();
    let key_file = write_test_key(&s, "a.key", "vmr-cli pack sign: an authority key (test-only)");
    let out = s.arg("signed.json");
    let run = vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &key_file, "--output", &out]);
    run.expect_code(0);
    let text = std::fs::read_to_string(&out).unwrap();
    let after: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(unsigned(after.clone()), before, "only the signature section was added");
    // The layout, however, is the tool's: the file comes back with its members
    // sorted, which docs/CLI.md §3.8 states. Signing a pack already in that
    // order therefore changes nothing but the added section - which is what
    // pinning this test protects.
    let sorted = format!("{}\n", serde_json::to_string_pretty(&before).unwrap());
    let resorted = s.write("sorted.json", sorted.as_bytes());
    let out2 = s.arg("signed-sorted.json");
    vmr(&["pack", "sign", "--pack", &resorted, "--key", &key_file, "--output", &out2]).expect_code(0);
    assert_eq!(std::fs::read_to_string(&out2).unwrap(), text, "the same bytes from the sorted pack");
    let hash = vmr_policy::payload_hash(&before);
    assert_eq!(after["signature"]["signed_payload_hash"], json!(hash));
    assert_eq!(after["signature"]["algorithm"], json!("ES256"));
    assert!(run.stdout.contains(&format!("Payload hash: {hash}")), "{}", run.transcript());
    // The pack check of the unsigned pack states the same hash: signing did
    // not move it.
    let unsigned_check = vmr(&["pack", "check", "--pack", &reference_pack(), "--json"]);
    unsigned_check.expect_code(0);
    let report: Value = serde_json::from_str(&unsigned_check.stdout).unwrap();
    assert_eq!(report["payload_hash"], json!(hash));
}

// ---------------------------------------------------------------------------
//  (2) What this tool signs, this tool and `record verify` accept
// ---------------------------------------------------------------------------

#[test]
fn a_pack_signed_here_checks_as_valid_against_an_authority_that_holds_the_key() {
    let s = Scratch::new("pack-check-valid");
    const LABEL: &str = "vmr-cli pack sign: the authority's own key (test-only)";
    let key_file = write_test_key(&s, "authority.key", LABEL);
    let out = s.arg("signed.json");
    vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &key_file, "--output", &out]).expect_code(0);
    // The pack names khalm-reference-packs as its authority; an operator who
    // trusts this key for that authority gets `valid`.
    let store = authority_store(&s, "authorities.json", "khalm-reference-packs", &[LABEL]);
    let run = vmr(&["pack", "check", "--pack", &out, "--authority-store", &store, "--at", T]);
    run.expect_code(0);
    assert!(run.stdout.contains("  Signature:    valid — signed by "), "{}", run.transcript());
    assert!(run.stdout.contains("khalm-reference-packs"), "{}", run.transcript());
    assert!(run.stdout.contains(&format!("at {T} (--at)")), "{}", run.transcript());

    let json_run = vmr(&["pack", "check", "--pack", &out, "--authority-store", &store, "--at", T, "--json"]);
    json_run.expect_code(0);
    let report: Value = serde_json::from_str(&json_run.stdout).unwrap();
    assert_eq!(report["signature"]["state"], json!("valid"));
    assert_eq!(report["pack_id"], json!("khalm-reading-eu-ai-act-2026"));
    assert_eq!(report["authority"]["authority_id"], json!("khalm-reference-packs"));
    assert_eq!(report["checked"]["at"], json!(T));
    assert_eq!(report["rules"].as_array().unwrap().len(), 6);
    assert_eq!(report["rules"][0]["severity"], json!("mandatory"));
}

#[test]
fn a_pack_signed_here_passes_record_verify_with_require_signed_pack() {
    // The claim this work exists to make true: a pack an authority signs with
    // this tool is one the reference verifier accepts as signed, with no hand
    // work in between. Without the signature the same run is refused.
    let s = Scratch::new("pack-sign-verify");
    const LABEL: &str = "vmr-cli pack sign: a verifier-facing authority key (test-only)";
    let key_file = write_test_key(&s, "authority.key", LABEL);
    let signed = s.arg("signed-pack.json");
    vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &key_file, "--output", &signed]).expect_code(0);
    let store = authority_store(&s, "authorities.json", "khalm-reference-packs", &[LABEL]);
    let record = s.write("record.json", vector().to_json().unwrap());
    let trust_store = s.write("trust-store.json", vector_store("ts-basic"));
    let args = |pack: &str| {
        vec![
            "record".to_string(), "verify".to_string(), "--record".to_string(), record.clone(),
            "--trust-store".to_string(), trust_store.clone(), "--at".to_string(), T.to_string(),
            "--policy-pack".to_string(), pack.to_string(), "--authority-store".to_string(), store.clone(),
            "--require-signed-pack".to_string(),
        ]
    };
    let run = vmr(&strs(&args(&signed)));
    run.expect_code(0);
    assert!(run.stdout.contains("valid"), "{}", run.transcript());

    let refused = vmr(&strs(&args(&reference_pack())));
    refused.expect_code(1);
    assert!(refused.stderr.contains("pack_signature.unsigned_refused"), "{}", refused.transcript());
}

// ---------------------------------------------------------------------------
//  (3) "Signed" never reads as "checked"
// ---------------------------------------------------------------------------

#[test]
fn an_unsigned_pack_is_reported_unsigned() {
    let run = vmr(&["pack", "check", "--pack", &reference_pack()]);
    run.expect_code(0);
    assert!(
        run.stdout.contains("  Signature:    unsigned — this pack carries no authority signature"),
        "{}",
        run.transcript()
    );
    let json_run = vmr(&["pack", "check", "--pack", &reference_pack(), "--json"]);
    json_run.expect_code(0);
    let report: Value = serde_json::from_str(&json_run.stdout).unwrap();
    assert_eq!(report["signature"], json!({"state": "unsigned"}));
    assert_eq!(report["checked"], Value::Null, "nothing checked it");
}

#[test]
fn without_an_authority_store_a_signature_is_named_and_not_checked() {
    let s = Scratch::new("pack-check-unchecked");
    let case = case_pack("valid");
    let pack = write_json(&s, "pack.json", &case);
    let named = case["signature"]["signing_key_id"].as_str().unwrap().to_string();
    let run = vmr(&["pack", "check", "--pack", &pack]);
    run.expect_code(0);
    assert!(run.stdout.contains(&format!("  Signature:    not checked — it names {named} as its signer")), "{}", run.transcript());
    assert!(run.stdout.contains("pass --authority-store"), "{}", run.transcript());
    assert!(!run.stdout.contains("valid"), "nothing was checked:\n{}", run.transcript());
}

#[test]
fn a_key_no_trusted_authority_holds_is_reported_not_checked_and_never_valid() {
    // The vectors' key Q is a key no case's authority holds. A pack signed
    // with it, checked against a store holding only key P, is `not checked`.
    let s = Scratch::new("pack-check-other-key");
    let pack = write_json(&s, "pack.json", &unsigned(case_pack("valid")));
    let key_file = write_test_key(&s, "q.key", generate::KEY_Q);
    let out = s.arg("signed.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out]).expect_code(0);
    let store = authority_store(&s, "authorities.json", generate::AUTHORITY_ID, &[generate::KEY_P]);
    let run = vmr(&["pack", "check", "--pack", &out, "--authority-store", &store, "--at", T]);
    run.expect_code(0);
    assert!(run.stdout.contains("  Signature:    not checked — it names "), "{}", run.transcript());
    assert!(
        run.stdout.contains("no policy authority in the authority store holds that key"),
        "{}",
        run.transcript()
    );
    assert!(!run.stdout.contains("Signature:    valid"), "{}", run.transcript());
}

#[test]
fn a_key_trusted_for_another_authority_is_refused_and_says_so() {
    // The key is held, the signature verifies, and it still may not speak for
    // the authority this pack names: `pack_signature.other_authority`, the
    // step `record verify` refuses at too.
    let s = Scratch::new("pack-check-other-authority");
    let pack = write_json(&s, "pack.json", &unsigned(case_pack("valid")));
    let key_file = write_test_key(&s, "p.key", generate::KEY_P);
    let out = s.arg("signed.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out]).expect_code(0);
    let store = authority_store(&s, "authorities.json", "some-other-authority.example", &[generate::KEY_P]);
    let run = vmr(&["pack", "check", "--pack", &out, "--authority-store", &store, "--at", T]);
    run.expect_code(1);
    assert!(run.stderr.contains("pack_signature.other_authority"), "{}", run.transcript());
}

// ---------------------------------------------------------------------------
//  (4) A pack changed after it was signed
// ---------------------------------------------------------------------------

#[test]
fn a_pack_changed_after_it_was_signed_fails_its_payload_hash() {
    // Step 4 of §4 needs no key: `pack check` refuses a tampered pack with or
    // without a store, naming `pack_signature.payload_hash`.
    let s = Scratch::new("pack-check-tampered");
    let mut document = case_pack("valid");
    document["description"] = json!("The pack of a KHALM pack-signature vector, changed after it was signed.");
    let pack = write_json(&s, "pack.json", &document);
    let store = authority_store(&s, "authorities.json", generate::AUTHORITY_ID, &[generate::KEY_P]);
    for (what, args) in [
        ("with no store", vec!["pack", "check", "--pack", &pack]),
        ("with the authority store", vec!["pack", "check", "--pack", &pack, "--authority-store", &store, "--at", T]),
    ] {
        let run = vmr(&args);
        run.expect_code(1);
        assert!(run.stderr.contains("pack_signature.payload_hash"), "{what}:\n{}", run.transcript());
        assert!(run.stderr.contains("the pack was changed after it was signed"), "{what}:\n{}", run.transcript());
    }
}

#[test]
fn a_changed_pack_can_be_signed_again_with_replace_and_then_checks_out() {
    // The other side of the same coin: an author who edits a pack they signed
    // re-signs it. `pack sign --replace` reads such a pack (its old section no
    // longer matches), and what it writes checks out.
    let s = Scratch::new("pack-resign-changed");
    let mut document = case_pack("valid");
    document["description"] = json!("The pack of a KHALM pack-signature vector, changed after it was signed.");
    let pack = write_json(&s, "pack.json", &document);
    let key_file = write_test_key(&s, "p.key", generate::KEY_P);
    let out = s.arg("resigned.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out, "--replace"]).expect_code(0);
    let store = authority_store(&s, "authorities.json", generate::AUTHORITY_ID, &[generate::KEY_P]);
    let run = vmr(&["pack", "check", "--pack", &out, "--authority-store", &store, "--at", T]);
    run.expect_code(0);
    assert!(run.stdout.contains("  Signature:    valid — signed by "), "{}", run.transcript());
}

// ---------------------------------------------------------------------------
//  (5) The file conventions every other command keeps
// ---------------------------------------------------------------------------

#[test]
fn an_existing_output_is_not_overwritten_without_force() {
    let s = Scratch::new("pack-sign-force");
    let key_file = write_test_key(&s, "a.key", "vmr-cli pack sign: a --force key (test-only)");
    let out = s.write("signed.json", b"keep me\n");
    let run = vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &key_file, "--output", &out]);
    run.expect_code(1);
    assert_eq!(std::fs::read(&out).unwrap(), b"keep me\n", "the file was not touched");
    let forced = vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &key_file, "--output", &out, "--force"]);
    forced.expect_code(0);
    assert_ne!(std::fs::read(&out).unwrap(), b"keep me\n");
}

#[test]
fn a_pack_that_is_already_signed_is_refused_without_replace() {
    let s = Scratch::new("pack-sign-already");
    let pack = write_json(&s, "pack.json", &case_pack("valid"));
    let key_file = write_test_key(&s, "p.key", generate::KEY_P);
    let out = s.arg("signed.json");
    let run = vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out]);
    run.expect_code(1);
    assert!(run.stderr.contains("pack_sign.already_signed"), "{}", run.transcript());
    assert!(run.stderr.contains("--replace"), "{}", run.transcript());
    assert!(!std::path::Path::new(&out).exists(), "nothing was written");
}

#[test]
fn a_file_that_is_not_a_pack_is_an_input_error_for_both_commands() {
    // The published schema is JSON and is not a pack; a record is not one
    // either. Both are the author's error, exit 1, with the loader's own
    // refusal identifier.
    let s = Scratch::new("pack-not-a-pack");
    let schema = repo().join("specs/policy-pack-schema/v0.1.json").to_string_lossy().into_owned();
    let record = s.write("record.json", vector().to_json().unwrap());
    let key_file = write_test_key(&s, "a.key", "vmr-cli pack sign: a refusal key (test-only)");
    let out = s.arg("signed.json");
    for path in [&schema, &record] {
        let signed = vmr(&["pack", "sign", "--pack", path, "--key", &key_file, "--output", &out]);
        signed.expect_code(1);
        assert!(signed.stderr.contains("cannot be used: policy_pack."), "{}", signed.transcript());
        assert!(!std::path::Path::new(&out).exists(), "nothing was written");
        let checked = vmr(&["pack", "check", "--pack", path]);
        checked.expect_code(1);
        assert!(checked.stderr.contains("cannot be used: policy_pack."), "{}", checked.transcript());
    }
    let missing = vmr(&["pack", "check", "--pack", &s.arg("no-such-pack.json")]);
    missing.expect_code(1);
    assert!(missing.stderr.contains("cannot read policy pack"), "{}", missing.transcript());
}

#[test]
fn a_key_file_that_is_not_a_private_key_is_refused_before_anything_is_written() {
    let s = Scratch::new("pack-sign-bad-key");
    let public = s.write("public.json", b"{\"key_id\": \"x\"}\n");
    let out = s.arg("signed.json");
    let run = vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &public, "--output", &out]);
    run.expect_code(1);
    assert!(run.stderr.contains("not a PKCS#8 PEM private key"), "{}", run.transcript());
    assert!(!std::path::Path::new(&out).exists(), "nothing was written");
}

#[test]
fn both_commands_document_themselves_and_claim_no_authority_of_their_own() {
    let sign = vmr(&["pack", "sign", "--help"]);
    sign.expect_code(0);
    for text in ["--pack", "--key", "--output", "--replace", "--force", "Any authority", "RFC 6979", "Exit codes"] {
        assert!(sign.stdout.contains(text), "{text} missing:\n{}", sign.transcript());
    }
    let check = vmr(&["pack", "check", "--help"]);
    check.expect_code(0);
    for text in
        ["--pack", "--authority-store", "--trust-store", "--require-signed", "--at", "--json", "is a claim", "Exit codes"]
    {
        assert!(check.stdout.contains(text), "{text} missing:\n{}", check.transcript());
    }
    // --at only means something against a store, so clap requires one.
    let alone = vmr(&["pack", "check", "--pack", &reference_pack(), "--at", T]);
    alone.expect_code(1);
}

#[test]
fn every_refusal_is_terminal_safe() {
    let s = Scratch::new("pack-terminal-safe");
    let pack = write_json(&s, "pack.json", &case_pack("valid"));
    let key_file = write_test_key(&s, "p.key", generate::KEY_P);
    let out = s.arg("signed.json");
    assert_terminal_safe(&vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out]), "already signed");
    assert_terminal_safe(&vmr(&["pack", "check", "--pack", &key_file]), "a PEM is not a pack");
}

// ---------------------------------------------------------------------------
//  (6) A check a script can gate on, against the store the operator keeps
// ---------------------------------------------------------------------------

#[test]
fn require_signed_refuses_an_unsigned_pack() {
    // Without it `pack check` exits 0 for a pack nobody vouched for, so
    // `vmr pack check ... && deploy` would deploy on it (M1).
    let s = Scratch::new("pack-require-unsigned");
    let store = authority_store(&s, "authorities.json", generate::AUTHORITY_ID, &[generate::KEY_P]);
    let args = ["pack", "check", "--pack", &reference_pack(), "--authority-store", &store, "--at", T];
    vmr(&args).expect_code(0);
    let refused = vmr(&[&args[..], &["--require-signed"][..]].concat());
    refused.expect_code(1);
    assert!(refused.stderr.contains("pack_signature.unsigned_refused"), "{}", refused.transcript());
    assert!(refused.stderr.contains("--require-signed"), "{}", refused.transcript());
    assert!(!refused.stderr.contains("--require-signed-pack"), "the flag of `record verify`:\n{}", refused.transcript());
}

#[test]
fn require_signed_refuses_a_pack_signed_by_a_key_no_trusted_authority_holds() {
    // The other state that vouches for nothing: a signature this operator's
    // store cannot check at all. Key Q signs; the store holds only key P.
    let s = Scratch::new("pack-require-not-checked");
    let pack = write_json(&s, "pack.json", &unsigned(case_pack("valid")));
    let key_file = write_test_key(&s, "q.key", generate::KEY_Q);
    let out = s.arg("signed.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out]).expect_code(0);
    let store = authority_store(&s, "authorities.json", generate::AUTHORITY_ID, &[generate::KEY_P]);
    let args = ["pack", "check", "--pack", &out, "--authority-store", &store, "--at", T];
    vmr(&args).expect_code(0);
    let refused = vmr(&[&args[..], &["--require-signed"][..]].concat());
    refused.expect_code(1);
    assert!(refused.stderr.contains("pack_signature.not_checked_refused"), "{}", refused.transcript());
    assert!(refused.stderr.contains("--require-signed"), "{}", refused.transcript());
    // The same pack, signed by the key the store does hold, passes the gate.
    let p_key = write_test_key(&s, "p.key", generate::KEY_P);
    let by_p = s.arg("signed-by-p.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &p_key, "--output", &by_p]).expect_code(0);
    let run = vmr(&["pack", "check", "--pack", &by_p, "--authority-store", &store, "--at", T, "--require-signed"]);
    run.expect_code(0);
    assert!(run.stdout.contains("Signature:    valid — signed by "), "{}", run.transcript());
}

#[test]
fn a_pack_is_checked_against_the_operators_own_trust_store_too() {
    // M2: an operator whose policy authorities live in the trust store they
    // verify records with could not use this command at all - the only store
    // option refused any file carrying issuers. `record verify` reads both;
    // so does `pack check` now, and the two options are mutually exclusive.
    let s = Scratch::new("pack-check-trust-store");
    const LABEL: &str = "vmr-cli pack check: an authority in the trust store (test-only)";
    let key_file = write_test_key(&s, "authority.key", LABEL);
    let signed = s.arg("signed.json");
    vmr(&["pack", "sign", "--pack", &reference_pack(), "--key", &key_file, "--output", &signed]).expect_code(0);
    // A trust store with issuers in it, and this authority added to it by the
    // command that provisions one: no hand-written JSON.
    let store = s.write("trust-store.json", vector_store("ts-basic"));
    let public = s.arg("authority.pub.json");
    vmr(&["key", "export", "--key", &key_file, "--output", &public]).expect_code(0);
    vmr(&[
        "trust-store", "add-authority", "--trust-store", &store, "--public-key", &public, "--authority-id",
        "khalm-reference-packs", "--authority-name", "KHALM reference packs, per this operator",
        "--valid-from", "2026-01-01T00:00:00Z",
    ])
    .expect_code(0);
    let run = vmr(&["pack", "check", "--pack", &signed, "--trust-store", &store, "--at", T]);
    run.expect_code(0);
    assert!(run.stdout.contains("Signature:    valid — signed by "), "{}", run.transcript());
    assert!(run.stdout.contains("which the trust store trusts for"), "{}", run.transcript());
    // The same file as --authority-store is still refused: it carries issuers.
    let as_authority = vmr(&["pack", "check", "--pack", &signed, "--authority-store", &store, "--at", T]);
    as_authority.expect_code(1);
    assert!(as_authority.stderr.contains("authority_store.issuers"), "{}", as_authority.transcript());
    // One store at a time.
    let both = vmr(&[
        "pack", "check", "--pack", &signed, "--trust-store", &store, "--authority-store", &store, "--at", T,
    ]);
    both.expect_code(1);
    assert!(both.stderr.contains("cannot be used with"), "{}", both.transcript());
}

#[test]
fn pack_check_shows_the_packs_own_disclaimer() {
    // M4: the one command whose job is reading a pack must not print an
    // authority's claims while dropping the authority's own limitation of
    // them. The reference packs' disclaimer is the line saying the pack is
    // not legal advice and not an official instrument.
    let pack: Value = serde_json::from_str(&std::fs::read_to_string(reference_pack()).unwrap()).unwrap();
    let disclaimer = pack["disclaimer"].as_str().expect("the format requires one");
    let run = vmr(&["pack", "check", "--pack", &reference_pack()]);
    run.expect_code(0);
    assert!(run.stdout.contains("  Disclaimer:   "), "{}", run.transcript());
    // Long values are shortened in the plain text, as the description is; the
    // sentence that limits the pack is what must be there.
    assert!(run.stdout.contains(&disclaimer[..120]), "{}", run.transcript());
    assert!(run.stdout.contains("not legal advice"), "{}", run.transcript());
    let json_run = vmr(&["pack", "check", "--pack", &reference_pack(), "--json"]);
    json_run.expect_code(0);
    let report: Value = serde_json::from_str(&json_run.stdout).unwrap();
    assert_eq!(report["disclaimer"], json!(disclaimer), "--json carries it whole");
}

#[test]
fn pack_sign_states_the_authority_as_a_claim_and_names_the_signature_it_replaced() {
    // L1: an authority's name under a SIGNED heading is the PACK's claim -
    // signing someone else's pack establishes nothing about its author.
    // L2: --replace drops another party's signature, and says whose.
    let s = Scratch::new("pack-sign-claim-and-replaced");
    let case = case_pack("valid");
    let replaced_key = case["signature"]["signing_key_id"].as_str().unwrap().to_string();
    let pack = write_json(&s, "pack.json", &case);
    let key_file = write_test_key(&s, "q.key", generate::KEY_Q);
    let out = s.arg("signed.json");
    let run = vmr(&["pack", "sign", "--pack", &pack, "--key", &key_file, "--output", &out, "--replace"]);
    run.expect_code(0);
    assert!(run.stdout.contains(" — the pack's own claim"), "{}", run.transcript());
    assert!(run.stdout.contains(&format!("  Replaced:     the signature of {replaced_key}")), "{}", run.transcript());
    // Nothing was replaced when nothing was there: no such line.
    let plain = write_json(&s, "unsigned.json", &unsigned(case_pack("valid")));
    let out2 = s.arg("signed2.json");
    let added = vmr(&["pack", "sign", "--pack", &plain, "--key", &key_file, "--output", &out2]);
    added.expect_code(0);
    assert!(added.stdout.contains(" — the pack's own claim"), "{}", added.transcript());
    assert!(!added.stdout.contains("Replaced:"), "{}", added.transcript());
}

#[test]
fn pack_check_json_says_checked_only_when_a_store_checked_the_signature() {
    // I1: a consumer that reads `checked != null` as "the signature was
    // checked" must be right. A store that was read and holds no key for the
    // pack's signer decided nothing, and is named by `consulted` instead.
    let s = Scratch::new("pack-check-json-checked");
    let pack = write_json(&s, "pack.json", &unsigned(case_pack("valid")));
    let q_key = write_test_key(&s, "q.key", generate::KEY_Q);
    let by_q = s.arg("by-q.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &q_key, "--output", &by_q]).expect_code(0);
    let p_key = write_test_key(&s, "p.key", generate::KEY_P);
    let by_p = s.arg("by-p.json");
    vmr(&["pack", "sign", "--pack", &pack, "--key", &p_key, "--output", &by_p]).expect_code(0);
    let store = authority_store(&s, "authorities.json", generate::AUTHORITY_ID, &[generate::KEY_P]);
    let report = |args: &[&str]| -> Value {
        let run = vmr(args);
        run.expect_code(0);
        serde_json::from_str(&run.stdout).unwrap()
    };

    // No store: nothing was read, and nothing was checked.
    let none = report(&["pack", "check", "--pack", &by_p, "--json"]);
    assert_eq!((&none["checked"], &none["consulted"]), (&Value::Null, &Value::Null));
    // A store that holds no key for this signer: read, decided nothing.
    let not_checked = report(&["pack", "check", "--pack", &by_q, "--authority-store", &store, "--at", T, "--json"]);
    assert_eq!(not_checked["signature"]["state"], json!("not_checked"));
    assert_eq!(not_checked["checked"], Value::Null, "nothing checked it");
    assert_eq!(not_checked["consulted"]["at"], json!(T));
    assert!(not_checked["consulted"]["authority_store"].is_object(), "the store is still named");
    // An unsigned pack with a store: the same, nothing was checked.
    let unsigned_report =
        report(&["pack", "check", "--pack", &pack, "--authority-store", &store, "--at", T, "--json"]);
    assert_eq!(unsigned_report["signature"], json!({"state": "unsigned"}));
    assert_eq!(unsigned_report["checked"], Value::Null);
    assert_eq!(unsigned_report["consulted"]["at"], json!(T));
    // A signature the store decided: `checked`, and nothing in `consulted`.
    let checked = report(&["pack", "check", "--pack", &by_p, "--authority-store", &store, "--at", T, "--json"]);
    assert_eq!(checked["signature"]["state"], json!("valid"));
    assert_eq!(checked["checked"]["at"], json!(T));
    assert_eq!(checked["checked"]["time_source"], json!("--at"));
    assert_eq!(checked["consulted"], Value::Null);
}
