// tests/pack_signature.rs — P6-7 and P6-8: a pack signature is checked with
// the format crate's primitives, over the DOCUMENT as received.
//
// The test keys are derived from fixed bytes, never generated, so this file
// is reproducible anywhere (the same discipline as the record vectors).

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_policy::vmr_record::encoding::b64url_encode;
use vmr_policy::vmr_record::hash::sha256;
use vmr_policy::vmr_record::{jwk, sign};
use vmr_policy::{load_pack, signing, Error};

fn key(label: &[u8]) -> p256::ecdsa::SigningKey {
    sign::signing_key_from_secret(&sha256(label)).expect("a derived test key")
}

fn authority_key() -> p256::ecdsa::SigningKey {
    key(b"vmr-policy test authority key")
}

fn other_key() -> p256::ecdsa::SigningKey {
    key(b"vmr-policy test key of someone else")
}

/// Sign `document` the way an authority's tooling would: over the JCS form
/// of the document with `/signature` removed.
fn sign_document(document: &Value, signing_key: &p256::ecdsa::SigningKey) -> Value {
    let payload = signing::signed_payload(document);
    let signature = sign::sign(signing_key, payload.as_bytes()).expect("ES256");
    let mut signed = document.clone();
    signed["signature"] = json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", b64url_encode(&signature.to_bytes())),
        "signed_payload_hash": signing::payload_hash(document),
        "signing_key_id": jwk::key_id(signing_key.verifying_key()),
    });
    signed
}

fn unsigned() -> Value {
    pack_document(json!([{
        "type": "attestation_level",
        "rule_id": "attest",
        "description": "The issuer attests.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, pack_signature.rs",
        "minimum_level": "software"
    }]))
}

#[test]
fn a_signed_pack_verifies_under_the_key_it_names() {
    let k = authority_key();
    let document = sign_document(&unsigned(), &k);
    let pack = load_pack(&document.to_string()).expect("a signed pack loads");
    pack.verify_signature(k.verifying_key()).expect("it verifies");
    assert_eq!(pack.payload_hash(), signing::payload_hash(&unsigned()));
}

#[test]
fn an_unsigned_pack_loads_and_evaluates_but_does_not_verify() {
    // v0.1 keeps `signature` optional; a caller that requires one asks.
    let pack = load_pack(&unsigned().to_string()).expect("an unsigned pack loads");
    assert!(pack.signature.is_none());
    assert_eq!(pack.evaluate(&conformance_record(), now()).results.len(), 1);
    let err = pack.verify_signature(authority_key().verifying_key()).expect_err("unsigned");
    assert!(matches!(err, Error::PackUnsigned), "{err}");
    assert_eq!((err.refusal(), err.refusal_id()), (None, "pack_signature.unsigned"));
}

#[test]
fn the_document_as_received_is_what_is_signed() {
    // P6-8: signing a re-serialisation of the Rust structs would let any
    // member this build does not model change the bytes an authority signed.
    // Written down differently, the same document has the same signed bytes.
    let document = sign_document(&unsigned(), &authority_key());
    let compact = document.to_string();
    let pretty = serde_json::to_string_pretty(&document).unwrap();
    assert_ne!(compact, pretty);
    for text in [compact, pretty] {
        let pack = load_pack(&text).expect("loads");
        pack.verify_signature(authority_key().verifying_key()).expect("verifies");
    }
}

#[test]
fn a_changed_pack_does_not_verify() {
    let k = authority_key();
    let mut document = sign_document(&unsigned(), &k);
    // The kind of edit a pack signature exists to catch: changing a rule
    // after the authority signed it. (Loosening it to "self" is no longer a
    // well-formed pack at all: P6-17.)
    document["rules"][0]["minimum_level"] = json!("hardware");
    let pack = load_pack(&document.to_string()).expect("still a well-formed pack");
    let err = pack.verify_signature(k.verifying_key()).expect_err("the bytes moved");
    // Step 4 of the format document's §4 needs no key, and has its own
    // refusal id (docs/dev/task-6.16.md A16-22); its message is unchanged.
    assert!(matches!(err, Error::PayloadHashMismatch { .. }), "{err}");
    assert_eq!(err.refusal_id(), "pack_signature.payload_hash");
    assert!(err.to_string().starts_with("policy pack signature invalid: signed_payload_hash \"sha256:"), "{err}");
    assert!(err.to_string().contains("is not the hash of the pack as received"), "{err}");
}

#[test]
fn the_payload_hash_is_checked_without_a_key() {
    // Format document §4 step 4, on its own (QA Q6-05): a pack whose section
    // states another payload hash was changed after it was signed, whoever
    // holds a key for it.
    load_pack(&unsigned().to_string()).unwrap().check_payload_hash().expect("an unsigned pack states no hash");
    let document = sign_document(&unsigned(), &other_key());
    load_pack(&document.to_string()).unwrap().check_payload_hash().expect("an intact signed pack");
    let mut edited = document.clone();
    edited["rules"][0]["minimum_level"] = json!("hardware");
    let err = load_pack(&edited.to_string()).unwrap().check_payload_hash().expect_err("changed after signing");
    match &err {
        Error::PayloadHashMismatch { stated, recomputed } => {
            assert_eq!(stated, document["signature"]["signed_payload_hash"].as_str().unwrap());
            assert_eq!(recomputed, &signing::payload_hash(&edited));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!((err.refusal(), err.refusal_id()), (None, "pack_signature.payload_hash"));
}

#[test]
fn a_signature_by_another_key_does_not_verify() {
    let document = sign_document(&unsigned(), &other_key());
    let pack = load_pack(&document.to_string()).expect("loads");
    // The pack names the other key, so checking it against this one is
    // refused before any curve arithmetic: a pack is verified against the
    // key it names.
    let err = pack.verify_signature(authority_key().verifying_key()).expect_err("wrong key");
    assert!(err.to_string().contains("signing_key_id"), "{err}");
    // And it does verify under the key it actually names.
    pack.verify_signature(other_key().verifying_key()).expect("verifies under its own key");
}

#[test]
fn a_signature_over_someone_elses_pack_does_not_verify() {
    // Same key, same key id, same algorithm: only the bytes differ. This is
    // the case a key-id check alone would let through.
    let k = authority_key();
    let mut other = unsigned();
    other["pack_id"] = json!("another-pack");
    let stolen = sign_document(&other, &k);
    let mut document = sign_document(&unsigned(), &k);
    document["signature"]["signature"] = stolen["signature"]["signature"].clone();
    let pack = load_pack(&document.to_string()).expect("loads");
    let err = pack.verify_signature(k.verifying_key()).expect_err("a signature over other bytes");
    assert!(matches!(err, Error::PackSignature(_)), "{err}");
    assert_eq!((err.refusal(), err.refusal_id()), (None, "pack_signature.invalid"));
}

#[test]
fn a_high_s_signature_does_not_verify() {
    // The format crate's low-s rule reaches packs too (P6-7): a signed pack
    // has exactly one valid encoding, so a second byte-different pack
    // cannot be made from it.
    let k = authority_key();
    let document = sign_document(&unsigned(), &k);
    let text = document["signature"]["signature"]
        .as_str()
        .unwrap()
        .strip_prefix("base64url:")
        .unwrap()
        .to_string();
    let low = sign::signature_from_b64url(&text).expect("the low-s signature");
    assert!(!sign::is_high_s(&low), "the signing path emits low-s");
    // (r, n - s): the non-canonical twin, which satisfies the ECDSA
    // equation and must still be refused.
    let twin_sig = p256::ecdsa::Signature::from_scalars(*low.r(), -*low.s()).expect("a valid pair");
    assert!(sign::is_high_s(&twin_sig), "the twin must be the high-s one");
    let twin = twin_sig.to_bytes();

    let mut forged = document.clone();
    forged["signature"]["signature"] = json!(format!("base64url:{}", b64url_encode(&twin)));
    let pack = load_pack(&forged.to_string()).expect("loads");
    let err = pack.verify_signature(k.verifying_key()).expect_err("high-s");
    assert!(err.to_string().contains("high-s"), "{err}");
}

#[test]
fn a_wrong_algorithm_is_refused_before_the_signature_is_read() {
    let document = sign_document(&unsigned(), &authority_key());
    let mut edited = document.clone();
    edited["signature"]["algorithm"] = json!("ES384");
    // The schema pins `algorithm` to ES256, so the loader refuses it first.
    let err = load_pack(&edited.to_string()).expect_err("ES384");
    assert!(matches!(err, Error::PackSchema(_)), "{err}");
    assert!(err.to_string().contains("/signature/algorithm"), "{err}");
}

#[test]
fn a_badly_encoded_signature_is_refused_by_the_schema() {
    let document = sign_document(&unsigned(), &authority_key());
    for bad in ["base64url:short", "no-prefix", ""] {
        let mut edited = document.clone();
        edited["signature"]["signature"] = json!(bad);
        let err = load_pack(&edited.to_string()).expect_err(bad);
        assert!(matches!(err, Error::PackSchema(_)), "{bad}: {err}");
    }
}
