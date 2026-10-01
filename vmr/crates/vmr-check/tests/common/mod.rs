// tests/common/mod.rs — shared support for vmr-check's tests: the published
// vectors, their inputs' bytes, and the derived test key A the record vector
// is signed with (worthless outside tests: derived from a fixed label).

#![allow(dead_code)]

use serde_json::Value;
use std::path::PathBuf;
use vmr_record::hash::sha256;
use vmr_record::record::{JwkPublicKey, Record, SignatureSection};

/// Key A: the record vector's key (spec §9).
pub const KEY_A: &str = "khalm v0.1 test-vector signing key";

/// The repository root.
pub fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A published vector file under specs/test-vectors/.
pub fn vector_file(rel: &str) -> Value {
    let path = repo().join("specs/test-vectors").join(rel);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

/// The `cases` of a published vector file.
pub fn cases(rel: &str) -> Vec<Value> {
    vector_file(rel)["cases"].as_array().unwrap().clone()
}

/// A verification vector's trust store by name (`ts-basic`).
pub fn vector_store(name: &str) -> Vec<u8> {
    std::fs::read(repo().join(format!("specs/test-vectors/verify/trust-stores/{name}.json"))).unwrap()
}

/// Lower-case hex to bytes.
pub fn hex_decode(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex length");
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// The bytes a vector input stands for: its `text` or `hex`, then
/// `append_spaces` spaces (specs/test-vectors/verify/README.md).
pub fn input_bytes(input: &Value) -> Vec<u8> {
    let mut bytes = match (input.get("text"), input.get("hex")) {
        (Some(t), None) => t.as_str().unwrap().as_bytes().to_vec(),
        (None, Some(h)) => hex_decode(h.as_str().unwrap()),
        other => panic!("an input has exactly one of text / hex: {other:?}"),
    };
    if let Some(n) = input.get("append_spaces") {
        bytes.resize(bytes.len() + n.as_u64().unwrap() as usize, b' ');
    }
    bytes
}

/// The verification case the other categories take their record from: the
/// committed record vector, JSON form, which verifies under ts-basic.
pub fn base_case() -> Value {
    cases("verify/cases.json").into_iter().find(|c| c["id"] == "pass-vector-json").unwrap()
}

/// A derived test key.
pub fn key(label: &str) -> p256::ecdsa::SigningKey {
    vmr_record::sign::signing_key_from_secret(&sha256(label.as_bytes())).unwrap()
}

/// Embed `label`'s key wherever the record names its key, then sign with it
/// (as vmr-cli's cross_impl replay of the policy vectors does).
pub fn reissue_with(p: &mut Record, label: &str) {
    let jwk = JwkPublicKey::from_verifying_key(key(label).verifying_key());
    p.issuer.key_id = jwk.key_id();
    p.signature.signing_key_id = jwk.key_id();
    p.issuer.public_key = jwk;
    let sig = vmr_record::sign::sign(&key(label), &p.signature_tbs().unwrap()).unwrap();
    p.signature.algorithm = "ES256".into();
    p.signature.signature = SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
}

/// The general description's record vector (four synthetic files).
pub fn general_vector() -> Record {
    let doc = vector_file("record/example-general-v0.1.json");
    serde_json::from_value(doc["record"].clone()).unwrap()
}

/// Unix seconds of a profile timestamp.
pub fn unix(t: &str) -> i64 {
    vmr_record::timestamp::Timestamp::parse(t).unwrap().unix_seconds()
}

/// The lower-case hex SHA-256 of `text`'s bytes.
pub fn sha256_hex(text: &str) -> String {
    vmr_record::hash::format_hash(&sha256(text.as_bytes())).trim_start_matches("sha256:").to_string()
}
