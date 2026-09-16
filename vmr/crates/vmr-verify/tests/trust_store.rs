// tests/trust_store.rs — the trust-store loader (Phase 4 task 4.2; TASKS
// "test_trust_store"): specs/trust-store-format-v0.1.md, one test per rule.
// Policy authorities, the nesting bound and the authority-key decision are
// docs/TASKS.md 6.16 (docs/dev/task-6.16.md A16-1 to A16-11).

use serde_json::{json, Value};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::JwkPublicKey;
use vmr_record::sign::signing_key_from_secret;
use vmr_record::timestamp::Timestamp;
use vmr_verify::trust_store::{
    AttestationLevel, AuthorityKeyRefusal, TrustStore, TrustStoreErrorKind as Kind, MAX_NESTING_DEPTH,
    SCHEMA_RULES,
};

/// The public JWK of the test key derived from `label`.
fn jwk(label: &str) -> JwkPublicKey {
    let k = signing_key_from_secret(&sha256(label.as_bytes())).unwrap();
    JwkPublicKey::from_verifying_key(k.verifying_key())
}

/// The record vector's key (spec: test-only).
const VECTOR_KEY: &str = "khalm v0.1 test-vector signing key";

fn key_entry(label: &str) -> Value {
    let j = jwk(label);
    json!({
        "key_id": j.key_id(),
        "public_key": j,
        "attestation_level": "software",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "revoked": false
    })
}

/// A valid store: the vector issuer with the vector key.
fn base() -> Value {
    json!({
        "trust_store_version": "0.1",
        "issuers": [{
            "issuer_id": "did:web:factory-operator.ph",
            "issuer_name": "New Clark City Fab Operator",
            "keys": [key_entry(VECTOR_KEY)]
        }]
    })
}

fn load(doc: &Value) -> Result<TrustStore, vmr_verify::trust_store::TrustStoreError> {
    TrustStore::from_json(serde_json::to_string_pretty(doc).unwrap().as_bytes())
}

fn kind_of(doc: &Value) -> Kind {
    load(doc).map(|_| ()).expect_err("store must be rejected").kind
}

fn kind_of_text(text: &str) -> Kind {
    TrustStore::from_json(text.as_bytes()).map(|_| ()).expect_err("store must be rejected").kind
}

#[test]
fn an_object_written_as_the_array_of_its_values_is_trust_store_structure() {
    // QA QT-01 (spec §3 kind 4: the members of §2 "with their JSON types at
    // every level"). serde's derive reads a struct from the array of its
    // values in declaration order, so each text below read as the store. The
    // loader reads strictly and refuses every one, whichever object it is:
    // the store itself, an issuer, a policy authority, a key of either, a JWK.
    let mut doc = base();
    doc["policy_authorities"] = json!([authority("khalm-vmr-trust-store-tests", &[AUTHORITY_KEY])]);
    let document: vmr_verify::trust_store::TrustStoreDocument = serde_json::from_value(doc.clone()).unwrap();
    load(&doc).expect("the unbroken store loads");
    const KEY: &[&str] = &["key_id", "public_key", "attestation_level", "valid_from", "valid_until", "revoked"];
    const JWK: &[&str] = &["kty", "crv", "x", "y"];
    let objects: [(&str, &[&str]); 7] = [
        ("", &["trust_store_version", "issuers", "policy_authorities"]),
        ("/issuers/0", &["issuer_id", "issuer_name", "keys"]),
        ("/issuers/0/keys/0", KEY),
        ("/issuers/0/keys/0/public_key", JWK),
        ("/policy_authorities/0", &["authority_id", "authority_name", "keys"]),
        ("/policy_authorities/0/keys/0", KEY),
        ("/policy_authorities/0/keys/0/public_key", JWK),
    ];
    for (pointer, fields) in objects {
        let mut respelled = doc.clone();
        let object = respelled.pointer_mut(pointer).unwrap();
        assert_eq!(object.as_object().unwrap().len(), fields.len(), "{pointer}: every member, in declaration order");
        let values: Vec<Value> = fields.iter().map(|f| object[*f].clone()).collect();
        *object = Value::Array(values);
        let text = serde_json::to_string_pretty(&respelled).unwrap();
        let lenient: vmr_verify::trust_store::TrustStoreDocument = serde_json::from_str(&text).unwrap();
        assert_eq!(lenient, document, "{pointer}: serde_json reads the respelling as the store");
        let err = TrustStore::from_json(text.as_bytes()).map(|_| ()).expect_err(pointer);
        assert_eq!(err.kind, Kind::Structure, "{pointer}: {err}");
        assert!(err.to_string().contains("invalid type: sequence, expected "), "{pointer}: {err}");
    }
}

/// Two policy authorities' test keys (derived, test-only).
const AUTHORITY_KEY: &str = "khalm-vmr v0.1 trust-store test policy authority key P";
const AUTHORITY_KEY_2: &str = "khalm-vmr v0.1 trust-store test policy authority key Q";

/// A policy authority entry holding the keys `labels` derive (P6-14: the
/// names a pack's `authority` member uses, and an issuer's key objects).
fn authority(id: &str, labels: &[&str]) -> Value {
    json!({
        "authority_id": id,
        "authority_name": format!("{id} (the operator's name)"),
        "keys": labels.iter().map(|l| key_entry(l)).collect::<Vec<_>>()
    })
}

/// [`base`] with one policy authority, `example-authority`, holding
/// [`AUTHORITY_KEY`].
fn with_authority() -> Value {
    let mut doc = base();
    doc["policy_authorities"] = json!([authority("example-authority", &[AUTHORITY_KEY])]);
    doc
}

#[test]
fn the_vector_store_loads_and_finds_the_vector_key() {
    let store = load(&base()).unwrap();
    assert_eq!((store.issuer_count(), store.key_count()), (1, 1));
    let kid = jwk(VECTOR_KEY).key_id();
    let k = store.lookup(&kid).expect("the vector key is trusted");
    assert_eq!(k.issuer_id, "did:web:factory-operator.ph");
    assert_eq!(k.issuer_name, "New Clark City Fab Operator");
    assert_eq!(k.key_id, kid);
    assert_eq!(k.public_key, &jwk(VECTOR_KEY));
    assert_eq!(JwkPublicKey::from_verifying_key(k.verifying_key), jwk(VECTOR_KEY));
    assert_eq!(k.attestation_level, AttestationLevel::Software);
    assert_eq!(k.valid_from.to_string(), "2026-01-01T00:00:00Z");
    assert_eq!(k.valid_until.map(|t| t.to_string()).as_deref(), Some("2027-01-01T00:00:00Z"));
    assert!(!k.revoked);
    assert!(store.sha256().starts_with("sha256:") && store.sha256().len() == 71);
}

#[test]
fn the_spec_examples_load() {
    // Both examples in specs/trust-store-format-v0.1.md §2 are valid stores:
    // the issuer store, and the store of one policy authority (6.16), whose
    // key is the policy vectors' pack authority key.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/trust-store-format-v0.1.md");
    let md = std::fs::read_to_string(path).unwrap();
    let blocks: Vec<&str> = md.split("```json\n").skip(1).map(|rest| &rest[..rest.find("```").unwrap()]).collect();
    assert_eq!(blocks.len(), 2, "two JSON examples");
    let issuers = TrustStore::from_json(blocks[0].as_bytes()).unwrap();
    assert!(issuers.lookup(&jwk(VECTOR_KEY).key_id()).is_some());
    let authorities = TrustStore::from_json(blocks[1].as_bytes()).unwrap();
    assert_eq!((authorities.issuer_count(), authorities.authority_count()), (0, 1));
    let pack_authority = jwk("khalm v0.1 policy-vector pack authority key (test-only)").key_id();
    let key = authorities.lookup_authority(&pack_authority).expect("the policy vectors' authority key");
    assert_eq!(key.authority_id, "khalm-policy-vectors");
}

#[test]
fn a_lookup_miss_is_none() {
    let store = load(&base()).unwrap();
    let kid = jwk(VECTOR_KEY).key_id();
    assert!(store.lookup(&jwk("someone else").key_id()).is_none());
    assert!(store.lookup("").is_none());
    assert!(store.lookup(&kid.to_uppercase()).is_none(), "exact string match only");
    assert!(store.lookup(&format!("{kid} ")).is_none());
}

#[test]
fn an_empty_store_is_valid_and_trusts_no_one() {
    let store = load(&json!({"trust_store_version": "0.1", "issuers": []})).unwrap();
    assert_eq!((store.issuer_count(), store.key_count()), (0, 0));
    assert!(store.lookup(&jwk(VECTOR_KEY).key_id()).is_none());
}

#[test]
fn unknown_members_are_rejected_at_every_level() {
    for pointer in ["", "/issuers/0", "/issuers/0/keys/0", "/issuers/0/keys/0/public_key"] {
        let mut doc = base();
        doc.pointer_mut(pointer).unwrap().as_object_mut().unwrap().insert("trusted".into(), json!(true));
        assert_eq!(kind_of(&doc), Kind::Structure, "{pointer}");
    }
}

#[test]
fn duplicate_members_are_rejected() {
    let text = serde_json::to_string(&base()).unwrap();
    for (member, dup) in [
        ("\"revoked\":false", "\"revoked\":false,\"revoked\":true"),
        ("\"issuers\":", "\"issuers\":[],\"issuers\":"),
        ("\"issuer_name\":", "\"issuer_name\":\"x\",\"issuer_name\":"),
    ] {
        assert!(text.contains(member), "{member}");
        let bad = text.replacen(member, dup, 1);
        let err = TrustStore::from_json(bad.as_bytes()).map(|_| ()).unwrap_err();
        assert_eq!(err.kind, Kind::Structure, "{dup}: {err}");
        assert!(err.to_string().contains("duplicate field"), "{err}");
    }
}

#[test]
fn null_missing_and_empty_members_are_rejected() {
    let mut doc = base();
    doc["issuers"][0]["keys"][0]["valid_until"] = Value::Null;
    assert_eq!(kind_of(&doc), Kind::Structure, "valid_until: null");
    let mut doc = base();
    doc["issuers"][0]["keys"][0].as_object_mut().unwrap().remove("revoked");
    assert_eq!(kind_of(&doc), Kind::Structure, "revoked missing");
    let mut doc = base();
    doc["issuers"][0]["keys"] = json!([]);
    assert_eq!(kind_of(&doc), Kind::Structure, "an issuer without keys");
    // valid_until is the one optional member.
    let mut doc = base();
    doc["issuers"][0]["keys"][0].as_object_mut().unwrap().remove("valid_until");
    let store = load(&doc).unwrap();
    assert_eq!(store.lookup(&jwk(VECTOR_KEY).key_id()).unwrap().valid_until, None);
}

#[test]
fn only_version_0_1_is_read() {
    let mut doc = base();
    doc["trust_store_version"] = json!("0.2");
    assert_eq!(kind_of(&doc), Kind::Version);
    // Checked before the structure: a later version with members this reader
    // does not know is reported as a version problem, not as a pile of
    // unknown members.
    doc["issuers"][0]["keys"][0]["revoked_at"] = json!("2026-06-01T00:00:00Z");
    assert_eq!(kind_of(&doc), Kind::Version);
    let mut doc = base();
    doc["trust_store_version"] = json!(0.1);
    assert_eq!(kind_of(&doc), Kind::Structure, "a number is not the version string");
    let mut doc = base();
    doc.as_object_mut().unwrap().remove("trust_store_version");
    assert_eq!(kind_of(&doc), Kind::Structure);
}

/// The base store as compact JSON with `from` replaced (once) by `to`.
fn base_text_with(from: &str, to: &str) -> String {
    let text = serde_json::to_string(&base()).unwrap();
    assert!(text.contains(from), "{from}");
    text.replacen(from, to, 1)
}

#[test]
fn a_lone_surrogate_escape_fails_trust_store_structure() {
    // QA P4-03, trust-store spec §2 / §3 kind 4: strings are sequences of
    // Unicode scalar values. A \u escape of an unpaired surrogate is valid
    // RFC 8259 syntax, so it is not trust_store.syntax; the store is
    // rejected as trust_store.structure - in a value, in the version, in a
    // member name.
    for escape in ["\\ud800", "\\udbff", "\\udc00", "\\udfff", "\\ud800\\u0041", "\\ud800\\ud800", "\\udc00\\ud800"] {
        for (from, to) in [
            ("\"New Clark", format!("\"New {escape}Clark")),
            ("\"0.1\"", format!("\"0.1{escape}\"")),
            ("\"issuers\":", format!("\"{escape}\":1,\"issuers\":")),
            ("\"revoked\":", format!("\"{escape}\":1,\"revoked\":")),
        ] {
            let text = base_text_with(from, &to);
            serde_json::from_str::<serde::de::IgnoredAny>(&text).expect("valid RFC 8259 syntax");
            let err = TrustStore::from_json(text.as_bytes()).map(|_| ()).unwrap_err();
            assert_eq!(err.kind, Kind::Structure, "{to}: {err}");
        }
    }
    // A surrogate PAIR is one scalar value (U+1F600) and loads.
    load_text(&base_text_with("\"New Clark", "\"New \\ud83d\\ude00Clark")).unwrap();
}

#[test]
fn a_later_version_is_still_reported_before_a_lone_surrogate() {
    // Kind 3 (version) is checked before kind 4 (structure), and a lone
    // surrogate is a structure failure: a store of version "0.2" is reported
    // as a version problem wherever else it carries one - in a value or in a
    // member name. (serde_json cannot read a member name holding one, so the
    // version peek must not need to.)
    for (from, to) in [
        ("\"New Clark", "\"New \\ud800Clark"),
        ("\"issuers\":", "\"\\ud800\":1,\"issuers\":"),
        ("\"issuer_name\":", "\"\\ud800\":1,\"issuer_name\":"),
    ] {
        let text = base_text_with("\"0.1\"", "\"0.2\"").replacen(from, to, 1);
        serde_json::from_str::<serde::de::IgnoredAny>(&text).expect("valid RFC 8259 syntax");
        let err = TrustStore::from_json(text.as_bytes()).map(|_| ()).unwrap_err();
        assert_eq!(err.kind, Kind::Version, "{to}: {err}");
    }
}

#[test]
fn noncharacters_are_scalar_values_and_are_accepted() {
    // Noncharacters (U+FDD0-U+FDEF, U+xFFFE/U+xFFFF of every plane) are
    // Unicode scalar values: permitted in a store, raw or escaped, and the
    // two spellings are one store with one identity.
    let name = "New Clark \u{fdd0}\u{fdef}\u{fffe}\u{ffff}\u{1fffe}\u{10ffff} Operator";
    let mut doc = base();
    doc["issuers"][0]["issuer_name"] = json!(name);
    let raw = load(&doc).unwrap();
    assert_eq!(raw.lookup(&jwk(VECTOR_KEY).key_id()).unwrap().issuer_name, name);
    let escaped = base_text_with(
        "\"New Clark City Fab Operator\"",
        "\"New Clark \\ufdd0\\uFDEF\\ufffe\\uffff\\ud83f\\udffe\\udbff\\udfff Operator\"",
    );
    assert_eq!(load_text(&escaped).unwrap().sha256(), raw.sha256());
}

#[test]
fn surrogates_encoded_in_utf8_fail_trust_store_syntax() {
    // A surrogate written as UTF-8 bytes (CESU-8 style: ED A0 80 for U+D800,
    // ED B0 80 for U+DC00) is not UTF-8: trust_store.syntax, as before.
    for bad in [&[0xed, 0xa0, 0x80][..], &[0xed, 0xb0, 0x80][..], &[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80][..]] {
        let text = serde_json::to_string(&base()).unwrap();
        let at = text.find("New Clark").unwrap() + "New ".len();
        let bytes = [&text.as_bytes()[..at], bad, &text.as_bytes()[at..]].concat();
        let err = TrustStore::from_json(&bytes).map(|_| ()).unwrap_err();
        assert_eq!(err.kind, Kind::Syntax, "{bad:02x?}: {err}");
    }
}

fn load_text(text: &str) -> Result<TrustStore, vmr_verify::trust_store::TrustStoreError> {
    TrustStore::from_json(text.as_bytes())
}

#[test]
fn issuer_ids_are_dids() {
    for bad in ["did:web:", "web:factory-operator.ph", "did:web:f\u{430}ctory-operator.ph", ""] {
        let mut doc = base();
        doc["issuers"][0]["issuer_id"] = json!(bad);
        assert_eq!(kind_of(&doc), Kind::IssuerId, "{bad:?}");
    }
}

#[test]
fn attestation_levels_are_the_three_values() {
    let mut doc = base();
    doc["issuers"][0]["keys"][0]["attestation_level"] = json!("root");
    assert_eq!(kind_of(&doc), Kind::Structure);
    for (text, level) in [
        ("self", AttestationLevel::SelfAttested),
        ("software", AttestationLevel::Software),
        ("hardware", AttestationLevel::Hardware),
    ] {
        let mut doc = base();
        doc["issuers"][0]["keys"][0]["attestation_level"] = json!(text);
        let store = load(&doc).unwrap();
        assert_eq!(store.lookup(&jwk(VECTOR_KEY).key_id()).unwrap().attestation_level, level);
        assert_eq!(level.as_str(), text);
        assert_eq!(AttestationLevel::parse(text), Some(level));
    }
    assert_eq!(AttestationLevel::parse("root"), None);
    assert!(AttestationLevel::SelfAttested < AttestationLevel::Software);
    assert!(AttestationLevel::Software < AttestationLevel::Hardware);
}

#[test]
fn timestamps_use_the_profile() {
    for field in ["valid_from", "valid_until"] {
        for bad in ["2026-01-01", "2026-02-30T00:00:00Z", "2026-01-01t00:00:00z", "2026-01-01T00:00:00+00:00"] {
            let mut doc = base();
            doc["issuers"][0]["keys"][0][field] = json!(bad);
            assert_eq!(kind_of(&doc), Kind::Timestamp, "{field} = {bad}");
        }
    }
}

#[test]
fn invalid_keys_are_rejected() {
    let good = jwk(VECTOR_KEY);
    let mut cases: Vec<(&str, JwkPublicKey)> = Vec::new();
    let mut j = good.clone();
    j.y = good.x.clone();
    cases.push(("off-curve (x, x)", j));
    let mut j = good.clone();
    j.kty = "RSA".into();
    cases.push(("kty", j));
    let mut j = good.clone();
    j.crv = "P-384".into();
    cases.push(("crv", j));
    let mut j = good.clone();
    j.x = format!("{}=", good.x);
    cases.push(("padded base64url", j));
    let mut j = good.clone();
    j.x = vmr_record::encoding::b64url_encode(&[1u8; 31]);
    cases.push(("31-byte coordinate", j));
    for (what, j) in cases {
        let mut doc = base();
        doc["issuers"][0]["keys"][0]["public_key"] = serde_json::to_value(&j).unwrap();
        // key_id stays the good one: the key check comes first (rule 8 < 9).
        assert_eq!(kind_of(&doc), Kind::InvalidKey, "{what}");
    }
}

#[test]
fn key_ids_are_the_thumbprint_of_their_key() {
    for bad in [jwk("another key").key_id(), "urn:example:kid".to_string()] {
        let mut doc = base();
        doc["issuers"][0]["keys"][0]["key_id"] = json!(bad);
        assert_eq!(kind_of(&doc), Kind::KeyIdMismatch, "{bad}");
    }
}

#[test]
fn issuer_ids_are_unique() {
    let mut doc = base();
    let mut second = doc["issuers"][0].clone();
    second["keys"] = json!([key_entry("key B")]);
    second["issuer_name"] = json!("A second entry for the same DID");
    doc["issuers"].as_array_mut().unwrap().push(second);
    assert_eq!(kind_of(&doc), Kind::DuplicateIssuer);
}

#[test]
fn a_key_id_appears_once_in_the_whole_store() {
    // Twice under one issuer.
    let mut doc = base();
    doc["issuers"][0]["keys"].as_array_mut().unwrap().push(key_entry(VECTOR_KEY));
    assert_eq!(kind_of(&doc), Kind::DuplicateKey, "same issuer");
    // Under two issuers: a key trusted for two issuers is ambiguous.
    let mut doc = base();
    doc["issuers"].as_array_mut().unwrap().push(json!({
        "issuer_id": "did:web:other.example",
        "issuer_name": "Other",
        "keys": [key_entry(VECTOR_KEY)]
    }));
    assert_eq!(kind_of(&doc), Kind::DuplicateKey, "two issuers");
}

#[test]
fn valid_until_is_after_valid_from() {
    for until in ["2026-01-01T00:00:00Z", "2025-12-31T23:59:59Z"] {
        let mut doc = base();
        doc["issuers"][0]["keys"][0]["valid_until"] = json!(until);
        assert_eq!(kind_of(&doc), Kind::ValidityWindow, "{until}");
    }
    let mut doc = base();
    doc["issuers"][0]["keys"][0]["valid_until"] = json!("2026-01-01T00:00:01Z");
    load(&doc).unwrap();
}

#[test]
fn malformed_input_is_rejected_with_its_kind() {
    let good = serde_json::to_string(&base()).unwrap();
    let cases: Vec<(&str, Vec<u8>, Kind)> = vec![
        ("empty", vec![], Kind::Syntax),
        ("truncated", good.as_bytes()[..good.len() / 2].to_vec(), Kind::Syntax),
        ("not UTF-8", [b"{\"trust_store_version\":\"0.1\xff\"}".as_slice()].concat(), Kind::Syntax),
        ("BOM", [&[0xef, 0xbb, 0xbf][..], good.as_bytes()].concat(), Kind::Syntax),
        ("trailing data", format!("{good} {{}}").into_bytes(), Kind::Syntax),
        ("not an object", b"[]".to_vec(), Kind::Structure),
        // 100 000-deep nesting is valid RFC 8259 JSON, but a store's text
        // nests at most 127 levels (spec §2, A16-5): rejected as syntax, and
        // without recursing (the syntax pass and the depth count are both
        // iterative). Inside a member, too.
        (
            "deep nesting",
            format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)).into_bytes(),
            Kind::Syntax,
        ),
        (
            "deep nesting in a member",
            format!("{{\"trust_store_version\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000))
                .into_bytes(),
            Kind::Syntax,
        ),
    ];
    for (what, bytes, kind) in cases {
        let err = TrustStore::from_json(&bytes).map(|_| ()).expect_err(what);
        assert_eq!(err.kind, kind, "{what}: {err}");
    }
}

#[test]
fn the_size_limit_is_16_mib() {
    let good = serde_json::to_string(&base()).unwrap();
    let limit = vmr_verify::trust_store::MAX_TRUST_STORE_BYTES;
    assert_eq!(limit, 16 * 1024 * 1024);
    let mut at_limit = good.clone().into_bytes();
    at_limit.resize(limit, b' '); // trailing whitespace is valid JSON
    TrustStore::from_json(&at_limit).unwrap();
    at_limit.push(b' ');
    let err = TrustStore::from_json(&at_limit).map(|_| ()).unwrap_err();
    assert_eq!(err.kind, Kind::Size);
}

#[test]
fn rules_are_checked_in_order_over_the_whole_document() {
    // A bad timestamp (rule 7) and a duplicate key (rule 12): rule 7 wins.
    let mut doc = base();
    doc["issuers"][0]["keys"][0]["valid_from"] = json!("soon");
    doc["issuers"][0]["keys"].as_array_mut().unwrap().push(key_entry(VECTOR_KEY));
    assert_eq!(kind_of(&doc), Kind::Timestamp);
    // Rule by rule, not entry by entry: a bad timestamp in the FIRST issuer
    // and a bad DID in the SECOND - the DID rule (5) comes first.
    let mut doc = base();
    doc["issuers"][0]["keys"][0]["valid_from"] = json!("soon");
    doc["issuers"].as_array_mut().unwrap().push(json!({
        "issuer_id": "not a did", "issuer_name": "x", "keys": [key_entry("key B")]
    }));
    assert_eq!(kind_of(&doc), Kind::IssuerId);
}

/// A store of two issuers with two keys each, in the given orders.
fn two_by_two(issuer_order: [usize; 2], key_order: [usize; 2]) -> Value {
    let issuers = [
        ("did:web:a.example", ["a1", "a2"]),
        ("did:web:b.example", ["b1", "b2"]),
    ];
    let list: Vec<Value> = issuer_order
        .iter()
        .map(|&i| {
            let (id, keys) = issuers[i];
            json!({
                "issuer_id": id,
                "issuer_name": id,
                "keys": key_order.iter().map(|&k| key_entry(keys[k])).collect::<Vec<_>>()
            })
        })
        .collect();
    json!({"trust_store_version": "0.1", "issuers": list})
}

#[test]
fn store_order_changes_no_lookup_and_no_hash() {
    let reference = load(&two_by_two([0, 1], [0, 1])).unwrap();
    for io in [[0, 1], [1, 0]] {
        for ko in [[0, 1], [1, 0]] {
            let store = load(&two_by_two(io, ko)).unwrap();
            assert_eq!(store.sha256(), reference.sha256(), "{io:?} {ko:?}");
            for label in ["a1", "a2", "b1", "b2"] {
                let kid = jwk(label).key_id();
                let (a, b) = (store.lookup(&kid).unwrap(), reference.lookup(&kid).unwrap());
                assert_eq!((a.issuer_id, a.key_id), (b.issuer_id, b.key_id), "{label}");
            }
            assert_eq!(store.to_document(), reference.to_document());
        }
    }
}

#[test]
fn reformatting_does_not_change_the_hash_and_any_value_does() {
    let doc = base();
    let reference = load(&doc).unwrap();
    let compact = serde_json::to_string(&doc).unwrap();
    // Members in another order, and a character written as a \u escape.
    // (serde_json writes members sorted: the version comes last.)
    let reordered = compact
        .replacen(",\"trust_store_version\":\"0.1\"", "", 1)
        .replacen('{', "{\"trust_store_version\":\"0.1\",", 1)
        .replace("Clark", "\\u0043lark");
    assert!(reordered.starts_with("{\"trust_store_version\""), "{reordered}");
    assert_ne!(reordered, compact);
    for text in [compact.clone(), serde_json::to_string_pretty(&doc).unwrap(), reordered] {
        let store = TrustStore::from_json(text.as_bytes()).unwrap();
        assert_eq!(store.sha256(), reference.sha256());
    }
    let edits: [(&str, Value); 4] = [
        ("/issuers/0/issuer_name", json!("New Clark City Fab Operators")),
        ("/issuers/0/keys/0/revoked", json!(true)),
        ("/issuers/0/keys/0/valid_until", json!("2027-01-01T00:00:01Z")),
        ("/issuers/0/keys/0/attestation_level", json!("hardware")),
    ];
    for (pointer, value) in edits {
        let mut changed = doc.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert_ne!(load(&changed).unwrap().sha256(), reference.sha256(), "{pointer}");
    }
}

#[test]
fn the_identity_is_the_sha256_of_the_sorted_jcs_form() {
    // specs/trust-store-format-v0.1.md §5, recomputed here from the rule:
    // issuers sorted by issuer_id, keys by key_id, JCS, SHA-256.
    let doc = two_by_two([1, 0], [1, 0]);
    let store = load(&doc).unwrap();
    let mut sorted = doc.clone();
    let issuers = sorted["issuers"].as_array_mut().unwrap();
    issuers.sort_by(|a, b| a["issuer_id"].as_str().cmp(&b["issuer_id"].as_str()));
    for i in issuers.iter_mut() {
        i["keys"].as_array_mut().unwrap().sort_by(|a, b| a["key_id"].as_str().cmp(&b["key_id"].as_str()));
    }
    let expected = format_hash(&sha256(vmr_record::canonical::jcs(&sorted).as_bytes()));
    assert_eq!(store.sha256(), expected);
}

#[test]
fn new_validates_a_document_built_in_code() {
    // TrustStore::new is the entry point for a document built in memory
    // (Phase 5 `key export`): the same rules apply.
    let doc: vmr_verify::trust_store::TrustStoreDocument = serde_json::from_value(base()).unwrap();
    let store = TrustStore::new(doc.clone()).unwrap();
    assert_eq!(store.sha256(), load(&base()).unwrap().sha256());
    assert_eq!(store.to_document(), doc);
    let mut bad = doc.clone();
    bad.issuers[0].keys[0].key_id = jwk("another key").key_id();
    assert_eq!(TrustStore::new(bad).map(|_| ()).unwrap_err().kind, Kind::KeyIdMismatch);
    let mut bad = doc;
    bad.trust_store_version = "1.0".into();
    assert_eq!(TrustStore::new(bad).map(|_| ()).unwrap_err().kind, Kind::Version);
}

#[test]
fn errors_name_their_stable_kind() {
    let all = [
        (Kind::Size, "trust_store.size"),
        (Kind::Syntax, "trust_store.syntax"),
        (Kind::Version, "trust_store.version"),
        (Kind::Structure, "trust_store.structure"),
        (Kind::IssuerId, "trust_store.issuer_id"),
        (Kind::AuthorityId, "trust_store.authority_id"),
        (Kind::Timestamp, "trust_store.timestamp"),
        (Kind::InvalidKey, "trust_store.invalid_key"),
        (Kind::KeyIdMismatch, "trust_store.key_id_mismatch"),
        (Kind::DuplicateIssuer, "trust_store.duplicate_issuer"),
        (Kind::DuplicateAuthority, "trust_store.duplicate_authority"),
        (Kind::DuplicateKey, "trust_store.duplicate_key"),
        (Kind::ValidityWindow, "trust_store.validity_window"),
    ];
    for (kind, id) in all {
        assert_eq!(kind.id(), id);
    }
    let err = TrustStore::from_json(b"").map(|_| ()).unwrap_err();
    assert!(err.to_string().starts_with("trust_store.syntax: "), "{err}");
}

/// Whether `c` is one of the characters `display_safe` escapes (the
/// backslash aside, which it doubles): what a terminal must never receive
/// raw. Asked of `display_safe` itself, so this test has no table of its own.
fn unsafe_char(c: char) -> bool {
    c != '\\' && vmr_verify::display_safe(&c.to_string()) != c.to_string()
}

/// Text a hostile store may carry: ANSI escapes that clear the screen and
/// paint a fake verdict, a C1 CSI, DEL, CR, a bidi override and an isolate,
/// zero-width and other invisible characters, a noncharacter, a tag
/// character.
const HOSTILE: &str = "\u{1b}[2J\u{1b}[H\u{1b}[32m\u{2713} Record valid\u{1b}[0m\u{9b}2J\u{7f}\r\u{202e}\u{2066}\u{200b}\u{feff}\u{3164}\u{fffe}\u{e0041}";

/// The most characters a loader error detail may have (the loader's own
/// bound, before escaping; the escaped details of these inputs stay within
/// it too).
const DETAIL_BOUND: usize = 4096;

#[test]
fn every_loader_error_detail_is_terminal_safe_and_bounded() {
    // A trust store is untrusted input when it reaches the wrong person, and
    // its loader errors reach a terminal (vmr prints them). Every rule a
    // string of the store can break, broken by hostile text - as it is,
    // 100 000 characters of it, and hidden after 100 000 harmless ones: every
    // detail is free of anything a terminal acts on, bounded whatever the
    // input's size, and quotes at most 64 characters of a value.
    assert!(HOSTILE.chars().filter(|&c| unsafe_char(c)).count() >= 12, "the probe is hostile");
    let long_hostile: String = HOSTILE.chars().cycle().take(100_000).collect();
    let long_tail = format!("{}{HOSTILE}", "a".repeat(100_000));
    for text in [HOSTILE.to_string(), long_hostile, long_tail] {
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut doc = base();
            f(&mut doc);
            serde_json::to_string(&doc).unwrap().into_bytes()
        };
        let edit_authority = |f: &dyn Fn(&mut Value)| {
            let mut doc = with_authority();
            f(&mut doc);
            serde_json::to_string(&doc).unwrap().into_bytes()
        };
        let v = json!(text);
        let cases: Vec<(&str, Vec<u8>, Kind)> = vec![
            ("syntax: raw controls in a string", format!("{{\"{text}\":1}}").into_bytes(), Kind::Syntax),
            ("version", edit(&|d| d["trust_store_version"] = v.clone()), Kind::Version),
            ("unknown member", edit(&|d| d[text.as_str()] = json!(1)), Kind::Structure),
            ("unknown issuer member", edit(&|d| d["issuers"][0][text.as_str()] = json!(1)), Kind::Structure),
            ("unknown key member", edit(&|d| d["issuers"][0]["keys"][0][text.as_str()] = json!(1)), Kind::Structure),
            (
                "unknown public_key member",
                edit(&|d| d["issuers"][0]["keys"][0]["public_key"][text.as_str()] = json!(1)),
                Kind::Structure,
            ),
            ("attestation_level", edit(&|d| d["issuers"][0]["keys"][0]["attestation_level"] = v.clone()), Kind::Structure),
            ("revoked, a string", edit(&|d| d["issuers"][0]["keys"][0]["revoked"] = v.clone()), Kind::Structure),
            ("issuers, a string", edit(&|d| d["issuers"] = v.clone()), Kind::Structure),
            (
                "an issuer without keys",
                edit(&|d| {
                    d["issuers"][0]["issuer_id"] = v.clone();
                    d["issuers"][0]["keys"] = json!([]);
                }),
                Kind::Structure,
            ),
            ("issuer_id", edit(&|d| d["issuers"][0]["issuer_id"] = v.clone()), Kind::IssuerId),
            ("valid_from", edit(&|d| d["issuers"][0]["keys"][0]["valid_from"] = v.clone()), Kind::Timestamp),
            ("kty", edit(&|d| d["issuers"][0]["keys"][0]["public_key"]["kty"] = v.clone()), Kind::InvalidKey),
            ("crv", edit(&|d| d["issuers"][0]["keys"][0]["public_key"]["crv"] = v.clone()), Kind::InvalidKey),
            ("x", edit(&|d| d["issuers"][0]["keys"][0]["public_key"]["x"] = v.clone()), Kind::InvalidKey),
            ("key_id", edit(&|d| d["issuers"][0]["keys"][0]["key_id"] = v.clone()), Kind::KeyIdMismatch),
            (
                "unknown authority member",
                edit_authority(&|d| d["policy_authorities"][0][text.as_str()] = json!(1)),
                Kind::Structure,
            ),
            (
                "an authority without keys",
                edit_authority(&|d| {
                    d["policy_authorities"][0]["authority_id"] = v.clone();
                    d["policy_authorities"][0]["keys"] = json!([]);
                }),
                Kind::Structure,
            ),
            (
                "an authority's key_id",
                edit_authority(&|d| d["policy_authorities"][0]["keys"][0]["key_id"] = v.clone()),
                Kind::KeyIdMismatch,
            ),
            (
                "a duplicate authority_id",
                edit_authority(&|d| {
                    d["policy_authorities"][0]["authority_id"] = v.clone();
                    let mut second = authority("second", &[AUTHORITY_KEY_2]);
                    second["authority_id"] = v.clone();
                    d["policy_authorities"].as_array_mut().unwrap().push(second);
                }),
                Kind::DuplicateAuthority,
            ),
        ];
        for (what, bytes, kind) in cases {
            let err = TrustStore::from_json(&bytes).map(|_| ()).expect_err(what);
            let size = text.chars().count();
            assert_eq!(err.kind, kind, "{what} ({size} characters): {err}");
            let shown = err.to_string();
            let raw: Vec<char> = shown.chars().filter(|&c| unsafe_char(c)).collect();
            assert!(raw.is_empty(), "{what} ({size} characters): raw {raw:?} in the detail");
            let n = err.detail.chars().count();
            assert!(n <= DETAIL_BOUND, "{what} ({size} characters): a detail of {n} characters");
            assert!(!err.detail.contains(&"a".repeat(65)), "{what}: more than 64 characters of a value quoted");
        }
    }
}

#[test]
fn a_member_name_of_100_000_characters_gives_a_short_message() {
    // serde_json's own message quotes the name whole ("unknown field `…`"):
    // the loader cuts what it quotes to 64 characters and keeps where it is.
    let mut doc = base();
    doc["issuers"][0][format!("{HOSTILE}{}", "x".repeat(100_000)).as_str()] = json!(1);
    let err = load(&doc).map(|_| ()).unwrap_err();
    assert_eq!(err.kind, Kind::Structure);
    assert!(err.detail.chars().count() < 1000, "{} characters", err.detail.chars().count());
    assert!(err.detail.starts_with("unknown field `"), "{err}");
    assert!(err.detail.contains("…`, expected one of `issuer_id`, `issuer_name`, `keys`"), "{err}");
    assert!(err.detail.contains("(line "), "{err}");
    assert!(err.detail.contains("\\u{001b}[2J"), "escaped, still legible: {err}");
}

// ---------------------------------------------------------------------------
//  schema_sync: specs/trust-store-schema/v0.1.json and SCHEMA_RULES agree,
//  in both directions, and every rule is enforced by the kind it names.
// ---------------------------------------------------------------------------

fn store_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/trust-store-schema/v0.1.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Every `(pointer, keyword, JSON value)` rule of a schema node and its
/// children; `*` stands for array items. Fails on any keyword outside the
/// set the loader implements, so the schema cannot grow a rule the code
/// lacks.
fn schema_rules(node: &Value, pointer: &str, out: &mut Vec<(String, String, String)>) {
    const ANNOTATIONS: [&str; 4] = ["$schema", "$id", "title", "description"];
    const RULES: [&str; 12] = [
        "type", "const", "enum", "pattern", "format", "minimum", "maximum", "minItems",
        "maxItems", "minLength", "required", "additionalProperties",
    ];
    for (k, v) in node.as_object().unwrap() {
        if RULES.contains(&k.as_str()) {
            out.push((pointer.to_string(), k.clone(), serde_json::to_string(v).unwrap()));
        } else if k == "properties" {
            for (name, sub) in v.as_object().unwrap() {
                schema_rules(sub, &format!("{pointer}/{name}"), out);
            }
        } else if k == "items" {
            schema_rules(v, &format!("{pointer}/*"), out);
        } else {
            assert!(ANNOTATIONS.contains(&k.as_str()), "unsupported schema keyword {k} at {pointer:?}");
        }
    }
}

#[test]
fn schema_sync() {
    let mut from_schema = Vec::new();
    schema_rules(&store_schema(), "", &mut from_schema);
    from_schema.sort();
    let mut from_code: Vec<(String, String, String)> = SCHEMA_RULES
        .iter()
        .map(|r| (r.pointer.to_string(), r.keyword.to_string(), r.value.to_string()))
        .collect();
    from_code.sort();
    for rule in &from_schema {
        assert!(from_code.contains(rule), "schema rule missing from SCHEMA_RULES: {rule:?}");
    }
    for rule in &from_code {
        assert!(from_schema.contains(rule), "SCHEMA_RULES entry not in the schema: {rule:?}");
    }
    // 39 for the store and its issuers, 34 for policy_authorities (6.16).
    assert_eq!(from_schema.len(), 73);
}

/// Replace, at `pointer` (`*` = the first element), the value with
/// `f(old)`; `None` removes the member.
fn edit_at(doc: &mut Value, pointer: &str, f: &dyn Fn(&Value) -> Option<Value>) {
    let concrete = pointer.replace('*', "0");
    if concrete.is_empty() {
        *doc = f(doc).unwrap();
        return;
    }
    let (parent, name) = concrete.rsplit_once('/').unwrap();
    match doc.pointer_mut(parent).unwrap() {
        Value::Array(items) => {
            let i: usize = name.parse().unwrap();
            items[i] = f(&items[i]).unwrap();
        }
        Value::Object(members) => match f(members.get(name).unwrap_or(&Value::Null)) {
            Some(v) => {
                members.insert(name.to_string(), v);
            }
            None => {
                members.remove(name);
            }
        },
        other => panic!("{pointer}: parent is {other}"),
    }
}

#[test]
fn every_schema_rule_is_enforced_by_the_kind_it_names() {
    for rule in SCHEMA_RULES {
        let value: Value = serde_json::from_str(rule.value).unwrap();
        // Violations of this rule, each applied to a fresh valid store that
        // has an issuer and a policy authority.
        let mut violations: Vec<Value> = Vec::new();
        let mut doc = with_authority();
        match rule.keyword {
            "type" => {
                edit_at(&mut doc, rule.pointer, &|_| {
                    Some(match value.as_str().unwrap() {
                        "string" => json!(1),
                        "array" => json!({}),
                        "object" => json!([]),
                        _ => json!("not a boolean"),
                    })
                });
                violations.push(doc);
            }
            "required" => {
                for member in value.as_array().unwrap() {
                    let mut doc = with_authority();
                    let m = member.as_str().unwrap();
                    edit_at(&mut doc, &format!("{}/{m}", rule.pointer), &|_| None);
                    violations.push(doc);
                }
            }
            "additionalProperties" => {
                edit_at(&mut doc, &format!("{}/extra", rule.pointer), &|_| Some(json!(true)));
                violations.push(doc);
            }
            "const" => {
                edit_at(&mut doc, rule.pointer, &|_| Some(json!("x")));
                violations.push(doc);
            }
            "enum" => {
                edit_at(&mut doc, rule.pointer, &|_| Some(json!("root")));
                violations.push(doc);
            }
            "pattern" => {
                edit_at(&mut doc, rule.pointer, &|_| Some(json!("not-matching")));
                violations.push(doc);
            }
            "format" => {
                edit_at(&mut doc, rule.pointer, &|_| Some(json!("yesterday")));
                violations.push(doc);
            }
            "minItems" => {
                edit_at(&mut doc, rule.pointer, &|_| Some(json!([])));
                violations.push(doc);
            }
            "minLength" => {
                edit_at(&mut doc, rule.pointer, &|_| Some(json!("")));
                violations.push(doc);
            }
            other => panic!("no violation generator for {other}"),
        }
        for doc in violations {
            assert_eq!(kind_of(&doc), rule.enforced_by, "{} {} {}", rule.pointer, rule.keyword, rule.value);
        }
    }
}

// ---------------------------------------------------------------------------
//  Policy authorities (P6-14; docs/dev/task-6.16.md A16-1 to A16-6): a list
//  beside issuers, kept apart by structure.
// ---------------------------------------------------------------------------

#[test]
fn policy_authorities_are_optional_and_a_store_without_them_keeps_its_identity() {
    // A16-2: every store written before 6.16 keeps its identity - the Gate 5
    // artifact's among them - and an empty list is the same store as none.
    let gate5 = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vmr-cli/tests/data/gate5/trust-store.json"),
    )
    .unwrap();
    let store = TrustStore::from_json(&gate5).unwrap();
    assert_eq!(store.sha256(), "sha256:d7986309810433bf829f208a54c0808c9c95d625d099af555924a86c654cb58b");
    assert_eq!((store.authority_count(), store.authority_key_count()), (0, 0));
    let mut empty: Value = serde_json::from_slice(&gate5).unwrap();
    empty["policy_authorities"] = json!([]);
    assert_eq!(load(&empty).unwrap().sha256(), store.sha256());

    let plain = load(&base()).unwrap();
    let mut doc = base();
    doc["policy_authorities"] = json!([]);
    let with_empty = load(&doc).unwrap();
    assert_eq!(with_empty.sha256(), plain.sha256());
    // Written back, the empty list is omitted: it is the document without it.
    assert_eq!(with_empty.to_document(), plain.to_document());
    assert!(serde_json::to_value(with_empty.to_document()).unwrap().get("policy_authorities").is_none());
    // A trusted authority is a value: it moves the identity.
    assert_ne!(load(&with_authority()).unwrap().sha256(), plain.sha256());
}

#[test]
fn an_authority_key_is_found_only_among_authorities_and_an_issuer_key_only_among_issuers() {
    // P6-14, A16-6: an issuer's key cannot vouch for a pack, nor an
    // authority's key for a record.
    let store = load(&with_authority()).unwrap();
    assert_eq!((store.issuer_count(), store.key_count()), (1, 1));
    assert_eq!((store.authority_count(), store.authority_key_count()), (1, 1));
    let (issuer_kid, authority_kid) = (jwk(VECTOR_KEY).key_id(), jwk(AUTHORITY_KEY).key_id());
    assert!(store.lookup(&authority_kid).is_none(), "an authority's key does not vouch for a record");
    assert!(store.lookup_authority(&issuer_kid).is_none(), "an issuer's key does not vouch for a pack");
    assert!(store.lookup(&issuer_kid).is_some());
    let k = store.lookup_authority(&authority_kid).expect("the authority's key");
    assert_eq!(k.authority_id, "example-authority");
    assert_eq!(k.authority_name, "example-authority (the operator's name)");
    assert_eq!(k.key_id, authority_kid);
    assert_eq!(k.public_key, &jwk(AUTHORITY_KEY));
    assert_eq!(JwkPublicKey::from_verifying_key(k.verifying_key), jwk(AUTHORITY_KEY));
    assert_eq!(k.attestation_level, AttestationLevel::Software);
    assert_eq!(k.valid_from.to_string(), "2026-01-01T00:00:00Z");
    assert_eq!(k.valid_until.map(|t| t.to_string()).as_deref(), Some("2027-01-01T00:00:00Z"));
    assert!(!k.revoked);
    assert!(store.lookup_authority(&authority_kid.to_uppercase()).is_none(), "exact string match only");
    assert!(store.lookup_authority("").is_none());
}

#[test]
fn a_store_of_authorities_alone_is_valid() {
    // A16-7: the file `--authority-store` names is this format, "issuers": [].
    let doc = json!({
        "trust_store_version": "0.1",
        "issuers": [],
        "policy_authorities": [authority("example-authority", &[AUTHORITY_KEY, AUTHORITY_KEY_2])]
    });
    let store = load(&doc).unwrap();
    assert_eq!(
        (store.issuer_count(), store.key_count(), store.authority_count(), store.authority_key_count()),
        (0, 0, 1, 2)
    );
    assert!(store.lookup_authority(&jwk(AUTHORITY_KEY_2).key_id()).is_some());
}

/// What an edit breaks, and the edit.
type NamedEdit<'a> = (&'a str, &'a dyn Fn(&mut Value));

#[test]
fn authority_entries_are_closed_complete_and_never_null() {
    for pointer in ["/policy_authorities/0", "/policy_authorities/0/keys/0", "/policy_authorities/0/keys/0/public_key"] {
        let mut doc = with_authority();
        doc.pointer_mut(pointer).unwrap().as_object_mut().unwrap().insert("trusted".into(), json!(true));
        assert_eq!(kind_of(&doc), Kind::Structure, "{pointer}");
    }
    let edits: [NamedEdit; 6] = [
        ("policy_authorities: null", &|d| d["policy_authorities"] = Value::Null),
        ("policy_authorities: an object", &|d| d["policy_authorities"] = json!({})),
        ("an authority without keys", &|d| d["policy_authorities"][0]["keys"] = json!([])),
        ("authority_name missing", &|d| {
            d["policy_authorities"][0].as_object_mut().unwrap().remove("authority_name");
        }),
        ("authority_id a number", &|d| d["policy_authorities"][0]["authority_id"] = json!(7)),
        ("attestation_level root", &|d| d["policy_authorities"][0]["keys"][0]["attestation_level"] = json!("root")),
    ];
    for (what, edit) in edits {
        let mut doc = with_authority();
        edit(&mut doc);
        assert_eq!(kind_of(&doc), Kind::Structure, "{what}");
    }
    let text = serde_json::to_string(&with_authority()).unwrap();
    for (member, dup) in [
        ("\"policy_authorities\":", "\"policy_authorities\":[],\"policy_authorities\":"),
        ("\"authority_id\":", "\"authority_id\":\"x\",\"authority_id\":"),
    ] {
        assert!(text.contains(member), "{member}");
        let err = TrustStore::from_json(text.replacen(member, dup, 1).as_bytes()).map(|_| ()).unwrap_err();
        assert_eq!(err.kind, Kind::Structure, "{dup}: {err}");
    }
}

#[test]
fn an_authority_id_is_a_non_empty_string() {
    // A16-1: the pack schema's rule for authority.authority_id, byte for
    // byte; whatever a pack may name is accepted.
    let mut doc = with_authority();
    doc["policy_authorities"][0]["authority_id"] = json!("");
    assert_eq!(kind_of(&doc), Kind::AuthorityId);
    for good in [" ", "did:web:regulator.example", "Autorit\u{e9} de r\u{e9}gulation", "\u{1f600}"] {
        let mut doc = with_authority();
        doc["policy_authorities"][0]["authority_id"] = json!(good);
        load(&doc).unwrap_or_else(|e| panic!("{good:?}: {e}"));
    }
}

#[test]
fn authority_ids_are_unique_and_apart_from_issuer_ids() {
    let mut doc = with_authority();
    doc["policy_authorities"].as_array_mut().unwrap().push(authority("example-authority", &[AUTHORITY_KEY_2]));
    assert_eq!(kind_of(&doc), Kind::DuplicateAuthority);
    // One organisation may be an issuer and an authority, with two keys: the
    // lists are apart, so their identifiers may meet.
    let mut doc = with_authority();
    doc["policy_authorities"][0]["authority_id"] = json!("did:web:factory-operator.ph");
    load(&doc).unwrap();
}

#[test]
fn a_key_is_trusted_in_one_list_only() {
    // A16-3: the lists are apart by structure only if they cannot share a key.
    let under = |f: &dyn Fn(&mut Value)| {
        let mut doc = with_authority();
        f(&mut doc);
        doc
    };
    let cases: [(&str, Value); 3] = [
        (
            "an issuer's key under an authority",
            under(&|d| d["policy_authorities"][0]["keys"].as_array_mut().unwrap().push(key_entry(VECTOR_KEY))),
        ),
        (
            "twice under one authority",
            under(&|d| d["policy_authorities"][0]["keys"].as_array_mut().unwrap().push(key_entry(AUTHORITY_KEY))),
        ),
        (
            "under two authorities",
            under(&|d| {
                d["policy_authorities"].as_array_mut().unwrap().push(authority("other-authority", &[AUTHORITY_KEY]))
            }),
        ),
    ];
    for (what, doc) in cases {
        let err = load(&doc).map(|_| ()).unwrap_err();
        assert_eq!(err.kind, Kind::DuplicateKey, "{what}: {err}");
    }
}

#[test]
fn an_authoritys_keys_follow_every_key_rule() {
    let edit = |pointer: &str, value: Value| {
        let mut doc = with_authority();
        *doc.pointer_mut(pointer).unwrap() = value;
        doc
    };
    let key = "/policy_authorities/0/keys/0";
    assert_eq!(kind_of(&edit(&format!("{key}/valid_from"), json!("2026-02-30T00:00:00Z"))), Kind::Timestamp);
    assert_eq!(kind_of(&edit(&format!("{key}/public_key/crv"), json!("P-384"))), Kind::InvalidKey);
    assert_eq!(kind_of(&edit(&format!("{key}/key_id"), json!(jwk("another key").key_id()))), Kind::KeyIdMismatch);
    assert_eq!(kind_of(&edit(&format!("{key}/valid_until"), json!("2026-01-01T00:00:00Z"))), Kind::ValidityWindow);
}

#[test]
fn the_rules_run_in_order_over_both_lists() {
    // Spec §3: each rule over the whole store - its issuers, then its
    // authorities - before the next rule.
    let mut doc = with_authority();
    doc["policy_authorities"][0]["keys"] = json!([]);
    doc["issuers"][0]["issuer_id"] = json!("not a did");
    assert_eq!(kind_of(&doc), Kind::Structure, "4 before 5");
    let mut doc = with_authority();
    doc["issuers"][0]["issuer_id"] = json!("not a did");
    doc["policy_authorities"][0]["authority_id"] = json!("");
    assert_eq!(kind_of(&doc), Kind::IssuerId, "5 before 6");
    let mut doc = with_authority();
    doc["policy_authorities"][0]["authority_id"] = json!("");
    doc["issuers"][0]["keys"][0]["valid_from"] = json!("soon");
    assert_eq!(kind_of(&doc), Kind::AuthorityId, "6 before 7");
    let mut doc = with_authority();
    doc["policy_authorities"][0]["keys"][0]["valid_from"] = json!("soon");
    doc["issuers"][0]["keys"][0]["public_key"]["crv"] = json!("P-384");
    assert_eq!(kind_of(&doc), Kind::Timestamp, "an authority's 7 before an issuer's 8");
    let mut doc = with_authority();
    doc["policy_authorities"].as_array_mut().unwrap().push(authority("example-authority", &[AUTHORITY_KEY_2]));
    doc["issuers"].as_array_mut().unwrap().push(json!({
        "issuer_id": "did:web:factory-operator.ph", "issuer_name": "again", "keys": [key_entry("key B")]
    }));
    assert_eq!(kind_of(&doc), Kind::DuplicateIssuer, "10 before 11");
    let mut doc = with_authority();
    doc["policy_authorities"].as_array_mut().unwrap().push(authority("example-authority", &[AUTHORITY_KEY]));
    assert_eq!(kind_of(&doc), Kind::DuplicateAuthority, "11 before 12");
    let mut doc = with_authority();
    doc["policy_authorities"][0]["keys"][0]["valid_until"] = json!("2026-01-01T00:00:00Z");
    doc["policy_authorities"][0]["keys"].as_array_mut().unwrap().push(key_entry(VECTOR_KEY));
    assert_eq!(kind_of(&doc), Kind::DuplicateKey, "12 before 13");
}

#[test]
fn authorities_and_their_keys_are_sorted_in_the_canonical_form() {
    // A16-2: authorities by authority_id in code-point order, each one's keys
    // by key_id; JCS; SHA-256. U+FF21 sorts before U+1F600 by code point and
    // after it by UTF-16 code unit: the identity takes code-point order.
    let a = authority("\u{ff21}-authority", &[AUTHORITY_KEY, AUTHORITY_KEY_2]);
    let b = authority("\u{1f600}-authority", &["khalm-vmr v0.1 trust-store test policy authority key R"]);
    let mut forward = base();
    forward["policy_authorities"] = json!([a.clone(), b.clone()]);
    let mut a_reversed = a;
    a_reversed["keys"].as_array_mut().unwrap().reverse();
    let mut reversed = base();
    reversed["policy_authorities"] = json!([b, a_reversed]);
    let (f, r) = (load(&forward).unwrap(), load(&reversed).unwrap());
    assert_eq!(f.sha256(), r.sha256());
    assert_eq!(f.to_document(), r.to_document());

    let mut sorted = forward.clone();
    let list = sorted["policy_authorities"].as_array_mut().unwrap();
    list.sort_by(|x, y| x["authority_id"].as_str().cmp(&y["authority_id"].as_str()));
    for entry in list.iter_mut() {
        entry["keys"].as_array_mut().unwrap().sort_by(|x, y| x["key_id"].as_str().cmp(&y["key_id"].as_str()));
    }
    assert_eq!(sorted["policy_authorities"][0]["authority_id"], "\u{ff21}-authority", "code-point order");
    let expected = format_hash(&sha256(vmr_record::canonical::jcs(&sorted).as_bytes()));
    assert_eq!(f.sha256(), expected);
}

#[test]
fn new_validates_authorities_built_in_code() {
    let doc: vmr_verify::trust_store::TrustStoreDocument = serde_json::from_value(with_authority()).unwrap();
    let store = TrustStore::new(doc.clone()).unwrap();
    assert_eq!(store.sha256(), load(&with_authority()).unwrap().sha256());
    assert_eq!(store.to_document(), doc);
    let mut bad = doc;
    bad.policy_authorities[0].authority_id = String::new();
    assert_eq!(TrustStore::new(bad).map(|_| ()).unwrap_err().kind, Kind::AuthorityId);
}

// ---------------------------------------------------------------------------
//  A trusted authority key and a pack (A16-9 to A16-11): once a pack's
//  signature verifies under the key, the key must speak for the authority
//  the pack names, be unrevoked, and be valid at the evaluation time.
// ---------------------------------------------------------------------------

#[test]
fn a_trusted_authority_key_may_sign_only_for_its_authority_unrevoked_and_inside_its_window() {
    let t = |s: &str| Timestamp::parse(s).unwrap();
    let kid = jwk(AUTHORITY_KEY).key_id();
    let store = load(&with_authority()).unwrap();
    let key = store.lookup_authority(&kid).unwrap();
    assert_eq!(key.may_sign_for("example-authority", t("2026-09-11T00:00:00Z")), Ok(()));
    assert_eq!(key.may_sign_for("example-authority", t("2026-01-01T00:00:00Z")), Ok(()), "valid_from is inside");
    for outside in ["2025-12-31T23:59:59Z", "2027-01-01T00:00:00Z", "2030-01-01T00:00:00Z"] {
        let refusal = key.may_sign_for("example-authority", t(outside));
        assert!(matches!(refusal, Err(AuthorityKeyRefusal::OutsideValidity { .. })), "{outside}: {refusal:?}");
    }
    let other = key.may_sign_for("Example-Authority", t("2026-09-11T00:00:00Z")).unwrap_err();
    assert!(matches!(other, AuthorityKeyRefusal::OtherAuthority { .. }), "exact string equality: {other}");
    let text = other.to_string();
    assert!(
        text.contains("\"Example-Authority\"") && text.contains("\"example-authority\"") && text.contains(&kid),
        "{text}"
    );

    // Revoked, and with no end: the binding is decided first, then
    // revocation, then the window.
    let mut revoked = with_authority();
    revoked["policy_authorities"][0]["keys"][0]["revoked"] = json!(true);
    revoked["policy_authorities"][0]["keys"][0].as_object_mut().unwrap().remove("valid_until");
    let store = load(&revoked).unwrap();
    let key = store.lookup_authority(&kid).unwrap();
    let at = t("2026-09-11T00:00:00Z");
    assert!(matches!(key.may_sign_for("example-authority", at), Err(AuthorityKeyRefusal::Revoked { .. })));
    assert!(matches!(key.may_sign_for("other", t("2020-01-01T00:00:00Z")), Err(AuthorityKeyRefusal::OtherAuthority { .. })));
    assert!(matches!(
        key.may_sign_for("example-authority", t("2020-01-01T00:00:00Z")),
        Err(AuthorityKeyRefusal::Revoked { .. })
    ));
    let mut open = with_authority();
    open["policy_authorities"][0]["keys"][0].as_object_mut().unwrap().remove("valid_until");
    let store = load(&open).unwrap();
    let key = store.lookup_authority(&kid).unwrap();
    assert_eq!(key.may_sign_for("example-authority", t("9999-12-31T23:59:59Z")), Ok(()), "no valid_until: no end");
}

#[test]
fn an_authority_key_refusal_has_a_stable_id() {
    // docs/dev/task-6.16.md A16-22: the ids a pack-signature vector names.
    let t = |s: &str| Timestamp::parse(s).unwrap();
    let kid = jwk(AUTHORITY_KEY).key_id();
    let mut revoked = with_authority();
    revoked["policy_authorities"][0]["keys"][0]["revoked"] = json!(true);
    let (plain, revoked) = (load(&with_authority()).unwrap(), load(&revoked).unwrap());
    let key = plain.lookup_authority(&kid).unwrap();
    let at = t("2026-09-11T00:00:00Z");
    let cases = [
        (key.may_sign_for("another-authority", at), "pack_signature.other_authority"),
        (revoked.lookup_authority(&kid).unwrap().may_sign_for("example-authority", at), "pack_signature.revoked"),
        (key.may_sign_for("example-authority", t("2027-01-01T00:00:00Z")), "pack_signature.outside_validity"),
    ];
    for (result, id) in cases {
        assert_eq!(result.expect_err(id).id(), id);
    }
}

#[test]
fn a_refusal_quotes_a_hostile_authority_id_escaped_and_short() {
    let store = load(&with_authority()).unwrap();
    let key = store.lookup_authority(&jwk(AUTHORITY_KEY).key_id()).unwrap();
    let named = format!("{HOSTILE}{}", "a".repeat(100_000));
    let text = key.may_sign_for(&named, Timestamp::parse("2026-09-11T00:00:00Z").unwrap()).unwrap_err().to_string();
    let raw: Vec<char> = text.chars().filter(|&c| unsafe_char(c)).collect();
    assert!(raw.is_empty(), "raw {raw:?} in {text}");
    assert!(text.chars().count() < 1000, "{} characters", text.chars().count());
    assert!(!text.contains(&"a".repeat(65)), "more than 64 characters of the value quoted");
}

// ---------------------------------------------------------------------------
//  The nesting bound (spec §2 and §3 kind 2; A16-5)
// ---------------------------------------------------------------------------

#[test]
fn text_nested_more_than_127_levels_is_trust_store_syntax() {
    // Kind 2, so a loader whose parser stops at a depth limit never has to
    // read past it to find the version.
    assert_eq!(MAX_NESTING_DEPTH, 127);
    // The store object is level 1; `arrays` arrays in a member reach level
    // arrays + 1.
    let nested = |version: &str, arrays: usize| {
        format!(
            "{{\"trust_store_version\":\"{version}\",\"issuers\":[],\"deep\":{}{}}}",
            "[".repeat(arrays),
            "]".repeat(arrays)
        )
    };
    assert_eq!(kind_of_text(&nested("0.1", 126)), Kind::Structure, "127 levels: read, refused for its member");
    assert_eq!(kind_of_text(&nested("0.1", 127)), Kind::Syntax, "128 levels");
    assert_eq!(kind_of_text(&nested("0.2", 126)), Kind::Version, "127 levels of a later version");
    assert_eq!(kind_of_text(&nested("0.2", 127)), Kind::Syntax, "128 levels, even of a later version");
    // Objects count as arrays do.
    let objects = format!(
        "{{\"trust_store_version\":\"0.1\",\"issuers\":[],\"deep\":{}1{}}}",
        "{\"a\":".repeat(127),
        "}".repeat(127)
    );
    assert_eq!(kind_of_text(&objects), Kind::Syntax);
    // Brackets inside a string are text, escaped quotes included.
    let mut doc = base();
    doc["issuers"][0]["issuer_name"] = json!(format!("{}\\\"{}", "[{".repeat(200), "]".repeat(3)));
    load(&doc).unwrap();
}
