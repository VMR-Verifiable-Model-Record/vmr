// tests/common/generate_pack_signature.rs — the generator of
// specs/test-vectors/policy/pack-signature.json (docs/TASKS.md 6.16;
// docs/dev/task-6.16.md A16-22, A16-24). Included by
// tests/pack_signature_vectors.rs; written only by
//
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-cli --test pack_signature_vectors -- --ignored
//
// A case is a pack text, a trust store, an authority store when there is one,
// an evaluation time and whether a signature is required. It gives what the
// reference verifier's check of the pack's signature decides
// (specs/trust-store-format-v0.1.md §4.2) - the signature state, or the
// identifier of the refusal - and the exit code of `vmr record verify
// --policy-pack` for the conformance record with those inputs.
//
// Written here by hand: every state, identifier and exit code. Computed here:
// every pack payload hash (policy-pack format §4, with the format crate's JCS
// and SHA-256, not through vmr_policy::signing), every key id and every
// signature (ES256, RFC 6979, low-s), so the file regenerates byte for byte.
// Nothing here runs the check.
//
// This crate generates the file because the check comes together here:
// vmr-policy verifies a pack's signature, vmr-verify decides whether its key
// may speak for the pack, and neither may depend on the other (P6-10).
//
// Every document text is in its JCS form. New cases go at the end of `cases`.

#![allow(dead_code)] // tests/pack_signature_vectors.rs uses part of this

use crate::common::*;
use serde_json::{json, Value};
use vmr_record::canonical::jcs;
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::JwkPublicKey;

/// Key P: the key the vectors' policy authority is trusted with. The label
/// of the trust-store loader vectors' key P (vmr-verify tests/common/mod.rs).
pub const KEY_P: &str = "khalm v0.1 trust-store-vector policy authority key P";
/// Key Q: a key no case's authority holds, unless it says so.
pub const KEY_Q: &str = "khalm v0.1 trust-store-vector policy authority key Q";
/// The authority the vector pack names.
pub const AUTHORITY_ID: &str = "khalm-pack-signature-vectors";
/// The pack's own name for it: a claim.
const AUTHORITY_NAME_IN_PACK: &str = "KHALM pack-signature vectors";
/// The trust store's name for it: the operator's, which a `valid` state names.
pub const AUTHORITY_NAME: &str = "KHALM pack-signature vectors, per this operator";
/// Another authority, which no store trusts.
const OTHER_AUTHORITY_ID: &str = "another-authority.example";
/// The conformance record's issuer, which every case's trust store trusts
/// with key A so that the record verifies.
const ISSUER: &str = "did:web:factory-operator.ph";
const ISSUER_NAME: &str = "New Clark City Fab Operator";
/// The evaluation time of most cases: the day after the conformance
/// record's issued_at.
const AT: &str = "2026-09-11T00:00:00Z";

/// Every generated file: (path relative to specs/test-vectors/, contents).
pub fn generate() -> Vec<(String, String)> {
    vec![("policy/pack-signature.json".to_string(), format!("{}\n", serde_json::to_string_pretty(&file()).unwrap()))]
}

// ---------------------------------------------------------------------------
//  Documents
// ---------------------------------------------------------------------------

/// The vector pack, naming `authority_id`: one mandatory attestation_level
/// rule the conformance record passes, so an evaluated case exits 0.
fn pack(authority_id: &str) -> Value {
    json!({
        "version": "0.1",
        "pack_id": "pack-signature-vector",
        "pack_version": "1.0.0",
        "jurisdiction": "test",
        "description": "The pack of a KHALM pack-signature vector.",
        "disclaimer": "A test vector, not legal advice.",
        "authority": {"authority_id": authority_id, "authority_name": AUTHORITY_NAME_IN_PACK},
        "rules": [{
            "type": "attestation_level",
            "rule_id": "vector-attestation-level",
            "description": "The issuer attests with a software-held key or better.",
            "severity": "mandatory",
            "reference": "KHALM pack-signature vectors (a test fixture, not a clause of any standard)",
            "minimum_level": "software"
        }]
    })
}

/// Policy-pack format §4: `sha256:` and the hex of the SHA-256 of the JCS
/// form of the document without its top-level `signature`.
fn payload_hash(document: &Value) -> String {
    let mut d = document.clone();
    d.as_object_mut().unwrap().remove("signature");
    format_hash(&sha256(jcs(&d).as_bytes()))
}

/// The RFC 7638 key id of `label`'s derived key.
fn key_id(label: &str) -> String {
    JwkPublicKey::from_verifying_key(key(label).verifying_key()).key_id()
}

/// `document` signed over its §4 payload by `signer`'s key, its section naming
/// `named`'s key id.
fn signed(document: Value, signer: &str, named: &str) -> Value {
    let mut d = document;
    d.as_object_mut().unwrap().remove("signature");
    let payload = jcs(&d);
    let signature = vmr_record::sign::sign(&key(signer), payload.as_bytes()).unwrap();
    d["signature"] = json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", vmr_record::sign::signature_to_b64url(&signature)),
        "signed_payload_hash": format_hash(&sha256(payload.as_bytes())),
        "signing_key_id": key_id(named),
    });
    d
}

/// The vector pack signed by `label`'s key, naming it.
fn signed_by(label: &str) -> Value {
    signed(pack(AUTHORITY_ID), label, label)
}

/// `document` with its signature replaced by the signature's high-s twin
/// (the same r, n − s), which satisfies the ECDSA equation.
fn high_s(document: Value) -> Value {
    let field = document["signature"]["signature"].as_str().unwrap().strip_prefix("base64url:").unwrap().to_string();
    let low = vmr_record::sign::signature_from_b64url(&field).unwrap();
    let twin = p256::ecdsa::Signature::from_scalars(*low.r(), -*low.s()).unwrap();
    let mut d = document;
    d["signature"]["signature"] = json!(format!("base64url:{}", vmr_record::sign::signature_to_b64url(&twin)));
    d
}

/// Key P's pack, changed after it was signed: its section still states the
/// payload hash of the text before the change.
fn changed_after_signing() -> Value {
    let mut d = signed_by(KEY_P);
    d["description"] = json!("The pack of a KHALM pack-signature vector, changed after it was signed.");
    d
}

/// A trust-store key object for `label`'s key, at `software`.
fn key_entry(label: &str, valid_from: &str, valid_until: Option<&str>, revoked: bool) -> Value {
    let jwk = JwkPublicKey::from_verifying_key(key(label).verifying_key());
    let mut k = json!({
        "key_id": jwk.key_id(),
        "public_key": jwk,
        "attestation_level": "software",
        "valid_from": valid_from,
        "revoked": revoked,
    });
    if let Some(until) = valid_until {
        k["valid_until"] = json!(until);
    }
    k
}

/// The vectors' authority holding key P with this window and revocation.
fn authority_with_p(valid_from: &str, valid_until: Option<&str>, revoked: bool) -> Vec<Value> {
    vec![json!({
        "authority_id": AUTHORITY_ID,
        "authority_name": AUTHORITY_NAME,
        "keys": [key_entry(KEY_P, valid_from, valid_until, revoked)],
    })]
}

/// The vectors' authority holding key P, from 2026-01-01 until 2027-01-01.
fn trusts_p() -> Vec<Value> {
    authority_with_p("2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), false)
}

/// A trust store: the conformance record's issuer with key A, and
/// `authorities` as its `policy_authorities` when there are any.
fn trust_store(authorities: Vec<Value>) -> Value {
    let mut store = json!({
        "trust_store_version": "0.1",
        "issuers": [{
            "issuer_id": ISSUER,
            "issuer_name": ISSUER_NAME,
            "keys": [key_entry(KEY_A, "2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), false)],
        }],
    });
    if !authorities.is_empty() {
        store["policy_authorities"] = json!(authorities);
    }
    store
}

/// An authority store (trust-store format §4.2): no issuers, `authorities`.
fn authority_store(authorities: Vec<Value>) -> Value {
    json!({"trust_store_version": "0.1", "issuers": [], "policy_authorities": authorities})
}

/// The vectors' authority holding the keys of `labels`, in that order, each
/// from 2026-01-01 until 2027-01-01.
fn authority_holding(labels: &[&str]) -> Vec<Value> {
    let keys: Vec<Value> =
        labels.iter().map(|label| key_entry(label, "2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), false)).collect();
    vec![json!({"authority_id": AUTHORITY_ID, "authority_name": AUTHORITY_NAME, "keys": keys})]
}

/// A file given as an authority store that lists an issuer, another DID holding
/// key Q, beside `authorities`.
fn authority_store_with_an_issuer(authorities: Vec<Value>) -> Value {
    json!({
        "trust_store_version": "0.1",
        "issuers": [{
            "issuer_id": "did:web:another-issuer.example",
            "issuer_name": "Another issuer",
            "keys": [key_entry(KEY_Q, "2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), false)],
        }],
        "policy_authorities": authorities,
    })
}

// ---------------------------------------------------------------------------
//  The cases
// ---------------------------------------------------------------------------

/// What a case gives, written by hand.
enum Gives {
    /// Evaluated, with this `pack_signature` state: exit code 0.
    State(Value),
    /// Refused with this identifier before anything is verified: exit code 1.
    Refused(&'static str),
}

struct Case {
    id: &'static str,
    description: &'static str,
    pack: Value,
    trust_store: Value,
    authority_store: Option<Value>,
    t: &'static str,
    require_signed_pack: bool,
    /// The policy-pack format's §3 refuses the pack text (QA QT-01's cases):
    /// no pack is loaded, so no payload hash is expected.
    pack_refused: bool,
    gives: Gives,
}

fn case(id: &'static str, description: &'static str, pack: Value, authorities: Vec<Value>, gives: Gives) -> Case {
    Case {
        id,
        description,
        pack,
        trust_store: trust_store(authorities),
        authority_store: None,
        t: AT,
        require_signed_pack: false,
        pack_refused: false,
        gives,
    }
}

impl Case {
    fn with_authority_store(mut self, store: Value) -> Self {
        self.authority_store = Some(store);
        self
    }

    fn with_trust_store(mut self, store: Value) -> Self {
        self.trust_store = store;
        self
    }

    /// The pack text is one the policy-pack format's §3 refuses: its expected
    /// `pack_payload_hash` is `null`, as a refused pack-loader case has none.
    fn pack_refused(mut self) -> Self {
        self.pack_refused = true;
        self
    }

    fn at(mut self, t: &'static str) -> Self {
        self.t = t;
        self
    }

    fn signature_required(mut self) -> Self {
        self.require_signed_pack = true;
        self
    }

    fn to_json(&self) -> Value {
        let expected = match &self.gives {
            Gives::State(state) => json!({
                "exit_code": 0,
                "pack_payload_hash": payload_hash(&self.pack),
                "pack_signature": state,
            }),
            Gives::Refused(refusal) => json!({
                "exit_code": 1,
                "pack_payload_hash": if self.pack_refused { Value::Null } else { json!(payload_hash(&self.pack)) },
                "refusal": refusal,
            }),
        };
        json!({
            "id": self.id,
            "description": self.description,
            "pack": {"text": jcs(&self.pack)},
            "trust_store": {"text": jcs(&self.trust_store)},
            "authority_store": self.authority_store.as_ref().map(|s| json!({"text": jcs(s)})),
            "evaluation_time": self.t,
            "require_signed_pack": self.require_signed_pack,
            "expected": expected,
        })
    }
}

fn unsigned() -> Gives {
    Gives::State(json!({"state": "unsigned"}))
}

fn not_checked(label: &str) -> Gives {
    Gives::State(json!({"state": "not_checked", "signing_key_id": key_id(label)}))
}

fn valid(label: &str) -> Gives {
    Gives::State(json!({
        "state": "valid",
        "signing_key_id": key_id(label),
        "authority_id": AUTHORITY_ID,
        "authority_name": AUTHORITY_NAME,
    }))
}

fn refused(identifier: &'static str) -> Gives {
    // §4.2 names a store the loader refuses by trust-store format §3's kinds
    // (steps 1 and 2) and a pack by the policy-pack format's §3 (step 3): the
    // two structure refusals QA QT-01's cases reach are listed with its own.
    const IDENTIFIERS: [&str; 11] = [
        "trust_store.structure",
        "policy_pack.structure",
        "authority_store.issuers",
        "authority_store.issuer_key",
        "pack_signature.payload_hash",
        "pack_signature.invalid",
        "pack_signature.other_authority",
        "pack_signature.revoked",
        "pack_signature.outside_validity",
        "pack_signature.unsigned_refused",
        "pack_signature.not_checked_refused",
    ];
    assert!(IDENTIFIERS.contains(&identifier), "{identifier} is not an identifier of trust-store format §4.2");
    Gives::Refused(identifier)
}

fn cases() -> Vec<Case> {
    let none = Vec::new;
    let elsewhere = || signed(pack(OTHER_AUTHORITY_ID), KEY_P, KEY_P);
    vec![
        // The states, and --require-signed-pack.
        case("unsigned", "An unsigned pack, and a trust store with no policy authority: evaluated, unsigned.",
            pack(AUTHORITY_ID), none(), unsigned()),
        case("unsigned-with-an-authority", "An unsigned pack, and a trust store that trusts key P for the pack's authority: still unsigned.",
            pack(AUTHORITY_ID), trusts_p(), unsigned()),
        case("unsigned-signature-required", "An unsigned pack when a signature is required: refused.",
            pack(AUTHORITY_ID), trusts_p(), refused("pack_signature.unsigned_refused")).signature_required(),
        case("not-checked-no-authorities", "A pack signed by key P, and a trust store with no policy authority: evaluated, not checked.",
            signed_by(KEY_P), none(), not_checked(KEY_P)),
        case("not-checked-key-not-held", "A pack signed by key Q, and a trust store whose authority holds key P only: not checked.",
            signed_by(KEY_Q), trusts_p(), not_checked(KEY_Q)),
        case("not-checked-issuer-key", "A pack signed by key A, which the trust store trusts for the record's issuer: an issuer's key never vouches for a pack, so not checked.",
            signed_by(KEY_A), trusts_p(), not_checked(KEY_A)),
        case("not-checked-signature-required", "not-checked-key-not-held when a signature is required: refused.",
            signed_by(KEY_Q), trusts_p(), refused("pack_signature.not_checked_refused")).signature_required(),
        case("valid", "A pack signed by key P, which the trust store trusts for the pack's authority, at a time inside the key's window.",
            signed_by(KEY_P), trusts_p(), valid(KEY_P)),
        case("valid-signature-required", "valid when a signature is required: accepted.",
            signed_by(KEY_P), trusts_p(), valid(KEY_P)).signature_required(),
        // The authority store.
        case("valid-authority-store", "A pack signed by key P, a trust store with no policy authority, and an authority store that trusts key P: valid.",
            signed_by(KEY_P), none(), valid(KEY_P)).with_authority_store(authority_store(trusts_p())),
        case("authority-store-no-fallback", "The trust store trusts key P, and the authority store given trusts no authority: the authorities come only from the authority store, so not checked.",
            signed_by(KEY_P), trusts_p(), not_checked(KEY_P)).with_authority_store(authority_store(none())),
        case("authority-store-lists-issuers", "An authority store that lists the record's issuer beside key P's authority: refused.",
            signed_by(KEY_P), none(), refused("authority_store.issuers")).with_authority_store(trust_store(trusts_p())),
        // The refusals, in the order of trust-store format §4.2.
        case("payload-hash-mismatch", "A pack signed by key P and changed after it was signed: its section states the payload hash of the text before the change.",
            changed_after_signing(), trusts_p(), refused("pack_signature.payload_hash")),
        case("payload-hash-mismatch-no-authorities", "payload-hash-mismatch's pack, and a trust store with no policy authority: the payload hash needs no key, so still refused.",
            changed_after_signing(), none(), refused("pack_signature.payload_hash")),
        case("invalid-another-key", "A pack whose section names key P, signed by key Q.",
            signed(pack(AUTHORITY_ID), KEY_Q, KEY_P), trusts_p(), refused("pack_signature.invalid")),
        case("invalid-high-s", "valid's pack with its signature replaced by the high-s twin, which satisfies the ECDSA equation.",
            high_s(signed_by(KEY_P)), trusts_p(), refused("pack_signature.invalid")),
        case("other-authority", "A pack naming another-authority.example, signed by key P, which the store trusts for khalm-pack-signature-vectors.",
            elsewhere(), trusts_p(), refused("pack_signature.other_authority")),
        case("revoked", "valid's pack, and key P revoked.",
            signed_by(KEY_P), authority_with_p("2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), true), refused("pack_signature.revoked")),
        // The window, at the evaluation time 2026-09-11T00:00:00Z.
        case("window-valid-from-is-t", "Key P may sign from 2026-09-11T00:00:00Z, the evaluation time: inside its window.",
            signed_by(KEY_P), authority_with_p(AT, Some("2027-01-01T00:00:00Z"), false), valid(KEY_P)),
        case("window-valid-from-after-t", "Key P may sign from 2026-09-11T00:00:01Z, one second after the evaluation time.",
            signed_by(KEY_P), authority_with_p("2026-09-11T00:00:01Z", Some("2027-01-01T00:00:00Z"), false), refused("pack_signature.outside_validity")),
        case("window-valid-until-after-t", "Key P may sign until 2026-09-11T00:00:01Z, one second after the evaluation time: inside its window.",
            signed_by(KEY_P), authority_with_p("2026-01-01T00:00:00Z", Some("2026-09-11T00:00:01Z"), false), valid(KEY_P)),
        case("window-valid-until-is-t", "Key P may sign until 2026-09-11T00:00:00Z, the evaluation time, which the window excludes.",
            signed_by(KEY_P), authority_with_p("2026-01-01T00:00:00Z", Some(AT), false), refused("pack_signature.outside_validity")),
        case("window-no-end", "Key P has no valid_until, and the evaluation time is 2031-01-01T00:00:00Z.",
            signed_by(KEY_P), authority_with_p("2026-01-01T00:00:00Z", None, false), valid(KEY_P)).at("2031-01-01T00:00:00Z"),
        // Neighbours in the order, each case breaking both steps.
        case("order-authority-store-before-payload-hash", "An authority store that lists issuers, and payload-hash-mismatch's pack: the stores are read before the pack.",
            changed_after_signing(), none(), refused("authority_store.issuers")).with_authority_store(trust_store(trusts_p())),
        case("order-payload-hash-before-lookup", "payload-hash-mismatch's pack, no policy authority, and a signature required: the payload hash is decided before the key is looked up.",
            changed_after_signing(), none(), refused("pack_signature.payload_hash")).signature_required(),
        case("order-signature-before-authority", "A pack naming another-authority.example whose section names key P, signed by key Q: the signature is decided before the binding.",
            signed(pack(OTHER_AUTHORITY_ID), KEY_Q, KEY_P), trusts_p(), refused("pack_signature.invalid")),
        case("order-authority-before-revocation", "other-authority's pack, and key P revoked: the binding is decided before revocation.",
            elsewhere(), authority_with_p("2026-01-01T00:00:00Z", Some("2027-01-01T00:00:00Z"), true), refused("pack_signature.other_authority")),
        case("order-revocation-before-window", "valid's pack, key P revoked, and the evaluation time before its window: revocation is decided before the window.",
            signed_by(KEY_P), authority_with_p("2026-09-12T00:00:00Z", Some("2027-01-01T00:00:00Z"), true), refused("pack_signature.revoked")),
        // One key, one role, across the trust store and the authority store
        // (docs/dev/task-6.16.md A16-25).
        case("authority-store-holds-an-issuer-key", "A pack signed by key A, and an authority store whose authority holds key A, which the trust store trusts for the record's issuer: refused, although the signature would be valid.",
            signed_by(KEY_A), none(), refused("authority_store.issuer_key")).with_authority_store(authority_store(authority_holding(&[KEY_A]))),
        case("authority-store-holds-an-issuer-key-beside-the-signing-key", "A pack signed by key P, and an authority store whose authority holds key P and key A: the store is refused for key A, whichever key signed the pack.",
            signed_by(KEY_P), none(), refused("authority_store.issuer_key")).with_authority_store(authority_store(authority_holding(&[KEY_P, KEY_A]))),
        case("order-authority-store-issuers-before-issuer-key", "A file given as an authority store that lists an issuer holding key Q, and whose authority holds key A, which the trust store trusts for the record's issuer: its issuers are decided first.",
            signed_by(KEY_A), none(), refused("authority_store.issuers")).with_authority_store(authority_store_with_an_issuer(authority_holding(&[KEY_A]))),
        case("order-issuer-key-before-payload-hash", "An authority store whose authority holds key A, and payload-hash-mismatch's pack: the stores are checked before the pack.",
            changed_after_signing(), none(), refused("authority_store.issuer_key")).with_authority_store(authority_store(authority_holding(&[KEY_A]))),
        // QA QT-01: an object written as the array of its values, in its
        // members' declaration order, the order serde's derive reads a struct
        // in. Each broken file is refused where §4.2 reads it: a store by
        // trust-store format §3 (kind 4), the pack by the policy-pack format's
        // §3 (refusal 2), before its signature.
        case("structure-trust-store-authority-as-array", "valid with the trust store's policy authority written as [authority_id, authority_name, keys]: the trust store is refused (trust-store format §3, kind 4).",
            signed_by(KEY_P), none(), refused("trust_store.structure")).with_trust_store(as_array(&trust_store(trusts_p()), "/policy_authorities/0", AUTHORITY_FIELDS)),
        case("structure-trust-store-authority-key-as-array", "valid with key P, in the trust store's policy authority, written as the array of its six values: the trust store is refused (kind 4).",
            signed_by(KEY_P), none(), refused("trust_store.structure")).with_trust_store(as_array(&trust_store(trusts_p()), "/policy_authorities/0/keys/0", KEY_FIELDS)),
        case("structure-authority-store-as-array", "valid-authority-store with the authority store written as [trust_store_version, issuers, policy_authorities]: the authority store is refused (kind 4).",
            signed_by(KEY_P), none(), refused("trust_store.structure")).with_authority_store(as_array(&authority_store(trusts_p()), "", STORE_FIELDS)),
        case("structure-authority-store-authority-as-array", "valid-authority-store with the authority store's policy authority written as [authority_id, authority_name, keys]: the authority store is refused (kind 4).",
            signed_by(KEY_P), none(), refused("trust_store.structure")).with_authority_store(as_array(&authority_store(trusts_p()), "/policy_authorities/0", AUTHORITY_FIELDS)),
        case("structure-authority-store-authority-key-as-array", "valid-authority-store with key P, in the authority store, written as the array of its six values: the authority store is refused (kind 4).",
            signed_by(KEY_P), none(), refused("trust_store.structure")).with_authority_store(as_array(&authority_store(trusts_p()), "/policy_authorities/0/keys/0", KEY_FIELDS)),
        case("structure-pack-signature-as-array", "valid's pack with its signature section written as [algorithm, signature, signed_payload_hash, signing_key_id], which the payload excludes: the pack is refused (policy-pack format §3, refusal 2) before its signature is checked.",
            as_array(&signed_by(KEY_P), "/signature", SIGNATURE_FIELDS), trusts_p(), refused("policy_pack.structure")).pack_refused(),
        case("structure-pack-authority-as-array", "A pack whose authority is written as [authority_id, authority_name], signed by key P over that text: the pack is refused (refusal 2), although its signature verifies.",
            signed(as_array(&pack(AUTHORITY_ID), "/authority", PACK_AUTHORITY_FIELDS), KEY_P, KEY_P), trusts_p(), refused("policy_pack.structure")).pack_refused(),
        case("order-authority-store-structure-before-pack-structure", "structure-authority-store-as-array's authority store and structure-pack-authority-as-array's pack: the stores are read before the pack.",
            signed(as_array(&pack(AUTHORITY_ID), "/authority", PACK_AUTHORITY_FIELDS), KEY_P, KEY_P), none(), refused("trust_store.structure"))
            .with_authority_store(as_array(&authority_store(trusts_p()), "", STORE_FIELDS))
            .pack_refused(),
    ]
}

/// A trust store's members, in declaration order (vmr-verify's
/// `TrustStoreDocument`).
const STORE_FIELDS: &[&str] = &["trust_store_version", "issuers", "policy_authorities"];
/// A policy authority's members, in declaration order.
const AUTHORITY_FIELDS: &[&str] = &["authority_id", "authority_name", "keys"];
/// A trust-store key's members, in declaration order.
const KEY_FIELDS: &[&str] = &["key_id", "public_key", "attestation_level", "valid_from", "valid_until", "revoked"];
/// A pack's signature section's members, in declaration order.
const SIGNATURE_FIELDS: &[&str] = &["algorithm", "signature", "signed_payload_hash", "signing_key_id"];
/// A pack's `authority` members, in declaration order.
const PACK_AUTHORITY_FIELDS: &[&str] = &["authority_id", "authority_name"];

/// `document` with the object at `pointer` written as the array of its
/// values, in the order `fields` gives, which names every member it has.
fn as_array(document: &Value, pointer: &str, fields: &[&str]) -> Value {
    let mut d = document.clone();
    let object = d.pointer_mut(pointer).expect("the object");
    let members = object.as_object().expect("an object");
    assert_eq!(members.len(), fields.len(), "{pointer}: every member, in declaration order");
    let values: Vec<Value> = fields.iter().map(|f| members.get(*f).cloned().expect("a member")).collect();
    *object = Value::Array(values);
    d
}

/// The whole file.
pub fn file() -> Value {
    let cases = cases();
    let mut ids = std::collections::BTreeSet::new();
    for c in &cases {
        assert!(ids.insert(c.id), "duplicate case id {}", c.id);
    }
    json!({
        "vector_version": "0.1",
        "description": "VMR pack-signature vectors v0.1 (trust-store format v0.1, §4.2; policy-pack format v0.1, §4, §9). Each case gives a pack text, a trust store, an authority store or null, an evaluation time and whether a signature is required. A conforming checker gives expected.pack_signature, or refuses with expected.refusal. expected.pack_payload_hash is the payload hash (policy-pack format v0.1, §4) of a pack that loads, or null when that format's §3 refuses the pack's text, which has none. expected.exit_code is what `vmr record verify --policy-pack` exits with for the conformance record with these inputs: the record member of ../record/example-v0.1.json, written to a file of its own (that file as a whole wraps the record, and is not one). Generated by the vmr-cli crate's vector generator (VMR_WRITE_VECTORS=1 cargo test -p vmr-cli --test pack_signature_vectors -- --ignored) - never hand-edited. Every key is test-only (README.md).",
        "cases": cases.iter().map(Case::to_json).collect::<Vec<_>>(),
    })
}
