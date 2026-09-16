// tests/common/mod.rs — shared support for vmr-verify's integration tests:
// the committed record vector, the derived test keys of plan §8, re-signing,
// trust stores, and report assertions. Test-only; every key here is derived
// from a fixed label, never generated, and is worthless outside tests.

#![allow(dead_code)]

use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use vmr_record::hash::sha256;
use vmr_record::record::{JwkPublicKey, Record, SignatureSection};
use vmr_record::sign::signing_key_from_secret;
use vmr_record::timestamp::Timestamp;
use vmr_verify::report::{CheckId, Outcome, Verdict};
use vmr_verify::{TrustStore, VerificationReport, Verifier, VerifyOptions};

/// Key A: the record vector's key (spec §9).
pub const KEY_A: &str = "khalm v0.1 test-vector signing key";
/// Key A2: a second key of the vector issuer (rotation).
pub const KEY_A2: &str = "khalm v0.1 verify-vector key A2";
/// Key B: the key of another issuer.
pub const KEY_B: &str = "khalm v0.1 verify-vector key B";
/// Key F: a forger's key, trusted by no store.
pub const KEY_F: &str = "khalm v0.1 verify-vector key F";
/// Keys P, Q and R: policy authorities' keys of the trust-store loader
/// vectors (docs/TASKS.md 6.16).
pub const KEY_P: &str = "khalm v0.1 trust-store-vector policy authority key P";
pub const KEY_Q: &str = "khalm v0.1 trust-store-vector policy authority key Q";
pub const KEY_R: &str = "khalm v0.1 trust-store-vector policy authority key R";

/// The policy authorities of the trust-store loader vectors.
pub const VECTOR_AUTHORITY: &str = "khalm-trust-store-vectors";
pub const OTHER_AUTHORITY: &str = "other-authority.example";

pub const VECTOR_ISSUER: &str = "did:web:factory-operator.ph";
pub const VECTOR_ISSUER_NAME: &str = "New Clark City Fab Operator";
pub const OTHER_ISSUER: &str = "did:web:other.example";

/// The evaluation time most cases use: the day after the vector's issued_at.
pub const T: &str = "2026-09-11T00:00:00Z";

pub fn key(label: &str) -> SigningKey {
    signing_key_from_secret(&sha256(label.as_bytes())).unwrap()
}

pub fn jwk(label: &str) -> JwkPublicKey {
    JwkPublicKey::from_verifying_key(key(label).verifying_key())
}

pub fn key_id(label: &str) -> String {
    jwk(label).key_id()
}

pub fn vector_file() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/test-vectors/record/example-v0.1.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

thread_local! {
    /// The record every `vector()` and `vector_edited()` below starts from,
    /// when a pass has set one (QA QR-09 / D-1.5): `None` is the committed
    /// vector.
    static BASE: std::cell::RefCell<Option<Record>> = const { std::cell::RefCell::new(None) };
}

/// The committed vector record, or the base the current pass set.
pub fn vector() -> Record {
    if let Some(p) = BASE.with(|b| b.borrow().clone()) {
        return p;
    }
    serde_json::from_value(vector_file()["record"].clone()).unwrap()
}

/// Run `build` with `base` standing in for the committed vector record
/// everywhere this module and the generator read it, then put the committed
/// one back.
pub fn with_base<T>(base: Record, build: impl FnOnce() -> T) -> T {
    BASE.with(|b| *b.borrow_mut() = Some(base));
    let out = build();
    BASE.with(|b| *b.borrow_mut() = None);
    out
}

/// The `model_format` the general-description twin carries: any value that is
/// not a registered profile selects the general description (spec §7.1).
pub const GENERAL_TWIN_FORMAT: &str = "tensor-files";

/// The committed vector record described GENERALLY: the same record, its
/// `model_format` a value that selects no registered profile and its
/// `learned_state_hash` recomputed as the named-set digest of its three
/// components (spec §7.2, §7.3), re-signed with key A. Every other byte is
/// the vector's.
///
/// Why it is built this way, and not from another model: the profile governs
/// `model_format` and the meaning of the state hashes, and nothing else
/// (§7.4). A rule of the general format therefore reads exactly the same
/// values in this record as in the vector, so a case copied onto it keeps its
/// expected verdict and check BY CONSTRUCTION, not because a verifier was run
/// to find out. `model_hash` is left as it is: under the general description
/// it covers files a record need not carry, so no verifier recomputes it
/// (§7.3).
pub fn general_twin() -> Record {
    use vmr_record::hash::parse_hash;
    use vmr_record::named_set::named_set_digest;
    let mut p: Record = serde_json::from_value(vector_file()["record"].clone()).unwrap();
    let parts: Vec<(String, [u8; 32])> = p
        .model_identity
        .learned_state_components
        .iter()
        .map(|c| (c.name.clone(), parse_hash(&c.hash).expect("a component hash")))
        .collect();
    let borrowed: Vec<(&str, [u8; 32])> = parts.iter().map(|(n, d)| (n.as_str(), *d)).collect();
    p.model_identity.model_format = GENERAL_TWIN_FORMAT.into();
    p.model_identity.learned_state_hash =
        vmr_record::hash::format_hash(&named_set_digest(&borrowed).expect("a named set"));
    // The one member the general description needs that the profile implies:
    // a record that commits training records names their format (§8.2). The
    // profile's are its frames, so the twin says so; the commitment itself -
    // the count, the digest and the Merkle root - is the vector's, unchanged.
    p.learning_provenance.training_input_format = Some("khalmtrn-frame-v1".into());
    sign_as(&mut p, KEY_A);
    p
}

/// The general description's conformance vector record
/// (`specs/test-vectors/record/example-general-v0.1.json`; spec §9, task
/// 10.11b): a model of four synthetic files, signed with key A.
pub fn general_vector() -> Record {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/test-vectors/record/example-general-v0.1.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    serde_json::from_value(file["record"].clone()).unwrap()
}

/// A record's JSON form (pretty-printed, as `to_json` writes it).
pub fn json_of(p: &Record) -> Vec<u8> {
    p.to_json().unwrap().into_bytes()
}

/// Sign `p` as it stands with `label`'s key: algorithm, signature and payload
/// hash are set; the key material in the record is left as it is.
pub fn sign_as(p: &mut Record, label: &str) {
    let sig = vmr_record::sign::sign(&key(label), &p.signature_tbs().unwrap()).unwrap();
    p.signature.algorithm = "ES256".into();
    p.signature.signature = SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
}

/// Embed `label`'s key everywhere a record names its key (JWK, key id,
/// signing key id) and sign with it: an internally consistent record of
/// that key holder.
pub fn reissue_with(p: &mut Record, label: &str) {
    let j = jwk(label);
    p.issuer.key_id = j.key_id();
    p.signature.signing_key_id = j.key_id();
    p.issuer.public_key = j;
    sign_as(p, label);
}

/// The vector record, edited, then re-signed with key A (so only the edit
/// can make it fail).
pub fn vector_edited(edit: impl FnOnce(&mut Record)) -> Record {
    let mut p = vector();
    edit(&mut p);
    sign_as(&mut p, KEY_A);
    p
}

/// One trust-store key entry.
pub struct Entry {
    pub issuer_id: &'static str,
    pub issuer_name: &'static str,
    pub key: &'static str,
    pub level: &'static str,
    pub valid_from: &'static str,
    pub valid_until: Option<&'static str>,
    pub revoked: bool,
}

impl Entry {
    /// `key` trusted for `issuer_id` at `software`, 2026-01-01 .. 2027-01-01.
    pub fn new(issuer_id: &'static str, key: &'static str) -> Self {
        let issuer_name = if issuer_id == VECTOR_ISSUER { VECTOR_ISSUER_NAME } else { "Other Example" };
        Entry {
            issuer_id,
            issuer_name,
            key,
            level: "software",
            valid_from: "2026-01-01T00:00:00Z",
            valid_until: Some("2027-01-01T00:00:00Z"),
            revoked: false,
        }
    }
}

/// A store document holding `entries` (grouped by issuer, in order).
pub fn store_json(entries: &[Entry]) -> Value {
    let mut issuers: Vec<Value> = Vec::new();
    for e in entries {
        let mut k = json!({
            "key_id": key_id(e.key),
            "public_key": jwk(e.key),
            "attestation_level": e.level,
            "valid_from": e.valid_from,
            "revoked": e.revoked,
        });
        if let Some(u) = e.valid_until {
            k["valid_until"] = json!(u);
        }
        match issuers.iter_mut().find(|i| i["issuer_id"] == e.issuer_id) {
            Some(i) => i["keys"].as_array_mut().unwrap().push(k),
            None => issuers.push(json!({
                "issuer_id": e.issuer_id, "issuer_name": e.issuer_name, "keys": [k]
            })),
        }
    }
    json!({"trust_store_version": "0.1", "issuers": issuers})
}

pub fn store(entries: &[Entry]) -> TrustStore {
    TrustStore::from_json(serde_json::to_string_pretty(&store_json(entries)).unwrap().as_bytes()).unwrap()
}

/// The basic store: key A for the vector issuer, key B for another issuer.
pub fn basic_store() -> TrustStore {
    store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(OTHER_ISSUER, KEY_B)])
}

pub fn at(t: &str) -> VerifyOptions<'static> {
    VerifyOptions::new(Timestamp::parse(t).unwrap())
}

pub fn verify_json_with(store: TrustStore, input: &[u8], t: &str) -> VerificationReport {
    Verifier::new(store).verify_json(input, &at(t))
}

/// Verify `p`'s JSON form against the basic store at [`T`].
pub fn verify_basic(p: &Record) -> VerificationReport {
    verify_json_with(basic_store(), &json_of(p), T)
}

/// The report fails, first at `id`; every earlier check passed, every later
/// one was skipped.
pub fn assert_fails_at(report: &VerificationReport, id: CheckId) {
    let failure = report.failure.as_ref().unwrap_or_else(|| panic!("expected a failure at {id}"));
    assert_eq!(report.verdict, Verdict::Fail);
    assert_eq!(failure.check, id, "failed at {} instead: {}", failure.check, failure.detail);
    let pos = report.checks.iter().position(|c| c.id == id).unwrap();
    for (i, c) in report.checks.iter().enumerate() {
        let expected = match i.cmp(&pos) {
            std::cmp::Ordering::Less => c.outcome == Outcome::Pass || c.outcome == Outcome::NotEvaluated,
            std::cmp::Ordering::Equal => c.outcome == Outcome::Fail,
            std::cmp::Ordering::Greater => c.outcome == Outcome::Skipped,
        };
        assert!(expected, "{} is {:?} ({})", c.id, c.outcome, c.detail);
    }
    assert!(!report.accepted);
    assert_eq!(report.exit_code(), 3);
}

/// The report passes: every check passed (lineage.chain may be not
/// evaluated), no failure, accepted, exit code 0.
pub fn assert_passes(report: &VerificationReport) {
    assert_eq!(report.verdict, Verdict::Pass, "{:?}", report.failure);
    assert!(report.failure.is_none());
    for c in &report.checks {
        let ok = c.outcome == Outcome::Pass
            || (c.id == CheckId::LineageChain && c.outcome == Outcome::NotEvaluated);
        assert!(ok, "{} is {:?} ({})", c.id, c.outcome, c.detail);
    }
    assert!(report.accepted);
    assert_eq!(report.exit_code(), 0);
}

// ---------------------------------------------------------------------------
//  Nesting (spec §2 rule 13): texts and envelopes nested to a chosen depth
// ---------------------------------------------------------------------------

/// How deep `text` nests arrays and objects, the outermost counting as the
/// first level. Brackets inside strings (escaped quotes included) do not
/// count. Iterative, so any depth.
pub fn nesting_depth(text: &str) -> usize {
    let (mut depth, mut deepest) = (0usize, 0usize);
    let (mut in_string, mut escaped) = (false, false);
    for b in text.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

/// `n` empty arrays, each inside the one before: `n` levels.
pub fn nested_arrays(n: usize) -> String {
    format!("{}{}", "[".repeat(n), "]".repeat(n))
}

/// A record's compact JSON text, or its COSE payload, with the value of
/// `issuer.issuer_name` replaced by nested empty arrays, so that the text
/// nests exactly `levels` deep: the record object is level 1, `issuer`
/// level 2, the arrays levels 3 to `levels`. The rest of the text is as it
/// was.
pub fn nested_at_issuer_name(text: &str, levels: usize) -> String {
    let member = format!("\"issuer_name\":\"{VECTOR_ISSUER_NAME}\"");
    assert!(levels > 4, "a record already nests four levels");
    assert_eq!(text.matches(&member).count(), 1, "a compact text naming the vector issuer once");
    let deep = text.replacen(&member, &format!("\"issuer_name\":{}", nested_arrays(levels - 2)), 1);
    assert_eq!(nesting_depth(&deep), levels);
    deep
}

/// `p`'s COSE envelope with `payload` in place of its payload, signed over
/// it by key A, so that only a payload rule can object.
pub fn cose_with_payload(p: &Record, payload: Vec<u8>) -> Vec<u8> {
    use coset::{CborSerializable, CoseSign1};
    let mut s = CoseSign1::from_slice(&p.to_cose().unwrap()).unwrap();
    s.payload = Some(payload);
    s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
    s.to_vec().unwrap()
}

/// `p`'s COSE envelope with the CBOR bytes `map` in place of its empty
/// unprotected header (the byte `a0` at offset 97, for a v0.1 key id).
pub fn cose_with_unprotected(p: &Record, map: &[u8]) -> Vec<u8> {
    let good = p.to_cose().unwrap();
    assert_eq!(good[97], 0xa0, "the empty unprotected map");
    [&good[..97], map, &good[98..]].concat()
}

/// An unprotected header `{0: [[...]]}` that makes an envelope nest exactly
/// `levels` deep: the envelope's array is level 1, this map level 2, the
/// arrays of its value levels 3 to `levels`.
pub fn unprotected_nested(levels: usize) -> Vec<u8> {
    assert!(levels > 2);
    [&[0xa1, 0x00][..], &vec![0x81; levels - 3], &[0x80][..]].concat()
}

// ---------------------------------------------------------------------------
//  Objects written as the array of their values (QA QT-01)
// ---------------------------------------------------------------------------

/// Every object kind of a record (`*`: each element of an array), with its
/// members in declaration order: the order in which serde's derive reads a
/// struct from the array of its values.
pub const OBJECT_FIELDS: &[(&str, &[&str])] = &[
    ("", &["record_version", "record_id", "issued_at", "issuer", "model_identity", "learning_provenance", "deployment_context", "policy_compliance", "lineage", "data_governance", "human_oversight", "signature"]),
    ("/issuer", &["issuer_id", "issuer_name", "public_key", "key_id", "attestation_level"]),
    ("/issuer/public_key", &["kty", "crv", "x", "y"]),
    ("/model_identity", &["model_hash", "model_format", "parameter_count", "architecture", "learned_state_hash", "learned_state_components", "derived_from", "statement_references"]),
    ("/model_identity/architecture", &["type", "topology", "precision"]),
    ("/model_identity/learned_state_components/*", &["name", "hash", "size_bytes"]),
    ("/model_identity/derived_from/*", &["model_hash", "name", "relation"]),
    ("/model_identity/statement_references/*", &["format", "digest"]),
    ("/learning_provenance", &["training_input_digest", "training_input_merkle_root", "training_input_count", "training_epochs", "training_started_at", "training_ended_at", "training_environment", "training_input_provenance", "training_input_format", "training_input_disclosure"]),
    ("/learning_provenance/training_environment", &["hardware_id", "tee_measurement", "software_hash", "accelerator_software", "training_software", "accelerator"]),
    ("/learning_provenance/training_input_provenance", &["source_type", "source_description", "data_residency", "collection_period", "data_residency_countries"]),
    ("/learning_provenance/training_input_provenance/collection_period", &["start", "end"]),
    ("/deployment_context", &["deployment_id", "deployed_at", "deployed_by", "hardware_id", "tee_measurement", "software_hash", "inference_boundary", "policy_pack_id"]),
    ("/deployment_context/inference_boundary", &["type", "egress_allowed", "allowed_egress_destinations"]),
    ("/policy_compliance", &["policy_pack_id", "evaluated_at", "results", "overall_status"]),
    ("/policy_compliance/results/*", &["rule_id", "status", "evidence_hash"]),
    ("/lineage", &["previous_record_id", "previous_record_hash", "lineage_chain_length", "root_record_id", "lineage_type"]),
    ("/data_governance", &["documentation_hash"]),
    ("/human_oversight", &["documentation_hash"]),
    ("/signature", &["algorithm", "signature", "signed_payload_hash", "signing_key_id"]),
];

/// `doc` with the object at `pointer` replaced by the array of its values, in
/// the declaration order [`OBJECT_FIELDS`] gives for its kind. An optional
/// member the object lacks is left out, so the array is shorter than the
/// struct (serde's derive then reads it only if nothing follows the gap).
pub fn respelled_as_array(doc: &Value, pointer: &str) -> Value {
    let kind = pointer.split('/').map(|s| if s.parse::<usize>().is_ok() { "*" } else { s }).collect::<Vec<_>>().join("/");
    let fields = OBJECT_FIELDS.iter().find(|(k, _)| *k == kind).unwrap_or_else(|| panic!("no field order for {kind}")).1;
    let mut out = doc.clone();
    let object = out.pointer_mut(pointer).unwrap();
    let members = object.as_object().unwrap();
    assert!(members.keys().all(|k| fields.contains(&k.as_str())), "{pointer}: {members:?}");
    let values = fields.iter().filter_map(|f| members.get(*f).cloned()).collect();
    *object = Value::Array(values);
    out
}
