// tests/conformance_tests.rs — the committed v0.1 test vector is the
// contract: re-emitting the record must reproduce the vector's expected
// canonical signed payload byte-for-byte, and the vector's signature must
// verify against the documented fixed signing key.

use serde_json::Value;
use vmr_record::hash::sha256;
use vmr_record::record::Record;
use vmr_record::sign::signing_key_from_secret;

fn vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("specs")
        .join("test-vectors")
        .join("record")
        .join("example-v0.1.json")
}

fn load_vector() -> Value {
    let text = std::fs::read_to_string(vector_path())
        .expect("committed test vector must exist under specs/test-vectors/");
    serde_json::from_str(&text).expect("vector must be valid JSON")
}

#[test]
fn canonical_payload_matches_committed_vector() {
    let vector = load_vector();
    let record: Record = serde_json::from_value(vector["record"].clone())
        .expect("vector record must parse");
    let expected_payload = vector["expected"]["signed_payload"]
        .as_str()
        .expect("vector must carry expected.signed_payload");

    let payload = String::from_utf8(record.signed_payload().unwrap()).unwrap();
    assert_eq!(payload, expected_payload);
}

#[test]
fn signed_payload_hash_matches_committed_vector() {
    let vector = load_vector();
    let record: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let expected_hash = vector["expected"]["signed_payload_hash"].as_str().unwrap();
    assert_eq!(record.signature.signed_payload_hash, expected_hash);
    assert_eq!(
        record.signed_payload_hash().unwrap(),
        record.signature.signed_payload_hash
    );
}

#[test]
fn vector_signature_verifies_with_documented_key() {
    let vector = load_vector();
    let record: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    // The key the vector documents: secret = SHA-256 of the fixed string.
    let key = signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key"))
        .expect("documented secret must be a valid scalar");
    record
        .verify_signature(key.verifying_key())
        .expect("vector signature must verify");
}

#[test]
fn vector_signature_is_raw_r_s() {
    // QA P3-02: the committed vector's signature is the 64-byte r||s form
    // (86 base64url characters), in the JSON field and in the COSE envelope.
    let vector = load_vector();
    let record: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let text = record.signature.signature.strip_prefix("base64url:").unwrap();
    assert_eq!(text.len(), 86);
    let raw = vmr_record::encoding::b64url_decode(text).unwrap();
    assert_eq!(raw.len(), 64);
    let sign1 = vmr_record::cose::decode_sign1(&record.to_cose().unwrap()).unwrap();
    assert_eq!(sign1.signature, raw);
}

#[test]
fn vector_signature_section_fields_are_checked() {
    // QA P3-05, PROBE 5 against the committed vector.
    let vector = load_vector();
    let base: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let key = signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap();

    let mut lying = base.clone();
    lying.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
    assert!(lying.verify_signature(key.verifying_key()).is_err());

    let mut none = base.clone();
    none.signature.algorithm = "none".into();
    assert!(none.verify_signature(key.verifying_key()).is_err());
}

#[test]
fn vector_signature_is_low_s_and_its_twin_is_rejected() {
    // QA P3-04, PROBE 4 against the committed vector.
    let vector = load_vector();
    let p: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let key = signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap();
    let sig = p.signature.parsed_signature().unwrap();
    assert!(sig.normalize_s().is_none(), "the committed signature is low-s");

    let high = p256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).unwrap();
    let mut twin = p.clone();
    twin.signature.signature =
        vmr_record::record::SignatureSection::signature_field(&high);
    assert!(twin.verify_signature(key.verifying_key()).is_err());
}

#[test]
fn vector_key_ids_are_the_jwk_thumbprint() {
    // QA P3-07: the committed vector's key ids were the literal
    // "urn:ietf:params:oauth:jwk-thumbprint:test-vector-v0.1". They are the
    // RFC 7638 thumbprint URN of the embedded JWK - computed independently
    // (Python cryptography + hashlib) as below - and the JWK is the key
    // derived from the documented secret.
    const KID: &str =
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg";
    let vector = load_vector();
    let p: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let key = signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap();
    assert_eq!(
        p.issuer.public_key,
        vmr_record::record::JwkPublicKey::from_verifying_key(key.verifying_key())
    );
    assert_eq!(p.issuer.public_key.key_id(), KID);
    assert_eq!(p.issuer.key_id, KID);
    assert_eq!(p.signature.signing_key_id, KID);
}

/// The vector's 16 training frames, exactly as examples/emit_vector.rs
/// generates them (2 words per frame).
fn vector_frames() -> Vec<[u32; 2]> {
    (1..=16u32)
        .map(|t| [0x0000_FFFF ^ t.wrapping_mul(0x9E37_79B9), t.wrapping_mul(0x85EB_CA6B) | 1])
        .collect()
}

#[test]
fn vector_merkle_root_recomputes_from_its_frames() {
    // Pins merkle_root's output (QA P3-08 changed the proof format, not the
    // root): leaf i = frame i's words as little-endian bytes.
    use vmr_record::merkle::{inclusion_proof, merkle_root, verify_inclusion};
    let vector = load_vector();
    let p: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let leaves: Vec<Vec<u8>> = vector_frames()
        .iter()
        .map(|f| f.iter().flat_map(|w| w.to_le_bytes()).collect())
        .collect();
    let root = merkle_root(&leaves);
    assert_eq!(
        vmr_record::hash::format_hash(&root),
        p.learning_provenance.training_input_merkle_root
    );
    // An inclusion proof checks against the signed root AND the signed
    // leaf count (training_input_count), never a count taken from the proof.
    let count = p.learning_provenance.training_input_count as usize;
    assert_eq!(count, leaves.len());
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = inclusion_proof(&leaves, i).unwrap();
        assert!(verify_inclusion(&root, count, leaf, &proof));
    }
}

#[test]
fn vector_signature_rejects_tampering() {
    let vector = load_vector();
    let mut record: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    record.learning_provenance.training_epochs = record.learning_provenance.training_epochs.map(|e| e + 1);
    let key = signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap();
    assert!(record.verify_signature(key.verifying_key()).is_err());
}

#[test]
fn the_vector_declares_a_neutral_example_pack() {
    // Owner decision, 2026-09-12 (spec §10): a test vector names no real
    // authority, and no jurisdiction's pack is the reference. The policy
    // section is illustrative: a neutral example pack, declared compliant
    // with four example results.
    let vector = load_vector();
    let p: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    assert_eq!(p.deployment_context.as_ref().unwrap().policy_pack_id, "example-policy-pack-v1");
    assert_eq!(p.policy_compliance.policy_pack_id, "example-policy-pack-v1");
    assert_eq!(p.policy_compliance.overall_status, "compliant");
    let rules: Vec<(&str, &str)> =
        p.policy_compliance.results.iter().map(|r| (r.rule_id.as_str(), r.status.as_str())).collect();
    assert_eq!(
        rules,
        [
            ("example-data-residency", "pass"),
            ("example-source-screening", "pass"),
            ("example-export-control", "pass"),
            ("example-audit-trail", "pass"),
        ]
    );
}

fn schema_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("specs")
        .join("record-schema")
        .join("v0.1.json")
}

fn load_schema() -> Value {
    let text = std::fs::read_to_string(schema_path()).expect("schema must exist under specs/");
    serde_json::from_str(&text).expect("schema must be valid JSON")
}

#[test]
fn injected_fields_make_the_vector_unparseable() {
    // QA P3-01, PROBE 2: the three nested fields the QA injected, plus a
    // top-level one. Each must be rejected at parse time; before the fix
    // serde dropped them, the signature still verified, and the fields
    // stayed in the document.
    let vector = load_vector();
    let injections: [(&str, &str); 4] = [
        ("/policy_compliance", "waiver"),
        ("/deployment_context/inference_boundary", "egress_override"),
        ("/issuer", "issuer_name_display"),
        ("", "trusted"),
    ];
    for (path, field) in injections {
        let mut doc = vector["record"].clone();
        doc.pointer_mut(path)
            .and_then(|o| o.as_object_mut())
            .unwrap()
            .insert(field.into(), serde_json::json!("granted-by-attacker"));
        let text = serde_json::to_string(&doc).unwrap();
        let err = Record::from_json(&text)
            .expect_err(&format!("injected '{path}/{field}' must be rejected"));
        assert!(err.to_string().contains("unknown field"), "{err}");
    }
}

/// Walk `value` against `schema`: every schema object must be closed
/// (`additionalProperties: false`), every member of `value` must be a
/// declared property, and every required property must be present.
fn check_closed(schema: &Value, value: &Value, path: &str) {
    match schema["type"].as_str() {
        Some("object") => {
            assert_eq!(
                schema["additionalProperties"],
                Value::Bool(false),
                "schema object at '{path}' must forbid additional properties"
            );
            let props = schema["properties"].as_object().unwrap();
            let obj = value.as_object().unwrap_or_else(|| panic!("'{path}' is not an object"));
            for key in obj.keys() {
                assert!(props.contains_key(key), "'{path}/{key}' is not in the schema");
            }
            for req in schema["required"].as_array().into_iter().flatten() {
                assert!(obj.contains_key(req.as_str().unwrap()), "'{path}' lacks {req}");
            }
            for (key, sub) in props {
                if let Some(child) = obj.get(key) {
                    check_closed(sub, child, &format!("{path}/{key}"));
                }
            }
        }
        Some("array") => {
            for (i, item) in value.as_array().unwrap().iter().enumerate() {
                check_closed(&schema["items"], item, &format!("{path}/{i}"));
            }
        }
        _ => {}
    }
}

#[test]
fn schema_closes_every_object_and_describes_the_vector() {
    // QA P3-01, schema half: 15 nested objects were open to additional
    // properties, so an injected field was schema-valid as well as
    // signature-valid.
    let schema = load_schema();
    let vector = load_vector();
    check_closed(&schema, &vector["record"], "");

    // Independently of the vector: every object schema anywhere in the file
    // is closed, and there are 20 of them: the record, its 15 nested kinds,
    // the two optional documentation members (task 10.11a, D11-1), an entry
    // of `derived_from` (task 10.11b, D11b-6), and an entry of
    // `statement_references` (task 10.11e, D11e-2).
    fn closed_objects(node: &Value) -> usize {
        match node {
            Value::Object(map) => {
                let here = map.get("type") == Some(&Value::from("object"));
                if here {
                    assert_eq!(map.get("additionalProperties"), Some(&Value::Bool(false)));
                }
                usize::from(here) + map.values().map(closed_objects).sum::<usize>()
            }
            Value::Array(items) => items.iter().map(closed_objects).sum(),
            _ => 0,
        }
    }
    assert_eq!(closed_objects(&schema), 20);
}

#[test]
fn schema_optional_members_are_the_ones_spec_2_rule_3_lists() {
    // Spec §2 rule 3: the only optional members are the two lineage links;
    // since task 10.11a (D11-1), `data_governance` and `human_oversight`; and
    // since task 10.11b (D11b-3 to D11b-10), the members an issuer may not
    // know or not have. Each documentation member is a closed object holding
    // exactly one required `documentation_hash`, a hash string (§2 rule 5, no
    // "" form).
    let schema = load_schema();
    let mut optional = Vec::new();
    let mut all = vec![(String::new(), schema.clone())];
    property_schemas(&schema, "", &mut all);
    for (path, node) in &all {
        let Some(props) = node.get("properties").and_then(Value::as_object) else { continue };
        let required: Vec<&str> =
            node["required"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        for name in props.keys() {
            if !required.contains(&name.as_str()) {
                optional.push(format!("{path}/{name}"));
            }
        }
    }
    optional.sort();
    assert_eq!(
        optional,
        sorted(&[
            "/data_governance",
            "/human_oversight",
            "/lineage/previous_record_hash",
            "/lineage/previous_record_id",
            "/deployment_context",
            "/model_identity/parameter_count",
            "/model_identity/derived_from",
            "/model_identity/statement_references",
            "/learning_provenance/training_epochs",
            "/learning_provenance/training_started_at",
            "/learning_provenance/training_ended_at",
            "/learning_provenance/training_input_format",
            "/learning_provenance/training_input_disclosure",
            "/learning_provenance/training_environment/accelerator_software",
            "/learning_provenance/training_environment/accelerator",
            "/learning_provenance/training_input_provenance/data_residency",
            "/learning_provenance/training_input_provenance/collection_period",
            "/learning_provenance/training_input_provenance/data_residency_countries",
        ])
    );
    let hash = &schema["properties"]["model_identity"]["properties"]["model_hash"];
    for member in ["data_governance", "human_oversight"] {
        let node = &schema["properties"][member];
        assert_eq!(node["type"], "object", "{member}");
        assert_eq!(node["additionalProperties"], false, "{member}");
        assert_eq!(node["required"], serde_json::json!(["documentation_hash"]), "{member}");
        let props = node["properties"].as_object().unwrap();
        assert_eq!(props.keys().collect::<Vec<_>>(), ["documentation_hash"], "{member}");
        assert_eq!(props["documentation_hash"], *hash, "{member}: the hash-string rule");
    }
    // The vector declares neither: it did not change.
    let vector = load_vector();
    assert!(vector["record"].get("data_governance").is_none());
    assert!(vector["record"].get("human_oversight").is_none());
}

#[test]
fn schema_limits_every_integer_to_2_53_minus_1() {
    // QA P3-10, schema half: the same limit the parser and builder enforce.
    fn integers(node: &Value, path: &str, out: &mut Vec<(String, Value)>) {
        match node {
            Value::Object(map) => {
                if map.get("type") == Some(&Value::from("integer")) {
                    out.push((path.to_string(), map.get("maximum").cloned().unwrap_or(Value::Null)));
                }
                for (k, v) in map {
                    integers(v, &format!("{path}/{k}"), out);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| integers(v, path, out)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    integers(&load_schema(), "", &mut found);
    assert_eq!(found.len(), 5, "{found:?}");
    for (path, max) in found {
        assert_eq!(max, Value::from(9_007_199_254_740_991u64), "{path}");
    }
}

#[test]
fn vector_cose_round_trip_is_identical() {
    let vector = load_vector();
    let record: Record = serde_json::from_value(vector["record"].clone()).unwrap();
    let cose = record.to_cose().unwrap();
    let back = Record::from_cose(&cose).unwrap();
    assert_eq!(back, record);
    assert_eq!(back.to_json().unwrap(), record.to_json().unwrap());
}

// ---------------------------------------------------------------------------
//  Phase 4 task 4.0d, decision D4: the tightened v0.1 string rules. Each
//  rule is pinned where it lives in the schema, and the committed vector is
//  checked against every rule by a small, independent validator (the
//  `regex` crate, a dev-dependency only - never on a verification path).
// ---------------------------------------------------------------------------

const TIMESTAMP_PATTERN: &str =
    "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$";
const UUID_URN_PATTERN: &str =
    "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
const OPTIONAL_HASH_PATTERN: &str = "^(sha256:[0-9a-f]{64})?$";
const DID_PATTERN: &str =
    "^did:[a-z0-9]+:([A-Za-z0-9._:-]|%[0-9A-Fa-f]{2})*([A-Za-z0-9._-]|%[0-9A-Fa-f]{2})$";

/// Every property schema in `node` with its instance path (`/a/b`; `*` for
/// array items), in a deterministic order.
fn property_schemas(node: &Value, path: &str, out: &mut Vec<(String, Value)>) {
    if let Some(props) = node.get("properties").and_then(Value::as_object) {
        for (k, sub) in props {
            let p = format!("{path}/{k}");
            out.push((p.clone(), sub.clone()));
            property_schemas(sub, &p, out);
        }
    }
    if let Some(items) = node.get("items") {
        let p = format!("{path}/*");
        out.push((p.clone(), items.clone()));
        property_schemas(items, &p, out);
    }
}

/// The instance paths whose schema has `keyword` == `value`, sorted.
fn paths_with(keyword: &str, value: &Value) -> Vec<String> {
    let mut all = Vec::new();
    property_schemas(&load_schema(), "", &mut all);
    let mut found: Vec<String> = all
        .into_iter()
        .filter(|(_, s)| s.get(keyword) == Some(value))
        .map(|(p, _)| p)
        .collect();
    found.sort();
    found
}

fn sorted(paths: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
    v.sort();
    v
}

#[test]
fn schema_timestamps_use_the_utc_seconds_profile() {
    // D4 (a): JSON Schema 2020-12 treats `format` as an annotation, so a
    // standard validator checked no timestamp at all. Every date-time field
    // now also carries the UTC-seconds profile YYYY-MM-DDTHH:MM:SSZ as a
    // pattern (calendar validity - e.g. no Feb 30 - is spec text, checked by
    // the reference implementation).
    let dated = paths_with("format", &Value::from("date-time"));
    assert_eq!(
        dated,
        sorted(&[
            "/issued_at",
            "/learning_provenance/training_started_at",
            "/learning_provenance/training_ended_at",
            "/learning_provenance/training_input_provenance/collection_period/start",
            "/learning_provenance/training_input_provenance/collection_period/end",
            "/deployment_context/deployed_at",
            "/policy_compliance/evaluated_at",
        ])
    );
    assert_eq!(paths_with("pattern", &Value::from(TIMESTAMP_PATTERN)), dated);
}

#[test]
fn schema_ids_are_canonical_lowercase_uuid_urns() {
    // D4 (b): only record_id had a pattern, and a loose one (36
    // hex-or-dash characters, either case); lineage ids were free text.
    assert_eq!(
        paths_with("pattern", &Value::from(UUID_URN_PATTERN)),
        sorted(&[
            "/record_id",
            "/deployment_context/deployment_id",
            "/lineage/previous_record_id",
            "/lineage/root_record_id",
        ])
    );
}

#[test]
fn schema_optional_hashes_are_sha256_or_empty() {
    // D4 (c): documented as `sha256:<hex>` or "" in record.rs, but
    // unconstrained in the schema. Task 10.11b (D11b-5): the two training
    // commitments are "" when the record commits to no records (§8.4).
    assert_eq!(
        paths_with("pattern", &Value::from(OPTIONAL_HASH_PATTERN)),
        sorted(&[
            "/learning_provenance/training_input_digest",
            "/learning_provenance/training_input_merkle_root",
            "/learning_provenance/training_environment/hardware_id",
            "/learning_provenance/training_environment/tee_measurement",
            "/learning_provenance/training_environment/software_hash",
            "/deployment_context/hardware_id",
            "/deployment_context/tee_measurement",
            "/deployment_context/software_hash",
        ])
    );
}

#[test]
fn schema_dids_use_the_did_core_syntax() {
    // D4 (d): `^did:` let look-alike Unicode into the field users read as
    // identity. W3C DID Core syntax, ASCII only.
    assert_eq!(
        paths_with("pattern", &Value::from(DID_PATTERN)),
        sorted(&["/issuer/issuer_id", "/deployment_context/deployed_by"])
    );
}

#[test]
fn schema_requires_one_or_more_components_and_leaves_the_profile_to_consistency() {
    // Task 10.11b (D11b-3): the general description names one or more
    // components (spec §7.3). The profile snn-compact-v1's exactly three,
    // named and ordered (§7.4; D4 (e)), are the verifier's format.consistency,
    // selected by model_format: the schema cannot say it, and no longer
    // pretends every model has three.
    let mut all = Vec::new();
    property_schemas(&load_schema(), "", &mut all);
    let find = |path: &str| all.iter().find(|(p, _)| p == path).unwrap().1.clone();
    let comps = find("/model_identity/learned_state_components");
    assert_eq!(comps["minItems"], Value::from(1));
    assert!(comps.get("maxItems").is_none());
    assert!(find("/model_identity/learned_state_components/*/name").get("enum").is_none());
}

/// A validator for exactly the JSON Schema keywords the record schema
/// uses; any other keyword is an error (so the schema cannot silently grow
/// a rule this oracle ignores). Errors are `path: message`.
fn validate(schema: &Value, value: &Value, path: &str, errors: &mut Vec<String>) {
    const KNOWN: [&str; 18] = [
        "$schema", "$id", "title", "description", "type", "const", "enum", "pattern", "format",
        "minimum", "maximum", "minItems", "maxItems", "minLength", "required", "properties",
        "additionalProperties", "items",
    ];
    let obj = schema.as_object().expect("schema node is an object");
    for k in obj.keys() {
        assert!(KNOWN.contains(&k.as_str()), "unknown schema keyword {k} at {path}");
    }
    let ty = obj.get("type").and_then(Value::as_str).expect("every schema node has a type");
    let type_ok = match ty {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_u64() || value.is_i64(),
        "boolean" => value.is_boolean(),
        other => panic!("unexpected type {other}"),
    };
    if !type_ok {
        errors.push(format!("{path}: not a {ty}"));
        return;
    }
    if let Some(c) = obj.get("const") {
        if c != value {
            errors.push(format!("{path}: const"));
        }
    }
    if let Some(e) = obj.get("enum").and_then(Value::as_array) {
        if !e.contains(value) {
            errors.push(format!("{path}: enum"));
        }
    }
    if let (Some(p), Some(s)) = (obj.get("pattern").and_then(Value::as_str), value.as_str()) {
        if !regex::Regex::new(p).unwrap().is_match(s) {
            errors.push(format!("{path}: pattern {p}"));
        }
    }
    if let (Some(m), Some(s)) = (obj.get("minLength").and_then(Value::as_u64), value.as_str()) {
        if (s.chars().count() as u64) < m {
            errors.push(format!("{path}: minLength"));
        }
    }
    if let Some(n) = value.as_u64() {
        if obj.get("minimum").and_then(Value::as_u64).is_some_and(|m| n < m) {
            errors.push(format!("{path}: minimum"));
        }
        if obj.get("maximum").and_then(Value::as_u64).is_some_and(|m| n > m) {
            errors.push(format!("{path}: maximum"));
        }
    }
    if let Some(items) = value.as_array() {
        let len = items.len() as u64;
        if obj.get("minItems").and_then(Value::as_u64).is_some_and(|m| len < m) {
            errors.push(format!("{path}: minItems"));
        }
        if obj.get("maxItems").and_then(Value::as_u64).is_some_and(|m| len > m) {
            errors.push(format!("{path}: maxItems"));
        }
        for (i, item) in items.iter().enumerate() {
            validate(&obj["items"], item, &format!("{path}/{i}"), errors);
        }
    }
    if let Some(members) = value.as_object() {
        let props = obj["properties"].as_object().unwrap();
        for req in obj.get("required").and_then(Value::as_array).into_iter().flatten() {
            if !members.contains_key(req.as_str().unwrap()) {
                errors.push(format!("{path}: required {req}"));
            }
        }
        assert_eq!(obj.get("additionalProperties"), Some(&Value::Bool(false)), "{path}");
        for (k, v) in members {
            match props.get(k) {
                Some(sub) => validate(sub, v, &format!("{path}/{k}"), errors),
                None => errors.push(format!("{path}: additional property {k}")),
            }
        }
    }
}

#[test]
fn the_committed_vector_satisfies_every_schema_rule() {
    // Acceptance of 4.0d: the tightened schema changes no vector byte - every
    // value in the vector already satisfies every rule.
    let schema = load_schema();
    let vector = load_vector();
    let mut errors = Vec::new();
    validate(&schema, &vector["record"], "", &mut errors);
    assert!(errors.is_empty(), "{errors:#?}");

    // And the validator is not vacuous: one violation per new rule class
    // (the DID case uses U+0430 CYRILLIC SMALL LETTER A for the `a`).
    let cases: [(&str, Value, &str); 6] = [
        ("/issued_at", Value::from("2026-09-10 00:00:00Z"), "/issued_at: pattern"),
        (
            "/record_id",
            Value::from("urn:uuid:2B6A0C48-9F21-4F3A-8C51-1D0B4A7E9C00"),
            "/record_id: pattern",
        ),
        ("/lineage/root_record_id", Value::from("root"), "/lineage/root_record_id: pattern"),
        (
            "/deployment_context/hardware_id",
            Value::from("none"),
            "/deployment_context/hardware_id: pattern",
        ),
        (
            "/issuer/issuer_id",
            Value::from("did:web:f\u{430}ctory-operator.ph"),
            "/issuer/issuer_id: pattern",
        ),
        (
            "/model_identity/learned_state_components/2",
            Value::Null,
            "/model_identity/learned_state_components: minItems",
        ),
    ];
    for (pointer, bad, expected) in cases {
        let mut doc = vector["record"].clone();
        if bad.is_null() {
            doc["model_identity"]["learned_state_components"].as_array_mut().unwrap().clear();
        } else {
            *doc.pointer_mut(pointer).unwrap() = bad;
        }
        let mut errors = Vec::new();
        validate(&schema, &doc, "", &mut errors);
        assert!(errors.iter().any(|e| e.starts_with(expected)), "{pointer}: {errors:?}");
    }
}
