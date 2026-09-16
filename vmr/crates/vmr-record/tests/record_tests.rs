// tests/record_tests.rs — Record serde round trip, signing contract,
// COSE round trip (TASKS 3.7–3.9).

use vmr_record::record::*;
use vmr_record::sign::signing_key_from_secret;
use vmr_record::hash::sha256;
use vmr_record::integrity::IntegrityError;

fn sample_record() -> Record {
    let mut p = Record {
        record_version: "0.1".into(),
        record_id: "urn:uuid:00000000-0000-4000-8000-000000000001".into(),
        issued_at: "2026-09-10T00:00:00Z".into(),
        issuer: Issuer {
            issuer_id: "did:web:example.ph".into(),
            issuer_name: "Example Operator".into(),
            public_key: JwkPublicKey::from_verifying_key(test_key().verifying_key()),
            key_id: vmr_record::jwk::key_id(test_key().verifying_key()),
            attestation_level: "software".into(),
        },
        model_identity: ModelIdentity {
            model_hash: "sha256:".to_string() + &hex::encode(sha256(b"model")),
            model_format: "snn-compact-v1".into(),
            parameter_count: Some(4096),
            architecture: Architecture {
                kind: "spiking-neural-network".into(),
                topology: "fully-connected".into(),
                precision: "int8".into(),
            },
            learned_state_hash: "sha256:".to_string() + &hex::encode(sha256(b"state")),
            learned_state_components: vec![StateComponent {
                name: "afferent_H".into(),
                hash: "sha256:".to_string() + &hex::encode(sha256(b"aff")),
                size_bytes: 8192,
            }],
            derived_from: None,
            statement_references: None,
        },
        learning_provenance: LearningProvenance {
            training_input_digest: "sha256:".to_string() + &hex::encode(sha256(b"input")),
            training_input_merkle_root: "sha256:".to_string() + &hex::encode(sha256(b"root")),
            training_input_count: 16,
            training_epochs: Some(12),
            training_started_at: Some("2026-09-01T00:00:00Z".into()),
            training_ended_at: Some("2026-09-08T00:00:00Z".into()),
            training_environment: TrainingEnvironment {
                hardware_id: String::new(),
                tee_measurement: String::new(),
                software_hash: String::new(),
                accelerator_software: Some("CUDA 13.0".into()),
                training_software: "0.1.0".into(),
                accelerator: None,
            },
            training_input_provenance: TrainingInputProvenance {
                source_type: "sensor_stream".into(),
                source_description: "test".into(),
                data_residency: Some("PH".into()),
                collection_period: Some(Period {
                    start: "2026-08-01T00:00:00Z".into(),
                    end: "2026-08-31T00:00:00Z".into(),
                }),
                data_residency_countries: None,
            },
            training_input_format: None,
            training_input_disclosure: None,
        },
        deployment_context: Some(DeploymentContext {
            deployment_id: "urn:uuid:00000000-0000-4000-8000-000000000002".into(),
            deployed_at: "2026-09-10T00:00:00Z".into(),
            deployed_by: "did:web:example.ph".into(),
            hardware_id: String::new(),
            tee_measurement: String::new(),
            software_hash: String::new(),
            inference_boundary: InferenceBoundary {
                kind: "air-gapped".into(),
                egress_allowed: false,
                allowed_egress_destinations: vec![],
            },
            policy_pack_id: "example-policy-pack-v1".into(),
        }),
        policy_compliance: PolicyCompliance {
            policy_pack_id: "example-policy-pack-v1".into(),
            evaluated_at: "2026-09-10T00:00:00Z".into(),
            results: vec![PolicyResult {
                rule_id: "example-data-residency".into(),
                status: "pass".into(),
                evidence_hash: "sha256:".to_string() + &hex::encode(sha256(b"ev")),
            }],
            overall_status: "compliant".into(),
        },
        lineage: Lineage {
            previous_record_id: None,
            previous_record_hash: None,
            lineage_chain_length: 1,
            root_record_id: "urn:uuid:00000000-0000-4000-8000-000000000001".into(),
            lineage_type: "initial".into(),
        },
        data_governance: None,
        human_oversight: None,
        signature: SignatureSection {
            algorithm: String::new(),
            signature: String::new(),
            signed_payload_hash: String::new(),
            signing_key_id: vmr_record::jwk::key_id(test_key().verifying_key()),
        },
    };
    sign_record(&mut p, &test_key());
    p
}

fn sign_record(p: &mut Record, key: &p256::ecdsa::SigningKey) {
    let tbs = p.signature_tbs().unwrap();
    let sig = vmr_record::sign::sign(key, &tbs).unwrap();
    p.signature.algorithm = "ES256".into();
    p.signature.signature = SignatureSection::signature_field(&sig);
    p.signature.signed_payload_hash = vmr_record::hash::format_hash(&sha256(&p.signed_payload().unwrap()));
}

fn test_key() -> p256::ecdsa::SigningKey {
    signing_key_from_secret(&sha256(b"passport tests key")).unwrap()
}

#[test]
fn serde_round_trip_all_sections() {
    let p = sample_record();
    let text = p.to_json().unwrap();
    let back = Record::from_json(&text).unwrap();
    assert_eq!(p, back);
}

#[test]
fn signed_payload_excludes_signature() {
    let p = sample_record();
    let payload = String::from_utf8(p.signed_payload().unwrap()).unwrap();
    assert!(!payload.contains("signature"), "signature must be excluded");
    assert!(payload.contains("\"record_id\""));
    assert!(payload.contains("\"policy_compliance\""));
    // The embedded hash matches the payload.
    assert_eq!(p.signature.signed_payload_hash, p.signed_payload_hash().unwrap());
}

#[test]
fn signature_verifies_and_rejects_tampering() {
    let key = test_key();
    let mut p = sample_record();
    assert!(p.verify_signature(key.verifying_key()).is_ok());

    // Tamper with a signed field: verification must fail.
    *p.model_identity.parameter_count.as_mut().unwrap() += 1;
    assert!(p.verify_signature(key.verifying_key()).is_err());
}

#[test]
fn verify_checks_algorithm_and_payload_hash() {
    // QA P3-05: the signature section's `algorithm` and
    // `signed_payload_hash` are outside the signed payload, so nothing bound
    // them: "none" or a hash of nothing still verified. verify_signature now
    // checks both before the signature.
    let key = test_key();
    let p = sample_record();

    for alg in ["none", "es256", "ES384", ""] {
        let mut q = p.clone();
        q.signature.algorithm = alg.into();
        let err = q.verify_signature(key.verifying_key()).expect_err(alg);
        assert!(err.to_string().contains("algorithm"), "{alg}: {err}");
    }

    let mut zeros = p.clone();
    zeros.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
    let err = zeros.verify_signature(key.verifying_key()).unwrap_err();
    assert!(err.to_string().contains("signed_payload_hash"), "{err}");

    let mut empty = p.clone();
    empty.signature.signed_payload_hash = String::new();
    assert!(empty.verify_signature(key.verifying_key()).is_err());

    // The untouched record still verifies.
    p.verify_signature(key.verifying_key()).unwrap();
}

fn other_key() -> p256::ecdsa::SigningKey {
    signing_key_from_secret(&sha256(b"some other key")).unwrap()
}

#[test]
fn verify_requires_the_embedded_key_and_its_thumbprint() {
    // QA P3-07: the key id was documented as the RFC 7638 thumbprint of the
    // embedded JWK but never computed or checked, and verify_signature never
    // compared the key it was given with issuer.public_key. Each case below
    // carries a signature that is VALID for the key it is checked against,
    // so only the binding checks can reject it.
    let key = test_key();
    let other = other_key();
    let p = sample_record();
    p.verify_signature(key.verifying_key()).unwrap();

    // 1. Re-signed by another key, issuer.public_key left as it was.
    let mut q = p.clone();
    sign_record(&mut q, &other);
    let err = q.verify_signature(other.verifying_key()).unwrap_err();
    assert!(err.to_string().contains("issuer.public_key"), "{err}");

    // 2. issuer.key_id is not the thumbprint of issuer.public_key.
    let mut q = p.clone();
    q.issuer.key_id = vmr_record::jwk::key_id(other.verifying_key());
    q.signature.signing_key_id = q.issuer.key_id.clone();
    sign_record(&mut q, &key);
    let err = q.verify_signature(key.verifying_key()).unwrap_err();
    assert!(err.to_string().contains("issuer.key_id"), "{err}");

    // 3. signature.signing_key_id differs from issuer.key_id.
    let mut q = p.clone();
    q.signature.signing_key_id = "urn:example:another-kid".into();
    sign_record(&mut q, &key);
    let err = q.verify_signature(key.verifying_key()).unwrap_err();
    assert!(err.to_string().contains("signing_key_id"), "{err}");
}

#[test]
fn verification_proves_integrity_not_trust() {
    // What the binding does NOT do, pinned so nobody mistakes it for trust
    // (QA PROBE 6): a forger who swaps in their OWN key everywhere, and
    // re-signs, produces a record that is internally consistent and
    // verifies against the forger's key. It fails against the real issuer's
    // key - which only a trust store (Phase 4) can supply.
    let key = test_key();
    let forger = other_key();
    let mut forged = sample_record();
    forged.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
    forged.issuer.public_key = JwkPublicKey::from_verifying_key(forger.verifying_key());
    forged.issuer.key_id = vmr_record::jwk::key_id(forger.verifying_key());
    forged.signature.signing_key_id = forged.issuer.key_id.clone();
    sign_record(&mut forged, &forger);

    assert_eq!(forged.issuer.issuer_id, "did:web:example.ph", "still claims the issuer");
    assert!(forged.verify_signature(forger.verifying_key()).is_ok());
    assert!(forged.verify_signature(key.verifying_key()).is_err());
}

#[test]
fn from_cose_rejects_a_non_utf8_kid() {
    // The kid was decoded lossily (invalid bytes became U+FFFD); a key id is
    // text, so anything but valid UTF-8 is rejected.
    use coset::CborSerializable;
    let p = sample_record();
    let mut sign1 = coset::CoseSign1::from_slice(&p.to_cose().unwrap()).unwrap();
    sign1.protected = coset::ProtectedHeader {
        original_data: None,
        header: coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .key_id(vec![0xff, 0xfe])
            .build(),
    };
    let err = Record::from_cose(&sign1.to_vec().unwrap()).unwrap_err();
    assert!(err.to_string().contains("kid"), "{err}");
}

#[test]
fn high_s_twin_is_rejected_in_both_forms() {
    // QA P3-04: from one signed record, anyone could derive a second one
    // with signature (r, n - s) - different bytes, different document hash,
    // equally valid. Only the low-s form may verify, in JSON and in COSE.
    let key = test_key();
    let p = sample_record();
    let sig = p.signature.parsed_signature().unwrap();
    assert!(sig.normalize_s().is_none(), "the builder/sign path emits low-s");
    let high = p256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).unwrap();

    let mut json_twin = p.clone();
    json_twin.signature.signature = SignatureSection::signature_field(&high);
    assert_ne!(json_twin.signature.signature, p.signature.signature);
    let err = json_twin.verify_signature(key.verifying_key()).unwrap_err();
    assert!(err.to_string().contains("high-s"), "{err}");

    let cose_twin = json_twin.to_cose().unwrap();
    let back = Record::from_cose(&cose_twin).unwrap();
    assert!(back.verify_signature(key.verifying_key()).is_err());
    let sign1 = vmr_record::cose::decode_sign1(&cose_twin).unwrap();
    assert!(vmr_record::cose::verify_sign1(&sign1, key.verifying_key()).is_err());
}

#[test]
fn integers_above_2_53_minus_1_are_rejected() {
    // QA P3-10: a record integer above 2^53 - 1 has no exact ECMAScript
    // value, so its JCS form could not be RFC-conformant and exact at once.
    // Such records are refused when signing (signed_payload) and when
    // parsing - every integer field, and 2^53 - 1 itself still works.
    const MAX: u64 = (1 << 53) - 1;
    type Field = fn(&mut Record) -> &mut u64;
    let fields: [(&str, Field); 5] = [
        ("parameter_count", |p| p.model_identity.parameter_count.as_mut().unwrap()),
        ("size_bytes", |p| &mut p.model_identity.learned_state_components[0].size_bytes),
        ("training_input_count", |p| &mut p.learning_provenance.training_input_count),
        ("training_epochs", |p| p.learning_provenance.training_epochs.as_mut().unwrap()),
        ("lineage_chain_length", |p| &mut p.lineage.lineage_chain_length),
    ];
    let p = sample_record();
    for (name, field) in fields {
        let mut ok = p.clone();
        *field(&mut ok) = MAX;
        ok.signed_payload().unwrap();
        Record::from_json(&serde_json::to_string(&ok).unwrap()).unwrap();

        let mut big = p.clone();
        *field(&mut big) = MAX + 1;
        let err = big.signed_payload().unwrap_err();
        assert!(err.to_string().contains(name), "{name}: {err}");
        assert!(big.signature_tbs().is_err(), "{name}: cannot be signed");
        let text = serde_json::to_string(&big).unwrap();
        let err = Record::from_json(&text).unwrap_err();
        assert!(err.to_string().contains("2^53"), "{name}: {err}");
    }
}

#[test]
fn an_integer_has_one_spelling() {
    // QA P4-01, spec §2 rule 4: an integer is written `0` or a non-zero digit
    // followed by digits - the only spelling JCS produces. Every other
    // spelling below is a valid RFC 8259 number (serde_json reads each as a
    // float), so the parser must refuse it at the typed stage even when the
    // value is in range: anyone can respell a signed record without the
    // key, and two verifiers must never disagree about such bytes.
    let mut p = sample_record();
    for (value, spellings) in [
        (0u64, &["-0", "0.0", "-0.0", "0e0", "0E0", "0e+0", "0e-0", "0.0e0"][..]),
        (10, &["1e1", "1E1", "1e+1", "10.0", "100e-1", "1.0e1", "10e0"][..]),
    ] {
        p.learning_provenance.training_epochs = Some(value);
        let canonical = serde_json::to_string(&p).unwrap();
        let written = format!("\"training_epochs\":{value}");
        assert!(canonical.contains(&written), "{canonical}");
        assert_eq!(Record::from_json(&canonical).unwrap(), p, "the one spelling parses");
        for spelling in spellings {
            let text = canonical.replacen(&written, &format!("\"training_epochs\":{spelling}"), 1);
            serde_json::from_str::<serde_json::Value>(&text).expect("valid RFC 8259 syntax");
            let err = Record::from_json(&text).expect_err(spelling);
            assert!(matches!(err, vmr_record::Error::Json(_)), "{spelling}: {err}");
        }
    }
}

#[test]
fn cose_round_trip() {
    let key = test_key();
    let p = sample_record();
    let cose_bytes = p.to_cose().unwrap();
    let back = Record::from_cose(&cose_bytes).unwrap();
    assert_eq!(back, p);
    assert!(back.verify_signature(key.verifying_key()).is_ok());
}

/// Every object path in a JSON value (the root is `""`), including objects
/// inside arrays.
fn object_paths(v: &serde_json::Value, path: &str, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            out.push(path.to_string());
            for (k, child) in map {
                object_paths(child, &format!("{path}/{k}"), out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                object_paths(child, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn unknown_fields_are_rejected_at_every_level() {
    // QA P3-01: a field the issuer never signed must make the record
    // unparseable, not be dropped before the signature check while staying
    // in the document other tools read. Inject one at the top level and in
    // every nested object, one at a time.
    let p = sample_record();
    let base = serde_json::to_value(&p).unwrap();
    let mut paths = Vec::new();
    object_paths(&base, "", &mut paths);
    // Record + its 15 nested object kinds (the sample has one element in
    // each array, so every kind appears once).
    assert_eq!(paths.len(), 16, "{paths:?}");

    for path in &paths {
        let mut doc = base.clone();
        doc.pointer_mut(path)
            .and_then(|o| o.as_object_mut())
            .unwrap()
            .insert("injected_by_attacker".into(), serde_json::json!(true));
        let text = serde_json::to_string(&doc).unwrap();
        let err = Record::from_json(&text)
            .expect_err(&format!("unknown field at '{path}' must be rejected"));
        assert!(
            err.to_string().contains("unknown field"),
            "'{path}': unexpected error {err}"
        );
    }
    // The untouched document still parses.
    assert_eq!(Record::from_json(&serde_json::to_string(&base).unwrap()).unwrap(), p);
}

#[test]
fn signature_is_raw_r_s_in_both_forms() {
    // QA P3-02: RFC 9052 §8.1 fixes the ES256 signature as r||s, 32 bytes
    // each (64 bytes), not DER. The JSON field carries the same 64 bytes
    // (the JOSE ES256 encoding, RFC 7518 §3.4): 86 base64url characters.
    let p = sample_record();
    let text = p.signature.signature.strip_prefix("base64url:").unwrap();
    assert_eq!(text.len(), 86, "{text}");
    let json_bytes = vmr_record::encoding::b64url_decode(text).unwrap();
    assert_eq!(json_bytes.len(), 64);

    let sign1 = vmr_record::cose::decode_sign1(&p.to_cose().unwrap()).unwrap();
    assert_eq!(sign1.signature.len(), 64, "COSE ES256 signature must be raw r||s");
    assert_eq!(sign1.signature, json_bytes, "one signature, one encoding, both forms");
}

#[test]
fn der_signatures_are_rejected_in_both_forms() {
    // The pre-fix encoding (DER) is not a second accepted form.
    let key = test_key();
    let p = sample_record();
    let raw = vmr_record::encoding::b64url_decode(
        p.signature.signature.strip_prefix("base64url:").unwrap(),
    )
    .unwrap();
    let sig = p256::ecdsa::Signature::from_slice(&raw).unwrap();
    let der = sig.to_der().as_bytes().to_vec();

    let mut json_der = p.clone();
    json_der.signature.signature =
        format!("base64url:{}", vmr_record::encoding::b64url_encode(&der));
    assert!(json_der.verify_signature(key.verifying_key()).is_err());
    assert!(json_der.to_cose().is_err());

    use coset::CborSerializable;
    let mut sign1 = coset::CoseSign1::from_slice(&p.to_cose().unwrap()).unwrap();
    sign1.signature = der;
    let cose_der = sign1.to_vec().unwrap();
    assert!(Record::from_cose(&cose_der).is_err());
    let decoded = vmr_record::cose::decode_sign1(&cose_der).unwrap();
    assert!(vmr_record::cose::verify_sign1(&decoded, key.verifying_key()).is_err());

    // The signature field's `base64url:` prefix is required, not optional.
    let mut bare = p.clone();
    bare.signature.signature = p.signature.signature["base64url:".len()..].to_string();
    assert!(bare.verify_signature(key.verifying_key()).is_err());
    assert!(bare.to_cose().is_err());
}

/// Re-encode `cose` with its payload replaced by `f(payload)`; the
/// protected header and the signature bytes are kept as they are.
fn with_payload(cose: &[u8], f: impl Fn(&str) -> String) -> Vec<u8> {
    use coset::CborSerializable;
    let mut sign1 = coset::CoseSign1::from_slice(cose).unwrap();
    let text = String::from_utf8(sign1.payload.take().unwrap()).unwrap();
    sign1.payload = Some(f(&text).into_bytes());
    sign1.to_vec().unwrap()
}

#[test]
fn cose_payload_must_be_the_exact_signed_bytes() {
    // The COSE signature covers the envelope's payload bytes. from_cose used
    // to re-canonicalize whatever JSON it found there, so envelopes whose
    // payload is NOT the signed byte string still "verified" here, while any
    // conformant COSE verifier rejects them: a parser differential. Two
    // cases: a `signature` member smuggled into the payload (a known field,
    // so deny_unknown_fields does not catch it), and the same content in a
    // non-canonical encoding.
    let key = test_key();
    let p = sample_record();
    let cose = p.to_cose().unwrap();

    let smuggled = with_payload(&cose, |t| {
        format!(
            "{},\"signature\":{{\"algorithm\":\"none\",\"signature\":\"\",\
             \"signed_payload_hash\":\"\",\"signing_key_id\":\"\"}}}}",
            &t[..t.len() - 1]
        )
    });
    let pretty = with_payload(&cose, |t| {
        let v: serde_json::Value = serde_json::from_str(t).unwrap();
        serde_json::to_string_pretty(&v).unwrap()
    });
    for (what, bytes) in [("smuggled signature member", smuggled), ("non-canonical", pretty)] {
        // A standard COSE check of the envelope as it stands fails ...
        let sign1 = vmr_record::cose::decode_sign1(&bytes).unwrap();
        assert!(
            vmr_record::cose::verify_sign1(&sign1, key.verifying_key()).is_err(),
            "{what}: the envelope's own signature check must fail"
        );
        // ... so from_cose must not turn it into a verifying record.
        let err = Record::from_cose(&bytes).expect_err(what);
        assert!(err.to_string().contains("canonical"), "{what}: {err}");
    }
}

#[test]
fn cose_rejects_tampered_bytes() {
    // QA P3-13: this test flipped the byte at len/2 and unwrap()ed the
    // parse, so it passed only while that offset happened to stay parseable
    // (the P3-07 fixture change moved it onto one that is not). Now:
    let key = test_key();
    let p = sample_record();
    let bytes = p.to_cose().unwrap();

    // 1. An arbitrary flip must never verify - rejected at decode time or at
    //    verification, whichever the byte's position decides.
    let mut blind = bytes.clone();
    blind[bytes.len() / 2] ^= 0x01;
    let verified = Record::from_cose(&blind)
        .map(|back| back.verify_signature(key.verifying_key()).is_ok())
        .unwrap_or(false);
    assert!(!verified);

    // 2. Flips at offsets chosen to keep the envelope DECODABLE, so the
    //    rejection must come from verification itself: a letter inside a
    //    signed string value (payload), a letter of the protected header's
    //    kid (its first occurrence - the header precedes the payload), and
    //    the low bit of s (the envelope's last byte).
    let find = |needle: &[u8]| bytes.windows(needle.len()).position(|w| w == needle).unwrap();
    let targets = [
        ("payload string value", find(b"Example Operator") + 1, 0x20),
        ("protected-header kid", find(b"jwk-thumbprint"), 0x20),
        ("signature s", bytes.len() - 1, 0x01),
    ];
    for (what, idx, mask) in targets {
        let mut t = bytes.clone();
        t[idx] ^= mask;
        let back = Record::from_cose(&t).unwrap_or_else(|e| panic!("{what}: must decode: {e}"));
        assert_ne!(back, p, "{what}: the flip changed the decoded record");
        assert!(back.verify_signature(key.verifying_key()).is_err(), "{what}");
    }
}

// ---------------------------------------------------------------------------
//  Phase 4 task 4.0b: strict presence rules (spec §2.3) and typed integrity
//  errors (docs/dev/phase4.md §2.3 #1-#2).
// ---------------------------------------------------------------------------

/// `p` as a JSON object, with `edit` applied to it.
fn json_with(p: &Record, edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> String {
    let mut v = serde_json::to_value(p).unwrap();
    edit(v.as_object_mut().unwrap());
    serde_json::to_string(&v).unwrap()
}

#[test]
fn from_json_requires_the_signature_member() {
    // §2.3 #1: a JSON record without its `signature` member parsed (the
    // section defaulted to empty strings), so a schema-invalid document got
    // past the parser and failed later for a misleading reason.
    let p = sample_record();
    let text = json_with(&p, |o| {
        o.remove("signature");
    });
    let err = Record::from_json(&text).expect_err("a record without `signature` must not parse");
    assert!(err.to_string().contains("missing field `signature`"), "{err}");
}

#[test]
fn optional_lineage_members_may_be_absent_but_never_null() {
    // §2.3 #2: spec §2.3 says the two optional lineage members are omitted,
    // never `null`; the schema types them `string`. `null` parsed as absent
    // (and then verified), so a document the schema rejects was accepted.
    let p = sample_record();
    for member in ["previous_record_id", "previous_record_hash"] {
        let text = json_with(&p, |o| {
            o["lineage"].as_object_mut().unwrap().insert(member.into(), serde_json::Value::Null);
        });
        let err = Record::from_json(&text).expect_err(member);
        assert!(err.to_string().contains("invalid type: null"), "{member}: {err}");
    }
    // Absent: fine (the sample is an initial record), and so is a string.
    assert!(p.lineage.previous_record_id.is_none());
    Record::from_json(&p.to_json().unwrap()).unwrap();
    let mut q = p.clone();
    q.lineage.previous_record_id = Some("urn:uuid:00000000-0000-4000-8000-000000000009".into());
    q.lineage.previous_record_hash = Some(format!("sha256:{}", "ab".repeat(32)));
    assert_eq!(Record::from_json(&q.to_json().unwrap()).unwrap(), q);
}

#[test]
fn the_integrity_sample_is_not_a_conforming_record() {
    // docs/dev/phase4.md 4.3a: this file's sample (one state component,
    // parameter_count 4 096) exercises the signing contract; it is not a v0.1
    // record a verifier accepts, and verifier tests must not use it. Since
    // task 10.11b the schema allows one component (spec §7.3), and the sample
    // names the profile snn-compact-v1, whose three components (§7.4) it lacks.
    let p = sample_record();
    p.verify_signature(test_key().verifying_key()).unwrap();
    p.validate_format().unwrap();
    let err = p.check_consistency().unwrap_err();
    assert_eq!((err.pointer.as_str(), err.rule), ("/model_identity/learned_state_components", "consistency"));
}

// ---------------------------------------------------------------------------
//  Task 10.11a, D11-1: the optional members `data_governance` and
//  `human_oversight`, each a closed object pinning one document by SHA-256.
// ---------------------------------------------------------------------------

fn documentation(label: &[u8]) -> DocumentationRef {
    DocumentationRef { documentation_hash: vmr_record::hash::format_hash(&sha256(label)) }
}

#[test]
fn absent_documentation_members_are_not_written() {
    // D11-1: absent members are omitted, never `null`. A record without
    // them serialises exactly as one did before they existed, so no signed
    // payload, hash or signature of an existing record moves.
    let p = sample_record();
    assert!(p.data_governance.is_none() && p.human_oversight.is_none());
    let payload = String::from_utf8(p.signed_payload().unwrap()).unwrap();
    let json = p.to_json().unwrap();
    for name in ["data_governance", "human_oversight", "documentation_hash"] {
        assert!(!payload.contains(name), "{name} in the signed payload");
        assert!(!json.contains(name), "{name} in the JSON form");
    }
}

#[test]
fn documentation_members_round_trip_in_both_forms_and_are_signed() {
    let key = test_key();
    let mut p = sample_record();
    p.data_governance = Some(documentation(b"data governance"));
    p.human_oversight = Some(documentation(b"human oversight"));
    sign_record(&mut p, &key);

    let payload = String::from_utf8(p.signed_payload().unwrap()).unwrap();
    let expected = format!(
        "\"data_governance\":{{\"documentation_hash\":\"{}\"}}",
        p.data_governance.as_ref().unwrap().documentation_hash
    );
    assert!(payload.contains(&expected), "{payload}");

    assert_eq!(Record::from_json(&p.to_json().unwrap()).unwrap(), p);
    let back = Record::from_cose(&p.to_cose().unwrap()).unwrap();
    assert_eq!(back, p);
    back.verify_signature(key.verifying_key()).unwrap();

    // The signature covers each member: another document, or none.
    let mut other = p.clone();
    other.human_oversight = Some(documentation(b"another document"));
    assert!(other.verify_signature(key.verifying_key()).is_err());
    let mut removed = p.clone();
    removed.data_governance = None;
    assert!(removed.verify_signature(key.verifying_key()).is_err());
}

#[test]
fn documentation_members_are_closed_objects_and_never_null() {
    // Spec §2 rules 2 and 3: an optional member is omitted, never `null`,
    // and its object has exactly the schema's members.
    let p = sample_record();
    let hash = documentation(b"doc").documentation_hash;
    for member in ["data_governance", "human_oversight"] {
        for (value, expect) in [
            (serde_json::Value::Null, "invalid type: null"),
            (serde_json::json!({}), "missing field `documentation_hash`"),
            (serde_json::json!({"documentation_hash": hash, "title": "x"}), "unknown field `title`"),
            (serde_json::json!({"documentation_hash": null}), "invalid type: null"),
            (serde_json::json!(hash), "invalid type: string"),
            // QA QT-01: the array of its one value, which serde's derive
            // reads as the struct.
            (serde_json::json!([hash]), "invalid type: sequence"),
        ] {
            let text = json_with(&p, |o| {
                o.insert(member.into(), value.clone());
            });
            let err = Record::from_json(&text).expect_err(member);
            assert!(err.to_string().contains(expect), "{member} = {value}: {err}");
        }
        let text = json_with(&p, |o| {
            o.insert(member.into(), serde_json::json!({ "documentation_hash": hash }));
        });
        assert!(Record::from_json(&text).unwrap().data_governance.is_some() == (member == "data_governance"));
    }
}

/// Every object kind of a record (`*`: each element of an array), with its
/// members in declaration order: the order in which serde's derive reads a
/// struct from the array of its values (QA QT-01).
const OBJECT_FIELDS: &[(&str, &[&str])] = &[
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
/// the declaration order `OBJECT_FIELDS` gives for its kind.
fn respelled_as_array(doc: &serde_json::Value, pointer: &str) -> serde_json::Value {
    let kind = pointer.split('/').map(|s| if s.parse::<usize>().is_ok() { "*" } else { s }).collect::<Vec<_>>().join("/");
    let fields = OBJECT_FIELDS.iter().find(|(k, _)| *k == kind).unwrap_or_else(|| panic!("no field order for {kind}")).1;
    let mut out = doc.clone();
    let object = out.pointer_mut(pointer).unwrap();
    let members = object.as_object().unwrap();
    assert_eq!(members.len(), fields.len(), "{pointer}: {members:?}");
    let values = fields.iter().map(|f| members.get(*f).unwrap_or_else(|| panic!("{pointer}: no member {f}")).clone()).collect();
    *object = serde_json::Value::Array(values);
    out
}

#[test]
fn every_object_written_as_the_array_of_its_values_is_refused() {
    // QA QT-01 (spec §2 rules 2 and 13, check 4j): serde's derive reads a
    // struct from the array of its values in declaration order, and the
    // signed payload is re-derived from the parsed struct, so each text
    // below was the signed record. Every object kind, the record itself
    // included, one at a time; serde_json reads each respelling as this
    // record, and Record::from_json refuses it.
    let mut p = with_every_new_optional_member();
    p.data_governance = Some(documentation(b"data governance"));
    p.human_oversight = Some(documentation(b"human oversight"));
    // Every optional member present, so that every object has all of its
    // members and each respelling is one serde_json reads.
    p.lineage.previous_record_id = Some("urn:uuid:00000000-0000-4000-8000-000000000000".into());
    p.lineage.previous_record_hash = Some(vmr_record::hash::format_hash(&sha256(b"previous")));
    let base = serde_json::to_value(&p).unwrap();
    let mut paths = Vec::new();
    object_paths(&base, "", &mut paths);
    assert_eq!(paths.len(), OBJECT_FIELDS.len(), "the record and its 19 nested object kinds, once each: {paths:?}");
    for path in &paths {
        let text = serde_json::to_string(&respelled_as_array(&base, path)).unwrap();
        assert_eq!(serde_json::from_str::<Record>(&text).unwrap(), p, "{path}: serde_json reads the respelling as the record");
        let err = Record::from_json(&text).expect_err(path).to_string();
        assert!(err.contains("invalid type: sequence, expected "), "{path}: {err}");
    }
}

#[test]
fn check_integrity_names_each_reason() {
    // The integrity steps of verify_signature, as typed reasons a verifier can
    // map to its check ids without matching message text. Every case below is
    // one of the P3-02/04/05/07 cases, and each carries exactly one fault.
    let key = test_key();
    let other = other_key();
    let p = sample_record();
    p.check_integrity(key.verifying_key()).unwrap();

    let expect = |q: &Record, k: &p256::ecdsa::SigningKey, what: &str| -> IntegrityError {
        let err = q.check_integrity(k.verifying_key()).expect_err(what);
        // verify_signature is check_integrity plus a conversion: same message.
        let old = q.verify_signature(k.verifying_key()).unwrap_err();
        assert_eq!(err.to_string(), old.to_string(), "{what}");
        err
    };

    let mut q = p.clone();
    q.signature.algorithm = "none".into();
    assert!(matches!(expect(&q, &key, "algorithm"), IntegrityError::Algorithm(ref a) if a == "none"));

    let mut q = p.clone();
    q.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
    assert!(matches!(expect(&q, &key, "payload hash"), IntegrityError::PayloadHash));

    // Re-signed by another key; checked against that key, which is not
    // issuer.public_key.
    let mut q = p.clone();
    sign_record(&mut q, &other);
    assert!(matches!(expect(&q, &other, "foreign key"), IntegrityError::KeyNotIssuerKey));

    let mut q = p.clone();
    q.issuer.key_id = vmr_record::jwk::key_id(other.verifying_key());
    q.signature.signing_key_id = q.issuer.key_id.clone();
    sign_record(&mut q, &key);
    assert!(matches!(expect(&q, &key, "key id"), IntegrityError::KeyIdNotThumbprint));

    let mut q = p.clone();
    q.signature.signing_key_id = "urn:example:another-kid".into();
    sign_record(&mut q, &key);
    assert!(matches!(expect(&q, &key, "signing key id"), IntegrityError::SigningKeyIdMismatch));

    for bad in [
        p.signature.signature["base64url:".len()..].to_string(), // prefix missing
        format!("base64url:{}", vmr_record::encoding::b64url_encode(
            p.signature.parsed_signature().unwrap().to_der().as_bytes(),
        )), // DER
        format!("base64url:{}", vmr_record::encoding::b64url_encode(&[7u8; 63])), // 63 bytes
    ] {
        let mut q = p.clone();
        q.signature.signature = bad;
        assert!(matches!(expect(&q, &key, "encoding"), IntegrityError::SignatureEncoding(_)));
    }

    let sig = p.signature.parsed_signature().unwrap();
    let mut q = p.clone();
    q.signature.signature = SignatureSection::signature_field(
        &p256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).unwrap(),
    );
    assert!(matches!(expect(&q, &key, "high-s"), IntegrityError::HighS));

    // A signed field changed and the payload hash recomputed to match: only
    // the ECDSA check itself can catch it.
    let mut q = p.clone();
    *q.model_identity.parameter_count.as_mut().unwrap() += 1;
    q.signature.signed_payload_hash = q.signed_payload_hash().unwrap();
    assert!(matches!(expect(&q, &key, "tampered"), IntegrityError::BadSignature(_)));
}

// ---------------------------------------------------------------------------
//  Task 10.11b: the new optional members (D11b-3 to D11b-10)
// ---------------------------------------------------------------------------

/// Each new optional member, with the object that holds it
/// (`parameter_count` since QA QB-09, `statement_references` since task
/// 10.11e).
const NEW_OPTIONAL: [(&str, &str); 14] = [
    ("", "deployment_context"),
    ("/model_identity", "parameter_count"),
    ("/model_identity", "derived_from"),
    ("/model_identity", "statement_references"),
    ("/learning_provenance", "training_epochs"),
    ("/learning_provenance", "training_started_at"),
    ("/learning_provenance", "training_ended_at"),
    ("/learning_provenance", "training_input_format"),
    ("/learning_provenance", "training_input_disclosure"),
    ("/learning_provenance/training_environment", "accelerator_software"),
    ("/learning_provenance/training_environment", "accelerator"),
    ("/learning_provenance/training_input_provenance", "data_residency"),
    ("/learning_provenance/training_input_provenance", "collection_period"),
    ("/learning_provenance/training_input_provenance", "data_residency_countries"),
];

/// The sample record with every new optional member present, signed. It
/// is not consistent (spec §7, §8): only parsing and signing run on it.
fn with_every_new_optional_member() -> Record {
    let mut p = sample_record();
    p.model_identity.derived_from = Some(vec![BaseModel {
        model_hash: vmr_record::hash::format_hash(&sha256(b"base")),
        name: "base".into(),
        relation: "fine-tune".into(),
    }]);
    p.model_identity.statement_references = Some(vec![StatementReference {
        format: "oms-v1".into(),
        digest: vmr_record::hash::format_hash(&sha256(b"an in-toto statement")),
    }]);
    p.learning_provenance.training_input_format = Some("named-set-v1".into());
    p.learning_provenance.training_input_disclosure = Some("not-held".into());
    p.learning_provenance.training_environment.accelerator = Some("8 accelerators".into());
    p.learning_provenance.training_input_provenance.data_residency_countries = Some(vec!["DE".into(), "FR".into()]);
    sign_record(&mut p, &test_key());
    p
}

/// The sample record with none of the new optional members, signed.
fn without_new_optional_members() -> Record {
    let mut p = sample_record();
    p.deployment_context = None;
    p.model_identity.parameter_count = None;
    let l = &mut p.learning_provenance;
    (l.training_epochs, l.training_started_at, l.training_ended_at) = (None, None, None);
    l.training_environment.accelerator_software = None;
    l.training_input_provenance.data_residency = None;
    l.training_input_provenance.collection_period = None;
    sign_record(&mut p, &test_key());
    p
}

/// `p`'s JSON text with the object at `parent` edited.
fn json_edited_at(p: &Record, parent: &str, edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>)) -> String {
    let mut v = serde_json::to_value(p).unwrap();
    edit(v.pointer_mut(parent).unwrap().as_object_mut().unwrap());
    serde_json::to_string(&v).unwrap()
}

#[test]
fn absent_new_optional_members_are_not_written_and_present_ones_are_signed() {
    // D11b-15: a record without the new members serialises as one did
    // before they existed, so no signed payload moves; a present member is in
    // the signed payload and reads back in both forms.
    let key = test_key();
    let bare = without_new_optional_members();
    let full = with_every_new_optional_member();
    let (bare_payload, full_payload) =
        (String::from_utf8(bare.signed_payload().unwrap()).unwrap(), String::from_utf8(full.signed_payload().unwrap()).unwrap());
    for (_, member) in NEW_OPTIONAL {
        let name = format!("\"{member}\"");
        assert!(!bare_payload.contains(&name) && !bare.to_json().unwrap().contains(&name), "{member} written when absent");
        assert!(full_payload.contains(&name), "{member} is not in the signed payload when present");
    }
    for p in [&bare, &full] {
        assert_eq!(&Record::from_json(&p.to_json().unwrap()).unwrap(), p);
        let back = Record::from_cose(&p.to_cose().unwrap()).unwrap();
        assert_eq!(&back, p);
        back.verify_signature(key.verifying_key()).unwrap();
    }
    let mut unsigned = full.clone();
    unsigned.model_identity.derived_from = None;
    assert!(unsigned.verify_signature(key.verifying_key()).is_err(), "derived_from is signed");
}

#[test]
fn new_optional_members_are_never_null() {
    // Spec §2 rule 3: an optional member is omitted, never `null`.
    let p = with_every_new_optional_member();
    for (parent, member) in NEW_OPTIONAL {
        let text = json_edited_at(&p, parent, |o| {
            o.insert(member.into(), serde_json::Value::Null);
        });
        let err = Record::from_json(&text).expect_err(member).to_string();
        assert!(err.contains("invalid type: null"), "{member}: {err}");
    }
}

#[test]
fn a_derived_from_entry_and_the_new_objects_are_never_read_from_an_array() {
    // QA QT-01 through strict_json: a derived_from entry written as the array
    // of its values in declaration order, which serde's derive reads as the
    // entry, is refused; so is the new members' parent written so.
    let p = with_every_new_optional_member();
    let entry = serde_json::to_value(&p.model_identity.derived_from.as_ref().unwrap()[0]).unwrap();
    let text = json_edited_at(&p, "/model_identity", |o| {
        o.insert(
            "derived_from".into(),
            serde_json::json!([[entry["model_hash"], entry["name"], entry["relation"]]]),
        );
    });
    assert_eq!(serde_json::from_str::<Record>(&text).unwrap(), p, "serde's derive reads the respelling as the record");
    let err = Record::from_json(&text).unwrap_err().to_string();
    assert!(err.contains("invalid type: sequence, expected "), "{err}");
    for kind in ["/learning_provenance/training_environment", "/learning_provenance/training_input_provenance"] {
        let text = serde_json::to_string(&respelled_as_array(&serde_json::to_value(&p).unwrap(), kind)).unwrap();
        assert!(Record::from_json(&text).unwrap_err().to_string().contains("invalid type: sequence"), "{kind}");
    }
}

#[test]
fn a_statement_reference_is_closed_and_never_read_from_an_array() {
    // Task 10.11e (D11e-2, D11e-8): an entry holds exactly `format` and
    // `digest`, both strings, and both required. Written as the array of its
    // values in declaration order, which serde's derive reads as the entry, it
    // is refused through strict_json (QA QT-01).
    let p = with_every_new_optional_member();
    let entry = serde_json::to_value(&p.model_identity.statement_references.as_ref().unwrap()[0]).unwrap();
    let with_entry = |value: serde_json::Value| {
        json_edited_at(&p, "/model_identity", |o| {
            o.insert("statement_references".into(), serde_json::json!([value]));
        })
    };
    let as_array = with_entry(serde_json::json!([entry["format"], entry["digest"]]));
    assert_eq!(serde_json::from_str::<Record>(&as_array).unwrap(), p, "serde's derive reads the respelling as the record");
    let err = Record::from_json(&as_array).unwrap_err().to_string();
    assert!(err.contains("invalid type: sequence, expected "), "{err}");
    let mut unknown = entry.clone();
    unknown["location"] = "https://example.org/bundle".into();
    assert!(Record::from_json(&with_entry(unknown)).unwrap_err().to_string().contains("unknown field"));
    let mut number = entry.clone();
    number["format"] = 1.into();
    assert!(Record::from_json(&with_entry(number)).unwrap_err().to_string().contains("invalid type"));
    for member in ["format", "digest"] {
        let mut missing = entry.clone();
        missing.as_object_mut().unwrap().remove(member);
        let err = Record::from_json(&with_entry(missing)).unwrap_err().to_string();
        assert!(err.contains("missing field"), "{member}: {err}");
    }
}
