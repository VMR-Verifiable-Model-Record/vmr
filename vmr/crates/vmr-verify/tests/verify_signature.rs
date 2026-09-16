// tests/verify_signature.rs — checks 5-19: format, signature, key binding
// and trust (Phase 4 task 4.3; TASKS "test_verify_sig"). Every case asserts
// the verdict AND the first failing check id. Negative records that need
// a valid signature are the vector re-signed with derived test keys.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_record::record::{Record, SignatureSection};
use vmr_verify::report::CheckId;

#[test]
fn the_vector_verifies_against_the_vector_store() {
    let report = verify_basic(&vector());
    assert_passes(&report);
    // The issuer section is the trust store's view, not the record's.
    let issuer = report.issuer.expect("issuer section once signature.valid and trust.issuer passed");
    assert_eq!(issuer.issuer_id, VECTOR_ISSUER);
    assert_eq!(issuer.issuer_name, VECTOR_ISSUER_NAME);
    assert_eq!(issuer.key_id, key_id(KEY_A));
    assert_eq!(issuer.attestation_level, "software");
    let ids: Vec<CheckId> = report.checks.iter().map(|c| c.id).collect();
    assert!(ids.contains(&CheckId::TimeNotFuture));
}

#[test]
fn any_json_encoding_of_the_same_record_verifies() {
    // Pretty, compact, members reordered, a character written as a \u
    // escape: one signed payload, one hash.
    let v = vector_file()["record"].clone();
    let compact = serde_json::to_string(&v).unwrap();
    let mut reordered = serde_json::Map::new();
    for (k, val) in v.as_object().unwrap().iter().rev() {
        reordered.insert(k.clone(), val.clone());
    }
    let escaped = compact.replace("New Clark", "New \\u0043lark");
    assert_ne!(escaped, compact);
    let expected = vector_file()["expected"]["signed_payload_hash"].as_str().unwrap().to_string();
    for text in [
        serde_json::to_string_pretty(&v).unwrap(),
        compact.clone(),
        serde_json::to_string(&Value::Object(reordered)).unwrap(),
        escaped,
    ] {
        let report = verify_json_with(basic_store(), text.as_bytes(), T);
        assert_passes(&report);
        assert_eq!(report.record.unwrap().signed_payload_hash.as_deref(), Some(expected.as_str()));
    }
}

#[test]
fn a_forged_record_fails_trust_key_known() {
    // QA PROBE 6: the forger swaps in their own key everywhere and re-signs.
    // The record is internally consistent and its signature verifies
    // against the embedded key - which proves nothing: the trust store does
    // not know that key.
    let mut forged = vector();
    forged.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
    reissue_with(&mut forged, KEY_F);
    forged.verify_signature(key(KEY_F).verifying_key()).unwrap();
    assert_eq!(forged.issuer.issuer_id, VECTOR_ISSUER, "it still claims the issuer");
    let report = verify_basic(&forged);
    assert_fails_at(&report, CheckId::TrustKeyKnown);
    assert!(report.issuer.is_none(), "no trusted issuer for an unknown key");
}

#[test]
fn a_key_trusted_for_another_issuer_fails_trust_issuer() {
    let store = store(&[Entry::new(OTHER_ISSUER, KEY_A)]);
    let report = verify_json_with(store, &json_of(&vector()), T);
    assert_fails_at(&report, CheckId::TrustIssuer);
    // QA P4-05: the key does not speak for the issuer the record names, so
    // the report names no issuer - not the store's entry for this key.
    assert!(report.issuer.is_none(), "no issuer before trust.issuer passes");
}

#[test]
fn a_forgery_citing_a_trusted_key_names_no_issuer() {
    // QA P4-05: key ids are public. A forger embeds the vector issuer's
    // genuine key and key id - so key.binding and trust.key_known pass - and
    // signs other content with their own key. signature.valid fails, and the
    // report must not name the genuine issuer the key belongs to: `issuer`
    // appears only once signature.valid and trust.issuer have passed.
    let mut forged = vector();
    forged.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
    sign_as(&mut forged, KEY_F);
    assert_eq!(forged.signature.signing_key_id, key_id(KEY_A), "cites trusted key A");
    let report = verify_basic(&forged);
    assert_fails_at(&report, CheckId::SignatureValid);
    assert!(report.issuer.is_none(), "{:?}", report.issuer);
    let cose = vmr_verify::Verifier::new(basic_store()).verify_cose(&forged.to_cose().unwrap(), &at(T));
    assert_fails_at(&cose, CheckId::SignatureValid);
    assert!(cose.issuer.is_none(), "{:?}", cose.issuer);
    // Signed by another TRUSTED key (B) while citing A: the same.
    let mut by_b = vector();
    sign_as(&mut by_b, KEY_B);
    let two = store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(VECTOR_ISSUER, KEY_B)]);
    let report = verify_json_with(two, &json_of(&by_b), T);
    assert_fails_at(&report, CheckId::SignatureValid);
    assert!(report.issuer.is_none(), "{:?}", report.issuer);
}

#[test]
fn a_failure_after_trust_issuer_still_names_the_issuer() {
    // From trust.issuer on, the name is truthful: the trusted key really
    // signed this record and speaks for the issuer it names. A later
    // failure - revocation, the key's window, attestation, time, lineage -
    // keeps it, so a report can say whose revoked key signed.
    let mut revoked = Entry::new(VECTOR_ISSUER, KEY_A);
    revoked.revoked = true;
    let mut expired = Entry::new(VECTOR_ISSUER, KEY_A);
    expired.valid_until = Some("2026-09-10T00:00:00Z");
    let hardware_claim = vector_edited(|p| p.issuer.attestation_level = "hardware".into());
    let orphan = {
        let mut p = vector();
        p.lineage.lineage_type = "training-update".into();
        sign_as(&mut p, KEY_A);
        p
    };
    for (what, report, check) in [
        ("revoked", verify_json_with(store(&[revoked]), &json_of(&vector()), T), CheckId::TrustKeyNotRevoked),
        ("expired", verify_json_with(store(&[expired]), &json_of(&vector()), T), CheckId::TrustKeyValidity),
        ("over-claim", verify_basic(&hardware_claim), CheckId::TrustAttestation),
        ("future", verify_json_with(basic_store(), &json_of(&vector()), "2026-09-09T23:59:59Z"), CheckId::TimeNotFuture),
        ("lineage", verify_basic(&orphan), CheckId::LineageConsistency),
    ] {
        assert_fails_at(&report, check);
        let issuer = report.issuer.unwrap_or_else(|| panic!("{what}: the issuer is named"));
        assert_eq!((issuer.issuer_id.as_str(), issuer.issuer_name.as_str()), (VECTOR_ISSUER, VECTOR_ISSUER_NAME), "{what}");
        assert_eq!(issuer.key_id, key_id(KEY_A), "{what}");
    }
}

#[test]
fn a_revoked_key_fails_trust_key_not_revoked() {
    let mut e = Entry::new(VECTOR_ISSUER, KEY_A);
    e.revoked = true;
    let report = verify_json_with(store(&[e]), &json_of(&vector()), T);
    assert_fails_at(&report, CheckId::TrustKeyNotRevoked);
}

#[test]
fn the_key_window_bounds_issued_at() {
    // The vector's issued_at is 2026-09-10T00:00:00Z.
    let window = |from: &'static str, until: Option<&'static str>| {
        let mut e = Entry::new(VECTOR_ISSUER, KEY_A);
        e.valid_from = from;
        e.valid_until = until;
        verify_json_with(store(&[e]), &json_of(&vector()), T)
    };
    assert_fails_at(&window("2026-09-10T00:00:01Z", None), CheckId::TrustKeyValidity);
    assert_fails_at(
        &window("2026-01-01T00:00:00Z", Some("2026-09-10T00:00:00Z")),
        CheckId::TrustKeyValidity,
    );
    assert_passes(&window("2026-09-10T00:00:00Z", Some("2026-09-10T00:00:01Z")));
    assert_passes(&window("2026-09-10T00:00:00Z", None));
    // The window judges issued_at, not T: a record outlives its key's
    // expiry (spec §6.4).
    let expired = {
        let mut e = Entry::new(VECTOR_ISSUER, KEY_A);
        e.valid_until = Some("2026-09-10T00:00:01Z");
        e
    };
    assert_passes(&verify_json_with(store(&[expired]), &json_of(&vector()), "2030-01-01T00:00:00Z"));
}

#[test]
fn a_declared_attestation_above_the_stores_fails_trust_attestation() {
    let hardware_claim = vector_edited(|p| p.issuer.attestation_level = "hardware".into());
    assert_fails_at(&verify_basic(&hardware_claim), CheckId::TrustAttestation);
    // An under-claim passes.
    let mut e = Entry::new(VECTOR_ISSUER, KEY_A);
    e.level = "hardware";
    assert_passes(&verify_json_with(store(&[e]), &json_of(&hardware_claim), T));
    let self_claim = vector_edited(|p| p.issuer.attestation_level = "self".into());
    assert_passes(&verify_basic(&self_claim));
}

#[test]
fn issued_after_the_evaluation_time_fails_time_not_future() {
    let p = json_of(&vector());
    assert_fails_at(&verify_json_with(basic_store(), &p, "2026-09-09T23:59:59Z"), CheckId::TimeNotFuture);
    assert_passes(&verify_json_with(basic_store(), &p, "2026-09-10T00:00:00Z"));
}

#[test]
fn a_policy_evaluated_after_issuance_fails_time_policy_not_after_issued() {
    // P6-6: policy_compliance.evaluated_at is inside the signed payload, so
    // a value later than issued_at claims a result the signature could not
    // have covered. Unlike time.not_future this uses no evaluation time T:
    // it is a relation between two of the record's own claims.
    let later = vector_edited(|p| p.policy_compliance.evaluated_at = "2026-09-10T00:00:01Z".into());
    assert_fails_at(&verify_basic(&later), CheckId::TimePolicyNotAfterIssued);
    // Equal passes (the vector itself: evaluated_at == issued_at), earlier
    // passes, and a re-signed record is judged the same way.
    assert_passes(&verify_basic(&vector()));
    let earlier = vector_edited(|p| p.policy_compliance.evaluated_at = "2026-09-09T00:00:00Z".into());
    assert_passes(&verify_basic(&earlier));
    // The check runs after trust: a record nobody trusts fails earlier.
    let mut forged = vector_edited(|p| p.policy_compliance.evaluated_at = "2026-09-10T00:00:01Z".into());
    reissue_with(&mut forged, KEY_F);
    assert_fails_at(&verify_basic(&forged), CheckId::TrustKeyKnown);
}

#[test]
fn a_wrong_algorithm_fails_signature_algorithm() {
    for alg in ["none", "es256", "", "ES384"] {
        let mut p = vector();
        p.signature.algorithm = alg.into();
        assert_fails_at(&verify_basic(&p), CheckId::SignatureAlgorithm);
    }
}

#[test]
fn a_badly_encoded_signature_fails_signature_encoding() {
    let v = vector();
    let raw = vmr_record::encoding::b64url_decode(v.signature.signature.strip_prefix("base64url:").unwrap()).unwrap();
    let der = p256::ecdsa::Signature::from_slice(&raw).unwrap().to_der().as_bytes().to_vec();
    let b64 = |bytes: &[u8]| format!("base64url:{}", vmr_record::encoding::b64url_encode(bytes));
    let mut long = raw.clone();
    long.push(0);
    let mut zero_r = raw.clone();
    zero_r[..32].fill(0);
    for bad in [
        b64(&der),
        v.signature.signature["base64url:".len()..].to_string(),
        b64(&raw[..63]),
        b64(&long),
        b64(&zero_r),
        format!("{}=", v.signature.signature),
    ] {
        let mut p = v.clone();
        p.signature.signature = bad.clone();
        assert_fails_at(&verify_basic(&p), CheckId::SignatureEncoding);
    }
}

#[test]
fn the_high_s_twin_fails_signature_low_s() {
    let mut p = vector();
    let sig = p.signature.parsed_signature().unwrap();
    let high = p256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).unwrap();
    p.signature.signature = SignatureSection::signature_field(&high);
    assert_fails_at(&verify_basic(&p), CheckId::SignatureLowS);
}

#[test]
fn a_lying_payload_hash_fails_signature_payload_hash() {
    let mut p = vector();
    p.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
    assert_fails_at(&verify_basic(&p), CheckId::SignaturePayloadHash);
}

#[test]
fn a_record_inconsistent_about_its_key_fails_key_binding() {
    // issuer.key_id is not the thumbprint of issuer.public_key.
    let p = vector_edited(|p| {
        p.issuer.key_id = key_id(KEY_B);
        p.signature.signing_key_id = key_id(KEY_B);
    });
    assert_fails_at(&verify_basic(&p), CheckId::KeyBinding);
    // signing_key_id differs from issuer.key_id.
    let p = vector_edited(|p| p.signature.signing_key_id = key_id(KEY_B));
    assert_fails_at(&verify_basic(&p), CheckId::KeyBinding);
    // issuer.public_key is not a point on P-256.
    let p = vector_edited(|p| p.issuer.public_key.y = p.issuer.public_key.x.clone());
    assert_fails_at(&verify_basic(&p), CheckId::KeyBinding);
}

#[test]
fn a_signature_by_another_trusted_key_fails_signature_valid() {
    // Signed by trusted key B, while claiming key A (also trusted): the
    // lookup finds A, and the signature does not verify under A.
    let mut p = vector();
    sign_as(&mut p, KEY_B);
    let store = store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(VECTOR_ISSUER, KEY_B)]);
    assert_fails_at(&verify_json_with(store, &json_of(&p), T), CheckId::SignatureValid);
}

#[test]
fn a_signed_field_changed_after_signing_fails_signature_valid() {
    // The tamperer also fixes up signed_payload_hash, so only the signature
    // itself can notice.
    let mut p = vector();
    p.learning_provenance.training_epochs = p.learning_provenance.training_epochs.map(|e| e + 1);
    p.signature.signed_payload_hash = p.signed_payload_hash().unwrap();
    assert_fails_at(&verify_basic(&p), CheckId::SignatureValid);
    // Without the fix-up, the payload hash check catches it first.
    let mut p = vector();
    p.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
    assert_fails_at(&verify_basic(&p), CheckId::SignaturePayloadHash);
}

#[test]
fn a_signature_that_does_not_match_is_explained_in_plain_words() {
    // What a reader of the headline needs: the signature does not match, and
    // why that can be - the record changed after signing, or the signature
    // is damaged or another key's. Never the crypto library's own text
    // ("signature: signature error"). The demo's tamper (a claim changed
    // after signing, JSON and COSE), a forgery citing a trusted key, and a
    // signature by another trusted key all read the same.
    const MISMATCH: &str = "the signature does not match the record's signed content under the trust \
        store's key: the record was changed after it was signed, or its signature was damaged or made \
        with another key";
    let mut tampered = vector();
    tampered.learning_provenance.training_input_provenance.data_residency = Some("SG".into());
    tampered.signature.signed_payload_hash = tampered.signed_payload_hash().unwrap();
    let mut forged = vector();
    sign_as(&mut forged, KEY_F);
    let mut by_b = vector();
    sign_as(&mut by_b, KEY_B);
    let two = store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(VECTOR_ISSUER, KEY_B)]);
    let reports = [
        ("tampered, JSON", verify_basic(&tampered)),
        ("tampered, COSE", vmr_verify::Verifier::new(basic_store()).verify_cose(&tampered.to_cose().unwrap(), &at(T))),
        ("forged citing a trusted key", verify_basic(&forged)),
        ("signed by another trusted key", verify_json_with(two, &json_of(&by_b), T)),
    ];
    for (what, report) in reports {
        assert_fails_at(&report, CheckId::SignatureValid);
        let detail = report.failure.unwrap().detail;
        assert_eq!(detail, MISMATCH, "{what}");
        assert!(!detail.contains("signature error"), "{what}: {detail}");
    }
}

/// Every object path of a JSON value (`""` = the root).
fn object_paths(v: &Value, path: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            out.push(path.to_string());
            for (k, child) in map {
                object_paths(child, &format!("{path}/{k}"), out);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                object_paths(child, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn an_injected_member_at_any_level_fails_json_structure() {
    let base = vector_file()["record"].clone();
    let mut paths = Vec::new();
    object_paths(&base, "", &mut paths);
    let mut kinds: Vec<String> = paths
        .iter()
        .map(|p| p.split('/').filter(|s| s.parse::<usize>().is_err()).collect::<Vec<_>>().join("/"))
        .collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), 16, "the record and its 15 nested object kinds: {kinds:?}");
    for path in &paths {
        let mut doc = base.clone();
        doc.pointer_mut(path).unwrap().as_object_mut().unwrap().insert("waiver".into(), json!(true));
        let report = verify_json_with(basic_store(), serde_json::to_string(&doc).unwrap().as_bytes(), T);
        assert_fails_at(&report, CheckId::JsonStructure);
    }
}

#[test]
fn an_object_written_as_the_array_of_its_values_fails_json_structure() {
    // QA QT-01 (spec §2 rules 2 and 13, check 4j). serde's derive reads a
    // struct from the array of its values in declaration order, and the
    // signed payload is re-derived from the parsed struct: each respelling
    // below of a record signed over its objects, not re-signed, verified.
    // Every object, each array element included, one at a time. The
    // record carries every optional member, so every object is complete.
    let doc = |label: &str| vmr_record::record::DocumentationRef {
        documentation_hash: vmr_record::hash::format_hash(&vmr_record::hash::sha256(label.as_bytes())),
    };
    const PREDECESSOR: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b1";
    let signed = vector_edited(|p| {
        p.data_governance = Some(doc("data governance"));
        p.human_oversight = Some(doc("human oversight"));
        p.lineage.previous_record_id = Some(PREDECESSOR.into());
        p.lineage.previous_record_hash = Some(doc("the predecessor").documentation_hash);
        p.lineage.lineage_chain_length = 2;
        p.lineage.root_record_id = PREDECESSOR.into();
        p.lineage.lineage_type = "training-update".into();
        // Task 10.11b: an entry of derived_from is an object kind too.
        p.model_identity.derived_from = Some(vec![vmr_record::record::BaseModel {
            model_hash: doc("a base model").documentation_hash,
            name: "a base model".into(),
            relation: "fine-tune".into(),
        }]);
        // Task 10.11e: and so is an entry of statement_references.
        p.model_identity.statement_references = Some(vec![vmr_record::record::StatementReference {
            format: "oms-v1".into(),
            digest: doc("an in-toto statement").documentation_hash,
        }]);
    });
    assert_passes(&verify_basic(&signed));
    let base = serde_json::to_value(&signed).unwrap();
    let mut paths = Vec::new();
    object_paths(&base, "", &mut paths);
    let kinds: std::collections::BTreeSet<String> = paths
        .iter()
        .map(|p| p.split('/').map(|s| if s.parse::<usize>().is_ok() { "*" } else { s }).collect::<Vec<_>>().join("/"))
        .collect();
    assert_eq!(kinds.len(), OBJECT_FIELDS.len(), "every object kind has its field order: {kinds:?}");
    for path in paths.iter().filter(|p| !p.is_empty()) {
        let text = serde_json::to_string(&respelled_as_array(&base, path)).unwrap();
        assert_eq!(serde_json::from_str::<Record>(&text).unwrap(), signed, "{path}: serde_json reads the signed record");
        assert_fails_at(&verify_json_with(basic_store(), text.as_bytes(), T), CheckId::JsonStructure);
    }
    // The record itself as the array of its values is not a JSON object.
    let text = serde_json::to_string(&respelled_as_array(&base, "")).unwrap();
    assert_fails_at(&verify_json_with(basic_store(), text.as_bytes(), T), CheckId::InputForm);
}

#[test]
fn the_documentation_members_are_closed_objects_judged_by_the_existing_checks() {
    // Task 10.11a (D11-1, D11-3). A record carrying both optional members
    // verifies, in both forms, with the same checks as before: no check id
    // or count changes. Their two objects are closed like the 15 others, so
    // a member injected into either fails json.structure; a hash that is not
    // a lower-case sha256 hash fails format.schema even when signed.
    let doc = |label: &str| vmr_record::record::DocumentationRef {
        documentation_hash: vmr_record::hash::format_hash(&vmr_record::hash::sha256(label.as_bytes())),
    };
    let declared = vector_edited(|p| {
        p.data_governance = Some(doc("data governance"));
        p.human_oversight = Some(doc("human oversight"));
    });
    let report = verify_basic(&declared);
    assert_passes(&report);
    assert_eq!(report.checks.len(), 21, "a JSON record still runs 21 checks");
    let cose = vmr_verify::Verifier::new(basic_store()).verify_cose(&declared.to_cose().unwrap(), &at(T));
    assert_passes(&cose);
    assert_eq!(cose.checks.len(), 25, "a COSE record still runs 25 checks");

    let base = serde_json::to_value(&declared).unwrap();
    let mut paths = Vec::new();
    object_paths(&base, "", &mut paths);
    let mut kinds: Vec<String> = paths
        .iter()
        .map(|p| p.split('/').filter(|s| s.parse::<usize>().is_err()).collect::<Vec<_>>().join("/"))
        .collect();
    kinds.sort();
    kinds.dedup();
    assert_eq!(kinds.len(), 18, "the record, its 15 nested object kinds and the two documentation members: {kinds:?}");
    for member in ["/data_governance", "/human_oversight"] {
        let mut injected = base.clone();
        injected.pointer_mut(member).unwrap().as_object_mut().unwrap().insert("title".into(), json!("x"));
        let report = verify_json_with(basic_store(), serde_json::to_string(&injected).unwrap().as_bytes(), T);
        assert_fails_at(&report, CheckId::JsonStructure);

        let upper = vector_edited(|p| {
            let mut d = doc("upper");
            d.documentation_hash = d.documentation_hash.to_ascii_uppercase();
            match member {
                "/data_governance" => p.data_governance = Some(d),
                _ => p.human_oversight = Some(d),
            }
        });
        assert_fails_at(&verify_basic(&upper), CheckId::FormatSchema);
    }
}

#[test]
fn a_format_violation_fails_format_schema_even_when_signed() {
    // One violation per rule class, each re-signed by the trusted key: the
    // signature is valid, the format is not.
    let cases: Vec<(&str, Record)> = vec![
        ("id", vector_edited(|p| p.record_id = "urn:uuid:2B6A0C48-9F21-4F3A-8C51-1D0B4A7E9C00".into())),
        ("DID", vector_edited(|p| p.deployment_context.as_mut().unwrap().deployed_by = "did:web:f\u{430}ctory-operator.ph".into())),
        ("enum", vector_edited(|p| p.policy_compliance.overall_status = "compliant-ish".into())),
        ("hash", vector_edited(|p| p.deployment_context.as_mut().unwrap().hardware_id = "none".into())),
        ("timestamp", vector_edited(|p| p.issued_at = "2026-02-30T00:00:00Z".into())),
        ("minimum", vector_edited(|p| p.lineage.lineage_chain_length = 0)),
    ];
    for (what, p) in cases {
        assert_fails_at(&verify_basic(&p), CheckId::FormatSchema);
        let _ = what;
    }
}

#[test]
fn an_inconsistent_learned_state_fails_format_consistency() {
    let reordered = vector_edited(|p| p.model_identity.learned_state_components.swap(0, 1));
    assert_fails_at(&verify_basic(&reordered), CheckId::FormatConsistency);
    let off_by_one = vector_edited(|p| *p.model_identity.parameter_count.as_mut().unwrap() += 1);
    assert_fails_at(&verify_basic(&off_by_one), CheckId::FormatConsistency);
}

#[test]
fn a_general_record_verifies_and_its_detail_names_the_description() {
    // Task 10.11b (spec §7.1, §7.3): the general conformance vector verifies,
    // and format.consistency says which description it checked. A profile
    // record's detail is the one it always had (the golden reports).
    let detail = |report: &vmr_verify::VerificationReport| {
        report.checks.iter().find(|c| c.id == CheckId::FormatConsistency).unwrap().detail.clone()
    };
    let general = verify_basic(&general_vector());
    assert_passes(&general);
    assert_eq!(
        detail(&general),
        "general model description: 4 components in name order; learned_state_hash is their named-set digest"
    );
    assert_eq!(detail(&verify_basic(&vector())), "three components in order; sizes, parameter_count and model_hash agree");
    // Editing model_format alone moves no record between the rules (§7.1).
    let added = vector_edited(|_| {});
    let mut named_the_profile = general_vector();
    named_the_profile.model_identity.model_format = "snn-compact-v1".into();
    sign_as(&mut named_the_profile, KEY_A);
    assert_fails_at(&verify_basic(&named_the_profile), CheckId::FormatConsistency);
    let dropped = vector_edited(|p| p.model_identity.model_format = "safetensors".into());
    assert_fails_at(&verify_basic(&dropped), CheckId::FormatConsistency);
    assert_passes(&verify_basic(&added));
}

#[test]
fn a_record_with_statement_references_verifies_and_its_detail_says_they_are_not_checked() {
    // Task 10.11e (D11e-6; spec §6.3, §7.7): references to other signed
    // statements are checked in form only, and format.consistency's detail
    // says so. A record without references keeps the detail it had.
    use vmr_record::record::StatementReference;
    let detail = |report: &vmr_verify::VerificationReport| {
        report.checks.iter().find(|c| c.id == CheckId::FormatConsistency).unwrap().detail.clone()
    };
    let reference = |format: &str, label: &str| StatementReference {
        format: format.into(),
        digest: vmr_record::hash::format_hash(&vmr_record::hash::sha256(label.as_bytes())),
    };
    let mut references = vec![reference("oms-v1", "an in-toto statement"), reference("org.example.model-card-v1", "a model card")];
    references.sort_by(|x, y| x.digest.cmp(&y.digest));
    let mut general = general_vector();
    general.model_identity.statement_references = Some(references.clone());
    sign_as(&mut general, KEY_A);
    let report = verify_basic(&general);
    assert_passes(&report);
    assert_eq!(
        detail(&report),
        "general model description: 4 components in name order; learned_state_hash is their named-set digest; \
         2 statement references: declared, not checked (their form only)"
    );
    let one = vector_edited(|p| p.model_identity.statement_references = Some(vec![reference("oms-v1", "an in-toto statement")]));
    let report = verify_basic(&one);
    assert_passes(&report);
    assert_eq!(
        detail(&report),
        "three components in order; sizes, parameter_count and model_hash agree; \
         1 statement reference: declared, not checked (its form only)"
    );
    let unregistered = vector_edited(|p| p.model_identity.statement_references = Some(vec![reference("c2pa-manifest", "a manifest")]));
    assert_fails_at(&verify_basic(&unregistered), CheckId::FormatConsistency);
}

#[test]
fn the_second_key_of_a_rotated_issuer_verifies() {
    let mut p = vector();
    reissue_with(&mut p, KEY_A2);
    let store = store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(VECTOR_ISSUER, KEY_A2)]);
    let report = verify_json_with(store, &json_of(&p), T);
    assert_passes(&report);
    assert_eq!(report.issuer.unwrap().key_id, key_id(KEY_A2));
}

#[test]
fn the_empty_store_trusts_nothing() {
    let empty = store(&[]);
    assert_fails_at(&verify_json_with(empty, &json_of(&vector()), T), CheckId::TrustKeyKnown);
}

#[test]
fn verify_record_runs_the_same_checks_in_memory() {
    // The in-memory entry point (Phase 7.2) starts at format.schema; from
    // there its checks are the JSON form's, outcome for outcome.
    let verifier = vmr_verify::Verifier::new(basic_store());
    let p = vector();
    let mem = verifier.verify_record(&p, &at(T));
    let json = verifier.verify_json(&json_of(&p), &at(T));
    assert_passes(&mem);
    assert_eq!(mem.checks.first().unwrap().id, CheckId::FormatSchema);
    let tail = &json.checks[json.checks.len() - mem.checks.len()..];
    assert_eq!(mem.checks.as_slice(), tail);
    let mut forged = vector();
    reissue_with(&mut forged, KEY_F);
    assert_fails_at(&verifier.verify_record(&forged, &at(T)), CheckId::TrustKeyKnown);
}
