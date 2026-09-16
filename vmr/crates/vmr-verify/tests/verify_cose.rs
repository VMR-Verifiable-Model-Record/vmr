// tests/verify_cose.rs — the COSE form (Phase 4 task 4.6; TASKS
// "test_verify_cose"): decode checks 3c-8c, the standard COSE check of the
// envelope next to the reconstructed-TBS check, and JSON/COSE equivalence.

mod common;

use common::*;
use coset::{CborSerializable, CoseSign1, HeaderBuilder};
use vmr_record::record::{Record, SignatureSection};
use vmr_verify::report::{CheckId, InputForm, VerificationReport};
use vmr_verify::{TrustStore, Verifier};

fn verify_cose_with(store: TrustStore, input: &[u8], t: &str) -> VerificationReport {
    Verifier::new(store).verify_cose(input, &at(t))
}

fn cose_basic(bytes: &[u8]) -> VerificationReport {
    verify_cose_with(basic_store(), bytes, T)
}

/// The checks from format.schema on (shared by both forms).
fn shared_tail(r: &VerificationReport) -> &[vmr_verify::report::CheckResult] {
    let at = r.checks.iter().position(|c| c.id == CheckId::FormatSchema).unwrap();
    &r.checks[at..]
}

#[test]
fn the_vectors_cose_form_verifies() {
    let cose = vector().to_cose().unwrap();
    let report = cose_basic(&cose);
    assert_passes(&report);
    assert_eq!(report.input.form, InputForm::Cose);
    let ids: Vec<CheckId> = report.checks.iter().take(8).map(|c| c.id).collect();
    assert_eq!(
        ids,
        [
            CheckId::InputSize,
            CheckId::InputForm,
            CheckId::CoseStructure,
            CheckId::CoseProtectedHeader,
            CheckId::CoseUnprotectedHeader,
            CheckId::CoseSignatureEncoding,
            CheckId::CosePayload,
            CheckId::CoseCanonical,
        ]
    );
}

#[test]
fn the_cose_report_equals_the_json_report_except_input_and_decoding() {
    let p = vector();
    let json = verify_basic(&p);
    let cose = cose_basic(&p.to_cose().unwrap());
    assert_eq!(json.verdict, cose.verdict);
    assert_eq!(json.failure, cose.failure);
    assert_eq!(json.accepted, cose.accepted);
    assert_eq!(json.evaluation_time, cose.evaluation_time);
    assert_eq!(json.trust_store, cose.trust_store);
    assert_eq!(json.record, cose.record, "same claims, same recomputed hash");
    assert_eq!(json.issuer, cose.issuer);
    assert_eq!(shared_tail(&json), shared_tail(&cose));
    assert_ne!(json.input, cose.input);
}

/// Cases of task 4.3 that have a COSE form: (what, record, store, T,
/// expected first failing check or None for a pass).
fn equivalence_cases() -> Vec<(&'static str, Record, TrustStore, &'static str, Option<CheckId>)> {
    let mut forged = vector();
    reissue_with(&mut forged, KEY_F);
    let mut revoked = Entry::new(VECTOR_ISSUER, KEY_A);
    revoked.revoked = true;
    let mut late = Entry::new(VECTOR_ISSUER, KEY_A);
    late.valid_from = "2026-09-10T00:00:01Z";
    let sig = vector().signature.parsed_signature().unwrap();
    let mut high_s = vector();
    high_s.signature.signature = SignatureSection::signature_field(
        &p256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).unwrap(),
    );
    let mut by_b = vector();
    sign_as(&mut by_b, KEY_B);
    let mut tampered = vector();
    tampered.learning_provenance.training_epochs = tampered.learning_provenance.training_epochs.map(|e| e + 1);
    tampered.signature.signed_payload_hash = tampered.signed_payload_hash().unwrap();
    let mut rotated = vector();
    reissue_with(&mut rotated, KEY_A2);
    vec![
        ("vector", vector(), basic_store(), T, None),
        ("forged", forged, basic_store(), T, Some(CheckId::TrustKeyKnown)),
        ("other issuer", vector(), store(&[Entry::new(OTHER_ISSUER, KEY_A)]), T, Some(CheckId::TrustIssuer)),
        ("revoked", vector(), store(&[revoked]), T, Some(CheckId::TrustKeyNotRevoked)),
        ("window", vector(), store(&[late]), T, Some(CheckId::TrustKeyValidity)),
        (
            "attestation",
            vector_edited(|p| p.issuer.attestation_level = "hardware".into()),
            basic_store(),
            T,
            Some(CheckId::TrustAttestation),
        ),
        ("future", vector(), basic_store(), "2026-09-09T23:59:59Z", Some(CheckId::TimeNotFuture)),
        ("high-s", high_s, basic_store(), T, Some(CheckId::SignatureLowS)),
        (
            "key id not thumbprint",
            vector_edited(|p| {
                p.issuer.key_id = key_id(KEY_B);
                p.signature.signing_key_id = key_id(KEY_B);
            }),
            basic_store(),
            T,
            Some(CheckId::KeyBinding),
        ),
        (
            "signing key id != key id",
            vector_edited(|p| p.signature.signing_key_id = key_id(KEY_B)),
            basic_store(),
            T,
            Some(CheckId::KeyBinding),
        ),
        (
            "signed by B claiming A",
            by_b,
            store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(VECTOR_ISSUER, KEY_B)]),
            T,
            Some(CheckId::SignatureValid),
        ),
        ("tampered", tampered, basic_store(), T, Some(CheckId::SignatureValid)),
        (
            "format",
            vector_edited(|p| p.deployment_context.as_mut().unwrap().hardware_id = "none".into()),
            basic_store(),
            T,
            Some(CheckId::FormatSchema),
        ),
        (
            "consistency",
            vector_edited(|p| *p.model_identity.parameter_count.as_mut().unwrap() += 1),
            basic_store(),
            T,
            Some(CheckId::FormatConsistency),
        ),
        (
            "rotated",
            rotated,
            store(&[Entry::new(VECTOR_ISSUER, KEY_A), Entry::new(VECTOR_ISSUER, KEY_A2)]),
            T,
            None,
        ),
    ]
}

#[test]
fn every_case_with_a_cose_form_gives_the_same_verdict_and_check() {
    // The signature section's algorithm and signed_payload_hash have no COSE
    // counterpart (the envelope's alg and payload determine them), and a
    // non-64-byte signature has no envelope: those JSON-only cases are
    // covered by verify_signature.rs and by the COSE-specific cases below.
    for (what, p, store, t, expected) in equivalence_cases() {
        let json = verify_json_with(store.clone(), &json_of(&p), t);
        let cose = verify_cose_with(store, &p.to_cose().unwrap(), t);
        match expected {
            None => {
                assert_passes(&json);
                assert_passes(&cose);
            }
            Some(id) => {
                assert_fails_at(&json, id);
                assert_fails_at(&cose, id);
            }
        }
        assert_eq!(shared_tail(&json), shared_tail(&cose), "{what}");
    }
}

fn vector_sign1() -> CoseSign1 {
    CoseSign1::from_slice(&vector().to_cose().unwrap()).unwrap()
}

#[test]
fn a_kid_in_the_unprotected_header_fails_cose_unprotected_header() {
    // §2.3 #3.
    let mut s = vector_sign1();
    s.unprotected = HeaderBuilder::new().key_id(key_id(KEY_F).into_bytes()).build();
    assert_fails_at(&cose_basic(&s.to_vec().unwrap()), CheckId::CoseUnprotectedHeader);
}

#[test]
fn a_non_preferred_length_fails_cose_canonical() {
    // §2.3 #4: `58 5e` -> `59 00 5e`; content and signature unchanged.
    let good = vector().to_cose().unwrap();
    let bytes = [&[0x84, 0x59, 0x00, 0x5e][..], &good[3..]].concat();
    assert_fails_at(&cose_basic(&bytes), CheckId::CoseCanonical);
}

#[test]
fn a_tagged_envelope_fails_input_form() {
    // §2.3 #5: tag 18 (0xD2) is not the v0.1 form.
    let bytes = [&[0xd2][..], &vector().to_cose().unwrap()].concat();
    let report = cose_basic(&bytes);
    assert_fails_at(&report, CheckId::InputForm);
    assert!(report.failure.unwrap().detail.contains("tag 18"));
}

#[test]
fn an_extra_protected_parameter_fails_cose_protected_header() {
    // §2.3 #6: correctly signed, so a standard COSE check passes - but the
    // protected header must be exactly {1: -7, 4: kid}.
    let p = vector();
    let mut s = vector_sign1();
    s.protected = coset::ProtectedHeader {
        original_data: None,
        header: HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .content_type("application/json".into())
            .key_id(p.signature.signing_key_id.as_bytes().to_vec())
            .build(),
    };
    let sig = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap();
    s.signature = sig.to_bytes().to_vec();
    assert_fails_at(&cose_basic(&s.to_vec().unwrap()), CheckId::CoseProtectedHeader);
}

#[test]
fn payload_problems_fail_cose_payload() {
    let with_payload = |f: &dyn Fn(&[u8]) -> Option<Vec<u8>>| {
        let mut s = vector_sign1();
        s.payload = f(s.payload.as_ref().unwrap());
        cose_basic(&s.to_vec().unwrap())
    };
    // Detached (nil) payload.
    assert_fails_at(&with_payload(&|_| None), CheckId::CosePayload);
    // A `signature` member smuggled into the payload.
    let smuggled = with_payload(&|t| {
        let text = std::str::from_utf8(t).unwrap();
        Some(
            format!(
                "{},\"signature\":{{\"algorithm\":\"none\",\"signature\":\"\",\"signed_payload_hash\":\"\",\"signing_key_id\":\"\"}}}}",
                &text[..text.len() - 1]
            )
            .into_bytes(),
        )
    });
    assert_fails_at(&smuggled, CheckId::CosePayload);
    // The same content, pretty-printed.
    let pretty = with_payload(&|t| {
        let v: serde_json::Value = serde_json::from_slice(t).unwrap();
        Some(serde_json::to_vec_pretty(&v).unwrap())
    });
    assert_fails_at(&pretty, CheckId::CosePayload);
    // Not a record.
    assert_fails_at(&with_payload(&|_| Some(b"{}".to_vec())), CheckId::CosePayload);
}

#[test]
fn an_integer_respelled_in_the_payload_fails_cose_payload() {
    // QA P4-01: the payload is a record under the rules of 3j-4j (so an
    // integer has one spelling) and byte-identical to its canonical form.
    // Each respelling is re-signed, so only the payload rule can object.
    for spelling in ["-0", "0.0", "0e0"] {
        let p = vector_edited(|p| p.learning_provenance.training_epochs = Some(0));
        let mut s = CoseSign1::from_slice(&p.to_cose().unwrap()).unwrap();
        let text = String::from_utf8(s.payload.take().unwrap()).unwrap();
        assert!(text.contains("\"training_epochs\":0,"));
        let respelled = text.replacen("\"training_epochs\":0,", &format!("\"training_epochs\":{spelling},"), 1);
        s.payload = Some(respelled.into_bytes());
        s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
        assert_fails_at(&cose_basic(&s.to_vec().unwrap()), CheckId::CosePayload);
    }
}

#[test]
fn a_huge_member_name_in_the_payload_gives_a_short_safe_detail() {
    // The headline of a failed verification is the first failure's detail.
    // A payload member name of 100 000 characters carrying terminal escapes
    // (re-signed, so only the payload rule objects) must not make it long or
    // let the escapes through - as for the JSON form
    // (verifier::details_quote_little_and_nothing_unsafe).
    let mut s = vector_sign1();
    let text = String::from_utf8(s.payload.take().unwrap()).unwrap();
    let name = format!("\u{1b}[2J\u{202e}{}", "x".repeat(100_000));
    let edited = format!("{{{}:1,{}", serde_json::to_string(&name).unwrap(), &text[1..]);
    s.payload = Some(edited.into_bytes());
    s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
    let report = cose_basic(&s.to_vec().unwrap());
    assert_fails_at(&report, CheckId::CosePayload);
    let detail = report.failure.unwrap().detail;
    assert!(detail.chars().count() < 400, "{} characters", detail.chars().count());
    assert!(!detail.contains(&"x".repeat(65)), "{detail}");
    assert!(!detail.contains('\u{1b}') && !detail.contains('\u{202e}'), "{detail}");
    assert!(detail.contains("\\u{001b}[2J\\u{202e}"), "{detail}");
}

#[test]
fn a_lone_surrogate_in_the_payload_fails_cose_payload() {
    // QA P4-03: the payload is a record under the rules of 3j-4j, and its
    // strings are Unicode scalar values. Re-signed, so only that rule objects.
    let mut s = vector_sign1();
    let text = String::from_utf8(s.payload.take().unwrap()).unwrap();
    assert!(text.contains("\"New Clark"));
    s.payload = Some(text.replacen("\"New Clark", "\"New \\ud800Clark", 1).into_bytes());
    s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
    assert_fails_at(&cose_basic(&s.to_vec().unwrap()), CheckId::CosePayload);
}

#[test]
fn structural_problems_fail_cose_structure() {
    let good = vector().to_cose().unwrap();
    assert_fails_at(&cose_basic(&[good.clone(), vec![0x00]].concat()), CheckId::CoseStructure);
    assert_fails_at(&cose_basic(&good[..good.len() - 1]), CheckId::CoseStructure);
    assert_fails_at(&cose_basic(&[0x84, 0x40, 0xa0, 0x40]), CheckId::CoseStructure);
    assert_fails_at(&cose_basic(&[0x84, 0xff]), CheckId::CoseStructure);
    // The outer shape [bstr, map, bstr / nil, bstr], element by element.
    assert_fails_at(&cose_basic(&[&[0x84, 0xd8, 0x18][..], &good[1..]].concat()), CheckId::CoseStructure);
    assert_fails_at(&cose_basic(&[&good[..97], &[0x80], &good[98..]].concat()), CheckId::CoseStructure);
    assert_eq!(good[98], 0x59, "the payload's bstr head");
    assert_fails_at(&cose_basic(&[&good[..98], &[0x79], &good[99..]].concat()), CheckId::CoseStructure);
}

/// The vector's envelope with its protected header bytes replaced by
/// `protected`, re-signed by key A over exactly those bytes.
fn with_protected_bytes(protected: &[u8]) -> Vec<u8> {
    let mut s = vector_sign1();
    s.protected = coset::ProtectedHeader { original_data: Some(protected.to_vec()), header: coset::Header::default() };
    s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
    s.to_vec().unwrap()
}

#[test]
fn errors_inside_the_protected_header_fail_cose_protected_header() {
    // QA P4-02: 3c is the envelope's outer shape; anything wrong inside the
    // protected bstr is 4c. The QA's two cases: (1) the kid's bstr head 0x58
    // turned into 0xd8 (a CBOR tag) inside the protected bstr - the envelope
    // is still [bstr, map, bstr, bstr]; (2) an empty kid, protected header
    // a2 01 26 04 40 with every other length adjusted and the envelope
    // correctly signed over it (spec §4.4: the kid is non-empty UTF-8).
    let good = vector().to_cose().unwrap();
    let mut tag_head = good.clone();
    assert_eq!(&tag_head[3..9], &[0xa2, 0x01, 0x26, 0x04, 0x58, 0x58]);
    tag_head[7] = 0xd8;
    let empty_kid = with_protected_bytes(&[0xa2, 0x01, 0x26, 0x04, 0x40]);
    assert_eq!(&empty_kid[..7], &[0x84, 0x45, 0xa2, 0x01, 0x26, 0x04, 0x40]);
    let kid = key_id(KEY_A).into_bytes();
    for (what, bytes) in [
        ("kid head 0x58 -> 0xd8", tag_head),
        ("empty kid", empty_kid),
        ("a duplicate label", with_protected_bytes(&[&[0xa3, 0x01, 0x26, 0x04, 0x58, 0x58][..], &kid, &[0x01, 0x26]].concat())),
        ("not a map", with_protected_bytes(&[0x81, 0x01])),
        ("truncated", with_protected_bytes(&[0xa2, 0x01, 0x26, 0x04, 0x58])),
        ("a non-UTF-8 kid", with_protected_bytes(&[0xa2, 0x01, 0x26, 0x04, 0x42, 0xc3, 0x28])),
    ] {
        let report = cose_basic(&bytes);
        assert_fails_at(&report, CheckId::CoseProtectedHeader);
        assert!(report.failure.unwrap().detail.contains("protected header"), "{what}");
    }
}

#[test]
fn a_malformed_unprotected_header_fails_cose_unprotected_header() {
    // The unprotected header is the empty map (5c): a map holding a
    // malformed kid or a duplicate label is 5c too, not 3c.
    let good = vector().to_cose().unwrap();
    assert_eq!(good[97], 0xa0);
    for map in [&[0xa1, 0x04, 0x61, 0x6b][..], &[0xa2, 0x04, 0x41, 0x6b, 0x04, 0x41, 0x6b][..]] {
        let bytes = [&good[..97], map, &good[98..]].concat();
        assert_fails_at(&cose_basic(&bytes), CheckId::CoseUnprotectedHeader);
    }
}

#[test]
fn a_payload_nested_deeper_than_a_record_fails_cose_payload_at_every_depth() {
    // Spec §2 rule 13 and check 7c: the payload is a record under the rules
    // of 3j-4j, so a payload nesting deeper than four levels fails
    // cose.payload at every depth, as the JSON form fails json.structure.
    // Re-signed, so only the payload rule can object.
    let p = vector();
    let payload = String::from_utf8(p.signed_payload().unwrap()).unwrap();
    assert_eq!(nesting_depth(&payload), 4);
    for levels in [5usize, 127, 128, 129, 100_000] {
        let report = cose_basic(&cose_with_payload(&p, nested_at_issuer_name(&payload, levels).into_bytes()));
        assert_fails_at(&report, CheckId::CosePayload);
        let detail = report.failure.unwrap().detail;
        assert!(!detail.contains("recursion"), "{levels} levels: {detail}");
    }
    // A signature member smuggled into the payload, 100 000 levels deep.
    let smuggled = format!("{},\"signature\":{}}}", &payload[..payload.len() - 1], nested_arrays(99_999));
    assert_eq!(nesting_depth(&smuggled), 100_000);
    assert_fails_at(&cose_basic(&cose_with_payload(&p, smuggled.into_bytes())), CheckId::CosePayload);
}

#[test]
fn the_envelopes_cbor_is_a_subset_nesting_at_most_16_levels() {
    // Spec §4.4 and checks 3c-5c (the reviewer's decision, 2026-09-13): the
    // envelope's CBOR is read head by head before anything is decoded. It
    // nests at most 16 levels (its array is the first; every array, map and
    // tag is one more) and holds only integers, byte and text strings,
    // arrays, maps and null, each argument in at most 4 bytes. Anything else
    // fails cose.structure, before the headers are judged; within the subset
    // and the depth, an unprotected map holding anything fails
    // cose.unprotected_header.
    let p = vector();
    let check = |map: &[u8]| cose_basic(&cose_with_unprotected(&p, map));
    for levels in [3usize, 16] {
        assert_fails_at(&check(&unprotected_nested(levels)), CheckId::CoseUnprotectedHeader);
    }
    for levels in [17usize, 257, 100_000] {
        assert_fails_at(&check(&unprotected_nested(levels)), CheckId::CoseStructure);
    }
    // Before the protected header too: its kid's bstr head turned into a tag.
    for (levels, first) in [(16usize, CheckId::CoseProtectedHeader), (17, CheckId::CoseStructure)] {
        let mut bytes = cose_with_unprotected(&p, &unprotected_nested(levels));
        bytes[7] = 0xd8;
        assert_fails_at(&cose_basic(&bytes), first);
    }
    // A map, and a map key, are levels as an array is.
    let maps = |levels: usize| [[0xa1u8, 0x00].repeat(levels - 2), vec![0xa0]].concat();
    assert_fails_at(&check(&maps(16)), CheckId::CoseUnprotectedHeader);
    assert_fails_at(&check(&maps(17)), CheckId::CoseStructure);
    let key = |levels: usize| [vec![0xa1u8], vec![0x81; levels - 3], vec![0x80, 0x00]].concat();
    assert_fails_at(&check(&key(16)), CheckId::CoseUnprotectedHeader);
    assert_fails_at(&check(&key(17)), CheckId::CoseStructure);
    // Outside the subset, at any depth: a bignum and every other tag, every
    // simple value but null, a float, an indefinite length, an 8-byte
    // argument, a text string that is not UTF-8.
    let outside: [&[u8]; 10] = [
        &[0xc2, 0x41, 0x01],
        &[0xc1, 0x00],
        &[0xf5],
        &[0xf0],
        &[0xf8, 0x20],
        &[0xf9, 0x00, 0x00],
        &[0x9f, 0xff],
        &[0x5f, 0xff],
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0],
        &[0x62, 0xc3, 0x28],
    ];
    for item in outside {
        assert_fails_at(&check(&[&[0xa1, 0x00][..], item].concat()), CheckId::CoseStructure);
    }
    // Inside it, the unprotected-header check decides.
    let inside: [&[u8]; 8] = [
        &[0x00],
        &[0x3a, 0xff, 0xff, 0xff, 0xff],
        &[0x5a, 0, 0, 0, 1, 0x00],
        &[0x61, 0x61],
        &[0x80],
        &[0xa0],
        &[0xf6],
        &[0x19, 0x00, 0x01],
    ];
    for item in inside {
        assert_fails_at(&check(&[&[0xa1, 0x00][..], item].concat()), CheckId::CoseUnprotectedHeader);
    }
    // The envelope's own items: an indefinite-length payload used to reach
    // cose.canonical; a non-preferred length inside the subset still does.
    let good = p.to_cose().unwrap();
    let sig_at = good.len() - 66;
    let indefinite_payload = [&good[..98], &[0x5f][..], &good[98..sig_at], &[0xff][..], &good[sig_at..]].concat();
    assert_fails_at(&cose_basic(&indefinite_payload), CheckId::CoseStructure);
    let wide_map = [&good[..97], &[0xb8, 0x00][..], &good[98..]].concat();
    assert_fails_at(&cose_basic(&wide_map), CheckId::CoseCanonical);
}

#[test]
fn a_short_signature_fails_cose_signature_encoding() {
    let mut s = vector_sign1();
    s.signature.truncate(63);
    assert_fails_at(&cose_basic(&s.to_vec().unwrap()), CheckId::CoseSignatureEncoding);
}

#[test]
fn the_json_form_is_not_the_cose_form() {
    let report = cose_basic(&json_of(&vector()));
    assert_fails_at(&report, CheckId::InputForm);
    assert_fails_at(&cose_basic(b""), CheckId::InputForm);
}

#[test]
fn verify_detects_the_form() {
    let verifier = Verifier::new(basic_store());
    let p = vector();
    let (json, cose) = (json_of(&p), p.to_cose().unwrap());
    assert_eq!(verifier.verify(&json, &at(T)), verifier.verify_json(&json, &at(T)));
    assert_eq!(verifier.verify(&cose, &at(T)), verifier.verify_cose(&cose, &at(T)));
    let spaced = [b" \n".as_slice(), &json].concat();
    assert_eq!(verifier.verify(&spaced, &at(T)).input.form, InputForm::Json);
    // Neither form: a BOM, a CBOR tag, garbage, nothing.
    for bad in [
        [&[0xef, 0xbb, 0xbf][..], &json].concat(),
        [&[0xd2][..], &cose].concat(),
        b"hello".to_vec(),
        Vec::new(),
    ] {
        let report = verifier.verify(&bad, &at(T));
        assert_fails_at(&report, CheckId::InputForm);
        assert_eq!(report.input.form, InputForm::Unknown);
    }
}
