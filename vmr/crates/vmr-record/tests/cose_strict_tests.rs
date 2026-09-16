// tests/cose_strict_tests.rs — the COSE form is exactly the canonical
// envelope (spec §4.4; Phase 4 task 4.0c, decision D4 (f)).
//
// Every envelope below carries a genuine record (the committed vector) and
// a signature that a standard COSE check of the envelope accepts or rejects
// for its own reasons; from_cose must reject each one with its OWN reason,
// never turn it into a record. Gaps §2.3 #3-#6 of docs/dev/phase4.md.

use coset::{CborSerializable, CoseSign1, HeaderBuilder};
use vmr_record::cose::{decode_record, CoseDecodeError};
use vmr_record::hash::sha256;
use vmr_record::record::Record;
use vmr_record::sign::signing_key_from_secret;

fn vector_record() -> Record {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/test-vectors/record/example-v0.1.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    serde_json::from_value(v["record"].clone()).unwrap()
}

fn vector_key() -> p256::ecdsa::SigningKey {
    signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap()
}

fn canonical_envelope() -> Vec<u8> {
    vector_record().to_cose().unwrap()
}

/// Re-sign `sign1` (its protected header and payload as they stand) with the
/// vector key, so the envelope's own signature is VALID and only the
/// envelope rules can reject it.
fn resign(mut sign1: CoseSign1) -> Vec<u8> {
    let tbs = sign1.tbs_data(&[]);
    let sig = vmr_record::sign::sign(&vector_key(), &tbs).unwrap();
    sign1.signature = sig.to_bytes().to_vec();
    sign1.to_vec().unwrap()
}

/// A standard COSE check of the envelope as it stands, with the vector key.
fn cose_signature_ok(bytes: &[u8]) -> bool {
    let sign1 = vmr_record::cose::decode_sign1(bytes).unwrap();
    vmr_record::cose::verify_sign1(&sign1, vector_key().verifying_key()).is_ok()
}

#[test]
fn the_canonical_envelope_still_round_trips() {
    // Acceptance of 4.0c: to_cose already emits the one canonical form.
    let p = vector_record();
    let bytes = p.to_cose().unwrap();
    assert_eq!(bytes[0], 0x84, "untagged 4-element array");
    assert_eq!(decode_record(&bytes).unwrap(), p);
    assert_eq!(Record::from_cose(&bytes).unwrap(), p);
    assert_eq!(Record::from_cose(&bytes).unwrap().to_cose().unwrap(), bytes);
}

#[test]
fn rejects_a_kid_in_the_unprotected_header() {
    // §2.3 #3: a kid (and a private label) in the UNPROTECTED header parsed
    // and verified - unsigned data inside a "verified" envelope, and a second
    // kid that other COSE libraries may prefer. Spec §4.4: unprotected is
    // the empty map.
    let mut sign1 = CoseSign1::from_slice(&canonical_envelope()).unwrap();
    sign1.unprotected = HeaderBuilder::new()
        .key_id(b"urn:attacker:kid".to_vec())
        .text_value("note".into(), coset::cbor::value::Value::Text("unsigned".into()))
        .build();
    let bytes = sign1.to_vec().unwrap();
    assert!(cose_signature_ok(&bytes), "the unprotected header is not signed");
    let err = Record::from_cose(&bytes).expect_err("unprotected header data must be rejected");
    assert!(err.to_string().contains("unprotected header"), "{err}");
    assert!(matches!(decode_record(&bytes), Err(CoseDecodeError::UnprotectedHeader)));
}

#[test]
fn rejects_extra_protected_parameters() {
    // §2.3 #6: an extra protected parameter (content type), correctly signed.
    // A standard COSE check of the envelope PASSES, and from_cose accepted it;
    // it only failed later as a generic signature mismatch. The protected
    // header must be exactly {1: -7, 4: kid}: an explicit rejection.
    let p = vector_record();
    let mut sign1 = CoseSign1::from_slice(&p.to_cose().unwrap()).unwrap();
    sign1.protected = coset::ProtectedHeader {
        original_data: None,
        header: HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::ES256)
            .content_type("application/json".into())
            .key_id(p.signature.signing_key_id.as_bytes().to_vec())
            .build(),
    };
    let bytes = resign(sign1);
    assert!(cose_signature_ok(&bytes), "the envelope's own signature is valid");
    let err = Record::from_cose(&bytes).expect_err("extra protected parameter must be rejected");
    assert!(err.to_string().contains("protected header"), "{err}");
    assert!(matches!(decode_record(&bytes), Err(CoseDecodeError::ProtectedHeader(_))));
}

#[test]
fn rejects_non_preferred_cbor_lengths() {
    // §2.3 #4: the protected header's bstr head written `59 00 5e` instead of
    // the preferred `58 5e`. The content is identical, so the record and its
    // signature check are unchanged - but the envelope bytes differ from
    // to_cose(): envelope malleability, the COSE analogue of P3-04.
    let good = canonical_envelope();
    assert_eq!(&good[1..3], &[0x58, 0x5e], "protected bstr head, 94 bytes");
    let mut bytes = vec![0x84, 0x59, 0x00, 0x5e];
    bytes.extend_from_slice(&good[3..]);
    assert!(cose_signature_ok(&bytes), "same content, same signature");
    let err = Record::from_cose(&bytes).expect_err("non-preferred length must be rejected");
    assert!(err.to_string().contains("canonical encoding"), "{err}");
    assert!(matches!(decode_record(&bytes), Err(CoseDecodeError::NotCanonical)));
}

#[test]
fn rejects_tag_18_with_a_specific_reason() {
    // §2.3 #5: tagged COSE_Sign1 (tag 18 = 0xD2) was rejected, but only as
    // "got tag, expected array". v0.1 envelopes are untagged; say so.
    let mut bytes = vec![0xd2];
    bytes.extend_from_slice(&canonical_envelope());
    let err = Record::from_cose(&bytes).expect_err("tagged envelope");
    assert!(err.to_string().contains("tag 18"), "{err}");
    assert!(matches!(decode_record(&bytes), Err(CoseDecodeError::Tagged)));
}

#[test]
fn decode_record_names_each_reason() {
    // One envelope per remaining CoseDecodeError variant.
    let p = vector_record();
    let good = p.to_cose().unwrap();
    let with = |f: &dyn Fn(&mut CoseSign1)| {
        let mut s = CoseSign1::from_slice(&good).unwrap();
        f(&mut s);
        s.to_vec().unwrap()
    };

    // Not CBOR at all / trailing data -> Cbor.
    assert!(matches!(decode_record(&[0x84]), Err(CoseDecodeError::Cbor(_))));
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert!(matches!(decode_record(&trailing), Err(CoseDecodeError::Cbor(_))));
    // CBOR, but not a COSE_Sign1 -> NotSign1.
    assert!(matches!(decode_record(&[0x83, 0x40, 0xa0, 0x40]), Err(CoseDecodeError::NotSign1(_))));
    // alg other than ES256 -> ProtectedHeader.
    let es384 = with(&|s| {
        s.protected = coset::ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES384)
                .key_id(p.signature.signing_key_id.as_bytes().to_vec())
                .build(),
        }
    });
    assert!(matches!(decode_record(&es384), Err(CoseDecodeError::ProtectedHeader(ref d)) if d.contains("ES256")));
    // 63-byte signature, and 64 bytes with r = 0 -> SignatureEncoding.
    let short = with(&|s| s.signature.truncate(63));
    assert!(matches!(decode_record(&short), Err(CoseDecodeError::SignatureEncoding(_))));
    let r_zero = with(&|s| s.signature[..32].fill(0));
    assert!(matches!(decode_record(&r_zero), Err(CoseDecodeError::SignatureEncoding(_))));
    // Detached (nil) payload -> NoPayload.
    let detached = with(&|s| s.payload = None);
    assert!(matches!(decode_record(&detached), Err(CoseDecodeError::NoPayload)));
    // Payload that is not a record -> Payload.
    let not_record = with(&|s| s.payload = Some(b"{\"record_version\":\"0.1\"}".to_vec()));
    assert!(matches!(decode_record(&not_record), Err(CoseDecodeError::Payload(_))));
    // Payload that is a record in a non-canonical encoding -> PayloadNotCanonical.
    let pretty = with(&|s| {
        let v: serde_json::Value = serde_json::from_slice(s.payload.as_ref().unwrap()).unwrap();
        s.payload = Some(serde_json::to_vec_pretty(&v).unwrap());
    });
    assert!(matches!(decode_record(&pretty), Err(CoseDecodeError::PayloadNotCanonical)));
}

#[test]
fn a_payload_object_written_as_the_array_of_its_values_is_not_a_record() {
    // QA QT-01: the payload is read like a JSON record, so an object written
    // as the array of its values is not a record (Payload). It failed 7c
    // before too, as a payload that is not canonical: the check is the same.
    let mut s = CoseSign1::from_slice(&canonical_envelope()).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(s.payload.as_ref().unwrap()).unwrap();
    let key = v["issuer"]["public_key"].clone();
    v["issuer"]["public_key"] = serde_json::json!([key["kty"], key["crv"], key["x"], key["y"]]);
    s.payload = Some(serde_json::to_vec(&v).unwrap());
    match decode_record(&resign(s)) {
        Err(CoseDecodeError::Payload(e)) => {
            assert!(e.to_string().contains("invalid type: sequence, expected struct JwkPublicKey"), "{e}")
        }
        other => panic!("expected CoseDecodeError::Payload, got {other:?}"),
    }
}

/// The canonical envelope with its protected header bytes replaced by
/// `protected` (the bstr head re-encoded for the new length) and re-signed by
/// the vector key over exactly those bytes: the protected header is the only
/// thing wrong with it.
fn with_protected_bytes(protected: &[u8]) -> Vec<u8> {
    let mut s = CoseSign1::from_slice(&canonical_envelope()).unwrap();
    s.protected = coset::ProtectedHeader { original_data: Some(protected.to_vec()), header: coset::Header::default() };
    resign(s)
}

/// The canonical protected header `a2 01 26 04 58 58` ‖ kid (spec §4.1).
fn canonical_protected() -> Vec<u8> {
    let good = canonical_envelope();
    assert_eq!(&good[..3], &[0x84, 0x58, 0x5e], "a 94-byte protected bstr");
    good[3..3 + 94].to_vec()
}

#[test]
fn errors_inside_the_protected_header_are_protected_header_errors() {
    // QA P4-02: check 3c is the outer shape only - one CBOR item, an array
    // [bstr, map, bstr / nil, bstr], nothing after it. Whatever is wrong
    // INSIDE the protected bstr is check 4c. decode_record used to let
    // coset decode the header's contents together with the envelope and
    // filed its errors under Cbor / NotSign1 (cose.structure).
    let good = canonical_envelope();
    let protected = canonical_protected();
    let kid = &protected[6..];
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

    // The QA's two cases. (1) The kid's bstr head 0x58 turned into 0xd8, a
    // CBOR tag, inside the protected bstr (the random-mutation case: not
    // re-signed); the envelope is still [bstr, map, bstr, bstr]. Also its
    // length byte 0x58 turned into 0xd8 (216 bytes: past the bstr's end).
    let mut tag_head = good.clone();
    assert_eq!(tag_head[7], 0x58);
    tag_head[7] = 0xd8;
    cases.push(("kid head 0x58 -> 0xd8 (a tag)", tag_head));
    let mut long_kid = good.clone();
    assert_eq!(long_kid[8], 0x58);
    long_kid[8] = 0xd8;
    cases.push(("kid length 88 -> 216", long_kid));
    // (2) An empty kid: protected header a2 01 26 04 40, every length
    // adjusted, correctly signed over it.
    cases.push(("empty kid", with_protected_bytes(&[0xa2, 0x01, 0x26, 0x04, 0x40])));

    // More of the same class, each correctly signed over its header.
    let concat = |parts: &[&[u8]]| parts.concat();
    cases.push(("truncated kid", with_protected_bytes(&[0xa2, 0x01, 0x26, 0x04, 0x58])));
    cases.push(("not CBOR", with_protected_bytes(&[0xff])));
    cases.push(("an array, not a map", with_protected_bytes(&[0x81, 0x01])));
    cases.push(("a tagged map", with_protected_bytes(&concat(&[&[0xd8, 0x18], &protected]))));
    cases.push(("data after the map", with_protected_bytes(&concat(&[&protected, &[0x00]]))));
    cases.push(("a duplicate label", with_protected_bytes(&concat(&[&[0xa3], &protected[1..], &[0x01, 0x26]]))));
    cases.push(("kid as a text string", with_protected_bytes(&concat(&[&[0xa2, 0x01, 0x26, 0x04, 0x78, 0x58], kid]))));
    // Already 4c before the fix, and still: a wrong alg, an extra parameter
    // (rejects_extra_protected_parameters), a non-deterministic encoding,
    // the empty header.
    cases.push(("alg ES384", with_protected_bytes(&concat(&[&[0xa2, 0x01, 0x38, 0x22, 0x04, 0x58, 0x58], kid]))));
    cases.push(("kid length written 59 00 58", with_protected_bytes(&concat(&[&[0xa2, 0x01, 0x26, 0x04, 0x59, 0x00, 0x58], kid]))));
    cases.push(("labels in reverse order", with_protected_bytes(&concat(&[&[0xa2, 0x04, 0x58, 0x58], kid, &[0x01, 0x26]]))));
    cases.push(("the empty header", with_protected_bytes(&[])));

    for (what, bytes) in cases {
        match decode_record(&bytes) {
            Err(CoseDecodeError::ProtectedHeader(_)) => {}
            other => panic!("{what}: expected ProtectedHeader, got {other:?}"),
        }
        let err = Record::from_cose(&bytes).expect_err(what);
        assert!(err.to_string().contains("protected header"), "{what}: {err}");
    }
}

#[test]
fn errors_inside_the_unprotected_header_are_unprotected_header_errors() {
    // The same split for check 5c: the unprotected header must be the empty
    // map, so a map with anything in it - well-formed COSE or not - is 5c,
    // never 3c. (A value that is not well-formed CBOR at all breaks the one
    // CBOR item of 3c: the map is not a bstr, so its bytes are the
    // envelope's own.)
    let with_unprotected = |map: &[u8]| {
        let good = canonical_envelope();
        let at = 3 + 94;
        assert_eq!(good[at], 0xa0, "the empty unprotected map");
        [&good[..at], map, &good[at + 1..]].concat()
    };
    for (what, map) in [
        ("a kid as a text string", &[0xa1, 0x04, 0x61, 0x6b][..]),
        ("a duplicate label", &[0xa2, 0x04, 0x41, 0x6b, 0x04, 0x41, 0x6b][..]),
        ("an empty kid", &[0xa1, 0x04, 0x40][..]),
    ] {
        match decode_record(&with_unprotected(map)) {
            Err(CoseDecodeError::UnprotectedHeader) => {}
            other => panic!("{what}: expected UnprotectedHeader, got {other:?}"),
        }
    }
}

#[test]
fn breaking_the_outer_shape_is_still_a_structure_error() {
    // What stays check 3c: not one well-formed CBOR item, data after it, or
    // not an array [bstr, map, bstr / nil, bstr].
    let good = canonical_envelope();
    let structure = |what: &str, bytes: &[u8]| {
        match decode_record(bytes) {
            Err(CoseDecodeError::Cbor(_) | CoseDecodeError::NotSign1(_)) => {}
            other => panic!("{what}: expected Cbor or NotSign1, got {other:?}"),
        }
    };
    structure("truncated", &good[..good.len() - 1]);
    structure("data after the array", &[good.clone(), vec![0x00]].concat());
    structure("an invalid UTF-8 text key in the unprotected map", &[&good[..97], &[0xa1, 0x61, 0xff, 0x01], &good[98..]].concat());
    structure("five elements", &[&[0x85][..], &good[1..], &[0x40]].concat());
    structure("a map, not an array", &[0xa0]);
    structure("a tagged protected bstr", &[&[0x84, 0xd8, 0x18][..], &good[1..]].concat());
    structure("protected as a text string", &[&[0x84, 0x78, 0x5e][..], &good[3..]].concat());
    structure("unprotected as an array", &[&good[..97], &[0x80], &good[98..]].concat());
    let payload_head = &good[98..101];
    assert_eq!(payload_head[0], 0x59, "a two-byte payload length");
    structure("payload as a text string", &[&good[..98], &[0x79], &good[99..]].concat());
    let sig_at = good.len() - 66;
    assert_eq!(&good[sig_at..sig_at + 2], &[0x58, 0x40]);
    structure("signature as a text string", &[&good[..sig_at], &[0x78], &good[sig_at + 1..]].concat());
}

#[test]
fn huge_declared_lengths_fail_fast() {
    // A CBOR head may declare a length up to 2^64 - 1. None of these is ever
    // allocated: the envelope's CBOR walk refuses an 8-byte argument (spec
    // §4.4) before any decoder reads it, and bounds every shorter length by
    // the bytes left.
    let huge = [0x5b, 0x40, 0, 0, 0, 0, 0, 0, 0]; // bstr of 2^62 bytes
    let cases: Vec<Vec<u8>> = vec![
        [&[0x84][..], &huge, b"abc"].concat(), // protected header bstr
        [&[0x84, 0x40, 0xa0][..], &huge, b"{}"].concat(), // payload bstr
        [&[0x84, 0x40, 0xa0, 0x40][..], &huge].concat(), // signature bstr
        vec![0x9b, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x01], // array of 2^62 items
        vec![0x84, 0x40, 0xbb, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01], // map of 2^62 pairs
        vec![0x84, 0x7b, 0x40, 0, 0, 0, 0, 0, 0, 0, b'a'], // tstr of 2^62 bytes
    ];
    for bytes in cases {
        let err = decode_record(&bytes).expect_err("must fail on end of input");
        assert!(matches!(err, CoseDecodeError::Cbor(_) | CoseDecodeError::NotSign1(_)), "{err}");
    }
}

#[test]
fn deep_nesting_fails_without_overflow() {
    // 10 000 nested arrays (and maps) inside the envelope: the envelope's
    // CBOR walk refuses level 17 (spec §4.4) without recursing, before any
    // decoder with a limit of its own.
    for open in [0x81u8, 0xa1] {
        let mut bytes = vec![0x84];
        for _ in 0..10_000 {
            bytes.push(open);
            if open == 0xa1 {
                bytes.push(0x00); // map key, then the nested value
            }
        }
        bytes.push(0x00);
        let err = decode_record(&bytes).expect_err("must fail, not overflow");
        assert!(matches!(err, CoseDecodeError::Cbor(_)), "{err}");
    }
}

// ---------------------------------------------------------------------------
//  The envelope's CBOR: a stated subset nesting at most 16 levels (spec §4.4;
//  the reviewer's decision, 2026-09-13). Read head by head before anything is
//  decoded, so the check an envelope fails follows from the spec alone, not
//  from a CBOR decoder's limits.
// ---------------------------------------------------------------------------

/// The canonical envelope with the CBOR bytes `map` in place of its empty
/// unprotected header.
fn with_unprotected_bytes(map: &[u8]) -> Vec<u8> {
    let good = canonical_envelope();
    let at = 3 + 94;
    assert_eq!(good[at], 0xa0, "the empty unprotected map");
    [&good[..at], map, &good[at + 1..]].concat()
}

/// `{0: item}`, as an unprotected header.
fn map_holding(item: &[u8]) -> Vec<u8> {
    [&[0xa1, 0x00][..], item].concat()
}

/// Fails with every case whose result `ok` does not accept, all at once.
fn expect_each(cases: Vec<(String, Vec<u8>)>, expected: &str, ok: impl Fn(&Result<Record, CoseDecodeError>) -> bool) {
    let wrong: Vec<String> = cases
        .iter()
        .filter_map(|(what, bytes)| {
            let got = decode_record(bytes);
            (!ok(&got)).then(|| format!("{what}: expected {expected}, got {:?}", got.map(|_| "a record")))
        })
        .collect();
    assert!(wrong.is_empty(), "{} of {} cases:\n{}", wrong.len(), cases.len(), wrong.join("\n"));
}

#[test]
fn the_envelopes_cbor_nests_at_most_16_levels() {
    // The envelope's array is level 1, and an array or map is one level deeper
    // than the array or map holding it, as a key or as a value; only arrays and
    // maps count (a tag is outside the subset). Up to 16 levels, an unprotected
    // map holding the value is the unprotected-header error; an array or map
    // at level 17 is refused as the envelope's CBOR (check 3c), whatever else
    // is wrong with the envelope.
    type Build = fn(usize) -> Vec<u8>;
    let shapes: [(&str, Build); 3] = [
        ("{0: [[...]]}", |levels| [vec![0xa1, 0x00], vec![0x81; levels - 3], vec![0x80]].concat()),
        ("{0: {0: ... {}}}", |levels| [[0xa1, 0x00].repeat(levels - 2), vec![0xa0]].concat()),
        ("{[[...]]: 0}", |levels| [vec![0xa1], vec![0x81; levels - 3], vec![0x80, 0x00]].concat()),
    ];
    let (mut within, mut past) = (Vec::new(), Vec::new());
    for (shape, build) in shapes {
        for levels in [3usize, 15, 16] {
            within.push((format!("{shape}, {levels} levels"), with_unprotected_bytes(&build(levels))));
        }
        for levels in [17usize, 18, 257, 100_000] {
            past.push((format!("{shape}, {levels} levels"), with_unprotected_bytes(&build(levels))));
        }
    }
    // The envelope's own elements count too: arrays in place of the payload.
    let good = canonical_envelope();
    let sig_at = good.len() - 66;
    let as_payload = |levels: usize| [&good[..98], &vec![0x81u8; levels - 2][..], &[0x80][..], &good[sig_at..]].concat();
    expect_each(vec![("payload [[...]], 16 levels".into(), as_payload(16))], "NotSign1", |r| {
        matches!(r, Err(CoseDecodeError::NotSign1(_)))
    });
    past.push(("payload [[...]], 17 levels".into(), as_payload(17)));
    // A broken protected header does not come first.
    let mut broken = with_unprotected_bytes(&shapes[0].1(17));
    broken[7] = 0xd8;
    past.push(("{0: [[...]]}, 17 levels, the kid's bstr head a tag".into(), broken));
    let mut broken_within = with_unprotected_bytes(&shapes[0].1(16));
    broken_within[7] = 0xd8;
    expect_each(vec![("{0: [[...]]}, 16 levels, the kid's bstr head a tag".into(), broken_within)], "ProtectedHeader", |r| {
        matches!(r, Err(CoseDecodeError::ProtectedHeader(_)))
    });

    expect_each(within, "UnprotectedHeader", |r| matches!(r, Err(CoseDecodeError::UnprotectedHeader)));
    expect_each(past, "Cbor naming level 17", |r| matches!(r, Err(CoseDecodeError::Cbor(m)) if m.contains("level 17")));
}

#[test]
fn items_outside_the_envelopes_cbor_subset_are_refused_before_decoding() {
    // The subset holds unsigned and negative integers, byte and text strings
    // (UTF-8), arrays, maps and null, every argument immediate or in 1, 2 or 4
    // bytes. Anything else among the envelope's own data items is refused as
    // the envelope's CBOR (check 3c), whether or not a CBOR decoder can read it.
    let z8 = [0u8; 8];
    let items: Vec<(&str, Vec<u8>, &str)> = vec![
        ("false", vec![0xf4], "simple value"),
        ("true", vec![0xf5], "simple value"),
        ("undefined", vec![0xf7], "simple value"),
        ("the unassigned simple value 16", vec![0xf0], "simple value"),
        ("the one-byte simple value 32", vec![0xf8, 0x20], "simple value"),
        ("a half float", vec![0xf9, 0x00, 0x00], "simple value"),
        ("a single float", vec![0xfa, 0x00, 0x00, 0x00, 0x00], "simple value"),
        ("a double float", [&[0xfb][..], &z8].concat(), "simple value"),
        ("a break", vec![0xff], "simple value"),
        ("the bignum 2(h'01')", vec![0xc2, 0x41, 0x01], "tag"),
        ("the bignum 3(h'01')", vec![0xc3, 0x41, 0x01], "tag"),
        ("tag 1 over 0", vec![0xc1, 0x00], "tag"),
        ("tag 24 over h''", vec![0xd8, 0x18, 0x40], "tag"),
        ("tag 55799 over 0", vec![0xd9, 0xd9, 0xf7, 0x00], "tag"),
        ("an indefinite byte string", vec![0x5f, 0x41, 0x00, 0xff], "indefinite"),
        ("an indefinite text string", vec![0x7f, 0x61, 0x61, 0xff], "indefinite"),
        ("an indefinite array", vec![0x9f, 0xff], "indefinite"),
        ("an indefinite map", vec![0xbf, 0xff], "indefinite"),
        ("an 8-byte unsigned integer", [&[0x1b][..], &z8].concat(), "8-byte"),
        ("an 8-byte negative integer", [&[0x3b][..], &z8].concat(), "8-byte"),
        ("an 8-byte byte-string length", [&[0x5b][..], &z8].concat(), "8-byte"),
        ("an 8-byte text-string length", [&[0x7b][..], &z8].concat(), "8-byte"),
        ("an 8-byte array count", [&[0x9b][..], &z8].concat(), "8-byte"),
        ("an 8-byte map count", [&[0xbb][..], &z8].concat(), "8-byte"),
        ("reserved additional information 28", vec![0x1c], "reserved"),
        ("reserved additional information 29", vec![0x3d], "reserved"),
        ("reserved additional information 30", vec![0x5e], "reserved"),
        ("a text string that is not UTF-8", vec![0x62, 0xc3, 0x28], "UTF-8"),
    ];
    let mut wrong = Vec::new();
    let mut check = |what: String, bytes: Vec<u8>, word: &str| match decode_record(&bytes) {
        Err(CoseDecodeError::Cbor(m)) if m.contains(word) => {}
        other => wrong.push(format!("{what}: expected Cbor naming \"{word}\", got {:?}", other.map(|_| "a record"))),
    };
    for (what, item, word) in &items {
        check(format!("{{0: {what}}}"), with_unprotected_bytes(&map_holding(item)), word);
    }
    // In the envelope's own items too, where cose.canonical used to be the
    // first check to object.
    let good = canonical_envelope();
    let sig_at = good.len() - 66;
    check("the envelope array, indefinite".into(), [&[0x9f][..], &good[1..], &[0xff]].concat(), "indefinite");
    check("the unprotected map, indefinite".into(), with_unprotected_bytes(&[0xbf, 0xff]), "indefinite");
    check("the payload, an indefinite byte string".into(), [&good[..98], &[0x5f][..], &good[98..sig_at], &[0xff][..], &good[sig_at..]].concat(), "indefinite");
    check("the signature's length in 8 bytes".into(), [&good[..sig_at], &[0x5b, 0, 0, 0, 0, 0, 0, 0, 0x40][..], &good[sig_at + 2..]].concat(), "8-byte");
    check("a tag on the unprotected map".into(), [&good[..97], &[0xd8, 0x18][..], &good[97..]].concat(), "tag");
    assert!(wrong.is_empty(), "{} cases:\n{}", wrong.len(), wrong.join("\n"));
}

#[test]
fn items_inside_the_envelopes_cbor_subset_reach_the_header_checks() {
    // Inside the subset, the unprotected header is judged as before: a map
    // holding anything is the unprotected-header error (check 5c). Arguments
    // of 1, 2 and 4 bytes are inside, preferred or not; a non-preferred one
    // is the canonical-encoding error (check 8c), as before.
    let items: Vec<(&str, Vec<u8>)> = vec![
        ("0", vec![0x00]),
        ("23", vec![0x17]),
        ("255 in 1 byte", vec![0x18, 0xff]),
        ("65535 in 2 bytes", vec![0x19, 0xff, 0xff]),
        ("2^32 - 1 in 4 bytes", vec![0x1a, 0xff, 0xff, 0xff, 0xff]),
        ("-1", vec![0x20]),
        ("-2^32 in 4 bytes", vec![0x3a, 0xff, 0xff, 0xff, 0xff]),
        ("h''", vec![0x40]),
        ("h'00' with a 4-byte length", vec![0x5a, 0x00, 0x00, 0x00, 0x01, 0x00]),
        ("\"\"", vec![0x60]),
        ("\"a\"", vec![0x61, 0x61]),
        ("a noncharacter in a text string", vec![0x63, 0xef, 0xb7, 0x90]),
        ("[]", vec![0x80]),
        ("[1, -1, h'', \"\", {}, null]", vec![0x86, 0x01, 0x20, 0x40, 0x60, 0xa0, 0xf6]),
        ("{}", vec![0xa0]),
        ("null", vec![0xf6]),
    ];
    let cases = items
        .into_iter()
        .map(|(what, item)| (format!("{{0: {what}}}"), with_unprotected_bytes(&map_holding(&item))))
        .chain([("{\"note\": 1}".to_string(), with_unprotected_bytes(&[0xa1, 0x64, b'n', b'o', b't', b'e', 0x01]))])
        .collect();
    expect_each(cases, "UnprotectedHeader", |r| matches!(r, Err(CoseDecodeError::UnprotectedHeader)));
    let wide = vec![("the empty unprotected map written b8 00".to_string(), with_unprotected_bytes(&[0xb8, 0x00]))];
    expect_each(wide, "NotCanonical", |r| matches!(r, Err(CoseDecodeError::NotCanonical)));
}

#[test]
fn a_truncated_or_overlong_envelope_is_refused_as_its_cbor() {
    // Every length and count is bounded by the bytes left, and every head is
    // read only where the input has it: each of these is the envelope's CBOR
    // error (check 3c), never a panic, an allocation or a decoder's guess.
    let good = canonical_envelope();
    let mut cases: Vec<(String, Vec<u8>)> = (0..good.len()).map(|n| (format!("the first {n} bytes"), good[..n].to_vec())).collect();
    for (what, bytes) in [
        ("a protected bstr of 2^32 - 1 bytes", vec![0x84, 0x5a, 0xff, 0xff, 0xff, 0xff, 0x00]),
        ("an array of 2^32 - 1 items", vec![0x9a, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00]),
        ("an unprotected map of 2^32 - 1 pairs", vec![0x84, 0x40, 0xba, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00]),
        ("a text string longer than the input", vec![0x84, 0x40, 0xa0, 0x79, 0x01, 0x00, 0x61]),
        ("a length head cut inside its argument", vec![0x84, 0x40, 0xa0, 0x59, 0xff]),
        ("an array of 4 with 3 items", vec![0x84, 0x40, 0xa0, 0x40]),
        ("data after the envelope", [good.clone(), vec![0xf6]].concat()),
    ] {
        cases.push((what.to_string(), bytes));
    }
    expect_each(cases, "Cbor", |r| matches!(r, Err(CoseDecodeError::Cbor(_))));
}
