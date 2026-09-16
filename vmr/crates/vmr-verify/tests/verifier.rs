// tests/verifier.rs — the Verifier's pipeline and report (Phase 4 task 4.1;
// TASKS "test_verifier"): the input and JSON stages, fail-fast semantics,
// what a report records, and terminal-safe text.

mod common;

use serde_json::{json, Value};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::record::{JwkPublicKey, Record};
use vmr_record::sign::signing_key_from_secret;
use vmr_record::timestamp::Timestamp;
use vmr_verify::report::{CheckId, InputForm, Outcome, Verdict};
use vmr_verify::{display_safe, TrustStore, Verifier, VerifyOptions};

fn vector() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/test-vectors/record/example-v0.1.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The vector record as a JSON document.
fn vector_text() -> String {
    serde_json::to_string_pretty(&vector()["record"]).unwrap()
}

/// A store that trusts the vector key for the vector issuer.
fn vector_store() -> TrustStore {
    let k = signing_key_from_secret(&sha256(b"khalm v0.1 test-vector signing key")).unwrap();
    let j = JwkPublicKey::from_verifying_key(k.verifying_key());
    let doc = json!({
        "trust_store_version": "0.1",
        "issuers": [{
            "issuer_id": "did:web:factory-operator.ph",
            "issuer_name": "New Clark City Fab Operator",
            "keys": [{
                "key_id": j.key_id(), "public_key": j, "attestation_level": "software",
                "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z",
                "revoked": false
            }]
        }]
    });
    TrustStore::from_json(serde_json::to_string(&doc).unwrap().as_bytes()).unwrap()
}

fn at() -> VerifyOptions<'static> {
    VerifyOptions::new(Timestamp::parse("2026-09-11T00:00:00Z").unwrap())
}

fn verify_json(input: &[u8]) -> vmr_verify::VerificationReport {
    Verifier::new(vector_store()).verify_json(input, &at())
}

fn outcome(report: &vmr_verify::VerificationReport, id: CheckId) -> Outcome {
    report.checks.iter().find(|c| c.id == id).unwrap_or_else(|| panic!("{id:?} not in report")).outcome
}

/// The report fails, first at `id`, and every later check is skipped.
fn assert_fails_at(report: &vmr_verify::VerificationReport, id: CheckId) {
    assert_eq!(report.verdict, Verdict::Fail);
    let failure = report.failure.as_ref().expect("a failing report names its failure");
    assert_eq!(failure.check, id, "{}", failure.detail);
    let pos = report.checks.iter().position(|c| c.id == id).unwrap();
    for (i, c) in report.checks.iter().enumerate() {
        let expected = match i.cmp(&pos) {
            std::cmp::Ordering::Less => Outcome::Pass,
            std::cmp::Ordering::Equal => Outcome::Fail,
            std::cmp::Ordering::Greater => Outcome::Skipped,
        };
        assert_eq!(c.outcome, expected, "{:?} ({})", c.id, c.detail);
    }
    assert!(!report.accepted);
    assert_eq!(report.exit_code(), 3);
}

#[test]
fn the_vector_passes_the_input_and_json_stages() {
    let report = verify_json(vector_text().as_bytes());
    let ids: Vec<CheckId> = report.checks.iter().map(|c| c.id).collect();
    assert_eq!(
        &ids[..4],
        [CheckId::InputSize, CheckId::InputForm, CheckId::JsonSyntax, CheckId::JsonStructure]
    );
    for c in &report.checks[..4] {
        assert_eq!(c.outcome, Outcome::Pass, "{:?}: {}", c.id, c.detail);
    }
}

#[test]
fn empty_input_fails_input_form() {
    assert_fails_at(&verify_json(b""), CheckId::InputForm);
}

#[test]
fn a_byte_order_mark_fails_input_form() {
    let bom = [&[0xef, 0xbb, 0xbf][..], vector_text().as_bytes()].concat();
    let report = verify_json(&bom);
    assert_fails_at(&report, CheckId::InputForm);
    assert!(report.failure.unwrap().detail.contains("byte order mark"));
}

#[test]
fn cose_bytes_are_not_the_json_form() {
    let p: Record = serde_json::from_value(vector()["record"].clone()).unwrap();
    assert_fails_at(&verify_json(&p.to_cose().unwrap()), CheckId::InputForm);
}

#[test]
fn leading_json_whitespace_is_fine() {
    let text = format!(" \t\r\n{}", vector_text());
    assert_eq!(outcome(&verify_json(text.as_bytes()), CheckId::JsonStructure), Outcome::Pass);
}

#[test]
fn invalid_utf8_fails_json_syntax() {
    let text = vector_text().replacen("New Clark", "New \u{e9}Clark", 1);
    let mut bytes = text.into_bytes();
    let at = bytes.iter().position(|&b| b == 0xc3).unwrap();
    bytes[at] = 0xff; // an invalid UTF-8 lead byte inside a string
    let report = verify_json(&bytes);
    assert_fails_at(&report, CheckId::JsonSyntax);
    assert!(report.failure.unwrap().detail.contains("UTF-8"));
}

#[test]
fn garbage_and_truncation_fail_json_syntax() {
    let text = vector_text();
    for bad in ["{garbage".to_string(), text[..text.len() / 2].to_string(), "{".to_string()] {
        assert_fails_at(&verify_json(bad.as_bytes()), CheckId::JsonSyntax);
    }
}

#[test]
fn trailing_data_fails_json_syntax() {
    let text = format!("{} {{}}", vector_text());
    assert_fails_at(&verify_json(text.as_bytes()), CheckId::JsonSyntax);
    // Trailing whitespace is not data.
    let spaced = format!("{}\n\n  ", vector_text());
    assert_eq!(outcome(&verify_json(spaced.as_bytes()), CheckId::JsonStructure), Outcome::Pass);
}

#[test]
fn input_over_1_mib_fails_input_size() {
    let limit = vmr_verify::MAX_RECORD_BYTES;
    assert_eq!(limit, 1024 * 1024);
    let mut bytes = vector_text().into_bytes();
    bytes.resize(limit, b' ');
    assert_eq!(outcome(&verify_json(&bytes), CheckId::InputSize), Outcome::Pass);
    bytes.push(b' ');
    assert_fails_at(&verify_json(&bytes), CheckId::InputSize);
}

/// The vector record as a JSON value, edited.
fn edited(f: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut v = vector()["record"].clone();
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn structure_violations_fail_json_structure() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("unknown member", edited(|v| {
            v["issuer"].as_object_mut().unwrap().insert("trusted".into(), json!(true));
        })),
        ("missing signature", edited(|v| {
            v.as_object_mut().unwrap().remove("signature");
        })),
        ("null lineage member", edited(|v| v["lineage"]["previous_record_id"] = Value::Null)),
        ("integer written 12.0", edited(|v| v["learning_provenance"]["training_epochs"] = json!(12.0))),
        ("integer above 2^53 - 1", edited(|v| {
            v["model_identity"]["parameter_count"] = json!(9_007_199_254_740_992u64)
        })),
        ("wrong type", edited(|v| v["deployment_context"]["inference_boundary"]["egress_allowed"] = json!("no"))),
        ("an object without the record's members", b"{\"record\": 1}".to_vec()),
    ];
    for (what, bytes) in cases {
        let report = verify_json(&bytes);
        assert_fails_at(&report, CheckId::JsonStructure);
        assert!(report.record.is_none(), "{what}: no record section before it parsed");
    }
    // Duplicate members, written by hand (serde_json never writes them).
    let text = vector_text().replacen("\"issued_at\":", "\"issued_at\": \"2020-01-01T00:00:00Z\",\n  \"issued_at\":", 1);
    let report = verify_json(text.as_bytes());
    assert_fails_at(&report, CheckId::JsonStructure);
    assert!(report.failure.unwrap().detail.contains("duplicate field"));
}

#[test]
fn another_spelling_of_a_signed_integer_fails_json_structure() {
    // QA P4-01, spec §2 rule 4 and check 4j: an integer is written `0` or a
    // non-zero digit followed by digits. Each record below is validly
    // signed by the trusted key with training_epochs = 0 or 10 and verifies
    // as written; respelled - no key needed - it is still valid RFC 8259,
    // passes json.syntax and fails json.structure. The QA's independent
    // verifier accepted `-0` under the old wording: one signed record, two
    // verdicts.
    for (value, spellings) in [
        (0u64, &["-0", "0.0", "-0.0", "0e0", "0E0", "0e+0"][..]),
        (10, &["1e1", "1E1", "1e+1", "10.0", "100e-1"][..]),
    ] {
        let p = common::vector_edited(|p| p.learning_provenance.training_epochs = Some(value));
        let text = serde_json::to_string(&p).unwrap();
        let written = format!("\"training_epochs\":{value}");
        assert!(text.contains(&written));
        let report = common::verify_json_with(common::basic_store(), text.as_bytes(), common::T);
        common::assert_passes(&report);
        for spelling in spellings {
            let respelled = text.replacen(&written, &format!("\"training_epochs\":{spelling}"), 1);
            let report = common::verify_json_with(common::basic_store(), respelled.as_bytes(), common::T);
            assert_fails_at(&report, CheckId::JsonStructure);
            assert_eq!(outcome(&report, CheckId::JsonSyntax), Outcome::Pass, "{spelling}");
        }
    }
}

#[test]
fn a_lone_surrogate_escape_fails_json_structure() {
    // QA P4-03, spec §2 rule 1 and check 4j: strings are sequences of
    // Unicode scalar values (RFC 8785 §3.1). A \u escape of an unpaired
    // surrogate is valid RFC 8259 syntax - json.syntax passes - and the
    // record fails json.structure: in a value, or in a member name.
    let text = serde_json::to_string(&vector()["record"]).unwrap();
    for escape in ["\\ud800", "\\udbff", "\\udc00", "\\udfff", "\\ud800\\u0041", "\\ud800\\ud800", "\\udc00\\ud800"] {
        for (from, to) in [
            ("\"New Clark", format!("\"New {escape}Clark")),
            ("\"issuer_name\":", format!("\"{escape}\":1,\"issuer_name\":")),
        ] {
            assert!(text.contains(from));
            let report = verify_json(text.replacen(from, &to, 1).as_bytes());
            assert_fails_at(&report, CheckId::JsonStructure);
        }
    }
    // A surrogate PAIR is one scalar value: the string parses (the
    // signature, over other bytes, fails later).
    let pair = text.replacen("\"New Clark", "\"New \\ud83d\\ude00Clark", 1);
    assert_eq!(outcome(&verify_json(pair.as_bytes()), CheckId::JsonStructure), Outcome::Pass);
}

#[test]
fn a_signed_record_with_noncharacters_verifies_raw_or_escaped() {
    // Noncharacters (U+FDD0-U+FDEF, U+xFFFE/U+xFFFF of every plane) are
    // scalar values: permitted, raw or escaped. A verifier that rejected
    // them "helpfully" would split from this one on a validly signed
    // record (spec §2 rule 1).
    let description = "sensor stream \u{fdd0}\u{fdef}\u{fffe}\u{ffff}\u{1fffe}\u{10ffff} end";
    let p = common::vector_edited(|p| {
        p.learning_provenance.training_input_provenance.source_description = description.into();
    });
    let raw = serde_json::to_string(&p).unwrap();
    assert!(raw.contains(description), "serde_json writes them raw");
    common::assert_passes(&common::verify_json_with(common::basic_store(), raw.as_bytes(), common::T));
    let escaped = raw.replacen(
        description,
        "sensor stream \\ufdd0\\uFDEF\\ufffe\\uffff\\ud83f\\udffe\\udbff\\udfff end",
        1,
    );
    assert_ne!(escaped, raw);
    let report = common::verify_json_with(common::basic_store(), escaped.as_bytes(), common::T);
    common::assert_passes(&report);
    assert_eq!(report.record.unwrap().signed_payload_hash, p.signed_payload_hash().ok());
}

#[test]
fn surrogates_encoded_in_utf8_fail_json_syntax() {
    // A surrogate written as UTF-8 bytes (CESU-8 style) is not UTF-8:
    // json.syntax, as before - only the \u escape form is a structure matter.
    let text = serde_json::to_string(&vector()["record"]).unwrap();
    let at = text.find("New Clark").unwrap() + "New ".len();
    for bad in [&[0xed, 0xa0, 0x80][..], &[0xed, 0xb0, 0x80][..], &[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80][..]] {
        let bytes = [&text.as_bytes()[..at], bad, &text.as_bytes()[at..]].concat();
        let report = verify_json(&bytes);
        assert_fails_at(&report, CheckId::JsonSyntax);
        assert!(report.failure.unwrap().detail.contains("UTF-8"));
    }
}

#[test]
fn deep_nesting_is_rejected_without_recursing() {
    // Valid JSON 100 000 levels deep: the syntax pass skips it iteratively;
    // the structure pass rejects the unknown member before descending.
    let text = format!("{{\"deep\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000));
    assert_fails_at(&verify_json(text.as_bytes()), CheckId::JsonStructure);
}

#[test]
fn nesting_deeper_than_a_record_fails_json_structure_at_every_depth() {
    // Spec §2 rule 13, checks 3j and 4j: a record nests arrays and objects
    // at most four levels deep, the outermost object counting as the first.
    // Depth is a structure rule, not a syntax rule. The syntax pass reads any
    // depth, and a deeper text fails json.structure on both sides of the
    // limits JSON parsers commonly have (64, serde_json's 128, 1 000) and far
    // past them.
    let compact = serde_json::to_string(&vector()["record"]).unwrap();
    assert_eq!(common::nesting_depth(&compact), 4);
    for levels in [5usize, 64, 65, 127, 128, 129, 1_000, 1_001, 100_000] {
        let text = common::nested_at_issuer_name(&compact, levels);
        let report = verify_json(text.as_bytes());
        assert_fails_at(&report, CheckId::JsonStructure);
        let detail = report.failure.unwrap().detail;
        assert!(!detail.contains("recursion"), "{levels} levels: {detail}");
        // A syntax error anywhere, even past the deep part, is json.syntax:
        // the whole text is read for syntax before its structure.
        assert_fails_at(&verify_json(format!("{text} x").as_bytes()), CheckId::JsonSyntax);
        let arrays = levels - 2;
        let unclosed = text.replacen(
            &common::nested_arrays(arrays),
            &format!("{}{}", "[".repeat(arrays), "]".repeat(arrays - 1)),
            1,
        );
        assert_fails_at(&verify_json(unclosed.as_bytes()), CheckId::JsonSyntax);
    }
}

#[test]
fn the_report_records_its_inputs() {
    let text = vector_text();
    let store = vector_store();
    let store_hash = store.sha256().to_string();
    let report = Verifier::new(store).verify_json(text.as_bytes(), &at());
    assert_eq!(report.report_version, "0.1");
    assert_eq!(report.evaluation_time, "2026-09-11T00:00:00Z");
    assert_eq!(report.input.form, InputForm::Json);
    assert_eq!(report.input.byte_length, text.len() as u64);
    assert_eq!(report.input.sha256, format_hash(&sha256(text.as_bytes())));
    assert_eq!(report.trust_store.sha256, store_hash);
    assert_eq!((report.trust_store.issuer_count, report.trust_store.key_count), (1, 1));
}

#[test]
fn the_record_section_holds_the_claims_once_parsed() {
    let report = verify_json(vector_text().as_bytes());
    let p = report.record.expect("parsed");
    let v = &vector()["record"];
    assert_eq!(p.record_id, v["record_id"].as_str().unwrap());
    assert_eq!(p.issued_at, "2026-09-10T00:00:00Z");
    assert_eq!(
        p.signed_payload_hash.as_deref(),
        Some(vector()["expected"]["signed_payload_hash"].as_str().unwrap()),
        "recomputed, not read from the signature section"
    );
    assert_eq!(p.learned_state_hash, v["model_identity"]["learned_state_hash"].as_str().unwrap());
    assert_eq!(p.training_input_digest, v["learning_provenance"]["training_input_digest"].as_str().unwrap());
    assert_eq!(p.issuer_id, "did:web:factory-operator.ph");
    assert_eq!(p.issuer_name, "New Clark City Fab Operator");
    assert_eq!(p.attestation_level, "software");
    assert_eq!(p.lineage_type, "initial");
}

#[test]
fn no_report_passes_without_a_signature_verified_under_a_trusted_key() {
    // The verdict is never `pass` unless `signature.valid` passed: a
    // pipeline that skipped the trust stage, for whatever reason, fails
    // on it. (Until the trust checks exist - task 4.3 - this is how the
    // vector's report ends.)
    let report = verify_json(vector_text().as_bytes());
    if report.verdict == Verdict::Pass {
        assert_eq!(outcome(&report, CheckId::SignatureValid), Outcome::Pass);
    } else {
        assert!(report.checks.iter().all(|c| c.outcome != Outcome::Fail));
        assert_eq!(report.failure.unwrap().check, CheckId::SignatureValid);
    }
}

#[test]
fn report_json_is_deterministic() {
    let text = vector_text();
    let a = Verifier::new(vector_store()).verify_json(text.as_bytes(), &at()).to_json().unwrap();
    let b = Verifier::new(vector_store()).verify_json(text.as_bytes(), &at()).to_json().unwrap();
    assert_eq!(a, b);
    let bad = verify_json(b"{nope").to_json().unwrap();
    assert_eq!(bad, verify_json(b"{nope").to_json().unwrap());
    // The JSON names checks by their stable ids.
    assert!(bad.contains("\"json.syntax\""), "{bad}");
}

#[test]
fn check_ids_are_the_stable_vocabulary() {
    let ids: Vec<&str> = CheckId::ALL.iter().map(|c| c.id()).collect();
    assert_eq!(
        ids,
        [
            "input.size", "input.form", "json.syntax", "json.structure", "cose.structure",
            "cose.protected_header", "cose.unprotected_header", "cose.signature_encoding",
            "cose.payload", "cose.canonical", "format.schema", "format.consistency",
            "signature.algorithm", "signature.encoding", "signature.low_s",
            "signature.payload_hash", "key.binding", "trust.key_known", "signature.valid",
            "trust.issuer", "trust.key_not_revoked", "trust.key_validity", "trust.attestation",
            "time.not_future", "time.policy_not_after_issued", "lineage.consistency",
            "lineage.chain",
        ]
    );
    for c in CheckId::ALL {
        assert_eq!(serde_json::to_value(c).unwrap(), json!(c.id()));
    }
}

#[test]
fn display_safe_escapes_what_can_hijack_a_terminal() {
    assert_eq!(display_safe("New Clark City Fab Operator"), "New Clark City Fab Operator");
    assert_eq!(display_safe("工場 ✓ ü"), "工場 ✓ ü");
    assert_eq!(display_safe("\u{1b}[2J\u{1b}[32m✓ valid"), "\\u{001b}[2J\\u{001b}[32m✓ valid");
    assert_eq!(display_safe("a\rb\nc\td\0"), "a\\u{000d}b\\u{000a}c\\u{0009}d\\u{0000}");
    assert_eq!(display_safe("\u{7f}\u{85}\u{9b}"), "\\u{007f}\\u{0085}\\u{009b}");
    for c in ['\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{2028}', '\u{2029}', '\u{200e}', '\u{200f}', '\u{61c}'] {
        let out = display_safe(&format!("x{c}y"));
        assert_eq!(out, format!("x\\u{{{:04x}}}y", u32::from(c)), "{c:?}");
    }
    // A backslash is doubled, so an escape cannot be forged by the input.
    assert_eq!(display_safe("\\u{001b}"), "\\\\u{001b}");
}

#[test]
fn display_safe_escapes_invisible_characters_and_noncharacters() {
    // QA P4-06: characters that render as nothing can make two names look
    // identical ("Fab\u{200b}Operator" vs "FabOperator"). display_safe now
    // escapes every Default_Ignorable_Code_Point (Unicode 16.0.0) and every
    // noncharacter, besides the controls and separators it escaped before.
    for (what, c) in [
        ("zero width space", '\u{200b}'),
        ("zero width non-joiner", '\u{200c}'),
        ("zero width joiner", '\u{200d}'),
        ("word joiner", '\u{2060}'),
        ("invisible plus", '\u{2064}'),
        ("byte order mark / ZWNBSP", '\u{feff}'),
        ("soft hyphen", '\u{ad}'),
        ("combining grapheme joiner", '\u{34f}'),
        ("hangul filler", '\u{3164}'),
        ("mongolian vowel separator", '\u{180e}'),
        ("tag LATIN CAPITAL A", '\u{e0041}'),
        ("cancel tag", '\u{e007f}'),
        ("variation selector 16", '\u{fe0f}'),
        ("variation selector 17", '\u{e0100}'),
        ("noncharacter U+FDD0", '\u{fdd0}'),
        ("noncharacter U+FFFE", '\u{fffe}'),
        ("noncharacter U+FFFF", '\u{ffff}'),
        ("noncharacter U+1FFFE", '\u{1fffe}'),
        ("noncharacter U+10FFFF", '\u{10ffff}'),
    ] {
        let out = display_safe(&format!("Fab{c}Operator"));
        assert_eq!(out, format!("Fab\\u{{{:04x}}}Operator", u32::from(c)), "{what}");
    }
    // Every range, at both ends and just outside. Outside stays as it is,
    // unless it is unsafe for another reason: U+2029 is a separator, U+DFFFF
    // (just before the tag block) a noncharacter.
    let ranges: [(u32, u32); 19] = [
        (0x00ad, 0x00ad), (0x034f, 0x034f), (0x061c, 0x061c), (0x115f, 0x1160), (0x17b4, 0x17b5),
        (0x180b, 0x180f), (0x200b, 0x200f), (0x202a, 0x202e), (0x2060, 0x206f), (0x3164, 0x3164),
        (0xfdd0, 0xfdef), (0xfe00, 0xfe0f), (0xfeff, 0xfeff), (0xffa0, 0xffa0), (0xfff0, 0xfff8),
        (0x1bca0, 0x1bca3), (0x1d173, 0x1d17a), (0x1fffe, 0x1ffff), (0xe0000, 0xe0fff),
    ];
    let escaped = |code: u32| {
        let c = char::from_u32(code).unwrap();
        display_safe(&c.to_string()) != c.to_string()
    };
    for (lo, hi) in ranges {
        assert!(escaped(lo) && escaped(hi), "U+{lo:04X}..U+{hi:04X}");
        for outside in [lo - 1, hi + 1] {
            assert_eq!(escaped(outside), matches!(outside, 0x2029 | 0xdffff), "U+{outside:04X}");
        }
    }
    // Ordinary text is untouched: ASCII, accented Latin, CJK, symbols,
    // emoji without a selector, U+FFFD, the Hangul letter after the filler.
    for fine in ["New Clark City Fab Operator", "Ünïcødé café – Łódź", "工場 東京 서울", "✓ ✗ € ¬ ®", "😀", "\u{fffd}", "\u{3165}"] {
        assert_eq!(display_safe(fine), fine, "{fine}");
    }
}

#[test]
fn details_quote_little_and_nothing_unsafe() {
    // A member name the size of a novel, carrying terminal escapes: the
    // detail stays short and escape-free.
    let name = format!("\u{1b}[2J{}", "x".repeat(10_000));
    let bytes = edited(|v| {
        v.as_object_mut().unwrap().insert(name.clone(), json!(1));
    });
    let report = verify_json(&bytes);
    assert_fails_at(&report, CheckId::JsonStructure);
    let detail = &report.failure.unwrap().detail;
    assert!(detail.chars().count() < 400, "{} characters", detail.chars().count());
    assert!(!detail.contains('\u{1b}'), "{detail}");
    for c in &report.checks {
        assert!(!c.detail.contains('\u{1b}'));
    }
}
