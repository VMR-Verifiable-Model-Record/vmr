// tests/common/generate.rs — the generator of specs/test-vectors/verify/ and
// specs/test-vectors/trust-store/ (Phase 4 task 4.9). Included by
// tests/vectors.rs. Every artifact starts from the committed record vector
// and is re-signed with the derived test keys of plan §8 - no engine, no GPU,
// no randomness (RFC 6979), so the files regenerate byte for byte anywhere.
//
// The EXPECTED result of every case is written here by hand, from the spec -
// never computed by running the verifier - so the vectors test the
// implementation instead of mirroring it.

#![allow(dead_code)] // several test crates include this file; each uses part of it

use crate::common::*;
use coset::{CborSerializable, CoseSign1, HeaderBuilder};
use serde_json::{json, Value};
use vmr_record::record::{DocumentationRef, Record, SignatureSection};

/// Every generated file: (path relative to specs/test-vectors/, contents).
pub fn generate() -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = stores()
        .into_iter()
        .map(|(name, doc)| (format!("verify/trust-stores/{name}.json"), pretty(&doc)))
        .collect();
    files.push(("verify/cases.json".into(), pretty(&verify_cases())));
    files.push(("trust-store/cases.json".into(), pretty(&loader_cases())));
    files
}

fn pretty(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap())
}

// ---------------------------------------------------------------------------
//  Trust stores
// ---------------------------------------------------------------------------

fn entry(issuer: &'static str, key: &'static str) -> Entry {
    Entry::new(issuer, key)
}

pub fn stores() -> Vec<(&'static str, Value)> {
    let mut revoked = entry(VECTOR_ISSUER, KEY_A);
    revoked.revoked = true;
    let mut before = entry(VECTOR_ISSUER, KEY_A);
    before.valid_from = "2026-09-10T00:00:01Z";
    let mut until = entry(VECTOR_ISSUER, KEY_A);
    until.valid_until = Some("2026-09-10T00:00:00Z");
    let mut from = entry(VECTOR_ISSUER, KEY_A);
    from.valid_from = "2026-09-10T00:00:00Z";
    from.valid_until = Some("2026-09-10T00:00:01Z");
    let mut hardware = entry(VECTOR_ISSUER, KEY_A);
    hardware.level = "hardware";
    let mut a_until = entry(VECTOR_ISSUER, KEY_A);
    a_until.valid_until = Some("2026-09-10T06:00:00Z");
    let mut a2_from = entry(VECTOR_ISSUER, KEY_A2);
    a2_from.valid_from = "2026-09-10T06:00:00Z";
    let mut a2_revoked = entry(VECTOR_ISSUER, KEY_A2);
    a2_revoked.revoked = true;
    vec![
        ("ts-basic", store_json(&[entry(VECTOR_ISSUER, KEY_A), entry(OTHER_ISSUER, KEY_B)])),
        ("ts-rotated", store_json(&[entry(VECTOR_ISSUER, KEY_A), entry(VECTOR_ISSUER, KEY_A2)])),
        ("ts-revoked", store_json(&[revoked])),
        ("ts-window-before", store_json(&[before])),
        ("ts-window-until", store_json(&[until])),
        ("ts-window-from", store_json(&[from])),
        ("ts-attestation-hardware", store_json(&[hardware])),
        ("ts-key-for-other-issuer", store_json(&[entry(OTHER_ISSUER, KEY_A)])),
        ("ts-two-keys", store_json(&[entry(VECTOR_ISSUER, KEY_A), entry(VECTOR_ISSUER, KEY_B)])),
        ("ts-rotation-window", store_json(&[a_until, a2_from])),
        ("ts-a2-revoked", store_json(&[entry(VECTOR_ISSUER, KEY_A), a2_revoked])),
        ("ts-empty", store_json(&[])),
    ]
}

// ---------------------------------------------------------------------------
//  Inputs
// ---------------------------------------------------------------------------

fn text(t: &str) -> Value {
    json!({"form": "json", "text": t})
}

fn json_hex(bytes: &[u8]) -> Value {
    json!({"form": "json", "hex": hex::encode(bytes)})
}

fn cose(bytes: &[u8]) -> Value {
    json!({"form": "cose", "hex": hex::encode(bytes)})
}

/// The record's JSON form, pretty-printed (as `to_json` writes it).
fn pj(p: &Record) -> Value {
    text(&p.to_json().unwrap())
}

/// The record's JSON form, compact.
fn cj(p: &Record) -> Value {
    text(&serde_json::to_string(p).unwrap())
}

fn pc(p: &Record) -> Value {
    cose(&p.to_cose().unwrap())
}

fn compact(p: &Record) -> String {
    serde_json::to_string(p).unwrap()
}

#[derive(Clone)]
struct Case {
    id: String,
    description: String,
    input: Value,
    store: &'static str,
    t: &'static str,
    previous: Vec<Value>,
    complete: bool,
    verdict: &'static str,
    check: Option<&'static str>,
    lineage: Option<&'static str>,
}

fn case(id: &str, description: &str, input: Value) -> Case {
    Case {
        id: id.to_string(),
        description: description.to_string(),
        input,
        store: "ts-basic",
        t: T,
        previous: Vec::new(),
        complete: false,
        verdict: "pass",
        check: None,
        lineage: None,
    }
}

impl Case {
    fn fails(mut self, check: &'static str) -> Self {
        self.verdict = "fail";
        self.check = Some(check);
        self
    }
    fn store(mut self, s: &'static str) -> Self {
        self.store = s;
        self
    }
    fn at(mut self, t: &'static str) -> Self {
        self.t = t;
        self
    }
    fn prev(mut self, previous: Vec<Value>) -> Self {
        self.previous = previous;
        self
    }
    fn complete(mut self) -> Self {
        self.complete = true;
        self
    }
    fn lineage(mut self, status: &'static str) -> Self {
        self.lineage = Some(status);
        self
    }
    fn to_json(&self) -> Value {
        let mut expected = json!({"verdict": self.verdict});
        if let Some(c) = self.check {
            expected["check"] = json!(c);
        }
        if let Some(l) = self.lineage {
            expected["lineage"] = json!(l);
        }
        json!({
            "id": self.id,
            "description": self.description,
            "input": self.input,
            "trust_store": self.store,
            "evaluation_time": self.t,
            "previous": self.previous,
            "require_complete_lineage": self.complete,
            "expected": expected,
        })
    }
}

// ---------------------------------------------------------------------------
//  Records: the vector and its variants
// ---------------------------------------------------------------------------

pub const U2: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b2";
pub const U3: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b3";
const U9: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b9";

/// A successor of `prev`, linked by its recomputed payload hash.
pub fn successor(prev: &Record, id: &str, issued_at: &str, kind: &str, key_label: &str) -> Record {
    let mut p = prev.clone();
    p.record_id = id.into();
    p.issued_at = issued_at.into();
    p.lineage.previous_record_id = Some(prev.record_id.clone());
    p.lineage.previous_record_hash = Some(prev.signed_payload_hash().unwrap());
    p.lineage.lineage_chain_length = prev.lineage.lineage_chain_length + 1;
    p.lineage.root_record_id = prev.lineage.root_record_id.clone();
    p.lineage.lineage_type = kind.into();
    reissue_with(&mut p, key_label);
    p
}

/// P2 edited after linking, re-signed with key A (a broken link).
fn p2_edited(edit: impl FnOnce(&mut Record)) -> Record {
    let mut p = successor(&vector(), U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
    edit(&mut p);
    sign_as(&mut p, KEY_A);
    p
}

fn with_sign1(p: &Record, edit: impl FnOnce(&mut CoseSign1)) -> Vec<u8> {
    let mut s = CoseSign1::from_slice(&p.to_cose().unwrap()).unwrap();
    edit(&mut s);
    s.to_vec().unwrap()
}

fn b64(bytes: &[u8]) -> String {
    format!("base64url:{}", vmr_record::encoding::b64url_encode(bytes))
}

// ---------------------------------------------------------------------------
//  The verification cases (expected results by hand, from spec §6)
// ---------------------------------------------------------------------------

/// Whether any record of the case names the engine profile, compared as
/// `specs/conformance/build_suite.py` compares it: as a JSON string anywhere
/// in the record's bytes.
fn names_profile(c: &Case) -> bool {
    let mut docs = vec![input_bytes(&c.input)];
    docs.extend(c.previous.iter().map(input_bytes));
    docs.iter().any(|d| {
        String::from_utf8_lossy(d).contains("snn-compact-v1")
            || d.windows(PROFILE_BYTES.len()).any(|w| w == PROFILE_BYTES)
    })
}

const PROFILE_BYTES: &[u8] = b"snn-compact-v1";

/// Cases of a rule that only the engine profile has, whose id does not say
/// so: the general description does not check `parameter_count` (spec §7.3,
/// "Neither is checked"), so the same edit passes on a general-description
/// record and the case has, and can have, no copy. Every other
/// `format.consistency` case of an engine record tests a rule of §7.2, §8.2,
/// §8.4 or §8.5 that both descriptions share, and does have one.
/// `specs/conformance/build_suite.py` keeps the same list.
const PROFILE_ONLY_CASES: &[&str] = &["fail-consistency-parameter-count"];

/// The committed cases, then a copy of each case of a general rule that the
/// committed set tests only on an engine record, over
/// [`crate::common::general_twin`] (the owner, 2026-09-16: the engine profile
/// is optional, so the general core must keep the failure coverage it has
/// today - `specs/conformance/suite.json`'s
/// `general_checks_on_engine_records`).
///
/// A copy is kept only when the original names the profile, the copy does
/// not, and the case is not one of the profile's OWN rules: an id with
/// `profile` in it, or one of [`PROFILE_ONLY_CASES`]. Those cannot be
/// described generally without ceasing to be what they test. Every kept
/// copy's expected verdict and check are the original's, which the twin makes
/// correct by construction.
pub fn verify_cases() -> Value {
    let base = built_cases();
    let twins = with_base(general_twin(), built_cases);
    assert_eq!(base.len(), twins.len(), "the two passes build the same cases");
    let mut c: Vec<Case> = Vec::with_capacity(base.len() + twins.len());
    let mut copied: Vec<Case> = Vec::new();
    for (original, mut twin) in base.iter().cloned().zip(twins) {
        c.push(original.clone());
        if !names_profile(&original) || names_profile(&twin) || original.id.contains("profile")
            || PROFILE_ONLY_CASES.contains(&original.id.as_str())
        {
            continue;
        }
        assert_eq!(twin.id, original.id, "the two passes build the same case ids");
        twin.description = format!(
            "{} The same check on a general-description record: the vector's model_format and \
             learned_state_hash are the general description's (spec §7.1, §7.3) and every other \
             byte is unchanged, so the checks read the same values and the expected result is \
             this case's.",
            original.description
        );
        twin.id = format!("{}-general-record", original.id);
        copied.push(twin);
    }
    assert!(copied.len() >= 120, "{} general-description copies", copied.len());
    c.extend(copied);

    json!({
        "description": "Verifiable Model Record verification vectors, v0.1. For each case a conforming verifier, given the input (in the form stated), the trust store (trust-stores/<name>.json), the evaluation time, the predecessors (immediate predecessor first) and the complete-lineage requirement, must produce the expected verdict and, for a failure, the expected first failing check (record format v0.1, §6.2); `lineage`, where given, is the expected lineage outcome (§6.5). Input bytes: `text` as UTF-8, or `hex`; then `append_spaces` ASCII spaces if present. Generated by the vmr-verify crate's vector generator (VMR_WRITE_VECTORS=1 cargo test -p vmr-verify --test vectors -- --ignored) - never hand-edited. Every key is test-only (see README.md).",
        "vector_version": "0.1",
        "cases": c.iter().map(Case::to_json).collect::<Vec<_>>(),
    })
}

#[allow(clippy::vec_init_then_push)]
fn built_cases() -> Vec<Case> {
    let v = vector();
    let p1 = vector();
    let p2 = successor(&p1, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
    let p3 = successor(&p2, U3, "2026-09-10T18:00:00Z", "fine-tune", KEY_A);
    let raw_sig = vmr_record::encoding::b64url_decode(v.signature.signature.strip_prefix("base64url:").unwrap()).unwrap();
    let sig = p256::ecdsa::Signature::from_slice(&raw_sig).unwrap();

    let mut c: Vec<Case> = Vec::new();

    // --- passes ------------------------------------------------------------
    c.push(case("pass-vector-json", "The committed record vector, JSON form, pretty-printed.", pj(&v)).lineage("initial"));
    c.push(case("pass-vector-json-compact", "The vector, compact JSON.", cj(&v)));
    {
        let reordered = {
            let value = serde_json::to_value(&v).unwrap();
            let mut m = serde_json::Map::new();
            for (k, val) in value.as_object().unwrap().iter().rev() {
                m.insert(k.clone(), val.clone());
            }
            serde_json::to_string(&Value::Object(m)).unwrap().replace("New Clark", "New \\u0043lark")
        };
        c.push(case(
            "pass-vector-json-reordered-escaped",
            "The vector with its members in reverse order and one character written as a \\u escape: the same signed payload.",
            text(&reordered),
        ));
    }
    c.push(case("pass-vector-cose", "The vector's COSE_Sign1 form.", pc(&v)));
    {
        let mut p = v.clone();
        reissue_with(&mut p, KEY_A2);
        c.push(case("pass-rotated-key", "Signed by the issuer's second trusted key (A2).", pj(&p)).store("ts-rotated"));
    }
    c.push(case("pass-window-starts-at-issued-at", "valid_from == issued_at: inside the key's window.", pj(&v)).store("ts-window-from"));
    c.push(case(
        "pass-attestation-under-claim",
        "Declares `self` for a key the store grants `software`: an under-claim passes.",
        pj(&vector_edited(|p| p.issuer.attestation_level = "self".into())),
    ));
    c.push(case("pass-issued-at-equals-t", "issued_at == T: not in the future.", pj(&v)).at("2026-09-10T00:00:00Z"));
    c.push(case("pass-expired-key-old-signature", "The key's window ended long before T; the record was signed inside it.", pj(&v)).at("2030-01-01T00:00:00Z"));
    c.push(case(
        "pass-declared-non-compliant",
        "The record declares non-compliant: it still verifies (the declaration is content, not a verdict).",
        pj(&vector_edited(|p| p.policy_compliance.overall_status = "non-compliant".into())),
    ));
    c.push(case("pass-chain-2-complete", "P2 with its predecessor P1 (initial): complete.", pj(&p2)).prev(vec![pj(&p1)]).complete().lineage("complete"));
    c.push(case("pass-chain-3-complete", "P3 with P2 and P1: complete.", pj(&p3)).prev(vec![pj(&p2), pj(&p1)]).complete().lineage("complete"));
    c.push(case("pass-chain-partial", "P3 with only P2: every supplied link verifies; lineage.chain is not evaluated.", pj(&p3)).prev(vec![pj(&p2)]).lineage("partial"));
    c.push(case("pass-chain-not-checked", "P2 without predecessors: lineage.chain is not evaluated.", pj(&p2)).lineage("not_checked"));
    c.push(case("pass-chain-mixed-forms", "P3 as COSE, P2 as JSON, P1 as COSE: one chain.", pc(&p3)).prev(vec![pj(&p2), pc(&p1)]).complete().lineage("complete"));
    {
        let q2 = successor(&p1, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A2);
        c.push(case(
            "pass-chain-across-key-rotation",
            "P1 signed by A inside A's window; P2 signed by A2 after A's window ended: complete.",
            pj(&q2),
        )
        .store("ts-rotation-window")
        .prev(vec![pj(&p1)])
        .complete()
        .lineage("complete"));
    }
    // Phase 4 QA (P4-03): noncharacters are Unicode scalar values and are
    // permitted, raw or escaped. The raw form is given as hex, so this file
    // itself holds no noncharacter.
    let nonchar = vector_edited(|p| {
        p.learning_provenance.training_input_provenance.source_description =
            format!("{} \u{fdd0}\u{fdef}\u{fffe}\u{ffff}\u{1fffe}\u{10ffff}", v.learning_provenance.training_input_provenance.source_description);
    });
    let nonchar_text = nonchar.to_json().unwrap();
    c.push(case(
        "pass-noncharacters",
        "source_description ends in the noncharacters U+FDD0 U+FDEF U+FFFE U+FFFF U+1FFFE U+10FFFF, written raw; re-signed. Noncharacters are scalar values: permitted (spec §2 rule 1).",
        json_hex(nonchar_text.as_bytes()),
    ));
    let escaped = nonchar_text.replacen(
        "\u{fdd0}\u{fdef}\u{fffe}\u{ffff}\u{1fffe}\u{10ffff}",
        "\\ufdd0\\uFDEF\\ufffe\\uffff\\ud83f\\udffe\\udbff\\udfff",
        1,
    );
    assert_ne!(escaped, nonchar_text);
    c.push(case(
        "pass-noncharacters-escaped",
        "pass-noncharacters with its noncharacters written as \\u escapes (U+1FFFE and U+10FFFF as surrogate pairs): the same signed payload.",
        text(&escaped),
    ));
    // Phase 4 QA (P4-01): the bases of the integer-spelling cases below -
    // validly signed with training_epochs 0 and 10, written as JCS does.
    let epochs0 = vector_edited(|p| p.learning_provenance.training_epochs = Some(0));
    let epochs10 = vector_edited(|p| p.learning_provenance.training_epochs = Some(10));
    c.push(case("pass-training-epochs-0", "The vector with training_epochs 0, re-signed (compact JSON): the base of the fail-integer-*-0 cases.", cj(&epochs0)));
    c.push(case("pass-training-epochs-10", "The vector with training_epochs 10, re-signed (compact JSON): the base of the fail-integer-exponent* cases.", cj(&epochs10)));

    // --- input and JSON ------------------------------------------------------
    c.push(case("fail-empty", "Empty input.", text("")).fails("input.form"));
    c.push(case("fail-bom", "The vector behind a UTF-8 byte order mark.", json_hex(&[&[0xef, 0xbb, 0xbf][..], compact(&v).as_bytes()].concat())).fails("input.form"));
    c.push(case("fail-garbage", "Not JSON.", text("{garbage")).fails("json.syntax"));
    {
        let t = compact(&v);
        c.push(case("fail-truncated", "The vector cut in half.", text(&t[..t.len() / 2])).fails("json.syntax"));
        let mut bytes = t.replacen("New Clark", "New \u{e9}Clark", 1).into_bytes();
        let at = bytes.iter().position(|&b| b == 0xc3).unwrap();
        bytes[at] = 0xff;
        c.push(case("fail-not-utf8", "An invalid UTF-8 byte inside a string.", json_hex(&bytes)).fails("json.syntax"));
        c.push(case("fail-trailing-data", "A second value after the record.", text(&format!("{t} {{}}"))).fails("json.syntax"));
        let mut over = cj(&v);
        over["append_spaces"] = json!(1_048_577 - t.len());
        c.push(case("fail-oversized", "The vector followed by spaces to 1 MiB + 1 byte.", over).fails("input.size"));
        c.push(case("fail-integer-written-12.0", "training_epochs written as 12.0.", text(&t.replacen("\"training_epochs\":12", "\"training_epochs\":12.0", 1))).fails("json.structure"));
        c.push(case("fail-duplicate-member", "issued_at twice.", text(&t.replacen("\"issued_at\":", "\"issued_at\":\"2020-01-01T00:00:00Z\",\"issued_at\":", 1))).fails("json.structure"));
    }
    {
        let mut value = serde_json::to_value(&v).unwrap();
        value["policy_compliance"]["waiver"] = json!(true);
        c.push(case("fail-unknown-member", "A member the schema does not define.", text(&value.to_string())).fails("json.structure"));
        let mut value = serde_json::to_value(&v).unwrap();
        value.as_object_mut().unwrap().remove("signature");
        c.push(case("fail-missing-signature", "No signature member.", text(&value.to_string())).fails("json.structure"));
        let mut value = serde_json::to_value(&v).unwrap();
        value["lineage"]["previous_record_id"] = Value::Null;
        c.push(case("fail-null-lineage-member", "previous_record_id: null.", text(&value.to_string())).fails("json.structure"));
    }
    {
        // Phase 4 QA (P4-01): an integer is written `0` or a non-zero digit
        // followed by digits. Each case is a validly signed record
        // (pass-training-epochs-0 / -10) with only that spelling changed.
        let (t0, t10) = (compact(&epochs0), compact(&epochs10));
        for (id, description, base, from, to) in [
            ("fail-integer-negative-zero", "pass-training-epochs-0 with training_epochs written -0 (valid RFC 8259, value 0).", &t0, "\"training_epochs\":0,", "\"training_epochs\":-0,"),
            ("fail-integer-zero-fraction", "pass-training-epochs-0 with training_epochs written 0.0.", &t0, "\"training_epochs\":0,", "\"training_epochs\":0.0,"),
            ("fail-integer-zero-exponent", "pass-training-epochs-0 with training_epochs written 0e0.", &t0, "\"training_epochs\":0,", "\"training_epochs\":0e0,"),
            ("fail-integer-exponent", "pass-training-epochs-10 with training_epochs written 1e1.", &t10, "\"training_epochs\":10,", "\"training_epochs\":1e1,"),
            ("fail-integer-exponent-upper", "pass-training-epochs-10 with training_epochs written 1E1.", &t10, "\"training_epochs\":10,", "\"training_epochs\":1E1,"),
        ] {
            assert!(base.contains(from), "{id}");
            c.push(case(id, description, text(&base.replacen(from, to, 1))).fails("json.structure"));
        }
        // Phase 4 QA (P4-03): strings are Unicode scalar values. A \u escape
        // of an unpaired surrogate is valid RFC 8259 syntax, so it fails
        // json.structure; surrogate bytes in UTF-8 form are not UTF-8.
        let t = compact(&v);
        c.push(case("fail-string-lone-high-surrogate", "issuer_name with \\ud800 before a letter: a high surrogate not followed by a low one.", text(&t.replacen("New Clark", "New \\ud800Clark", 1))).fails("json.structure"));
        c.push(case("fail-string-lone-low-surrogate", "issuer_name with \\udc00: a low surrogate on its own.", text(&t.replacen("New Clark", "New \\udc00Clark", 1))).fails("json.structure"));
        let at = t.find("New Clark").unwrap() + "New ".len();
        let cesu = [&t.as_bytes()[..at], &[0xed, 0xa0, 0x80][..], &t.as_bytes()[at..]].concat();
        c.push(case("fail-string-cesu8-surrogate", "issuer_name holding U+D800 as the bytes ED A0 80 (CESU-8): not UTF-8.", json_hex(&cesu)).fails("json.syntax"));
    }

    // --- signature, key binding, trust (task 4.3) -----------------------------
    {
        let mut forged = v.clone();
        forged.deployment_context.as_mut().unwrap().inference_boundary.egress_allowed = true;
        reissue_with(&mut forged, KEY_F);
        c.push(case("fail-forged", "The forger's own key embedded everywhere, re-signed: internally consistent, trusted by no one.", pj(&forged)).fails("trust.key_known"));
    }
    c.push(case("fail-empty-store", "A store that trusts no one.", pj(&v)).store("ts-empty").fails("trust.key_known"));
    c.push(case("fail-key-for-other-issuer", "The store trusts the key for did:web:other.example.", pj(&v)).store("ts-key-for-other-issuer").fails("trust.issuer"));
    c.push(case("fail-revoked", "The key is revoked.", pj(&v)).store("ts-revoked").fails("trust.key_not_revoked"));
    c.push(case("fail-issued-before-window", "issued_at before valid_from.", pj(&v)).store("ts-window-before").fails("trust.key_validity"));
    c.push(case("fail-issued-at-window-end", "issued_at == valid_until.", pj(&v)).store("ts-window-until").fails("trust.key_validity"));
    c.push(case("fail-attestation-over-claim", "Declares hardware; the store grants software.", pj(&vector_edited(|p| p.issuer.attestation_level = "hardware".into()))).fails("trust.attestation"));
    c.push(case("fail-future", "issued_at is one second after T.", pj(&v)).at("2026-09-09T23:59:59Z").fails("time.not_future"));
    // P6-6: the declared policy evaluation cannot post-date the signature
    // over it. Both claims are the record's own, so T plays no part.
    c.push(
        case(
            "fail-policy-evaluated-after-issued",
            "policy_compliance.evaluated_at is one second after issued_at.",
            pj(&vector_edited(|p| p.policy_compliance.evaluated_at = "2026-09-10T00:00:01Z".into())),
        )
        .fails("time.policy_not_after_issued"),
    );
    c.push(case(
        "pass-policy-evaluated-before-issued",
        "policy_compliance.evaluated_at is a day before issued_at: an evaluation older than the signature is fine.",
        pj(&vector_edited(|p| p.policy_compliance.evaluated_at = "2026-09-09T00:00:00Z".into())),
    ));
    for (id, alg) in [("fail-algorithm-none", "none"), ("fail-algorithm-lowercase", "es256")] {
        let mut p = v.clone();
        p.signature.algorithm = alg.into();
        c.push(case(id, "signature.algorithm is not ES256.", pj(&p)).fails("signature.algorithm"));
    }
    {
        let mut der = v.clone();
        der.signature.signature = b64(sig.to_der().as_bytes());
        c.push(case("fail-signature-der", "The signature DER-encoded.", pj(&der)).fails("signature.encoding"));
        let mut bare = v.clone();
        bare.signature.signature = v.signature.signature["base64url:".len()..].to_string();
        c.push(case("fail-signature-no-prefix", "No base64url: prefix.", pj(&bare)).fails("signature.encoding"));
        let mut short = v.clone();
        short.signature.signature = b64(&raw_sig[..63]);
        c.push(case("fail-signature-63-bytes", "63 signature bytes.", pj(&short)).fails("signature.encoding"));
        let mut high = v.clone();
        high.signature.signature = SignatureSection::signature_field(&p256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).unwrap());
        c.push(case("fail-high-s", "The high-s twin of the vector's signature.", pj(&high)).fails("signature.low_s"));
        let mut zero = v.clone();
        zero.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
        c.push(case("fail-payload-hash-zeroed", "signed_payload_hash does not match.", pj(&zero)).fails("signature.payload_hash"));
    }
    c.push(case(
        "fail-key-id-not-thumbprint",
        "issuer.key_id (and signing_key_id) name key B while the JWK is key A.",
        pj(&vector_edited(|p| {
            p.issuer.key_id = key_id(KEY_B);
            p.signature.signing_key_id = key_id(KEY_B);
        })),
    )
    .fails("key.binding"));
    c.push(case("fail-signing-key-id-mismatch", "signing_key_id differs from issuer.key_id.", pj(&vector_edited(|p| p.signature.signing_key_id = key_id(KEY_B)))).fails("key.binding"));
    {
        let mut by_b = v.clone();
        sign_as(&mut by_b, KEY_B);
        c.push(case("fail-signed-by-other-trusted-key", "Signed by trusted key B while claiming trusted key A.", pj(&by_b)).store("ts-two-keys").fails("signature.valid"));
        let mut tampered = v.clone();
        tampered.learning_provenance.training_epochs = tampered.learning_provenance.training_epochs.map(|e| e + 1);
        tampered.signature.signed_payload_hash = tampered.signed_payload_hash().unwrap();
        c.push(case("fail-field-changed", "training_epochs changed after signing, signed_payload_hash fixed up.", pj(&tampered)).fails("signature.valid"));
    }
    c.push(case("fail-format-uuid", "record_id in upper case, re-signed.", pj(&vector_edited(|p| p.record_id = "urn:uuid:2B6A0C48-9F21-4F3A-8C51-1D0B4A7E9C00".into()))).fails("format.schema"));
    c.push(case("fail-format-did-homoglyph", "deployed_by with a Cyrillic а, re-signed.", pj(&vector_edited(|p| p.deployment_context.as_mut().unwrap().deployed_by = "did:web:f\u{430}ctory-operator.ph".into()))).fails("format.schema"));
    c.push(case("fail-format-enum", "overall_status outside the enum, re-signed.", pj(&vector_edited(|p| p.policy_compliance.overall_status = "compliant-ish".into()))).fails("format.schema"));
    c.push(case("fail-format-hash", "hardware_id \"none\", re-signed.", pj(&vector_edited(|p| p.deployment_context.as_mut().unwrap().hardware_id = "none".into()))).fails("format.schema"));
    c.push(case("fail-format-calendar", "issued_at 2026-02-30T00:00:00Z, re-signed.", pj(&vector_edited(|p| p.issued_at = "2026-02-30T00:00:00Z".into()))).fails("format.schema"));
    c.push(case("fail-consistency-order", "Components reordered, re-signed.", pj(&vector_edited(|p| p.model_identity.learned_state_components.swap(0, 1)))).fails("format.consistency"));
    c.push(case("fail-consistency-parameter-count", "parameter_count + 1, re-signed.", pj(&vector_edited(|p| *p.model_identity.parameter_count.as_mut().unwrap() += 1))).fails("format.consistency"));

    // --- COSE (task 4.6) ------------------------------------------------------
    c.push(case("fail-cose-tagged", "Tag 18 before the envelope.", cose(&[&[0xd2][..], &v.to_cose().unwrap()].concat())).fails("input.form"));
    c.push(case(
        "fail-cose-unprotected-kid",
        "A kid in the unprotected header.",
        cose(&with_sign1(&v, |s| s.unprotected = HeaderBuilder::new().key_id(key_id(KEY_F).into_bytes()).build())),
    )
    .fails("cose.unprotected_header"));
    {
        let mut s = CoseSign1::from_slice(&v.to_cose().unwrap()).unwrap();
        s.protected = coset::ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::ES256)
                .content_type("application/json".into())
                .key_id(v.signature.signing_key_id.as_bytes().to_vec())
                .build(),
        };
        s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
        c.push(case("fail-cose-extra-protected", "A content type in the protected header, correctly signed.", cose(&s.to_vec().unwrap())).fails("cose.protected_header"));
    }
    {
        let good = v.to_cose().unwrap();
        c.push(case("fail-cose-non-preferred-length", "The protected header's bstr length written 59 00 5e.", cose(&[&[0x84, 0x59, 0x00, 0x5e][..], &good[3..]].concat())).fails("cose.canonical"));
        c.push(case("fail-cose-trailing", "A byte after the envelope.", cose(&[good.clone(), vec![0]].concat())).fails("cose.structure"));
    }
    c.push(case("fail-cose-detached", "A nil (detached) payload.", cose(&with_sign1(&v, |s| s.payload = None))).fails("cose.payload"));
    c.push(case(
        "fail-cose-smuggled-signature",
        "A signature member inside the payload.",
        cose(&with_sign1(&v, |s| {
            let t = String::from_utf8(s.payload.take().unwrap()).unwrap();
            s.payload = Some(format!("{},\"signature\":{{\"algorithm\":\"none\",\"signature\":\"\",\"signed_payload_hash\":\"\",\"signing_key_id\":\"\"}}}}", &t[..t.len() - 1]).into_bytes());
        })),
    )
    .fails("cose.payload"));
    c.push(case(
        "fail-cose-pretty-payload",
        "The same payload pretty-printed.",
        cose(&with_sign1(&v, |s| {
            let value: Value = serde_json::from_slice(s.payload.as_ref().unwrap()).unwrap();
            s.payload = Some(serde_json::to_vec_pretty(&value).unwrap());
        })),
    )
    .fails("cose.payload"));
    c.push(case("fail-cose-short-signature", "A 63-byte signature.", cose(&with_sign1(&v, |s| s.signature.truncate(63)))).fails("cose.signature_encoding"));
    {
        // Phase 4 QA (P4-02): cose.structure is the outer shape only; what is
        // wrong inside the protected bstr is cose.protected_header, inside
        // the unprotected map cose.unprotected_header.
        let good = v.to_cose().unwrap();
        let mut tag_head = good.clone();
        assert_eq!(&tag_head[3..9], &[0xa2, 0x01, 0x26, 0x04, 0x58, 0x58]);
        tag_head[7] = 0xd8;
        c.push(case(
            "fail-cose-protected-kid-tag-head",
            "pass-vector-cose with byte 7, the kid's bstr head 0x58, changed to 0xd8 (a CBOR tag) inside the protected bstr: the envelope is still [bstr, map, bstr, bstr].",
            cose(&tag_head),
        )
        .fails("cose.protected_header"));
        let empty_kid = with_sign1(&v, |s| {
            s.protected = coset::ProtectedHeader { original_data: Some(vec![0xa2, 0x01, 0x26, 0x04, 0x40]), header: coset::Header::default() };
            s.signature = vmr_record::sign::sign(&key(KEY_A), &s.tbs_data(&[])).unwrap().to_bytes().to_vec();
        });
        assert_eq!(&empty_kid[..7], &[0x84, 0x45, 0xa2, 0x01, 0x26, 0x04, 0x40]);
        c.push(case(
            "fail-cose-protected-kid-empty",
            "An empty kid: protected header a2 01 26 04 40 (every length adjusted), correctly signed over it by key A. The kid is non-empty UTF-8 (spec §4.4).",
            cose(&empty_kid),
        )
        .fails("cose.protected_header"));
        assert_eq!(good[97], 0xa0, "the empty unprotected map");
        let text_kid = [&good[..97], &[0xa1, 0x04, 0x61, 0x6b][..], &good[98..]].concat();
        c.push(case(
            "fail-cose-unprotected-text-kid",
            "pass-vector-cose with the unprotected map {4: \"k\"} (a kid that is not even a bstr): anything in the unprotected map fails cose.unprotected_header.",
            cose(&text_kid),
        )
        .fails("cose.unprotected_header"));
    }

    // --- lineage (task 4.4) ---------------------------------------------------
    for (id, description, bad) in [
        ("fail-chain-hash", "P2 names another previous_record_hash.", p2_edited(|p| p.lineage.previous_record_hash = Some(format!("sha256:{}", "ab".repeat(32))))),
        ("fail-chain-id", "P2 names another previous_record_id.", p2_edited(|p| p.lineage.previous_record_id = Some(U9.into()))),
        ("fail-chain-root", "P2 names another root.", p2_edited(|p| p.lineage.root_record_id = U9.into())),
        ("fail-chain-length", "P2 declares length 3 after a length-1 predecessor.", p2_edited(|p| p.lineage.lineage_chain_length = 3)),
        // The policy evaluation moves with issued_at: the case is about
        // the link rule, not about time.policy_not_after_issued (P6-6).
        ("fail-chain-issued-before-predecessor", "P2 issued before P1 (its declared policy evaluation moves with it).", p2_edited(|p| {
            p.issued_at = "2026-09-09T00:00:00Z".into();
            p.policy_compliance.evaluated_at = "2026-09-09T00:00:00Z".into();
        })),
    ] {
        c.push(case(id, description, pj(&bad)).prev(vec![pj(&p1)]).fails("lineage.chain").lineage("broken"));
    }
    {
        let mut unknown = v.clone();
        reissue_with(&mut unknown, KEY_F);
        let head = successor(&unknown, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
        c.push(case("fail-chain-predecessor-unknown-key", "The predecessor is signed by an untrusted key.", pj(&head)).prev(vec![pj(&unknown)]).fails("lineage.chain").lineage("broken"));
        let mut by_a2 = v.clone();
        reissue_with(&mut by_a2, KEY_A2);
        let head = successor(&by_a2, U2, "2026-09-10T12:00:00Z", "training-update", KEY_A);
        c.push(case("fail-chain-predecessor-revoked-key", "The predecessor is signed by a revoked key.", pj(&head)).store("ts-a2-revoked").prev(vec![pj(&by_a2)]).fails("lineage.chain").lineage("broken"));
        let mut lying = p1.clone();
        lying.signature.signed_payload_hash = format!("sha256:{}", "00".repeat(32));
        c.push(case("fail-chain-predecessor-lying-hash", "The predecessor's signature section lies about its payload hash.", pj(&p2)).prev(vec![pj(&lying)]).fails("lineage.chain").lineage("broken"));
    }
    c.push(case("fail-chain-wrong-order", "P3 with P1 before P2.", pj(&p3)).prev(vec![pj(&p1), pj(&p2)]).fails("lineage.chain").lineage("broken"));
    c.push(case("fail-chain-predecessor-for-initial", "An initial record given a predecessor.", pj(&p1)).prev(vec![pj(&p1)]).fails("lineage.chain").lineage("broken"));
    c.push(case("fail-chain-beyond-initial", "P2 with P1 and then another record.", pj(&p2)).prev(vec![pj(&p1), pj(&p1)]).fails("lineage.chain").lineage("broken"));
    c.push(case("fail-chain-required-not-checked", "A complete lineage required, none supplied.", pj(&p2)).complete().fails("lineage.chain").lineage("not_checked"));
    c.push(case("fail-chain-required-partial", "A complete lineage required, only P2 supplied for P3.", pj(&p3)).prev(vec![pj(&p2)]).complete().fails("lineage.chain").lineage("partial"));
    c.push(case(
        "fail-lineage-initial-with-previous",
        "An initial record naming a predecessor, re-signed.",
        pj(&vector_edited(|p| {
            p.lineage.previous_record_id = Some(U9.into());
            p.lineage.previous_record_hash = Some(format!("sha256:{}", "ab".repeat(32)));
        })),
    )
    .fails("lineage.consistency")
    .lineage("broken"));
    {
        let mut orphan = p2.clone();
        orphan.lineage.previous_record_id = None;
        orphan.lineage.previous_record_hash = None;
        sign_as(&mut orphan, KEY_A);
        c.push(case("fail-lineage-non-initial-without-previous", "A training-update naming no predecessor, re-signed.", pj(&orphan)).fails("lineage.consistency").lineage("broken"));
        let mut short = p2.clone();
        short.lineage.lineage_chain_length = 1;
        sign_as(&mut short, KEY_A);
        c.push(case("fail-lineage-length-1-non-initial", "A training-update with chain length 1, re-signed.", pj(&short)).fails("lineage.consistency").lineage("broken"));
    }

    // --- nesting (spec §2 rule 13, §4.4; the spec pass before Phase 9) -------
    // A record nests four levels. A deeper text fails json.structure (in a
    // COSE payload, cose.payload) at every depth, never json.syntax, and a
    // syntax error anywhere in it still fails json.syntax first. Each deep
    // value is written into its case's text as brackets, so cases.json itself
    // nests no deeper than before.
    {
        let t = compact(&v);
        for (id, levels, description) in [
            ("fail-nesting-5-levels", 5, "The vector (compact JSON) with the value of issuer.issuer_name replaced by nested empty arrays, so that the text nests 5 levels deep, the outermost object counting as the first: one level past a record's four (spec §2 rule 13)."),
            ("fail-nesting-127-levels", 127, "As fail-nesting-5-levels, 127 levels deep: the deepest text serde_json's default recursion limit admits. Depth is not a syntax rule."),
            ("fail-nesting-128-levels", 128, "As fail-nesting-5-levels, 128 levels deep: the shallowest text serde_json's default recursion limit refuses. Depth is not a syntax rule."),
            ("fail-nesting-10000-levels", 10_000, "As fail-nesting-5-levels, 10 000 levels deep, past the depth limits JSON parsers commonly have: a verifier checks syntax at any depth (spec §2 rule 13)."),
        ] {
            c.push(case(id, description, text(&nested_at_issuer_name(&t, levels))).fails("json.structure"));
        }
        let deep = nested_at_issuer_name(&t, 128);
        let unclosed = deep.replacen(&nested_arrays(126), &format!("{}{}", "[".repeat(126), "]".repeat(125)), 1);
        c.push(case(
            "fail-nesting-128-levels-unclosed",
            "fail-nesting-128-levels with one of its arrays left unclosed: a syntax error past the deepest point still fails json.syntax, which reads the whole text first.",
            text(&unclosed),
        )
        .fails("json.syntax"));
        let payload = String::from_utf8(v.signed_payload().unwrap()).unwrap();
        for (id, levels, description) in [
            ("fail-cose-nesting-5-levels", 5, "The vector's COSE form with its payload nested as in fail-nesting-5-levels, re-signed by key A: the payload rule of check 7c (spec §2 rule 13)."),
            ("fail-cose-nesting-127-levels", 127, "As fail-cose-nesting-5-levels, the payload 127 levels deep."),
            ("fail-cose-nesting-128-levels", 128, "As fail-cose-nesting-5-levels, the payload 128 levels deep."),
        ] {
            c.push(case(id, description, cose(&cose_with_payload(&v, nested_at_issuer_name(&payload, levels).into_bytes()))).fails("cose.payload"));
        }
        c.push(case(
            "fail-chain-predecessor-nesting-128-levels",
            "P2 with its predecessor P1 given as compact JSON nested 128 levels deep, as in fail-nesting-128-levels: the predecessor fails json.structure on its own, and the chain is broken (spec §2 rule 13, §6.5).",
            pj(&p2),
        )
        .prev(vec![text(&nested_at_issuer_name(&compact(&p1), 128))])
        .fails("lineage.chain")
        .lineage("broken"));
        // The envelope's CBOR (spec §4.4; the reviewer's decision of
        // 2026-09-13): one data item of a stated subset, nesting at most 16
        // levels, read head by head before anything is decoded. Its CBOR is
        // written into each case's hex.
        c.push(case(
            "fail-cose-nesting-16-cbor-levels",
            "pass-vector-cose with the unprotected map {0: [[...]]}, so that the envelope's CBOR nests 16 levels, its array counting as the first: within the depth, and the map is not empty (spec §4.4).",
            cose(&cose_with_unprotected(&v, &unprotected_nested(16))),
        )
        .fails("cose.unprotected_header"));
        c.push(case(
            "fail-cose-nesting-17-cbor-levels",
            "As fail-cose-nesting-16-cbor-levels, 17 levels deep: an array at level 17 is past the envelope's depth (spec §4.4).",
            cose(&cose_with_unprotected(&v, &unprotected_nested(17))),
        )
        .fails("cose.structure"));
        c.push(case(
            "fail-cose-cbor-null-in-unprotected-map",
            "pass-vector-cose with the unprotected map {0: null}: null is in the envelope's CBOR subset, so the map is judged as an unprotected header (spec §4.4).",
            cose(&cose_with_unprotected(&v, &[0xa1, 0x00, 0xf6])),
        )
        .fails("cose.unprotected_header"));
        for (id, item, description) in [
            ("fail-cose-cbor-simple-value", &[0xf0][..], "pass-vector-cose with the unprotected map {0: simple(16)}, an unassigned simple value: outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-true", &[0xf5][..], "pass-vector-cose with the unprotected map {0: true}: a simple value other than null, outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-float", &[0xf9, 0x00, 0x00][..], "pass-vector-cose with the unprotected map {0: 0.0}, a half-precision float: outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-bignum", &[0xc2, 0x41, 0x01][..], "pass-vector-cose with the unprotected map {0: 2(h'01')}, a bignum: a tag, outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-indefinite-length", &[0x9f, 0xff][..], "pass-vector-cose with the unprotected map {0: [_ ]}, an empty indefinite-length array: outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-8-byte-argument", &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0][..], "pass-vector-cose with the unprotected map {0: 0}, its 0 written with an 8-byte argument: outside the envelope's CBOR subset (spec §4.4)."),
        ] {
            let map = [&[0xa1, 0x00][..], item].concat();
            c.push(case(id, description, cose(&cose_with_unprotected(&v, &map))).fails("cose.structure"));
        }
        let envelope = v.to_cose().unwrap();
        let signature_at = envelope.len() - 66;
        assert_eq!((envelope[98], &envelope[signature_at..signature_at + 2]), (0x59, &[0x58, 0x40][..]));
        let indefinite_payload =
            [&envelope[..98], &[0x5f][..], &envelope[98..signature_at], &[0xff][..], &envelope[signature_at..]].concat();
        c.push(case(
            "fail-cose-cbor-indefinite-payload",
            "pass-vector-cose with its payload written as an indefinite-length byte string holding the one definite chunk it had: outside the envelope's CBOR subset (spec §4.4), where it used to reach cose.canonical.",
            cose(&indefinite_payload),
        )
        .fails("cose.structure"));
        // The spec pass's QA (QS-01): a map key's depth, a text string that
        // is not UTF-8, 4- and 8-byte arguments, undefined, reserved
        // additional information and a double, where a CBOR decoder's own
        // reading could name another check; and a JSON text 100 000 levels
        // deep. Appended, so every earlier case keeps its bytes and place.
        let key_nested = |levels: usize| [vec![0xa1u8], vec![0x81; levels - 3], vec![0x80, 0x00]].concat();
        c.push(case(
            "fail-cose-nesting-16-cbor-levels-in-a-key",
            "pass-vector-cose with the unprotected map {[[...]]: 0}, so that the envelope's CBOR nests 16 levels in the map's key, its array counting as the first: a map's keys are inside the map, within the depth, and the map is not empty (spec §4.4).",
            cose(&cose_with_unprotected(&v, &key_nested(16))),
        )
        .fails("cose.unprotected_header"));
        c.push(case(
            "fail-cose-nesting-17-cbor-levels-in-a-key",
            "As fail-cose-nesting-16-cbor-levels-in-a-key, 17 levels deep: an array at level 17 is past the envelope's depth, in a key as in a value (spec §4.4).",
            cose(&cose_with_unprotected(&v, &key_nested(17))),
        )
        .fails("cose.structure"));
        c.push(case(
            "fail-cose-cbor-text-not-utf8",
            "pass-vector-cose with the unprotected map {0: text}, the text string's two bytes c3 28, which are not UTF-8: outside the envelope's CBOR subset (spec §4.4).",
            cose(&cose_with_unprotected(&v, &[0xa1, 0x00, 0x62, 0xc3, 0x28])),
        )
        .fails("cose.structure"));
        c.push(case(
            "fail-cose-cbor-4-byte-argument",
            "pass-vector-cose with the unprotected map {0: h'00'}, the byte string's length written with a 4-byte argument: in the envelope's CBOR subset, so the map is judged as an unprotected header (spec §4.4).",
            cose(&cose_with_unprotected(&v, &[0xa1, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x01, 0x00])),
        )
        .fails("cose.unprotected_header"));
        let with_signature_head =
            |head: &[u8]| [&envelope[..signature_at], head, &envelope[signature_at + 2..]].concat();
        c.push(case(
            "fail-cose-non-preferred-4-byte-length",
            "pass-vector-cose with its signature's length, 64, written with a 4-byte argument (5a 00 00 00 40): in the envelope's CBOR subset, but not the canonical envelope (spec §4.4).",
            cose(&with_signature_head(&[0x5a, 0x00, 0x00, 0x00, 0x40][..])),
        )
        .fails("cose.canonical"));
        c.push(case(
            "fail-cose-cbor-8-byte-signature-length",
            "pass-vector-cose with its signature's length, 64, written with an 8-byte argument: outside the envelope's CBOR subset, in the envelope's own items as in the unprotected map (spec §4.4).",
            cose(&with_signature_head(&[0x5b, 0, 0, 0, 0, 0, 0, 0, 0x40][..])),
        )
        .fails("cose.structure"));
        for (id, item, description) in [
            ("fail-cose-cbor-undefined", &[0xf7][..], "pass-vector-cose with the unprotected map {0: undefined}: a simple value other than null, outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-reserved-additional-information", &[0x1c][..], "pass-vector-cose with the unprotected map a1 00 1c, its value's head an unsigned integer with the reserved additional information 28: outside the envelope's CBOR subset (spec §4.4)."),
            ("fail-cose-cbor-double-float", &[0xfb, 0, 0, 0, 0, 0, 0, 0, 0][..], "pass-vector-cose with the unprotected map {0: 0.0}, a double-precision float: outside the envelope's CBOR subset (spec §4.4)."),
        ] {
            let map = [&[0xa1, 0x00][..], item].concat();
            c.push(case(id, description, cose(&cose_with_unprotected(&v, &map))).fails("cose.structure"));
        }
        c.push(case(
            "fail-nesting-100000-levels",
            "As fail-nesting-5-levels, 100 000 levels deep: rule 13 has no depth past which a verifier may stop checking syntax, within 1 MiB (spec §2 rule 13).",
            text(&nested_at_issuer_name(&t, 100_000)),
        )
        .fails("json.structure"));
    }

    // --- the optional documentation members (task 10.11a, D11-1 and D11-3) ----
    // Judged by the existing checks only; every earlier case is unchanged,
    // and the committed record vector declares neither member.
    {
        let doc = |label: &str| DocumentationRef {
            documentation_hash: vmr_record::hash::format_hash(&vmr_record::hash::sha256(label.as_bytes())),
        };
        const DATA: &str = "khalm verify vectors: a data governance document";
        const OVERSIGHT: &str = "khalm verify vectors: a human oversight document";
        let declared = vector_edited(|p| {
            p.data_governance = Some(doc(DATA));
            p.human_oversight = Some(doc(OVERSIGHT));
        });
        c.push(case(
            "pass-documentation-declared",
            "The vector declaring both optional members, data_governance and human_oversight, each holding a documentation_hash, re-signed: it verifies with the same 21 checks.",
            pj(&declared),
        ));
        c.push(case("pass-documentation-declared-cose", "pass-documentation-declared in its COSE_Sign1 form: it verifies with the same 25 checks.", pc(&declared)));
        let mut edited = declared.clone();
        edited.human_oversight = Some(doc("khalm verify vectors: another document"));
        c.push(case(
            "fail-documentation-hash-edited",
            "pass-documentation-declared with human_oversight's documentation_hash changed after signing and signed_payload_hash left as signed: the members are signed content.",
            pj(&edited),
        )
        .fails("signature.payload_hash"));
        let upper = vector_edited(|p| {
            let hex = doc(DATA).documentation_hash["sha256:".len()..].to_ascii_uppercase();
            p.data_governance = Some(DocumentationRef { documentation_hash: format!("sha256:{hex}") });
        });
        c.push(case(
            "fail-documentation-hash-uppercase",
            "data_governance.documentation_hash with upper-case hex digits, re-signed: a hash string is lower-case (spec §2 rule 5).",
            pj(&upper),
        )
        .fails("format.schema"));
        let empty = vector_edited(|p| p.human_oversight = Some(DocumentationRef { documentation_hash: String::new() }));
        c.push(case(
            "fail-documentation-hash-empty",
            "human_oversight.documentation_hash \"\", re-signed: a documentation hash has no empty form, because an absent member already says none (spec §2 rule 3).",
            pj(&empty),
        )
        .fails("format.schema"));
        let base = serde_json::to_value(&declared).unwrap();
        let edited_text = |edit: &dyn Fn(&mut Value)| {
            let mut value = base.clone();
            edit(&mut value);
            text(&value.to_string())
        };
        c.push(case(
            "fail-documentation-null",
            "pass-documentation-declared with data_governance: null. An optional member is omitted, never null.",
            edited_text(&|v| v["data_governance"] = Value::Null),
        )
        .fails("json.structure"));
        c.push(case(
            "fail-documentation-unknown-member",
            "pass-documentation-declared with a title member inside human_oversight: the object is closed.",
            edited_text(&|v| v["human_oversight"]["title"] = json!("Human oversight measures")),
        )
        .fails("json.structure"));
        c.push(case(
            "fail-documentation-missing-hash",
            "pass-documentation-declared with data_governance: {}, which has no documentation_hash.",
            edited_text(&|v| v["data_governance"] = json!({})),
        )
        .fails("json.structure"));
        c.push(case(
            "fail-documentation-not-an-object",
            "pass-documentation-declared with human_oversight written as its hash string instead of an object.",
            edited_text(&|v| {
                let hash = v["human_oversight"]["documentation_hash"].clone();
                v["human_oversight"] = hash;
            }),
        )
        .fails("json.structure"));

        // QA QT-02 (10.11a): each case above set one member. The same edits
        // on the other member follow, so that a verifier misreading §2 rule 3
        // for either member fails a case. Every earlier case is unchanged.
        let mut governance_edited = declared.clone();
        governance_edited.data_governance = Some(doc("khalm verify vectors: another document"));
        c.push(case(
            "fail-documentation-governance-hash-edited",
            "pass-documentation-declared with data_governance's documentation_hash changed after signing and signed_payload_hash left as signed: the members are signed content.",
            pj(&governance_edited),
        )
        .fails("signature.payload_hash"));
        let oversight_upper = vector_edited(|p| {
            let hex = doc(OVERSIGHT).documentation_hash["sha256:".len()..].to_ascii_uppercase();
            p.human_oversight = Some(DocumentationRef { documentation_hash: format!("sha256:{hex}") });
        });
        c.push(case(
            "fail-documentation-oversight-hash-uppercase",
            "human_oversight.documentation_hash with upper-case hex digits, re-signed: a hash string is lower-case (spec §2 rule 5).",
            pj(&oversight_upper),
        )
        .fails("format.schema"));
        let governance_empty = vector_edited(|p| p.data_governance = Some(DocumentationRef { documentation_hash: String::new() }));
        c.push(case(
            "fail-documentation-governance-hash-empty",
            "data_governance.documentation_hash \"\", re-signed: a documentation hash has no empty form, because an absent member already says none (spec §2 rule 3). It is not one of rule 9's optional hashes, which may be empty.",
            pj(&governance_empty),
        )
        .fails("format.schema"));
        c.push(case(
            "fail-documentation-oversight-null",
            "pass-documentation-declared with human_oversight: null. An optional member is omitted, never null.",
            edited_text(&|v| v["human_oversight"] = Value::Null),
        )
        .fails("json.structure"));
        c.push(case(
            "fail-documentation-governance-unknown-member",
            "pass-documentation-declared with a title member inside data_governance: the object is closed.",
            edited_text(&|v| v["data_governance"]["title"] = json!("Data governance practices")),
        )
        .fails("json.structure"));
        c.push(case(
            "fail-documentation-oversight-missing-hash",
            "pass-documentation-declared with human_oversight: {}, which has no documentation_hash.",
            edited_text(&|v| v["human_oversight"] = json!({})),
        )
        .fails("json.structure"));
        c.push(case(
            "fail-documentation-governance-not-an-object",
            "pass-documentation-declared with data_governance written as its hash string instead of an object.",
            edited_text(&|v| {
                let hash = v["data_governance"]["documentation_hash"].clone();
                v["data_governance"] = hash;
            }),
        )
        .fails("json.structure"));
    }

    // --- objects written as the array of their values (QA QT-01) -----------
    // serde's derive reads a struct from the array of its values in
    // declaration order, which is the order of the schema's `properties`, and
    // the signed payload is re-derived from the struct: a verifier with that
    // fault verifies each text below. Each record is signed over its
    // objects and respelled after signing, never re-signed (spec §2 rule 2,
    // check 4j). Every earlier case is unchanged.
    {
        let doc = |label: &str| DocumentationRef {
            documentation_hash: vmr_record::hash::format_hash(&vmr_record::hash::sha256(label.as_bytes())),
        };
        // pass-documentation-declared's record.
        let declared = vector_edited(|p| {
            p.data_governance = Some(doc("khalm verify vectors: a data governance document"));
            p.human_oversight = Some(doc("khalm verify vectors: a human oversight document"));
        });
        // `signed`'s compact text with the object at `pointer` written as the
        // array of its values. serde_json's own reader must take it for
        // `signed`, so the case is one the fault verifies.
        let as_array = |signed: &Record, pointer: &str| {
            let text = respelled_as_array(&serde_json::to_value(signed).unwrap(), pointer).to_string();
            assert!(serde_json::from_str::<Record>(&text).unwrap() == *signed, "{pointer}: serde_json reads the signed record");
            text
        };
        let mut kinds = std::collections::BTreeSet::new();
        for (id, record, pointer, description) in [
            ("fail-issuer-as-array", &v, "/issuer", "The vector with issuer written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-public-key-as-array", &v, "/issuer/public_key", "The vector with issuer.public_key written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-model-identity-as-array", &v, "/model_identity", "The vector with model_identity written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-architecture-as-array", &v, "/model_identity/architecture", "The vector with model_identity.architecture written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-state-component-as-array", &v, "/model_identity/learned_state_components/0", "The vector with the first learned_state_components element written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-learning-provenance-as-array", &v, "/learning_provenance", "The vector with learning_provenance written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-training-environment-as-array", &v, "/learning_provenance/training_environment", "The vector with learning_provenance.training_environment written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-training-input-provenance-as-array", &v, "/learning_provenance/training_input_provenance", "The vector with learning_provenance.training_input_provenance written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-collection-period-as-array", &v, "/learning_provenance/training_input_provenance/collection_period", "The vector with training_input_provenance.collection_period written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-deployment-context-as-array", &v, "/deployment_context", "The vector with deployment_context written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-inference-boundary-as-array", &v, "/deployment_context/inference_boundary", "The vector with deployment_context.inference_boundary written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-policy-compliance-as-array", &v, "/policy_compliance", "The vector with policy_compliance written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-policy-result-as-array", &v, "/policy_compliance/results/0", "The vector with the first policy_compliance.results element written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-lineage-as-array", &p2, "/lineage", "P2 with lineage, all five of its members present, written after signing as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-signature-section-as-array", &v, "/signature", "The vector with its signature section written as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-documentation-governance-as-array", &declared, "/data_governance", "pass-documentation-declared with data_governance written, after signing, as the array of its one value: an array where the schema has an object (spec §2 rule 2)."),
            ("fail-documentation-oversight-as-array", &declared, "/human_oversight", "pass-documentation-declared with human_oversight written, after signing, as the array of its one value: an array where the schema has an object (spec §2 rule 2)."),
        ] {
            kinds.insert(pointer.replace("/0", "/*"));
            c.push(case(id, description, text(&as_array(record, pointer))).fails("json.structure"));
        }
        // A derived_from entry (task 10.11b) and a statement_references entry
        // (task 10.11e) are later object kinds: their cases,
        // fail-derived-from-entry-as-array and
        // fail-statement-references-entry-as-array, are appended after every
        // earlier case, below.
        let every_kind: std::collections::BTreeSet<String> = OBJECT_FIELDS
            .iter()
            .map(|(kind, _)| kind.to_string())
            .filter(|kind| {
                !kind.is_empty()
                    && kind != "/model_identity/derived_from/*"
                    && kind != "/model_identity/statement_references/*"
            })
            .collect();
        assert_eq!(kinds, every_kind, "one case per nested object kind of a record");
        c.push(case(
            "fail-chain-predecessor-public-key-as-array",
            "P2 with its predecessor P1 given with issuer.public_key written, after signing, as the array of its values in the order of the schema's properties: the predecessor fails json.structure on its own, and the chain is broken (spec §2 rule 2, §6.5).",
            pj(&p2),
        )
        .prev(vec![text(&as_array(&p1, "/issuer/public_key"))])
        .fails("lineage.chain")
        .lineage("broken"));
        // Appended after the QT-01 fix's QA (QJ-04; spec §2 rule 2, §6.2 check
        // 2): the record itself written as the array of its values. Its first
        // byte is `[`, so check 2 fails before any structure rule is reached.
        c.push(case(
            "fail-record-as-array",
            "The vector written, after signing, as the array of its values in the order of the schema's properties: its first byte is [ where check 2 needs {, so it fails input.form before json.structure is reached (spec §2 rule 2, §6.2).",
            text(&respelled_as_array(&serde_json::to_value(&v).unwrap(), "").to_string()),
        )
        .fails("input.form"));
    }

    // --- task 10.11b: records of any kind of model (spec §7, §8) ---------
    // model_format selects the KHALM engine profile snn-compact-v1 or the
    // general description (§7.1). Each case starts from the general
    // conformance vector (test-vectors/record/example-general-v0.1.json) or
    // from the vector, and is re-signed with key A unless it says otherwise.
    // Every earlier case is unchanged, and each names snn-compact-v1.
    {
        use vmr_record::hash::{format_hash, sha256};
        use vmr_record::merkle::MerkleStream;
        use vmr_record::named_set::{member_encoding, named_set_digest, NamedSetDigest};
        use vmr_record::record::{BaseModel, StateComponent};

        let h = |label: &str| format_hash(&sha256(label.as_bytes()));
        let general = general_vector();
        let general_edited = |edit: &dyn Fn(&mut Record)| {
            let mut p = general.clone();
            edit(&mut p);
            sign_as(&mut p, KEY_A);
            p
        };
        // The components of synthetic files (name, contents), and their
        // named-set digest (§7.2).
        let components = |files: &[(&str, &str)]| {
            let parts: Vec<(&str, [u8; 32])> = files.iter().map(|(name, t)| (*name, sha256(t.as_bytes()))).collect();
            let listed: Vec<StateComponent> = files
                .iter()
                .map(|(name, t)| StateComponent { name: name.to_string(), hash: format_hash(&sha256(t.as_bytes())), size_bytes: t.len() as u64 })
                .collect();
            (listed, format_hash(&named_set_digest(&parts).unwrap()))
        };
        // The record commits `files` as named-set-v1 records (§8.2, §8.3).
        let commit = |p: &mut Record, files: &[(&str, &str)]| {
            let (mut digest, mut root) = (NamedSetDigest::new(), MerkleStream::new());
            for (name, t) in files {
                let d = sha256(t.as_bytes());
                digest.push(name, &d).unwrap();
                root.push(&member_encoding(name, &d));
            }
            let l = &mut p.learning_provenance;
            l.training_input_count = root.count();
            l.training_input_digest = format_hash(&digest.finish());
            l.training_input_merkle_root = format_hash(&root.finish());
            l.training_input_format = Some("named-set-v1".into());
            l.training_input_disclosure = None;
        };
        const ADDED_DATA: [(&str, &str); 3] = [
            ("fine-tune/shard-00000.jsonl", "{\"text\":\"synthetic example 1\"}\n"),
            ("fine-tune/shard-00001.jsonl", "{\"text\":\"synthetic example 2\"}\n"),
            ("fine-tune/shard-00002.jsonl", "{\"text\":\"synthetic example 3\"}\n"),
        ];
        const FINE_TUNED: [(&str, &str); 3] = [
            ("adapter_config.json", "{\"base\":\"synthetic\",\"rank\":4}\n"),
            ("adapter_model.safetensors", "synthetic adapter weights: not a real model\n"),
            ("config.json", "{\"architectures\":[\"ExampleDecoderOnly\"],\"hidden_size\":8,\"num_hidden_layers\":2}\n"),
        ];
        const DIFFUSION: [(&str, &str); 4] = [
            ("model_index.json", "{\"pipeline\":\"ExampleDiffusion\"}\n"),
            ("text_encoder/model.safetensors", "synthetic text encoder: not a real model\n"),
            ("unet/diffusion_pytorch_model.safetensors", "synthetic unet: not a real model\n"),
            ("vae/diffusion_pytorch_model.safetensors", "synthetic vae: not a real model\n"),
        ];
        const CLASSICAL: [(&str, &str); 1] = [("model.onnx", "synthetic gradient-boosted trees: not a real model\n")];

        // --- verify ---
        c.push(
            case(
                "pass-general-open-weights-not-held",
                "The general conformance vector: an open-weight model of four synthetic files in the general description (spec §7.3), from a party that holds the files and deploys the model but does not hold its training records (§8.4). It verifies with the same 21 checks.",
                pj(&general),
            )
            .lineage("initial"),
        );
        c.push(
            case("pass-general-open-weights-not-held-cose", "pass-general-open-weights-not-held in its COSE_Sign1 form: it verifies with the same 25 checks.", pc(&general))
                .lineage("initial"),
        );
        let fine_tune = general_edited(&|p| {
            let (listed, digest) = components(&FINE_TUNED[..]);
            p.model_identity.learned_state_components = listed;
            p.model_identity.learned_state_hash = digest.clone();
            p.model_identity.model_hash = digest;
            p.model_identity.derived_from = Some(vec![BaseModel {
                model_hash: h("khalm verify vectors: an open-weight base model with no passport"),
                name: "an open-weight base model".into(),
                relation: "fine-tune".into(),
            }]);
            commit(p, &ADDED_DATA[..]);
            let l = &mut p.learning_provenance;
            l.training_epochs = Some(2);
            l.training_started_at = Some("2026-09-05T00:00:00Z".into());
            l.training_ended_at = Some("2026-09-06T00:00:00Z".into());
            l.training_environment.training_software = "a training library 1.0".into();
            l.training_environment.accelerator = Some("8 accelerators".into());
            l.training_input_provenance.source_type = "curated_text".into();
            l.training_input_provenance.source_description = "Synthetic examples written for the vectors".into();
            l.training_input_provenance.data_residency_countries = Some(vec!["DE".into(), "FR".into()]);
            p.deployment_context = None;
        });
        c.push(
            case(
                "pass-general-fine-tune-unrecorded-base",
                "A fine-tune in the general description: its own three files, derived_from naming a base model that has no record by model_hash (spec §7.5), its own added data committed as three named-set-v1 records (§8.2), an accelerator, residency in two countries (§8.5), and no deployment_context.",
                pj(&fine_tune),
            )
            .lineage("initial"),
        );
        let mut across = fine_tune.clone();
        across.record_id = "urn:uuid:00000000-0000-4000-8000-0000000000c1".into();
        across.issued_at = "2026-09-10T12:00:00Z".into();
        across.issuer.issuer_id = OTHER_ISSUER.into();
        across.issuer.issuer_name = "Other Example".into();
        across.model_identity.derived_from = Some(vec![BaseModel {
            model_hash: general.model_identity.model_hash.clone(),
            name: "the model of the general conformance vector".into(),
            relation: "fine-tune".into(),
        }]);
        across.lineage.previous_record_id = Some(general.record_id.clone());
        across.lineage.previous_record_hash = Some(general.signed_payload_hash().unwrap());
        across.lineage.lineage_chain_length = 2;
        across.lineage.root_record_id = general.record_id.clone();
        across.lineage.lineage_type = "fine-tune".into();
        reissue_with(&mut across, KEY_B);
        c.push(
            case(
                "pass-general-fine-tune-chain-across-issuers",
                "pass-general-fine-tune-unrecorded-base issued by did:web:other.example with key B as a fine-tune of the general conformance vector's model (derived_from and lineage), whose record (issuer A) is supplied as its predecessor: a chain across two issuers is complete (spec §6.5, §7.5).",
                pj(&across),
            )
            .prev(vec![pj(&general)])
            .lineage("complete"),
        );
        let diffusion = general_edited(&|p| {
            let (_, every_file) = components(&DIFFUSION[..]);
            let (weights, digest) = components(&DIFFUSION[1..]);
            let m = &mut p.model_identity;
            m.parameter_count = Some(96);
            m.architecture.kind = "latent-diffusion".into();
            m.architecture.topology = "unet".into();
            m.architecture.precision = "float16".into();
            m.learned_state_components = weights;
            m.learned_state_hash = digest;
            m.model_hash = every_file;
        });
        assert_ne!(diffusion.model_identity.model_hash, diffusion.model_identity.learned_state_hash);
        c.push(
            case(
                "pass-general-diffusion-weights-only",
                "A diffusion model of four files whose components are its three weight files only: learned_state_hash is their named-set digest and model_hash every file's, so the two differ (spec §7.3).",
                pj(&diffusion),
            )
            .lineage("initial"),
        );
        let classical = general_edited(&|p| {
            let (listed, digest) = components(&CLASSICAL[..]);
            let m = &mut p.model_identity;
            m.model_format = "onnx".into();
            m.parameter_count = Some(1200);
            m.architecture.kind = "gradient-boosted-trees".into();
            m.architecture.topology = "ensemble".into();
            m.architecture.precision = "float32".into();
            m.learned_state_components = listed;
            m.learned_state_hash = digest.clone();
            m.model_hash = digest;
            p.learning_provenance.training_input_disclosure = Some("not-disclosed".into());
            p.deployment_context = None;
        });
        c.push(
            case(
                "pass-general-classical-one-file-not-disclosed",
                "A classical model distributed as one ONNX file, its training records not disclosed by an issuer that holds them (spec §8.4), with no deployment_context.",
                pj(&classical),
            )
            .lineage("initial"),
        );
        let bare = vector_edited(|p| {
            p.deployment_context = None;
            p.learning_provenance.training_environment.accelerator_software = None;
        });
        c.push(
            case(
                "pass-vector-without-deployment-and-accelerator-software",
                "The vector, a record in the profile snn-compact-v1, without deployment_context and accelerator_software, re-signed: both are optional (spec §2 rule 3, §8.5).",
                pj(&bare),
            )
            .lineage("initial"),
        );

        // --- the profile, and bytes fitted to it (spec §7.1, §7.4) ---
        let fitted = general_edited(&|p| {
            // Another model's bytes cut to the engine's layout with one hidden
            // neuron: afferent_H the rest, recurrent_H one byte, thresholds four.
            let weights: &[u8] = b"synthetic weights of another kind of model, cut to the engine's layout";
            let (afferent, rest) = weights.split_at(weights.len() - 5);
            let (recurrent, thresholds) = rest.split_at(1);
            let mut state = b"KHALMTLM".to_vec();
            state.resize(48, 0);
            state.extend_from_slice(weights);
            let part = |name: &str, bytes: &[u8]| StateComponent {
                name: name.into(),
                hash: format_hash(&sha256(bytes)),
                size_bytes: bytes.len() as u64,
            };
            let m = &mut p.model_identity;
            m.learned_state_components = vec![part("afferent_H", afferent), part("recurrent_H", recurrent), part("thresholds", thresholds)];
            m.parameter_count = Some(afferent.len() as u64 + 2);
            m.learned_state_hash = format_hash(&sha256(&state));
            m.model_hash = m.learned_state_hash.clone();
        });
        for (id, description, p) in [
            (
                "fail-profile-extra-component",
                "The vector with a fourth component, tokenizer.json, re-signed: the profile has exactly three (spec §7.4).",
                vector_edited(|p| {
                    p.model_identity.learned_state_components.push(StateComponent {
                        name: "tokenizer.json".into(),
                        hash: h("khalm verify vectors: a tokenizer"),
                        size_bytes: 45,
                    })
                }),
            ),
            (
                "fail-profile-model-hash-of-files",
                "The vector with the general vector's files digest as model_hash, re-signed: in the profile model_hash is learned_state_hash (spec §7.4).",
                vector_edited(|p| p.model_identity.model_hash = general.model_identity.model_hash.clone()),
            ),
            (
                "fail-profile-identifier-dropped",
                "The vector with model_format edited to safetensors, re-signed: the general description's learned_state_hash is its components' named-set digest, and the engine state's hash is not (spec §7.1, §7.3).",
                vector_edited(|p| p.model_identity.model_format = "safetensors".into()),
            ),
            (
                "fail-profile-identifier-added",
                "The general vector with model_format edited to snn-compact-v1, re-signed: its four components are not the profile's three (spec §7.1, §7.4).",
                general_edited(&|p| p.model_identity.model_format = "snn-compact-v1".into()),
            ),
            (
                "fail-profile-byte-fitted-under-general-format",
                "Another model's bytes cut to the engine's layout with one hidden neuron (afferent_H, recurrent_H, thresholds, the state hash as learned_state_hash and model_hash) under model_format safetensors, re-signed: the general description's learned_state_hash must be the components' named-set digest (spec §7.3, §7.4).",
                fitted,
            ),
            (
                "fail-profile-training-input-format",
                "The vector naming a training_input_format, re-signed: the profile's records are its frames, and the member is absent (spec §7.4, §8.2).",
                vector_edited(|p| p.learning_provenance.training_input_format = Some("khalmtrn-frame-v1".into())),
            ),
        ] {
            c.push(case(id, description, pj(&p)).fails("format.consistency"));
        }

        // --- the general description (spec §7.2, §7.3) ---
        let mut component_hash_edited = general.clone();
        component_hash_edited.model_identity.learned_state_components[3].hash = h("khalm verify vectors: edited after signing");
        for (id, description, p) in [
            (
                "fail-general-state-hash-not-digest",
                "The general vector with another learned_state_hash, re-signed: it is not the components' named-set digest (spec §7.3).",
                general_edited(&|p| p.model_identity.learned_state_hash = h("khalm verify vectors: not the components' digest")),
            ),
            (
                "fail-general-components-unordered",
                "The general vector with its first two components swapped, re-signed: names ascend (spec §7.2).",
                general_edited(&|p| p.model_identity.learned_state_components.swap(0, 1)),
            ),
            (
                "fail-general-component-name-repeated",
                "The general vector with its second component named config.json too, re-signed: no name appears twice (spec §7.2).",
                general_edited(&|p| p.model_identity.learned_state_components[1].name = "config.json".into()),
            ),
            (
                "fail-general-component-name-dot-segment",
                "The general vector with its first component named ./config.json, re-signed: no segment is . (spec §7.2).",
                general_edited(&|p| p.model_identity.learned_state_components[0].name = "./config.json".into()),
            ),
            (
                "fail-general-component-name-leading-slash",
                "The general vector with its first component named /config.json, re-signed: no segment is empty (spec §7.2).",
                general_edited(&|p| p.model_identity.learned_state_components[0].name = "/config.json".into()),
            ),
            (
                "fail-general-component-name-empty",
                "The general vector with its first component named \"\", re-signed: a name is one or more non-empty segments (spec §7.2).",
                general_edited(&|p| p.model_identity.learned_state_components[0].name = String::new()),
            ),
            (
                "fail-general-component-hash-edited",
                "The general vector with its last component's hash changed after signing: format.consistency, which recomputes the named-set digest, runs before signature.payload_hash (spec §6.2).",
                component_hash_edited,
            ),
            (
                "fail-general-training-format-missing",
                "The general vector committing three records without training_input_format, re-signed: a general record that commits records names their format (spec §8.2).",
                general_edited(&|p| {
                    commit(p, &ADDED_DATA[..]);
                    p.learning_provenance.training_input_format = None;
                }),
            ),
        ] {
            c.push(case(id, description, pj(&p)).fails("format.consistency"));
        }
        c.push(
            case(
                "fail-general-no-components",
                "The general vector with no components, re-signed: learned_state_components holds one or more (spec §7.3, schema minItems).",
                pj(&general_edited(&|p| p.model_identity.learned_state_components.clear())),
            )
            .fails("format.schema"),
        );

        // --- the training commitment (spec §8.4) ---
        for (id, description, p) in [
            (
                "fail-not-held-with-digest",
                "The general vector, not-held, with a training_input_digest, re-signed: a record that commits no records has \"\" there (spec §8.4).",
                general_edited(&|p| p.learning_provenance.training_input_digest = h("khalm verify vectors: records")),
            ),
            (
                "fail-not-held-count-not-zero",
                "The general vector, not-held, with training_input_count 1, re-signed (spec §8.4).",
                general_edited(&|p| p.learning_provenance.training_input_count = 1),
            ),
            (
                "fail-not-held-with-format",
                "The general vector, not-held, naming training_input_format named-set-v1, re-signed (spec §8.4).",
                general_edited(&|p| p.learning_provenance.training_input_format = Some("named-set-v1".into())),
            ),
            (
                "fail-committed-root-empty",
                "The vector with training_input_merkle_root \"\" and no training_input_disclosure, re-signed: \"\" passes format.schema (spec §2 rule 9) but commits nothing (spec §8.4).",
                vector_edited(|p| p.learning_provenance.training_input_merkle_root = String::new()),
            ),
        ] {
            c.push(case(id, description, pj(&p)).fails("format.consistency"));
        }
        c.push(
            case(
                "fail-disclosure-outside-enum",
                "The general vector with training_input_disclosure withheld, re-signed: not-disclosed or not-held (spec §8.4).",
                pj(&general_edited(&|p| p.learning_provenance.training_input_disclosure = Some("withheld".into()))),
            )
            .fails("format.schema"),
        );
        let mut disclosure_edited = general.clone();
        disclosure_edited.learning_provenance.training_input_disclosure = Some("not-disclosed".into());
        c.push(
            case(
                "fail-disclosure-edited",
                "The general vector with training_input_disclosure changed from not-held to not-disclosed after signing and signed_payload_hash left as signed: the disclosure is signed content.",
                pj(&disclosure_edited),
            )
            .fails("signature.payload_hash"),
        );

        // --- residency (spec §8.5) ---
        let countries = |list: &[&str]| Some(list.iter().map(|c| c.to_string()).collect::<Vec<String>>());
        for (id, description, p, check) in [
            (
                "fail-residency-countries-with-residency",
                "The vector, whose data_residency is PH, also naming data_residency_countries PH and SG, re-signed: data_residency is absent when the countries are named (spec §8.5).",
                vector_edited(|p| p.learning_provenance.training_input_provenance.data_residency_countries = countries(&["PH", "SG"][..])),
                "format.consistency",
            ),
            (
                "fail-residency-countries-unordered",
                "The general vector naming data_residency_countries FR then DE, re-signed: the codes ascend (spec §8.5).",
                general_edited(&|p| p.learning_provenance.training_input_provenance.data_residency_countries = countries(&["FR", "DE"][..])),
                "format.consistency",
            ),
            (
                "fail-residency-countries-one",
                "The general vector naming one country in data_residency_countries, re-signed: one country is data_residency (schema minItems 2).",
                general_edited(&|p| p.learning_provenance.training_input_provenance.data_residency_countries = countries(&["DE"][..])),
                "format.schema",
            ),
            (
                "fail-residency-countries-lowercase",
                "The general vector naming data_residency_countries de and fr, re-signed: two capital letters each (schema pattern).",
                general_edited(&|p| p.learning_provenance.training_input_provenance.data_residency_countries = countries(&["de", "fr"][..])),
                "format.schema",
            ),
        ] {
            c.push(case(id, description, pj(&p)).fails(check));
        }

        // --- derived models, empty strings and structure (spec §2, §7.5, §8) ---
        let (mut lo, mut hi) = (h("khalm verify vectors: one base"), h("khalm verify vectors: another base"));
        if hi < lo {
            std::mem::swap(&mut lo, &mut hi);
        }
        let bases = |first: &str, second: &str| {
            Some(vec![
                BaseModel { model_hash: first.into(), name: String::new(), relation: "merge".into() },
                BaseModel { model_hash: second.into(), name: "the second base".into(), relation: "merge".into() },
            ])
        };
        c.push(
            case(
                "fail-derived-from-unordered",
                "The general vector naming two merged bases in descending model_hash order, re-signed: entries ascend by model_hash (spec §7.5).",
                pj(&general_edited(&|p| p.model_identity.derived_from = bases(&hi, &lo))),
            )
            .fails("format.consistency"),
        );
        for (id, description, p) in [
            (
                "fail-derived-from-relation-outside-enum",
                "The general vector naming a base with relation finetune, re-signed: the relation is fine-tune, adapter, merge, quantization, distillation or other (spec §7.5).",
                general_edited(&|p| {
                    let mut entries = bases(&lo, &hi).unwrap();
                    entries.truncate(1);
                    entries[0].relation = "finetune".into();
                    p.model_identity.derived_from = Some(entries);
                }),
            ),
            (
                "fail-derived-from-empty",
                "The general vector with derived_from [], re-signed: a present derived_from names one or more bases (schema minItems 1); none is its absence.",
                general_edited(&|p| p.model_identity.derived_from = Some(Vec::new())),
            ),
            (
                "fail-general-training-format-empty",
                "The general vector committing three records with training_input_format \"\", re-signed: the format is never empty (schema minLength 1).",
                general_edited(&|p| {
                    commit(p, &ADDED_DATA[..]);
                    p.learning_provenance.training_input_format = Some(String::new());
                }),
            ),
            (
                "fail-accelerator-empty",
                "The general vector with accelerator \"\", re-signed: an accelerator is never empty; none is its absence (schema minLength 1).",
                general_edited(&|p| p.learning_provenance.training_environment.accelerator = Some(String::new())),
            ),
        ] {
            c.push(case(id, description, pj(&p)).fails("format.schema"));
        }
        let fine_tune_value = serde_json::to_value(&fine_tune).unwrap();
        let fine_tune_text = |edit: &dyn Fn(&mut Value)| {
            let mut doc = fine_tune_value.clone();
            edit(&mut doc);
            text(&doc.to_string())
        };
        let mut without_deployment = serde_json::to_value(&v).unwrap();
        without_deployment["deployment_context"] = Value::Null;
        let entry_as_array = respelled_as_array(&fine_tune_value, "/model_identity/derived_from/0").to_string();
        assert!(
            serde_json::from_str::<Record>(&entry_as_array).unwrap() == fine_tune,
            "serde_json reads the respelled entry as the signed record"
        );
        assert!(OBJECT_FIELDS.iter().any(|(kind, _)| *kind == "/model_identity/derived_from/*"));
        for (id, description, input) in [
            (
                "fail-derived-from-null",
                "pass-general-fine-tune-unrecorded-base with derived_from: null. An optional member is omitted, never null (spec §2 rule 3).",
                fine_tune_text(&|doc| doc["model_identity"]["derived_from"] = Value::Null),
            ),
            (
                "fail-deployment-context-null",
                "The vector with deployment_context: null. An optional member is omitted, never null (spec §2 rule 3).",
                text(&without_deployment.to_string()),
            ),
            (
                "fail-training-epochs-null",
                "pass-general-fine-tune-unrecorded-base with training_epochs: null (spec §2 rule 3).",
                fine_tune_text(&|doc| doc["learning_provenance"]["training_epochs"] = Value::Null),
            ),
            (
                "fail-accelerator-not-a-string",
                "pass-general-fine-tune-unrecorded-base with accelerator 8, a number where the schema has a string.",
                fine_tune_text(&|doc| doc["learning_provenance"]["training_environment"]["accelerator"] = json!(8)),
            ),
            (
                "fail-derived-from-entry-unknown-member",
                "pass-general-fine-tune-unrecorded-base with a url member inside its derived_from entry: the object is closed (spec §2 rule 2).",
                fine_tune_text(&|doc| doc["model_identity"]["derived_from"][0]["url"] = json!("https://example.org/base-model")),
            ),
            (
                "fail-derived-from-entry-as-array",
                "pass-general-fine-tune-unrecorded-base with its derived_from entry written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2).",
                text(&entry_as_array),
            ),
        ] {
            c.push(case(id, description, input).fails("json.structure"));
        }

        // --- after the task 10.11b QA (QA/QA_REPORT_TASK_10_11B.md) and task
        // 10.11e (docs/dev/task-10.11e.md): cases that pin rules the QA's wrong
        // readings passed (QB-01, QB-03, QB-05, QB-08), parameter_count
        // (QB-09) and statement_references. Appended after every case above,
        // each of which stays as it was.
        {
            use vmr_record::hash::parse_hash;
            use vmr_record::record::StatementReference;

            let push = |c: &mut Vec<Case>, id: &'static str, description: &'static str, input: Value, check: Option<&'static str>| {
                let one = case(id, description, input);
                c.push(match check {
                    Some(check) => one.fails(check),
                    None => one.lineage("initial"),
                });
            };
            let component = |name: &str, contents: &str| StateComponent {
                name: name.into(),
                hash: format_hash(&sha256(contents.as_bytes())),
                size_bytes: contents.len() as u64,
            };
            // The named-set digest by its definition (spec §7.2), over the
            // components in the order given, whatever their names: a case whose
            // name or order a rule refuses keeps a digest that agrees, so only
            // that rule can refuse it.
            let digest_of = |parts: &[StateComponent]| {
                let mut bytes = Vec::new();
                for part in parts {
                    bytes.extend_from_slice(&(part.name.len() as u64).to_be_bytes());
                    bytes.extend_from_slice(part.name.as_bytes());
                    bytes.extend_from_slice(&parse_hash(&part.hash).unwrap());
                }
                format_hash(&sha256(&bytes))
            };
            // The general vector with its components edited, and
            // learned_state_hash and model_hash (the components are every file)
            // recomputed over them, re-signed with key A.
            let with_components = |edit: &dyn Fn(&mut Vec<StateComponent>)| {
                general_edited(&|p| {
                    edit(&mut p.model_identity.learned_state_components);
                    let digest = digest_of(&p.model_identity.learned_state_components);
                    p.model_identity.learned_state_hash = digest.clone();
                    p.model_identity.model_hash = digest;
                })
            };
            let sorted = |parts: &mut Vec<StateComponent>| parts.sort_by(|x, y| x.name.as_bytes().cmp(y.name.as_bytes()));

            // QB-01: a name is taken as stored (spec §7.2).
            for (id, description, p) in [
                (
                    "pass-general-component-name-backslash",
                    "The general vector with a fifth file named unet\\config.json, the digests recomputed: a \\ inside a name is a name character, kept as stored (spec §7.2).",
                    with_components(&|parts| parts.push(component("unet\\config.json", "{\"sample_size\":8}\n"))),
                ),
                (
                    "pass-general-component-names-nfc-and-nfd",
                    "The general vector with two more files, one named mod\u{e8}le.bin in NFC (U+00E8) and one in NFD (e, U+0300), the digests recomputed: names are not normalised, so the two are distinct names (spec §7.2).",
                    with_components(&|parts| {
                        parts.push(component("mod\u{e8}le.bin", "the NFC name"));
                        parts.push(component("mode\u{300}le.bin", "the NFD name"));
                        sorted(parts);
                    }),
                ),
                (
                    "pass-general-component-names-case-twins",
                    "The general vector with a fifth file named Tokenizer.json beside tokenizer.json, the digests recomputed: names are compared exactly, so the two are distinct names (spec §7.2).",
                    with_components(&|parts| {
                        parts.push(component("Tokenizer.json", "{\"version\":\"2.0\"}\n"));
                        sorted(parts);
                    }),
                ),
            ] {
                push(&mut c, id, description, pj(&p), None);
            }

            // QB-03: the name rules and the order, each broken with every other
            // member consistent.
            for (id, description, p) in [
                (
                    "fail-general-component-name-empty-digest-kept",
                    "The general vector with its first component named \"\", the digests recomputed over the components as named: only the name rule refuses it (spec §7.2).",
                    with_components(&|parts| parts[0].name = String::new()),
                ),
                (
                    "fail-general-component-name-dot-segment-digest-kept",
                    "The general vector with its first component named ./config.json, the digests recomputed: only the name rule refuses the segment . (spec §7.2).",
                    with_components(&|parts| parts[0].name = "./config.json".into()),
                ),
                (
                    "fail-general-component-name-dotdot-segment-digest-kept",
                    "The general vector with its first component named ../config.json, the digests recomputed: only the name rule refuses the segment .. (spec §7.2).",
                    with_components(&|parts| parts[0].name = "../config.json".into()),
                ),
                (
                    "fail-general-component-name-leading-slash-digest-kept",
                    "The general vector with its first component named /config.json, the digests recomputed: only the name rule refuses the empty first segment (spec §7.2).",
                    with_components(&|parts| parts[0].name = "/config.json".into()),
                ),
                (
                    "fail-general-component-name-trailing-slash-digest-kept",
                    "The general vector with its first component named config.json/, the digests recomputed: only the name rule refuses the empty last segment (spec §7.2).",
                    with_components(&|parts| parts[0].name = "config.json/".into()),
                ),
                (
                    "fail-general-component-name-double-slash-digest-kept",
                    "The general vector with its first component named config//config.json, the digests recomputed: only the name rule refuses the empty segment (spec §7.2).",
                    with_components(&|parts| parts[0].name = "config//config.json".into()),
                ),
                (
                    "fail-general-component-name-repeated-digest-kept",
                    "The general vector with its second component named config.json too, the digests recomputed over the names as given: only the order rule refuses the repeat (spec §7.2).",
                    with_components(&|parts| parts[1].name = "config.json".into()),
                ),
                (
                    "fail-general-components-unordered-digest-kept",
                    "The general vector with its first two components swapped, the digests recomputed in that order: only the order rule refuses it (spec §7.2).",
                    with_components(&|parts| parts.swap(0, 1)),
                ),
                (
                    "fail-general-component-names-utf16-order",
                    "The general vector with two components, U+1F600 then U+FF5E, the digests recomputed in that order: by Unicode scalar value U+FF5E comes first, although UTF-16 code units (spec §3's order) put U+1F600 first (spec §7.2).",
                    with_components(&|parts| *parts = vec![component("\u{1f600}", "first"), component("\u{ff5e}", "second")]),
                ),
                (
                    "fail-general-component-names-case-insensitive-order",
                    "The general vector with two components, a.bin then B.bin, the digests recomputed in that order: by bytes B comes first; only a case-insensitive order would accept it (spec §7.2).",
                    with_components(&|parts| *parts = vec![component("a.bin", "small"), component("B.bin", "capital")]),
                ),
                (
                    "fail-profile-identifier-case",
                    "The vector with model_format SNN-compact-v1, re-signed: not the registered identifier, compared exactly, so the general description applies, and the engine state's hash is not the components' named-set digest (spec §7.1, §7.3).",
                    vector_edited(|p| p.model_identity.model_format = "SNN-compact-v1".into()),
                ),
                (
                    "fail-not-held-with-root",
                    "The general vector, not-held, with a training_input_merkle_root, re-signed: a record that commits no records has \"\" there (spec §8.4).",
                    general_edited(&|p| p.learning_provenance.training_input_merkle_root = h("verification vectors: a records root")),
                ),
                (
                    "fail-committed-digest-empty",
                    "The vector with training_input_digest \"\" and no training_input_disclosure, re-signed: \"\" passes format.schema (spec §2 rule 9) but commits nothing (spec §8.4).",
                    vector_edited(|p| p.learning_provenance.training_input_digest = String::new()),
                ),
                (
                    "fail-residency-countries-repeated",
                    "The general vector naming data_residency_countries DE and DE, re-signed: the codes ascend, none repeated (spec §8.5).",
                    general_edited(&|p| p.learning_provenance.training_input_provenance.data_residency_countries = countries(&["DE", "DE"][..])),
                ),
                (
                    "fail-derived-from-repeated",
                    "The general vector naming two merged bases with one model_hash, re-signed: entries ascend by model_hash, none repeated (spec §7.5).",
                    general_edited(&|p| p.model_identity.derived_from = bases(&lo, &lo)),
                ),
            ] {
                push(&mut c, id, description, pj(&p), Some("format.consistency"));
            }
            let look_alike = |identifier: &'static str| {
                vector_edited(|p| {
                    p.model_identity.model_format = identifier.into();
                    let digest = digest_of(&p.model_identity.learned_state_components);
                    p.model_identity.learned_state_hash = digest.clone();
                    p.model_identity.model_hash = digest;
                    p.learning_provenance.training_input_format = Some("khalmtrn-frame-v1".into());
                })
            };
            for (id, description, p) in [
                (
                    "pass-general-component-names-utf8-order",
                    "The general vector with two components, U+FF5E then U+1F600, the digests recomputed: ascending by Unicode scalar value, which is UTF-8 byte order (spec §7.2).",
                    with_components(&|parts| *parts = vec![component("\u{ff5e}", "first"), component("\u{1f600}", "second")]),
                ),
                (
                    "pass-general-component-names-capitals-first",
                    "The general vector with two components, B.bin then a.bin, the digests recomputed: ascending by bytes, capitals first (spec §7.2).",
                    with_components(&|parts| *parts = vec![component("B.bin", "capital"), component("a.bin", "small")]),
                ),
                (
                    "pass-general-profile-look-alike",
                    "The vector under model_format SNN-compact-v1, with its three components' named-set digest as learned_state_hash and model_hash and training_input_format khalmtrn-frame-v1, re-signed: a look-alike identifier selects the general description, whose rules it meets (spec §7.1, §7.3, §8.2).",
                    look_alike("SNN-compact-v1"),
                ),
                (
                    "pass-general-profile-look-alike-fullwidth",
                    "pass-general-profile-look-alike under snn\u{ff0d}compact\u{ff0d}v1, with FULLWIDTH HYPHEN-MINUS (U+FF0D), which NFKC maps to -: identifiers are compared without normalisation, so the general description applies (spec §7.1).",
                    look_alike("snn\u{ff0d}compact\u{ff0d}v1"),
                ),
                (
                    "pass-general-empty-model-format",
                    "The general vector with model_format \"\", re-signed: \"\" is not the registered identifier, so the general description applies (spec §7.1).",
                    general_edited(&|p| p.model_identity.model_format = String::new()),
                ),
                (
                    "pass-general-empty-file-component",
                    "The general vector with a fifth file of 0 bytes, added_tokens.json, the digests recomputed: an empty file is a component (spec §7.2, §7.3).",
                    with_components(&|parts| {
                        parts.push(component("added_tokens.json", ""));
                        sorted(parts);
                    }),
                ),
                // QB-05: shape selects nothing.
                (
                    "pass-general-profile-shaped-components",
                    "The general vector described by the vector's three components, named and sized as the profile's, with their named-set digest as learned_state_hash and model_hash and the vector's parameter_count, re-signed: under model_format safetensors it verifies as a general description; the shape selects no rules (spec §7.1).",
                    general_edited(&|p| {
                        let m = &mut p.model_identity;
                        m.learned_state_components = v.model_identity.learned_state_components.clone();
                        m.parameter_count = v.model_identity.parameter_count;
                        let digest = digest_of(&m.learned_state_components);
                        m.learned_state_hash = digest.clone();
                        m.model_hash = digest;
                    }),
                ),
                // QB-08: settled by the text.
                (
                    "pass-profile-not-held",
                    "The vector, in the profile snn-compact-v1, with training_input_disclosure not-held, \"\" digest and root and count 0, re-signed: the disclosure applies in the profile too (spec §8.4).",
                    vector_edited(|p| {
                        let l = &mut p.learning_provenance;
                        l.training_input_digest = String::new();
                        l.training_input_merkle_root = String::new();
                        l.training_input_count = 0;
                        l.training_input_disclosure = Some("not-held".into());
                    }),
                ),
                (
                    "pass-profile-derived-from",
                    "The vector, in the profile snn-compact-v1, naming a base model in derived_from, re-signed: derived_from applies in the profile too (spec §7.5).",
                    vector_edited(|p| {
                        p.model_identity.derived_from = Some(vec![BaseModel {
                            model_hash: h("verification vectors: an earlier engine state"),
                            name: "an earlier engine state".into(),
                            relation: "fine-tune".into(),
                        }])
                    }),
                ),
                (
                    "pass-general-file-and-directory-names",
                    "The general vector with two more files, unet and unet/config.json, the digests recomputed: a file and a directory of one name are two names (spec §7.2).",
                    with_components(&|parts| {
                        parts.push(component("unet", "a file named unet"));
                        parts.push(component("unet/config.json", "{}"));
                        sorted(parts);
                    }),
                ),
            ] {
                push(&mut c, id, description, pj(&p), None);
            }
            let controls = with_components(&|parts| {
                parts.push(component("\u{1}control.bin", "a name holding U+0001"));
                parts.push(component("override\u{202e}nib.bin", "a name holding U+202E"));
                sorted(parts);
            });
            push(
                &mut c,
                "pass-general-component-name-with-controls",
                "The general vector with two more files whose names hold U+0001 and U+202E (written as JSON escapes), the digests recomputed: no rule refuses such a name (spec §7.2); a tool shows it escaped.",
                text(&controls.to_json().unwrap().replace('\u{202e}', "\\u202e")),
                None,
            );
            push(
                &mut c,
                "fail-derived-from-itself",
                "The general vector naming its own model_hash in derived_from, re-signed: a model is not made from itself (spec §7.5).",
                pj(&general_edited(&|p| {
                    p.model_identity.derived_from = Some(vec![BaseModel {
                        model_hash: p.model_identity.model_hash.clone(),
                        name: "this model".into(),
                        relation: "other".into(),
                    }])
                })),
                Some("format.consistency"),
            );

            // QB-09: parameter_count optional in the general description,
            // required in the profile.
            let unstated = general_edited(&|p| p.model_identity.parameter_count = None);
            push(
                &mut c,
                "pass-general-parameter-count-not-stated",
                "The general vector without parameter_count, re-signed: optional in the general description, where its absence says that the issuer does not state it (spec §2 rule 3, §7.3).",
                pj(&unstated),
                None,
            );
            push(
                &mut c,
                "pass-general-parameter-count-not-stated-cose",
                "pass-general-parameter-count-not-stated in its COSE_Sign1 form.",
                pc(&unstated),
                None,
            );
            push(
                &mut c,
                "fail-profile-parameter-count-absent",
                "The vector without parameter_count, re-signed: the profile snn-compact-v1 requires it (spec §7.4).",
                pj(&vector_edited(|p| p.model_identity.parameter_count = None)),
                Some("format.consistency"),
            );
            let mut null_count = serde_json::to_value(&general).unwrap();
            null_count["model_identity"]["parameter_count"] = Value::Null;
            push(
                &mut c,
                "fail-general-parameter-count-null",
                "The general vector with parameter_count: null. An optional member is omitted, never null (spec §2 rule 3).",
                text(&null_count.to_string()),
                Some("json.structure"),
            );

            // Task 10.11e: statement_references (spec §7.7).
            let (mut first, mut second) =
                (h("verification vectors: an in-toto statement about the general vector's files"), h("verification vectors: a model card"));
            if second < first {
                std::mem::swap(&mut first, &mut second);
            }
            let reference = |format: &str, digest: &str| StatementReference { format: format.into(), digest: digest.into() };
            let with_references =
                |references: Vec<StatementReference>| general_edited(&move |p| p.model_identity.statement_references = Some(references.clone()));
            let oms = with_references(vec![reference("oms-v1", &first)]);
            let two = with_references(vec![reference("oms-v1", &first), reference("org.example.model-card-v1", &second)]);
            push(
                &mut c,
                "pass-statement-references-oms-v1",
                "The general vector naming one OpenSSF Model Signing bundle in statement_references, format oms-v1, by the SHA-256 of a synthetic DSSE payload, re-signed: a verifier checks the reference's form only (spec §7.7).",
                pj(&oms),
                None,
            );
            push(
                &mut c,
                "pass-statement-references-issuer-format",
                "The general vector naming an oms-v1 statement and one of the issuer's own format, org.example.model-card-v1, ascending by digest, re-signed: a format with . is the issuer's (spec §7.7).",
                pj(&two),
                None,
            );
            push(
                &mut c,
                "pass-statement-references-issuer-format-cose",
                "pass-statement-references-issuer-format in its COSE_Sign1 form.",
                pc(&two),
                None,
            );
            for (id, description, p, check) in [
                (
                    "fail-statement-references-dotless-unregistered",
                    "The general vector naming a statement of format c2pa-manifest, re-signed: a format without . must be registered, and v0.1 registers only oms-v1 and vmr-audit-checkpoint-v1 (spec §7.7).",
                    with_references(vec![reference("c2pa-manifest", &first)]),
                    "format.consistency",
                ),
                (
                    "fail-statement-references-unordered",
                    "The general vector naming two oms-v1 statements in descending digest order, re-signed: entries ascend by digest (spec §7.7).",
                    with_references(vec![reference("oms-v1", &second), reference("oms-v1", &first)]),
                    "format.consistency",
                ),
                (
                    "fail-statement-references-repeated",
                    "The general vector naming one digest twice, under oms-v1 and under org.example.model-card-v1, re-signed: one byte string is one statement, listed once (spec §7.7).",
                    with_references(vec![reference("oms-v1", &first), reference("org.example.model-card-v1", &first)]),
                    "format.consistency",
                ),
                (
                    "fail-statement-references-empty",
                    "The general vector with statement_references [], re-signed: a present list names one or more statements (schema minItems 1); none is its absence.",
                    with_references(Vec::new()),
                    "format.schema",
                ),
                (
                    "fail-statement-references-digest-uppercase",
                    "The general vector naming an oms-v1 statement by a digest in upper case, re-signed: a hash string (spec §2 rule 5).",
                    with_references(vec![reference("oms-v1", &first.to_uppercase())]),
                    "format.schema",
                ),
                (
                    "fail-statement-references-digest-empty",
                    "The general vector naming an oms-v1 statement by the digest \"\", re-signed: a hash string, never \"\" (spec §2 rules 5 and 9).",
                    with_references(vec![reference("oms-v1", "")]),
                    "format.schema",
                ),
                (
                    "fail-statement-references-format-uppercase",
                    "The general vector naming a statement of format OMS-v1, re-signed: lower-case ASCII only (schema pattern), so no look-alike of a registered format passes (spec §7.7).",
                    with_references(vec![reference("OMS-v1", &first)]),
                    "format.schema",
                ),
                (
                    "fail-statement-references-format-look-alike",
                    "The general vector naming a statement of format \u{43e}ms-v1, whose first letter is CYRILLIC SMALL LETTER O (U+043E), re-signed: lower-case ASCII only (schema pattern; spec §7.7).",
                    with_references(vec![reference("\u{43e}ms-v1", &first)]),
                    "format.schema",
                ),
            ] {
                push(&mut c, id, description, pj(&p), Some(check));
            }
            let oms_value = serde_json::to_value(&oms).unwrap();
            let oms_text = |edit: &dyn Fn(&mut Value)| {
                let mut doc = oms_value.clone();
                edit(&mut doc);
                text(&doc.to_string())
            };
            let compact = oms_value.to_string();
            assert_eq!(compact.matches("\"format\":\"oms-v1\"").count(), 1);
            let member_repeated = compact.replacen("\"format\":\"oms-v1\"", "\"format\":\"oms-v1\",\"format\":\"oms-v1\"", 1);
            let reference_as_array = respelled_as_array(&oms_value, "/model_identity/statement_references/0").to_string();
            assert!(
                serde_json::from_str::<Record>(&reference_as_array).unwrap() == oms,
                "serde_json reads the respelled entry as the signed record"
            );
            for (id, description, input) in [
                (
                    "fail-statement-references-null",
                    "pass-statement-references-oms-v1 with statement_references: null. An optional member is omitted, never null (spec §2 rule 3).",
                    oms_text(&|doc| doc["model_identity"]["statement_references"] = Value::Null),
                ),
                (
                    "fail-statement-references-entry-member-repeated",
                    "pass-statement-references-oms-v1 with the member format written twice in its entry: member names are unique in every object (spec §2 rule 1).",
                    text(&member_repeated),
                ),
                (
                    "fail-statement-references-entry-unknown-member",
                    "pass-statement-references-oms-v1 with a location member in its entry: the object is closed, and no entry says where a statement is (spec §2 rule 2, §7.7).",
                    oms_text(&|doc| doc["model_identity"]["statement_references"][0]["location"] = json!("https://example.org/bundle.sigstore.json")),
                ),
                (
                    "fail-statement-references-entry-as-array",
                    "pass-statement-references-oms-v1 with its entry written, after signing, as the array of its values in the order of the schema's properties: an array where the schema has an object (spec §2 rule 2).",
                    text(&reference_as_array),
                ),
                (
                    "fail-statement-references-format-not-a-string",
                    "pass-statement-references-oms-v1 with format 1, a number where the schema has a string.",
                    oms_text(&|doc| doc["model_identity"]["statement_references"][0]["format"] = json!(1)),
                ),
            ] {
                push(&mut c, id, description, input, Some("json.structure"));
            }

            // After the task 10.11e QA (QA/QA_REPORT_TASK_10_11E.md, QE-02):
            // readings of the new rules no earlier case told apart. Appended
            // after every case above, each of which stays as it was.
            push(
                &mut c,
                "fail-statement-references-dotless-oms-v2",
                "The general vector naming a statement of format oms-v2, re-signed: a format without . that looks registered is not; v0.1 registers only oms-v1 and vmr-audit-checkpoint-v1 (spec §7.7).",
                pj(&with_references(vec![reference("oms-v2", &first)])),
                Some("format.consistency"),
            );
            push(
                &mut c,
                "fail-statement-references-format-fullwidth",
                "The general vector naming a statement of format \u{ff4f}\u{ff4d}\u{ff53}-v1, in FULLWIDTH LATIN SMALL LETTERS, which NFKC maps to oms-v1, re-signed: lower-case ASCII only, never normalised (schema pattern; spec §7.7).",
                pj(&with_references(vec![reference("\u{ff4f}\u{ff4d}\u{ff53}-v1", &first)])),
                Some("format.schema"),
            );
            push(
                &mut c,
                "pass-statement-references-registered-name-as-segment",
                "The general vector naming statements of formats oms-v1.x and x.oms-v1, ascending by digest, re-signed: a format with . is the issuer's own, whatever its segments, and is not oms-v1 (spec §7.7).",
                pj(&with_references(vec![reference("oms-v1.x", &first), reference("x.oms-v1", &second)])),
                None,
            );
            push(
                &mut c,
                "pass-statement-references-two-of-one-format",
                "The general vector naming two oms-v1 statements with different digests, ascending, re-signed: entries are ordered and unique by digest, and one format may name several statements (spec §7.7).",
                pj(&with_references(vec![reference("oms-v1", &first), reference("oms-v1", &second)])),
                None,
            );
            let profile_referenced = vector_edited(|p| p.model_identity.statement_references = Some(vec![reference("oms-v1", &first)]));
            push(
                &mut c,
                "pass-profile-statement-references",
                "The vector, in the profile snn-compact-v1, naming one oms-v1 statement, re-signed: statement_references applies whichever description model_format selects (spec §7.7).",
                pj(&profile_referenced),
                None,
            );
            push(
                &mut c,
                "pass-profile-statement-references-cose",
                "pass-profile-statement-references in its COSE_Sign1 form.",
                pc(&profile_referenced),
                None,
            );
            // pass-general-diffusion-weights-only's record, whose components
            // are fewer than its files, so model_hash and learned_state_hash
            // differ, naming one base.
            assert_ne!(diffusion.model_identity.model_hash, diffusion.model_identity.learned_state_hash);
            let derived_from = |base: &str| {
                let mut p = diffusion.clone();
                p.model_identity.derived_from =
                    Some(vec![BaseModel { model_hash: base.into(), name: "a base".into(), relation: "other".into() }]);
                sign_as(&mut p, KEY_A);
                p
            };
            push(
                &mut c,
                "fail-derived-from-own-model-hash-differs-from-state-hash",
                "pass-general-diffusion-weights-only, whose model_hash and learned_state_hash differ, naming its own model_hash in derived_from, re-signed: a model is not made from itself, judged by model_hash (spec §7.5).",
                pj(&derived_from(&diffusion.model_identity.model_hash)),
                Some("format.consistency"),
            );
            push(
                &mut c,
                "pass-derived-from-learned-state-hash",
                "pass-general-diffusion-weights-only naming its own learned_state_hash, not its model_hash, in derived_from, re-signed: only the model's own model_hash is refused (spec §7.5).",
                pj(&derived_from(&diffusion.model_identity.learned_state_hash)),
                None,
            );
            push(
                &mut c,
                "pass-general-parameter-count-zero",
                "The general vector with parameter_count 0, re-signed: 0 states a model with no learned parameters, a claim nothing checks in the general description (spec §7.3).",
                pj(&general_edited(&|p| p.model_identity.parameter_count = Some(0))),
                None,
            );

            // Task 10.11cd (the owner, 2026-09-15, answering Phase 8's
            // Q9(b)): a record names an audit-log checkpoint, format
            // vmr-audit-checkpoint-v1, by the SHA-256 of the checkpoint's
            // signed payload: its JCS form without its signature section
            // (sovereignty format §3, §8). Appended after every case above,
            // each of which stays as it was.
            let checkpoint_payload = json!({
                "checkpoint_type": "vmr.audit-checkpoint",
                "checkpoint_version": "0.1",
                "issued_at": "2026-09-10T00:00:00Z",
                "log_id": key_id(KEY_B),
                "root_hash": h("verification vectors: the root of an audit log of two entries"),
                "tree_size": 2,
            });
            let checkpoint = format_hash(&sha256(vmr_record::canonical::jcs(&checkpoint_payload).as_bytes()));
            let audited = with_references(vec![reference("vmr-audit-checkpoint-v1", &checkpoint)]);
            push(
                &mut c,
                "pass-statement-references-vmr-audit-checkpoint-v1",
                "The general vector naming an audit-log checkpoint in statement_references, format vmr-audit-checkpoint-v1, by the SHA-256 of a synthetic checkpoint's signed payload (its JCS form without its signature section), re-signed: a verifier checks the reference's form only, never the checkpoint (spec §7.7).",
                pj(&audited),
                None,
            );
            push(
                &mut c,
                "pass-statement-references-vmr-audit-checkpoint-v1-cose",
                "pass-statement-references-vmr-audit-checkpoint-v1 in its COSE_Sign1 form.",
                pc(&audited),
                None,
            );
            push(
                &mut c,
                "fail-statement-references-vmr-audit-checkpoint-v1-case-variant",
                "The general vector naming a statement of format VMR-audit-checkpoint-v1, re-signed: lower-case ASCII only, so the registered name in another letter case fails the schema's pattern (spec §7.7).",
                pj(&with_references(vec![reference("VMR-audit-checkpoint-v1", &checkpoint)])),
                Some("format.schema"),
            );
            push(
                &mut c,
                "fail-statement-references-vmr-audit-checkpoint-look-alike",
                "The general vector naming a statement of format vmr-audit-checkpoint-v2, re-signed: a format without . that looks registered is not; v0.1 registers only oms-v1 and vmr-audit-checkpoint-v1 (spec §7.7).",
                pj(&with_references(vec![reference("vmr-audit-checkpoint-v2", &checkpoint)])),
                Some("format.consistency"),
            );

            // Task 10.12a (D12a-1): accelerator_software, the general member
            // in place of cuda_version, is never empty. Appended after every
            // case above, each of which stays as it was.
            push(
                &mut c,
                "fail-accelerator-software-empty",
                "The general vector with accelerator_software \"\", re-signed: the accelerator's software is never empty; none is its absence (schema minLength 1, spec §8.5).",
                pj(&general_edited(&|p| p.learning_provenance.training_environment.accelerator_software = Some(String::new()))),
                Some("format.schema"),
            );
        }
    }

    c
}

// ---------------------------------------------------------------------------
//  The trust-store loader cases (trust-store-format-v0.1.md §3)
// ---------------------------------------------------------------------------

pub fn loader_cases() -> Value {
    let base = store_json(&[entry(VECTOR_ISSUER, KEY_A), entry(OTHER_ISSUER, KEY_B)]);
    let text_of = |v: &Value| serde_json::to_string_pretty(v).unwrap();
    let ok = |id: &str, description: &str, input: Value, doc_for_hash: &Value| {
        let store = vmr_verify::TrustStore::from_json(&input_bytes(&input)).unwrap();
        // The expected identity, recomputed here from the spec's rule
        // (sorted, JCS, SHA-256) - not read from the implementation's
        // TrustStore::sha256 - and then checked against it.
        let expected = canonical_hash(doc_for_hash);
        assert_eq!(store.sha256(), expected, "{id}");
        json!({"id": id, "description": description, "input": input, "expected": {"result": "ok", "sha256": expected}})
    };
    let err = |id: &str, description: &str, input: Value, kind: &str| {
        json!({"id": id, "description": description, "input": input, "expected": {"result": "error", "kind": kind}})
    };
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut d = base.clone();
        f(&mut d);
        d
    };
    let mut out = Vec::new();
    out.push(ok("ok-basic", "Two issuers, one key each.", json!({"text": text_of(&base)}), &base));
    let reordered = edit(&|d| d["issuers"].as_array_mut().unwrap().reverse());
    out.push(ok("ok-reordered", "The same store, issuers in the other order: the same identity.", json!({"text": text_of(&reordered)}), &base));
    out.push(ok("ok-compact", "The same store, compact: the same identity.", json!({"text": serde_json::to_string(&base).unwrap()}), &base));
    let no_until = edit(&|d| {
        d["issuers"][0]["keys"][0].as_object_mut().unwrap().remove("valid_until");
    });
    out.push(ok("ok-no-valid-until", "valid_until omitted: no end.", json!({"text": text_of(&no_until)}), &no_until));
    let empty = store_json(&[]);
    out.push(ok("ok-empty", "A store that trusts no one.", json!({"text": text_of(&empty)}), &empty));
    // Phase 4 QA (P4-03): noncharacters are scalar values - permitted, raw
    // (given as hex, so this file holds none) or escaped, one identity.
    let nonchar = edit(&|d| d["issuers"][0]["issuer_name"] = json!("New Clark City Fab Operator \u{fdd0}\u{fffe}\u{10ffff}"));
    out.push(ok("ok-noncharacters", "issuer_name ending in the noncharacters U+FDD0 U+FFFE U+10FFFF, written raw.", json!({"hex": hex::encode(text_of(&nonchar))}), &nonchar));
    let escaped = text_of(&nonchar).replacen("\u{fdd0}\u{fffe}\u{10ffff}", "\\ufdd0\\ufffe\\udbff\\udfff", 1);
    assert!(escaped.is_ascii());
    out.push(ok("ok-noncharacters-escaped", "ok-noncharacters with the noncharacters written as \\u escapes: the same store, the same identity.", json!({"text": escaped}), &nonchar));

    let t = serde_json::to_string(&base).unwrap();
    out.push(err("error-size", "16 MiB + 1 byte (the store followed by spaces).", json!({"text": t.clone(), "append_spaces": 16 * 1024 * 1024 + 1 - t.len()}), "trust_store.size"));
    out.push(err("error-syntax-not-utf8", "An invalid UTF-8 byte.", json!({"hex": hex::encode([&b"{\"trust_store_version\":\"0.1\xff\"}"[..]].concat())}), "trust_store.syntax"));
    out.push(err("error-syntax-trailing", "Data after the store.", json!({"text": format!("{t} []")}), "trust_store.syntax"));
    {
        let at = t.find("New Clark").unwrap() + "New ".len();
        let cesu = [&t.as_bytes()[..at], &[0xed, 0xa0, 0x80][..], &t.as_bytes()[at..]].concat();
        out.push(err("error-syntax-cesu8-surrogate", "issuer_name holding U+D800 as the bytes ED A0 80 (CESU-8): not UTF-8.", json!({"hex": hex::encode(cesu)}), "trust_store.syntax"));
    }
    out.push(err("error-version", "trust_store_version 0.2.", json!({"text": text_of(&edit(&|d| d["trust_store_version"] = json!("0.2")))}), "trust_store.version"));
    {
        let later = serde_json::to_string(&edit(&|d| d["trust_store_version"] = json!("0.2"))).unwrap();
        assert!(later.starts_with("{\"issuers\":"));
        let named = later.replacen("{\"issuers\":", "{\"\\ud800\":1,\"issuers\":", 1);
        out.push(err(
            "error-version-before-lone-surrogate",
            "trust_store_version 0.2 and a top-level member named \\ud800: the version (kind 3) is checked over the whole store before the structure (kind 4), where the lone surrogate would fail.",
            json!({"text": named}),
            "trust_store.version",
        ));
    }
    out.push(err("error-structure-unknown-member", "A member the format does not define.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"][0]["trusted"] = json!(true)))}), "trust_store.structure"));
    out.push(err("error-structure-duplicate-member", "revoked twice.", json!({"text": t.replacen("\"revoked\":false", "\"revoked\":false,\"revoked\":true", 1)}), "trust_store.structure"));
    out.push(err("error-structure-null", "valid_until: null.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"][0]["valid_until"] = Value::Null))}), "trust_store.structure"));
    out.push(err("error-structure-no-keys", "An issuer without keys.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"] = json!([])))}), "trust_store.structure"));
    out.push(err("error-structure-attestation", "attestation_level root.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"][0]["attestation_level"] = json!("root")))}), "trust_store.structure"));
    out.push(err(
        "error-structure-lone-surrogate",
        "issuer_name with \\ud800 before a letter: valid RFC 8259 syntax, but not a Unicode scalar value.",
        json!({"text": t.replacen("New Clark", "New \\ud800Clark", 1)}),
        "trust_store.structure",
    ));
    out.push(err("error-issuer-id", "An issuer_id with a Cyrillic а.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["issuer_id"] = json!("did:web:f\u{430}ctory-operator.ph")))}), "trust_store.issuer_id"));
    out.push(err("error-timestamp", "valid_from 2026-02-30T00:00:00Z.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"][0]["valid_from"] = json!("2026-02-30T00:00:00Z")))}), "trust_store.timestamp"));
    out.push(err(
        "error-invalid-key",
        "A JWK whose y is its x: not on P-256.",
        json!({"text": text_of(&edit(&|d| {
            let x = d["issuers"][0]["keys"][0]["public_key"]["x"].clone();
            d["issuers"][0]["keys"][0]["public_key"]["y"] = x;
        }))}),
        "trust_store.invalid_key",
    ));
    out.push(err("error-key-id-mismatch", "key_id of another key.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"][0]["key_id"] = json!(key_id(KEY_F))))}), "trust_store.key_id_mismatch"));
    out.push(err(
        "error-duplicate-issuer",
        "Two entries for one issuer_id.",
        json!({"text": text_of(&edit(&|d| {
            let mut second = d["issuers"][1].clone();
            second["issuer_id"] = d["issuers"][0]["issuer_id"].clone();
            d["issuers"][1] = second;
        }))}),
        "trust_store.duplicate_issuer",
    ));
    out.push(err(
        "error-duplicate-key",
        "Key A trusted for two issuers.",
        json!({"text": text_of(&edit(&|d| {
            let a = d["issuers"][0]["keys"][0].clone();
            d["issuers"][1]["keys"] = json!([a]);
        }))}),
        "trust_store.duplicate_key",
    ));
    out.push(err("error-validity-window", "valid_until == valid_from.", json!({"text": text_of(&edit(&|d| d["issuers"][0]["keys"][0]["valid_until"] = json!("2026-01-01T00:00:00Z")))}), "trust_store.validity_window"));

    // docs/TASKS.md 6.16 (docs/dev/task-6.16.md A16-1 to A16-5): policy
    // authorities, the two kinds they add in rule order, and the nesting
    // bound. Appended, so no earlier case moves.
    let with_authorities = |authorities: Value| {
        let mut d = base.clone();
        d["policy_authorities"] = authorities;
        d
    };
    let one_authority = with_authorities(json!([authority_entry(VECTOR_AUTHORITY, &[KEY_P])]));
    let edit_authority = |f: &dyn Fn(&mut Value)| {
        let mut d = one_authority.clone();
        f(&mut d);
        d
    };
    out.push(ok("ok-policy-authorities", "ok-basic and one policy authority holding key P.", json!({"text": text_of(&one_authority)}), &one_authority));
    let empty_list = with_authorities(json!([]));
    out.push(ok("ok-policy-authorities-empty", "ok-basic with an empty policy_authorities: the same store, with ok-basic's identity.", json!({"text": text_of(&empty_list)}), &base));
    let two = with_authorities(json!([authority_entry(VECTOR_AUTHORITY, &[KEY_P, KEY_Q]), authority_entry(OTHER_AUTHORITY, &[KEY_R])]));
    out.push(ok("ok-two-policy-authorities", "ok-basic and two policy authorities, one holding keys P and Q, the other key R.", json!({"text": text_of(&two)}), &two));
    let reordered_authorities = {
        let mut d = two.clone();
        let list = d["policy_authorities"].as_array_mut().unwrap();
        list.reverse();
        for authority in list.iter_mut() {
            authority["keys"].as_array_mut().unwrap().reverse();
        }
        d
    };
    out.push(ok("ok-two-policy-authorities-reordered", "ok-two-policy-authorities with the authorities in the other order and each one's keys reversed: the same store, the same identity.", json!({"text": text_of(&reordered_authorities)}), &two));
    let authority_store = json!({"trust_store_version": "0.1", "issuers": [], "policy_authorities": [authority_entry(VECTOR_AUTHORITY, &[KEY_P])]});
    out.push(ok("ok-authority-store", "No issuers and one policy authority holding key P: a store of the kind an authority store is (trust-store format §4.2).", json!({"text": text_of(&authority_store)}), &authority_store));
    let code_points = with_authorities(json!([authority_entry("\u{1f600} authority", &[KEY_P]), authority_entry("\u{ff21} authority", &[KEY_Q])]));
    out.push(ok("ok-policy-authorities-code-point-order", "Two policy authorities named U+1F600 and U+FF21 (each followed by \" authority\"): the canonical form sorts them by code point, U+FF21 first; UTF-16 code-unit order would put U+1F600 first and give another identity.", json!({"text": text_of(&code_points)}), &code_points));

    out.push(err("error-structure-authority-no-keys", "ok-policy-authorities with an authority without keys.", json!({"text": text_of(&edit_authority(&|d| d["policy_authorities"][0]["keys"] = json!([])))}), "trust_store.structure"));
    out.push(err("error-structure-authority-unknown-member", "A member the format does not define, in a policy authority.", json!({"text": text_of(&edit_authority(&|d| d["policy_authorities"][0]["trusted"] = json!(true)))}), "trust_store.structure"));
    out.push(err("error-structure-policy-authorities-null", "policy_authorities: null (an optional member is omitted, never null).", json!({"text": text_of(&with_authorities(Value::Null))}), "trust_store.structure"));
    out.push(err("error-authority-id", "An empty authority_id.", json!({"text": text_of(&edit_authority(&|d| d["policy_authorities"][0]["authority_id"] = json!("")))}), "trust_store.authority_id"));
    out.push(err(
        "error-authority-id-before-timestamp",
        "An empty authority_id and an issuer key's valid_from 2026-02-30T00:00:00Z: kind 6 is checked over the whole store before kind 7.",
        json!({"text": text_of(&edit_authority(&|d| {
            d["policy_authorities"][0]["authority_id"] = json!("");
            d["issuers"][0]["keys"][0]["valid_from"] = json!("2026-02-30T00:00:00Z");
        }))}),
        "trust_store.authority_id",
    ));
    out.push(err("error-timestamp-authority-key", "A policy authority key's valid_from 2026-02-30T00:00:00Z: the key rules apply to an authority's keys.", json!({"text": text_of(&edit_authority(&|d| d["policy_authorities"][0]["keys"][0]["valid_from"] = json!("2026-02-30T00:00:00Z")))}), "trust_store.timestamp"));
    out.push(err("error-key-id-mismatch-authority-key", "A policy authority key whose key_id is key F's.", json!({"text": text_of(&edit_authority(&|d| d["policy_authorities"][0]["keys"][0]["key_id"] = json!(key_id(KEY_F))))}), "trust_store.key_id_mismatch"));
    out.push(err("error-duplicate-authority", "Two policy authorities with one authority_id, holding keys P and Q.", json!({"text": text_of(&with_authorities(json!([authority_entry(VECTOR_AUTHORITY, &[KEY_P]), authority_entry(VECTOR_AUTHORITY, &[KEY_Q])])))}), "trust_store.duplicate_authority"));
    out.push(err("error-duplicate-authority-before-duplicate-key", "Two policy authorities with one authority_id, both holding key P: kind 11 is checked before kind 12.", json!({"text": text_of(&with_authorities(json!([authority_entry(VECTOR_AUTHORITY, &[KEY_P]), authority_entry(VECTOR_AUTHORITY, &[KEY_P])])))}), "trust_store.duplicate_authority"));
    out.push(err("error-duplicate-key-issuer-and-authority", "Key A trusted for an issuer and for a policy authority: a key is in one list only.", json!({"text": text_of(&with_authorities(json!([authority_entry(VECTOR_AUTHORITY, &[KEY_A])])))}), "trust_store.duplicate_key"));
    out.push(err("error-duplicate-key-two-authorities", "Key P under two policy authorities.", json!({"text": text_of(&with_authorities(json!([authority_entry(VECTOR_AUTHORITY, &[KEY_P]), authority_entry(OTHER_AUTHORITY, &[KEY_P])])))}), "trust_store.duplicate_key"));
    // The store object is level 1, so `arrays` arrays in one of its members
    // reach level arrays + 1.
    let nested = |version: &str, arrays: usize| {
        format!("{{\"trust_store_version\":\"{version}\",\"issuers\":[],\"deep\":{}{}}}", "[".repeat(arrays), "]".repeat(arrays))
    };
    out.push(err("error-structure-nesting-127-levels", "Text nested 127 levels deep (126 arrays in an unknown member of the store object): within the bound, so read, and refused for its member.", json!({"text": nested("0.1", 126)}), "trust_store.structure"));
    out.push(err("error-syntax-nesting-128-levels", "Text nested 128 levels deep (127 arrays in a member): past the bound of §2.", json!({"text": nested("0.1", 127)}), "trust_store.syntax"));
    out.push(err("error-syntax-nesting-128-levels-later-version", "error-syntax-nesting-128-levels with trust_store_version 0.2: the bound is kind 2, checked before the version.", json!({"text": nested("0.2", 127)}), "trust_store.syntax"));
    // QA QT-01 (§3 kind 4): an object written as the array of its values, in
    // its members' declaration order, the order serde's derive reads a struct
    // in: one case per object kind. Appended, so no earlier case moves.
    let as_array = |document: &Value, pointer: &str, fields: &[&str]| {
        let mut d = document.clone();
        let object = d.pointer_mut(pointer).unwrap();
        assert_eq!(object.as_object().unwrap().len(), fields.len(), "{pointer}: every member, in declaration order");
        let values: Vec<Value> = fields.iter().map(|f| object[*f].clone()).collect();
        *object = Value::Array(values);
        d
    };
    const KEY: &[&str] = &["key_id", "public_key", "attestation_level", "valid_from", "valid_until", "revoked"];
    for (id, description, document, pointer, fields) in [
        ("error-structure-store-as-array", "ok-policy-authorities written as [trust_store_version, issuers, policy_authorities].", &one_authority, "", &["trust_store_version", "issuers", "policy_authorities"][..]),
        ("error-structure-issuer-as-array", "ok-basic with its first issuer written as [issuer_id, issuer_name, keys].", &base, "/issuers/0", &["issuer_id", "issuer_name", "keys"][..]),
        ("error-structure-key-as-array", "ok-basic with its first issuer's key written as the array of its six values.", &base, "/issuers/0/keys/0", KEY),
        ("error-structure-public-key-as-array", "ok-basic with its first issuer's public_key written as [kty, crv, x, y].", &base, "/issuers/0/keys/0/public_key", &["kty", "crv", "x", "y"][..]),
        ("error-structure-authority-as-array", "ok-policy-authorities with its authority written as [authority_id, authority_name, keys].", &one_authority, "/policy_authorities/0", &["authority_id", "authority_name", "keys"][..]),
        ("error-structure-authority-key-as-array", "ok-policy-authorities with its authority's key P written as the array of its six values.", &one_authority, "/policy_authorities/0/keys/0", KEY),
    ] {
        out.push(err(id, description, json!({"text": text_of(&as_array(document, pointer, fields))}), "trust_store.structure"));
    }
    json!({
        "description": "VMR trust store loader vectors, v0.1 (trust-store format v0.1, §2, §3, §5). A conforming loader accepts each `ok` store with the expected canonical identity (sha256 of the JCS form with issuers sorted by issuer_id, policy authorities by authority_id in code-point order, each entry's keys by key_id, and an empty policy_authorities omitted), and rejects each `error` store with the expected kind. Input bytes: `text` as UTF-8, or `hex`; then `append_spaces` ASCII spaces if present. Generated by the vmr-verify crate's vector generator (VMR_WRITE_VECTORS=1 cargo test -p vmr-verify --test vectors -- --ignored) - never hand-edited.",
        "vector_version": "0.1",
        "cases": out,
    })
}

/// The canonical identity from the spec's rule (§5), independently of
/// TrustStore::sha256: issuers sorted by issuer_id, policy authorities by
/// authority_id in code-point order (`str` compares the bytes of UTF-8,
/// which is code-point order), each entry's keys by key_id, an empty
/// policy_authorities omitted; JCS; SHA-256.
fn canonical_hash(doc: &Value) -> String {
    let mut d = doc.clone();
    for (list, id) in [("issuers", "issuer_id"), ("policy_authorities", "authority_id")] {
        if let Some(entries) = d.get_mut(list).and_then(Value::as_array_mut) {
            entries.sort_by(|a, b| a[id].as_str().cmp(&b[id].as_str()));
            for e in entries.iter_mut() {
                e["keys"].as_array_mut().unwrap().sort_by(|a, b| a["key_id"].as_str().cmp(&b["key_id"].as_str()));
            }
        }
    }
    if d.get("policy_authorities").and_then(Value::as_array).is_some_and(Vec::is_empty) {
        d.as_object_mut().unwrap().remove("policy_authorities");
    }
    vmr_record::hash::format_hash(&vmr_record::hash::sha256(vmr_record::canonical::jcs(&d).as_bytes()))
}

/// A policy authority entry holding `labels`' keys, each key object exactly
/// as [`Entry::new`] shapes an issuer's (software, 2026-01-01 .. 2027-01-01).
fn authority_entry(id: &str, labels: &[&'static str]) -> Value {
    let keys: Vec<Value> =
        labels.iter().map(|l| store_json(&[entry(VECTOR_ISSUER, l)])["issuers"][0]["keys"][0].clone()).collect();
    json!({"authority_id": id, "authority_name": format!("{id} (test-only)"), "keys": keys})
}

/// The bytes a vector input stands for: `text` (UTF-8) or `hex`, then
/// `append_spaces` spaces.
pub fn input_bytes(input: &Value) -> Vec<u8> {
    let mut bytes = match (input.get("text"), input.get("hex")) {
        (Some(t), None) => t.as_str().unwrap().as_bytes().to_vec(),
        (None, Some(h)) => hex::decode(h.as_str().unwrap()).unwrap(),
        other => panic!("an input has exactly one of text / hex: {other:?}"),
    };
    if let Some(n) = input.get("append_spaces") {
        bytes.resize(bytes.len() + n.as_u64().unwrap() as usize, b' ');
    }
    bytes
}
