// tests/api.rs — vmr-check's calls, natively: inspect, storeForEmbeddedKey,
// checkFiles, verify's refusals and its two report forms (docs/BROWSER.md).
// The same behaviour through the built module is js/test/api.test.mjs.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_check::api::{self, VerifyRequest};
use vmr_check::files::{GivenFile, GivenName};
use vmr_check::refusal;

fn base_record() -> Vec<u8> {
    input_bytes(&base_case()["input"])
}

fn base_at() -> i64 {
    unix(base_case()["evaluation_time"].as_str().unwrap())
}

fn verify(record: &[u8], store: &[u8]) -> Value {
    api::verify(&VerifyRequest { record, trust_store: store, at: Some(base_at()), ..Default::default() })
}

/// The vector key's fingerprint, as its issuer would publish it.
const VECTOR_FINGERPRINT: &str = "HyoP YysS FOQ5 d6x6 4H8_ pHdd";

#[test]
fn version_names_this_build_and_the_record_format() {
    assert_eq!(api::version(), json!({ "vmr": env!("CARGO_PKG_VERSION"), "record_format": "0.1" }));
    // The record format this build reads is the record vector's.
    assert_eq!(vmr_check::RECORD_FORMAT, general_vector().record_version);
}

#[test]
fn inspect_shows_a_valid_record_and_its_fingerprint_and_says_its_signature_matches() {
    let out = api::inspect(&base_record());
    assert_eq!(out["issuer"], json!({ "name": "New Clark City Fab Operator", "id": "did:web:factory-operator.ph" }));
    assert_eq!(
        out["signing_key_id"],
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg"
    );
    assert_eq!(out["fingerprint"], VECTOR_FINGERPRINT);
    assert_eq!(out["integrity_against_embedded_key"], "matches");
    assert_eq!(out["declared"]["record_id"], "urn:uuid:2b6a0c48-9f21-4f3a-8c51-1d0b4a7e9c00");
    assert!(out["declared"].get("signature").is_none(), "the signature section is not a declaration");
    // Never "verified": the word appears nowhere in what inspect says.
    assert!(!out.to_string().contains("verified"), "{out}");
}

fn tampered_record() -> Vec<u8> {
    let mut r: vmr_record::Record = serde_json::from_slice(&base_record()).unwrap();
    r.issuer.issuer_name = "Evil \u{202e}Corp".into();
    r.to_json().unwrap().into_bytes()
}

#[test]
fn inspect_of_a_tampered_record_says_its_signature_does_not_match_and_escapes_what_it_shows() {
    let out = api::inspect(&tampered_record());
    assert_eq!(out["integrity_against_embedded_key"], "does_not_match");
    assert_eq!(out["issuer"]["name"], "Evil \\u{202e}Corp");
    assert_eq!(out["declared"]["issuer"]["issuer_name"], "Evil \\u{202e}Corp");

    // A key that is not a point on P-256 cannot be read at all.
    let mut r: vmr_record::Record = serde_json::from_slice(&base_record()).unwrap();
    r.issuer.public_key.y = r.issuer.public_key.x.clone();
    assert_eq!(api::inspect(r.to_json().unwrap().as_bytes())["integrity_against_embedded_key"], "unreadable");

    // Bytes that are no record: the verifier's own first failing check.
    let out = api::inspect(b"not a record");
    assert_eq!(out["refusal"]["id"], "input.form", "{out}");
    assert_eq!(out["refusal"]["input"], "record");
    assert_eq!(api::inspect(b"{\"record_version\": 1}")["refusal"]["input"], "record");
}

// ---------------------------------------------------------------------------
//  storeForEmbeddedKey (QA S4: the reader's decision is an input)
// ---------------------------------------------------------------------------

#[test]
fn a_store_for_the_embedded_key_at_the_records_level_lets_the_record_verify() {
    let store = api::store_for_embedded_key(&base_record(), VECTOR_FINGERPRINT, Some("software"));
    let text = store["trust_store"].as_str().unwrap();
    let parsed = vmr_verify::TrustStore::from_json(text.as_bytes()).unwrap();
    assert_eq!((parsed.issuer_count(), parsed.key_count()), (1, 1));
    let doc = parsed.to_document();
    assert_eq!(doc.issuers[0].issuer_id, "did:web:factory-operator.ph");
    assert_eq!(doc.issuers[0].keys[0].valid_from, "2026-09-10T00:00:00Z", "the record's issued_at");
    let out = verify(&base_record(), text.as_bytes());
    assert_eq!(out["report"]["verdict"], "pass", "{}", out["report_json"]);
    // The fingerprint compares with its spaces removed, however it was typed.
    for typed in ["HyoPYysSFOQ5d6x64H8_pHdd", " HyoP  YysS FOQ5 d6x6 4H8_ pHdd "] {
        assert!(api::store_for_embedded_key(&base_record(), typed, Some("software"))["trust_store"].is_string(), "{typed}");
    }
}

#[test]
fn a_store_is_refused_unless_the_reader_s_fingerprint_is_the_key_s_and_the_record_matches_its_key() {
    for wrong in ["", "HyoP YysS FOQ5 d6x6 4H8_ pHdD", "hyop yyss foq5 d6x6 4h8_ phdd", "HyoP YysS FOQ5 d6x6 4H8_", &format!("{VECTOR_FINGERPRINT} cHp7")] {
        let out = api::store_for_embedded_key(&base_record(), wrong, Some("software"));
        assert_eq!(out["refusal"]["id"], refusal::STORE_FINGERPRINT_MISMATCH, "{wrong:?}: {out}");
        assert_eq!(out["refusal"]["input"], "expected_fingerprint");
    }
    // A record its own key does not match is refused even with the right
    // fingerprint: trusting the key would not make that record verify.
    let out = api::store_for_embedded_key(&tampered_record(), VECTOR_FINGERPRINT, Some("software"));
    assert_eq!(out["refusal"]["id"], refusal::STORE_INTEGRITY, "{out}");
    assert_eq!(out["refusal"]["input"], "record");
}

#[test]
fn without_a_level_the_store_trusts_the_key_at_self_only_and_the_record_cannot_raise_it() {
    // The record declares "software"; a store made without a level trusts
    // its key up to "self", the most conservative, so verification fails
    // on the attestation check: the record never decides its own trust.
    let text = api::store_for_embedded_key(&base_record(), VECTOR_FINGERPRINT, None)["trust_store"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(text.contains("\"attestation_level\": \"self\""), "{text}");
    let out = verify(&base_record(), text.as_bytes());
    assert_eq!(out["report"]["verdict"], "fail");
    assert_eq!(out["report"]["failure"]["check"], "trust.attestation", "{}", out["report_json"]);

    let out = api::store_for_embedded_key(&base_record(), VECTOR_FINGERPRINT, Some("platinum"));
    assert_eq!(out["refusal"]["id"], refusal::ATTESTATION_LEVEL_UNKNOWN);
    assert_eq!(api::store_for_embedded_key(b"", VECTOR_FINGERPRINT, None)["refusal"]["input"], "record");
}

// ---------------------------------------------------------------------------
//  verify
// ---------------------------------------------------------------------------

#[test]
fn verify_refuses_a_store_a_time_and_a_pack_it_cannot_use_with_the_librarys_ids() {
    let out = verify(&base_record(), b"{");
    assert_eq!((&out["refusal"]["id"], &out["refusal"]["input"]), (&json!("trust_store.syntax"), &json!("trust_store")));
    for at in [None, Some(i64::MAX), Some(-62_167_219_201)] {
        let out = api::verify(&VerifyRequest {
            record: &base_record(),
            trust_store: &vector_store("ts-basic"),
            at,
            ..Default::default()
        });
        assert_eq!(out["refusal"]["id"], refusal::EVALUATION_TIME_RANGE, "{at:?}");
    }
    let out = api::verify(&VerifyRequest {
        record: &base_record(),
        trust_store: &vector_store("ts-basic"),
        at: Some(base_at()),
        pack: Some(b"[]"),
        ..Default::default()
    });
    assert_eq!(out["refusal"]["input"], "pack", "{out}");
    assert!(out["refusal"]["id"].as_str().unwrap().starts_with("policy_pack."), "{out}");
}

#[test]
fn the_report_is_the_librarys_json_once_byte_for_byte_and_once_display_safe() {
    // A record whose claims carry a bidi override: the library writes it as
    // a JSON escape in report_json, which a parser turns back into the raw
    // character; `report` shows it as visible text.
    let out = verify(&tampered_record(), &vector_store("ts-basic"));
    let raw: Value = serde_json::from_str(out["report_json"].as_str().unwrap()).unwrap();
    assert_eq!(raw["record"]["issuer_name"], "Evil \u{202e}Corp");
    assert_eq!(out["report"]["record"]["issuer_name"], "Evil \\u{202e}Corp");
    assert_eq!(vmr_check::safe::display_safe_value(raw), out["report"]);
    assert_eq!((&out["policy"], &out["at_source"]), (&Value::Null, &json!("caller")));
}

#[test]
fn verify_with_a_pack_returns_its_evaluation_as_policy() {
    let pack = std::fs::read(repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json")).unwrap();
    let out = api::verify(&VerifyRequest {
        record: &base_record(),
        trust_store: &vector_store("ts-basic"),
        at: Some(base_at()),
        pack: Some(&pack),
        ..Default::default()
    });
    assert_eq!(out["policy"]["state"], "evaluated", "{out}");
    assert_eq!(out["policy"], out["report"]["policy"]["evaluation"]);
}

#[test]
fn verify_says_whether_the_record_is_accepted_as_the_cli_s_exit_code_does() {
    // QA S3: 0 verified (and accepted), 4 verified but the pack does not
    // accept it, 3 failed.
    let passed = verify(&base_record(), &vector_store("ts-basic"));
    assert_eq!((&passed["accepted"], &passed["outcome"]), (&json!(true), &json!("verified")));

    let failed = verify(&tampered_record(), &vector_store("ts-basic"));
    assert_eq!((&failed["accepted"], &failed["outcome"]), (&json!(false), &json!("failed")));

    let case = cases("policy/cases.json")
        .into_iter()
        .find(|c| c["verifiable"] == true && c["expected"]["overall"] == "fail" && c["context"].is_null())
        .unwrap();
    let mut r = vmr_record::Record::from_json(case["record"]["text"].as_str().unwrap()).unwrap();
    reissue_with(&mut r, KEY_A);
    let out = api::verify(&VerifyRequest {
        record: r.to_json().unwrap().as_bytes(),
        trust_store: &vector_store("ts-basic"),
        at: Some(unix(case["evaluation_time"].as_str().unwrap())),
        pack: Some(case["pack"]["text"].as_str().unwrap().as_bytes()),
        ..Default::default()
    });
    assert_eq!(out["report"]["verdict"], "pass", "{}", case["id"]);
    assert_eq!((&out["accepted"], &out["outcome"]), (&json!(false), &json!("verified_not_accepted")));
}

#[test]
fn verify_names_the_trusted_key_s_fingerprint_as_the_cli_prints_it() {
    // QA N5: the key the trust store trusted, not the one the record embeds.
    assert_eq!(verify(&base_record(), &vector_store("ts-basic"))["fingerprint"], VECTOR_FINGERPRINT);
    // No trusted issuer, no fingerprint.
    assert_eq!(verify(&base_record(), &vector_store("ts-empty"))["fingerprint"], Value::Null);
}

// ---------------------------------------------------------------------------
//  checkFiles
// ---------------------------------------------------------------------------

/// The general record vector's components as the files a reader holds.
fn held_files() -> (Vec<u8>, Vec<GivenFile>) {
    let r = general_vector();
    let files = r
        .model_identity
        .learned_state_components
        .iter()
        .map(|c| GivenFile::named(&c.name, &c.hash, c.size_bytes))
        .collect();
    (r.to_json().unwrap().into_bytes(), files)
}

fn zero(name: &str) -> GivenFile {
    GivenFile::named(name, &format!("sha256:{}", "00".repeat(32)), 0)
}

#[test]
fn check_files_matches_every_listed_file_and_computes_both_hashes() {
    let (record, files) = held_files();
    let out = api::check_files(&record, &files);
    let r = general_vector();
    // The general vector lists every file, so both hashes are the digest of
    // its components (spec §7.3: "When the components are every file, it
    // equals learned_state_hash").
    for hash in ["learned_state_hash", "model_hash"] {
        assert_eq!(out[hash]["computed"], out[hash]["listed"], "{hash}: {out}");
        assert_eq!(out[hash]["matches"], true, "{hash}");
    }
    assert_eq!(out["model_hash"]["listed"], r.model_identity.model_hash.as_str());
    for (i, f) in out["files"].as_array().unwrap().iter().enumerate() {
        let c = &r.model_identity.learned_state_components[i];
        assert_eq!(f, &json!({ "index": i, "name": c.name, "shown": c.name, "status": "match", "given_index": i }));
    }
    assert_eq!((&out["extra"], &out["refused_names"]), (&json!([]), &json!([])));
}

#[test]
fn a_record_that_lists_some_files_is_checked_against_its_learned_state_hash_and_all_files_against_its_model_hash() {
    // QA S2, spec §7.3: an issuer MAY list only the files it names as the
    // learned state; learned_state_hash is the digest of those, model_hash
    // the digest of every file.
    let full = general_vector();
    let mut r = full.clone();
    r.model_identity.learned_state_components.truncate(2);
    let members: Vec<(String, [u8; 32])> = r
        .model_identity
        .learned_state_components
        .iter()
        .map(|c| (c.name.clone(), vmr_record::hash::parse_hash(&c.hash).unwrap()))
        .collect();
    let listed = vmr_record::hash::format_hash(&vmr_record::named_set::named_set_digest(&members).unwrap());
    r.model_identity.learned_state_hash = listed.clone();
    let record = r.to_json().unwrap().into_bytes();
    let (_, all) = held_files();

    let out = api::check_files(&record, &all);
    assert_eq!(out["learned_state_hash"], json!({ "listed": listed, "computed": listed, "matches": true }));
    assert_eq!(out["model_hash"]["computed"], full.model_identity.model_hash.as_str());
    assert_eq!(out["model_hash"]["matches"], true, "{out}");
    assert_eq!(out["extra"].as_array().unwrap().len(), 2);

    // Only the listed files held: the learned state checks, the model does not.
    let out = api::check_files(&record, &all[..2]);
    assert_eq!(out["learned_state_hash"]["matches"], true);
    assert_eq!(out["model_hash"]["matches"], false);
}

#[test]
fn an_extra_gitattributes_is_extra_changes_the_model_hash_and_not_the_learned_state() {
    let (record, mut files) = held_files();
    let clean = api::check_files(&record, &files);
    files.insert(0, GivenFile::named(".gitattributes", &format!("sha256:{}", "ab".repeat(32)), 10));
    let out = api::check_files(&record, &files);
    assert_eq!(out["extra"], json!([{ "index": 0, "name": ".gitattributes", "shown": ".gitattributes" }]));
    assert_eq!(out["learned_state_hash"], clean["learned_state_hash"]);
    // Every file given is in the model hash: the folder holds a file the
    // model is not distributed as (spec §7.2), so it does not match.
    assert_eq!(out["model_hash"]["matches"], false);
    assert_eq!(out["files"][0]["given_index"], 1);
}

#[test]
fn a_missing_file_leaves_no_learned_state_hash_and_a_changed_one_is_a_mismatch() {
    let (record, files) = held_files();
    let first = files[0].clone();
    let first_name = match &first.name {
        GivenName::Text(name) => name.clone(),
        GivenName::NotUnicode(_) => unreachable!(),
    };

    let out = api::check_files(&record, &files[1..]);
    assert_eq!(out["learned_state_hash"]["computed"], Value::Null);
    assert_eq!(out["learned_state_hash"]["matches"], false);
    assert_eq!(
        out["files"][0],
        json!({ "index": 0, "name": first_name, "shown": first_name, "status": "missing", "given_index": null })
    );

    let mut changed = files.clone();
    changed[0].sha256 = format!("sha256:{}", "cd".repeat(32));
    let out = api::check_files(&record, &changed);
    assert_eq!(out["files"][0]["status"], "mismatch");
    assert_eq!(out["learned_state_hash"]["matches"], false);
    assert!(out["learned_state_hash"]["computed"].is_string(), "every listed file is there, so a hash is computed");

    let mut resized = files.clone();
    resized[0].size = Some(first.size.unwrap() + 1);
    assert_eq!(api::check_files(&record, &resized)["files"][0]["status"], "mismatch");
}

#[test]
fn each_entry_carries_the_exact_name_the_shown_name_and_its_index() {
    // QA S1: a page matches by index or exact name and shows only `shown`.
    let (record, mut files) = held_files();
    files.push(zero("dir\\w.bin"));
    files.push(zero("zero\u{200b}width"));
    files.push(zero("a//b"));
    let out = api::check_files(&record, &files);
    let n = files.len();
    assert_eq!(
        out["extra"],
        json!([
            { "index": n - 3, "name": "dir\\w.bin", "shown": "dir\\\\w.bin" },
            { "index": n - 2, "name": "zero\u{200b}width", "shown": "zero\\u{200b}width" },
        ])
    );
    assert_eq!(out["refused_names"], json!([{ "index": n - 1, "name": "a//b", "shown": "a//b", "reason": "empty-segment" }]));
}

#[test]
fn a_name_spec_7_2_refuses_is_refused_with_its_reason_and_names_match_exactly() {
    let (record, mut files) = held_files();
    for name in ["a//b", "../weights.bin", "./x", "", "/abs"] {
        files.push(zero(name));
    }
    // Case and separators are part of the name: this is extra, not a match.
    let upper = match &files[0].name {
        GivenName::Text(name) => name.to_uppercase(),
        GivenName::NotUnicode(_) => unreachable!(),
    };
    files.push(zero(&upper));
    let out = api::check_files(&record, &files);
    let reasons: Vec<(u64, &str)> = out["refused_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["index"].as_u64().unwrap(), r["reason"].as_str().unwrap()))
        .collect();
    assert_eq!(reasons, [(4, "empty-segment"), (5, "dotdot-segment"), (6, "dot-segment"), (7, "empty"), (8, "empty-segment")]);
    assert_eq!(out["extra"][0]["name"], upper.as_str());
    assert_eq!(out["learned_state_hash"]["matches"], true);
    // A refused name leaves the given set without a digest (§7.2).
    assert_eq!(out["model_hash"]["computed"], Value::Null);
}

#[test]
fn a_name_given_twice_is_refused_at_both_indexes_and_neither_copy_is_used() {
    // QA N4: §7.2's not-ascending, with both positions; the listed file it
    // names is undecided, never matched against one copy.
    let (record, mut files) = held_files();
    let mut copy = files[1].clone();
    copy.sha256 = format!("sha256:{}", "ef".repeat(32));
    files.push(copy);
    let n = files.len() - 1;
    let out = api::check_files(&record, &files);
    let name = out["files"][1]["name"].clone();
    assert_eq!(
        out["refused_names"],
        json!([
            { "index": 1, "name": name, "shown": name, "reason": "not-ascending", "indexes": [1, n] },
            { "index": n, "name": name, "shown": name, "reason": "not-ascending", "indexes": [1, n] },
        ])
    );
    assert_eq!(out["files"][1]["status"], "duplicate");
    assert_eq!(out["files"][1]["given_index"], Value::Null);
    assert_eq!(out["learned_state_hash"]["computed"], Value::Null);
    assert_eq!(out["model_hash"]["computed"], Value::Null);
}

#[test]
fn a_name_that_is_not_unicode_is_refused_as_that_one_name() {
    // QA N1: a lone surrogate (JavaScript can hold one) refuses that name,
    // never the whole call.
    let (record, mut files) = held_files();
    files.push(GivenFile { name: GivenName::NotUnicode(vec![0x61, 0xD800]), sha256: format!("sha256:{}", "00".repeat(32)), size: Some(0) });
    let out = api::check_files(&record, &files);
    assert_eq!(out["refused_names"], json!([{ "index": 4, "name": null, "shown": "a\\u{d800}", "reason": "not-unicode" }]));
    assert_eq!(out["learned_state_hash"]["matches"], true);
}

#[test]
fn check_files_refuses_bad_digests_sizes_and_an_engine_profile_record() {
    let (record, files) = held_files();
    for bad in ["SHA256:00", "sha256:ABCD", &format!("sha256:{}", "AB".repeat(32)), &format!("sha256:{}", "a".repeat(63))] {
        let mut f = files.clone();
        f[0].sha256 = bad.to_string();
        assert_eq!(api::check_files(&record, &f)["refusal"]["id"], refusal::CHECK_FILES_DIGEST, "{bad}");
    }
    for size in [None, Some(1u64 << 53)] {
        let mut f = files.clone();
        f[0].size = size;
        assert_eq!(api::check_files(&record, &f)["refusal"]["id"], refusal::CHECK_FILES_SIZE, "{size:?}");
    }
    // The engine profile's model hash is the engine state's, not a digest of
    // files: unsupported, never "mismatch".
    let out = api::check_files(&base_record(), &files);
    assert_eq!(out["refusal"]["id"], refusal::CHECK_FILES_UNSUPPORTED_PROFILE, "{out}");
    assert_eq!(api::check_files(b"x", &files)["refusal"]["input"], "record");
}

// ---------------------------------------------------------------------------
//  The framed entry point the module exports
// ---------------------------------------------------------------------------

fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

#[test]
fn a_framed_verify_request_gives_the_direct_calls_answer() {
    let store = vector_store("ts-basic");
    let header = format!("{{\"at\":{},\"previous\":0,\"pack\":false,\"authority_store\":false}}", base_at());
    let answer: Value =
        serde_json::from_slice(&api::call(api::OP_VERIFY, &framed(&[header.as_bytes(), &base_record(), &store])))
            .unwrap();
    assert_eq!(answer, verify(&base_record(), &store));
    // The two forms of a given name.
    let files = r#"{"files":[{"name":"a","sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0},{"name_utf16":[98,56320],"sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0}]}"#;
    let (record, _) = held_files();
    let answer: Value = serde_json::from_slice(&api::call(api::OP_CHECK_FILES, &framed(&[files.as_bytes(), &record]))).unwrap();
    assert_eq!(answer["extra"][0]["name"], "a");
    assert_eq!(answer["refused_names"][0]["shown"], "b\\u{dc00}");
    // A header that does not match the frames, an unknown call, broken framing.
    for (op, request) in [
        (api::OP_VERIFY, framed(&[b"{\"previous\":2}", &base_record(), &store])),
        (99, framed(&[b"{}", b"x"])),
        (api::OP_INSPECT, vec![9, 0, 0, 0, b'{']),
        (api::OP_INSPECT, framed(&[b"[]", b"x"])),
        (api::OP_CHECK_FILES, framed(&[b"{}", b"x"])),
    ] {
        let answer: Value = serde_json::from_slice(&api::call(op, &request)).unwrap();
        assert_eq!(answer["refusal"]["id"], refusal::REQUEST_MALFORMED, "{op}: {answer}");
    }
}
