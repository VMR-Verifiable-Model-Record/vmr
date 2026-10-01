// tests/parity.rs — the expected answers js/test/parity.test.mjs holds the
// built vmr-check.wasm to (docs/BROWSER.md, "Proof").
//
// For every published vector the browser can be asked about, this computes
// what the native libraries answer, and tests/data/parity.json pins it:
//
//   verify/          the SHA-256 of vmr-verify's own report JSON
//                    (`VerificationReport::to_json`), computed here with the
//                    library directly, not through vmr-check;
//   trust-store/     each store with the record vector: the loader's refusal
//                    id, or the report's SHA-256;
//   policy/cases     each case's report with its pack, the verifiable records
//                    re-signed with key A first (which the parity file
//                    carries: the wasm test cannot sign);
//   policy/pack-loader, policy/pack-signature
//                    the refusal id, or the report's SHA-256;
//   model-hash/      the records `checkFiles` is asked about: the general
//                    record vector with the case's members as its components.
//
// The pack categories go through vmr-check's native build (its pack
// evaluator is the policy hook); tests/cli_agreement.rs holds those reports
// equal to `vmr record verify --json`'s. Regenerate, and review the diff like
// a vector change, with
//   VMR_WRITE_PARITY=1 cargo test -p vmr-check --test parity -- --ignored

mod common;

use common::*;
use serde_json::{json, Map, Value};
use vmr_check::api::{self, VerifyRequest};
use vmr_record::record::StateComponent;
use vmr_record::timestamp::Timestamp;
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

const PARITY: &str = "tests/data/parity.json";

/// The report SHA-256 or the refusal id of a vmr-check verify answer.
fn outcome(answer: &Value) -> Value {
    match answer.get("report_json").and_then(Value::as_str) {
        Some(report) => json!({ "report_sha256": sha256_hex(report) }),
        None => json!({ "refusal": answer["refusal"]["id"] }),
    }
}

fn generate() -> Value {
    let mut verify = Map::new();
    for c in cases("verify/cases.json") {
        let store = TrustStore::from_json(&vector_store(c["trust_store"].as_str().unwrap())).unwrap();
        let previous: Vec<Vec<u8>> = c["previous"].as_array().unwrap().iter().map(input_bytes).collect();
        let refs: Vec<&[u8]> = previous.iter().map(Vec::as_slice).collect();
        let opts = VerifyOptions::new(Timestamp::parse(c["evaluation_time"].as_str().unwrap()).unwrap())
            .with_previous(&refs)
            .require_complete_lineage(c["require_complete_lineage"].as_bool().unwrap());
        let report = Verifier::new(store).verify(&input_bytes(&c["input"]), &opts).to_json().unwrap();
        verify.insert(c["id"].as_str().unwrap().into(), Value::from(sha256_hex(&report)));
    }

    let base = base_case();
    let base_record = input_bytes(&base["input"]);
    let base_at = unix(base["evaluation_time"].as_str().unwrap());
    let ts_basic = vector_store("ts-basic");

    let mut trust_store = Map::new();
    for c in cases("trust-store/cases.json") {
        let store = input_bytes(&c["input"]);
        let answer = api::verify(&VerifyRequest { record: &base_record, trust_store: &store, at: Some(base_at), ..Default::default() });
        trust_store.insert(c["id"].as_str().unwrap().into(), outcome(&answer));
    }

    let mut policy = Map::new();
    for c in cases("policy/cases.json") {
        let id = c["id"].as_str().unwrap();
        let text = c["record"]["text"].as_str().unwrap();
        let record = if c["verifiable"] == true {
            let mut r = vmr_record::Record::from_json(text).unwrap_or_else(|e| panic!("{id}: {e}"));
            reissue_with(&mut r, KEY_A);
            Some(r.to_json().unwrap())
        } else {
            None
        };
        let previous: Vec<Vec<u8>> = c["context"]["predecessors"]
            .as_array()
            .map(|ps| ps.iter().map(|p| p["text"].as_str().unwrap().as_bytes().to_vec()).collect())
            .unwrap_or_default();
        let answer = api::verify(&VerifyRequest {
            record: record.as_deref().unwrap_or(text).as_bytes(),
            trust_store: &ts_basic,
            at: Some(unix(c["evaluation_time"].as_str().unwrap())),
            pack: Some(c["pack"]["text"].as_str().unwrap().as_bytes()),
            previous: previous.iter().map(Vec::as_slice).collect(),
            ..Default::default()
        });
        let mut entry = outcome(&answer);
        if let Some(record) = record {
            entry["record"] = Value::from(record);
        }
        policy.insert(id.into(), entry);
    }

    let mut pack_loader = Map::new();
    for c in vector_file("policy/pack-loader.json")["cases"].as_array().unwrap() {
        let pack = input_bytes(&c["pack"]);
        let answer = api::verify(&VerifyRequest {
            record: &base_record,
            trust_store: &ts_basic,
            at: Some(base_at),
            pack: Some(&pack),
            ..Default::default()
        });
        pack_loader.insert(c["id"].as_str().unwrap().into(), outcome(&answer));
    }

    let mut pack_signature = Map::new();
    for c in vector_file("policy/pack-signature.json")["cases"].as_array().unwrap() {
        let authorities = c["authority_store"]["text"].as_str().map(str::as_bytes);
        let answer = api::verify(&VerifyRequest {
            record: &base_record,
            trust_store: c["trust_store"]["text"].as_str().unwrap().as_bytes(),
            at: Some(unix(c["evaluation_time"].as_str().unwrap())),
            pack: Some(c["pack"]["text"].as_str().unwrap().as_bytes()),
            authority_store: authorities,
            require_signed_pack: c["require_signed_pack"].as_bool().unwrap(),
            ..Default::default()
        });
        pack_signature.insert(c["id"].as_str().unwrap().into(), outcome(&answer));
    }

    let mut model_hash = Map::new();
    model_hash.insert("base".into(), Value::from(general_vector().to_json().unwrap()));
    for c in cases("model-hash/cases.json") {
        let id = c["id"].as_str().unwrap();
        let sets: Vec<(String, Vec<Member>)> = match c["kind"].as_str().unwrap() {
            "named-set-digest" => vec![(id.to_string(), members(&c["members"]))],
            "named-set-digests" => c["sets"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, set)| (format!("{id}/{name}"), members(set)))
                .collect(),
            "set-refused" => vec![(
                id.to_string(),
                c["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| (n.as_str().unwrap().to_string(), format!("sha256:{}", "00".repeat(32)), 0))
                    .collect(),
            )],
            // Names are checked against the base record; named-set-v1
            // training records are not files (spec §8.2).
            "name" | "named-set-records" => vec![],
            other => panic!("{id}: a model-hash kind this generator does not know: {other}"),
        };
        for (key, set) in sets {
            model_hash.insert(key.clone(), Value::from(record_listing(&key, &set)));
        }
    }

    json!({
        "description": "What the native libraries answer for every published vector vmr-check is asked about: generated by vmr/crates/vmr-check/tests/parity.rs, read by js/test/parity.test.mjs. Report hashes are the SHA-256 of vmr-verify's report JSON (VerificationReport::to_json), lower-case hex.",
        "parity_version": "0.1",
        "verify": verify,
        "trust_store": trust_store,
        "policy": policy,
        "pack_loader": pack_loader,
        "pack_signature": pack_signature,
        "model_hash": model_hash,
    })
}

/// A member of a model-hash case: name, `sha256:` digest, size.
type Member = (String, String, u64);

/// A model-hash case's members.
fn members(v: &Value) -> Vec<Member> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|m| {
            let size = m["bytes_hex"].as_str().unwrap().len() as u64 / 2;
            (m["name"].as_str().unwrap().to_string(), format!("sha256:{}", m["sha256"].as_str().unwrap()), size)
        })
        .collect()
}

/// The general record vector listing `set` as its components, in the given
/// order, its two digests the named-set digest when the set is one (else
/// left as they were). Unsigned: `checkFiles` reads a record, it does not
/// verify it.
fn record_listing(key: &str, set: &[Member]) -> String {
    let mut r = general_vector();
    r.model_identity.learned_state_components =
        set.iter().map(|(name, hash, size)| StateComponent { name: name.clone(), hash: hash.clone(), size_bytes: *size }).collect();
    let members: Vec<(&str, [u8; 32])> =
        set.iter().map(|(n, h, _)| (n.as_str(), vmr_record::hash::parse_hash(h).unwrap())).collect();
    if let Ok(digest) = vmr_record::named_set::named_set_digest(&members) {
        let digest = vmr_record::hash::format_hash(&digest);
        r.model_identity.learned_state_hash = digest.clone();
        r.model_identity.model_hash = digest;
    }
    let text = r.to_json().unwrap();
    vmr_record::Record::from_json(&text).unwrap_or_else(|e| panic!("{key}: the record does not read back: {e}"));
    text
}

fn pretty(v: &Value) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).unwrap())
}

#[test]
fn the_parity_file_is_what_the_native_libraries_answer() {
    let committed = std::fs::read_to_string(PARITY).expect("tests/data/parity.json (VMR_WRITE_PARITY=1 writes it)");
    assert!(
        committed == pretty(&generate()),
        "tests/data/parity.json differs from what the native libraries answer: regenerate it with \
         VMR_WRITE_PARITY=1 cargo test -p vmr-check --test parity -- --ignored, and review the diff"
    );
}

#[test]
fn every_verify_vectors_report_is_the_librarys_bytes_through_vmr_check() {
    // `report_json` is the library's report unchanged: vmr-check's verify
    // gives, for every verification vector, the SHA-256 the library gives.
    let parity: Value = serde_json::from_str(&std::fs::read_to_string(PARITY).unwrap()).unwrap();
    let mut n = 0;
    for c in cases("verify/cases.json") {
        let previous: Vec<Vec<u8>> = c["previous"].as_array().unwrap().iter().map(input_bytes).collect();
        let answer = api::verify(&VerifyRequest {
            record: &input_bytes(&c["input"]),
            trust_store: &vector_store(c["trust_store"].as_str().unwrap()),
            at: Some(unix(c["evaluation_time"].as_str().unwrap())),
            previous: previous.iter().map(Vec::as_slice).collect(),
            require_complete_lineage: c["require_complete_lineage"].as_bool().unwrap(),
            ..Default::default()
        });
        let id = c["id"].as_str().unwrap();
        assert_eq!(sha256_hex(answer["report_json"].as_str().unwrap()), parity["verify"][id], "{id}");
        assert_eq!(answer["at_source"], "caller");
        assert_eq!(answer["policy"], Value::Null);
        n += 1;
    }
    assert!(n >= 400, "{n}");
}

#[test]
#[ignore = "writes tests/data/parity.json; run with VMR_WRITE_PARITY=1"]
#[allow(clippy::disallowed_methods)] // the generator's opt-in switch
fn write_parity_file() {
    if std::env::var("VMR_WRITE_PARITY").as_deref() == Ok("1") {
        std::fs::write(PARITY, pretty(&generate())).unwrap();
    }
}
