// tests/pack_signature_vectors.rs — the pack-signature vectors
// (docs/TASKS.md 6.16; docs/dev/task-6.16.md A16-22, A16-24). The committed
// file specs/test-vectors/policy/pack-signature.json is written only by
// tests/common/generate_pack_signature.rs:
//
//     VMR_WRITE_VECTORS=1 cargo test -p vmr-cli --test pack_signature_vectors -- --ignored
//
// and pack_signature_vectors_are_reproducible fails if the committed bytes
// differ from a fresh generation. Here every case is replayed through the
// libraries, in the order of specs/trust-store-format-v0.1.md §4.2: vmr-policy
// loads the pack and checks its signature, vmr-verify loads the stores and
// decides whether the key may speak for the pack. The same cases go through
// the `vmr` binary, in both builds, in tests/cross_impl/policy_vectors.rs.

mod common;
#[path = "common/generate_pack_signature.rs"]
mod generate;

use common::repo;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use vmr_record::timestamp::Timestamp;
use vmr_verify::TrustStore;

fn read(rel: &str) -> String {
    let path = repo().join("specs/test-vectors").join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()))
}

fn cases() -> Vec<Value> {
    let doc: Value = serde_json::from_str(&read("policy/pack-signature.json")).unwrap();
    assert_eq!(doc["vector_version"], "0.1");
    doc["cases"].as_array().unwrap().clone()
}

#[test]
fn pack_signature_vectors_are_reproducible() {
    for (rel, contents) in generate::generate() {
        assert!(read(&rel) == contents, "{rel} differs from a fresh generation: regenerate with VMR_WRITE_VECTORS=1, in its own commit");
    }
}

/// What the libraries decide for a case, in trust-store format §4.2's order:
/// `Ok(state)` for an evaluated pack, `Err(identifier)` for a refusal. The
/// identifiers of `--require-signed-pack` and of an authority store that
/// lists issuers, or holds an issuer's key, are the reference CLI's (§4.2's
/// table); every other one comes from the library that refuses.
fn replay(case: &Value) -> Result<Value, String> {
    let id = case["id"].as_str().unwrap();
    let text = |member: &str| case[member]["text"].as_str().unwrap_or_else(|| panic!("{id}: no {member}.text"));
    let require = case["require_signed_pack"].as_bool().unwrap();
    let t = Timestamp::parse(case["evaluation_time"].as_str().unwrap()).unwrap();
    // A store the loader refuses is named by its kind, and a pack by its
    // refusal (§4.2's steps 1 to 3; QA QT-01's cases).
    let trust = TrustStore::from_json(text("trust_store").as_bytes()).map_err(|e| e.kind.id().to_string())?;
    let authorities = match case["authority_store"].is_null() {
        true => trust,
        false => {
            let store = TrustStore::from_json(text("authority_store").as_bytes()).map_err(|e| e.kind.id().to_string())?;
            if store.issuer_count() > 0 {
                return Err("authority_store.issuers".into());
            }
            // One key, one role, across the two files (A16-25): compared by
            // key id, as the loader compares keys inside one store.
            let document = store.to_document();
            if document.policy_authorities.iter().flat_map(|a| &a.keys).any(|k| trust.lookup(&k.key_id).is_some()) {
                return Err("authority_store.issuer_key".into());
            }
            store
        }
    };
    let pack = vmr_policy::load_pack(text("pack")).map_err(|e| e.refusal_id().to_string())?;
    // Step 1.
    let Some(section) = &pack.pack().signature else {
        return if require { Err("pack_signature.unsigned_refused".into()) } else { Ok(json!({"state": "unsigned"})) };
    };
    // Step 2, which needs no key.
    pack.check_payload_hash().map_err(|e| e.refusal_id().to_string())?;
    // Step 3.
    let Some(key) = authorities.lookup_authority(&section.signing_key_id) else {
        return if require {
            Err("pack_signature.not_checked_refused".into())
        } else {
            Ok(json!({"state": "not_checked", "signing_key_id": section.signing_key_id}))
        };
    };
    // Step 4.
    pack.verify_signature(key.verifying_key).map_err(|e| e.refusal_id().to_string())?;
    // Steps 5 to 7.
    key.may_sign_for(&pack.authority.authority_id, t).map_err(|r| r.id().to_string())?;
    Ok(json!({
        "state": "valid",
        "signing_key_id": section.signing_key_id,
        "authority_id": key.authority_id,
        "authority_name": key.authority_name,
    }))
}

#[test]
fn every_pack_signature_vector_gives_its_expected_result_through_the_libraries() {
    let all = cases();
    let (mut states, mut refusals, mut ids) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for case in &all {
        let id = case["id"].as_str().unwrap();
        assert!(ids.insert(id.to_string()), "duplicate case id {id}");
        let expected = &case["expected"];
        if let Ok(pack) = vmr_policy::load_pack(case["pack"]["text"].as_str().unwrap()) {
            assert_eq!(pack.payload_hash(), expected["pack_payload_hash"], "{id}");
        }
        match (replay(case), expected["exit_code"].as_i64()) {
            (Ok(state), Some(0)) => {
                assert_eq!(state, expected["pack_signature"], "{id}");
                states.insert(state["state"].as_str().unwrap().to_string());
            }
            (Err(refusal), Some(1)) => {
                assert_eq!(refusal, expected["refusal"].as_str().unwrap(), "{id}");
                refusals.insert(refusal);
            }
            (got, code) => panic!("{id}: the libraries give {got:?}, the vector expects exit code {code:?}: {expected}"),
        }
    }
    assert_eq!(states.len(), 3, "every state: {states:?}");
    assert_eq!(refusals.len(), 11, "every refusal identifier, a store's and a pack's structure included: {refusals:?}");
}

#[test]
#[ignore = "writes specs/test-vectors/policy/pack-signature.json; run with VMR_WRITE_VECTORS=1 to regenerate"]
#[allow(clippy::disallowed_methods)] // reading the opt-in switch is this generator's whole job
fn write_pack_signature_vectors() {
    if std::env::var("VMR_WRITE_VECTORS").as_deref() != Ok("1") {
        eprintln!("VMR_WRITE_VECTORS is not 1: nothing written");
        return;
    }
    for (rel, contents) in generate::generate() {
        let path = repo().join("specs/test-vectors").join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
}
