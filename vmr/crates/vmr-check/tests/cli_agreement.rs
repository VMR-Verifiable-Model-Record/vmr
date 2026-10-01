// tests/cli_agreement.rs — vmr-check says what `vmr` says (docs/BROWSER.md).
//
// The browser and the command line must give a reader the same answer. Two
// pieces cannot be one shared library call, and are held equal here instead,
// running `vmr`'s own commands in this process (vmr-cli is a dev-dependency
// only, never in the wasm build):
//
//   - the policy hook: vmr-check's pack evaluator and vmr-cli's (vmr-policy
//     may not depend on a verifier, P6-10, nor vmr-verify on a policy crate,
//     G4-5). For every published policy and pack-signature vector, the report
//     is `vmr record verify --json`'s, byte for byte, and a refused pack is
//     refused by both with the same id;
//   - storeForEmbeddedKey: the bytes `vmr trust-store add` writes for the
//     record's key, its issuer, the level asked for and the record's
//     issued_at.

mod common;

use common::*;
use std::path::{Path, PathBuf};
use vmr_check::api::{self, VerifyRequest};
use vmr_cli::cli::{AttestationArg, TrustStoreAddArgs, VerifyArgs};
use vmr_record::timestamp::Timestamp;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("vmr-check").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn write(&self, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

/// One `record verify --json` against the same inputs as a vmr-check call,
/// and the two answers compared: the same report bytes, or both refusing the
/// input with the same id.
#[allow(clippy::too_many_arguments)]
fn agree(s: &Scratch, id: &str, record: &[u8], store: &[u8], at: &str, pack: &[u8], authorities: Option<&[u8]>, require_signed: bool, previous: &[Vec<u8>]) {
    let answer = api::verify(&VerifyRequest {
        record,
        trust_store: store,
        at: Some(unix(at)),
        pack: Some(pack),
        authority_store: authorities,
        require_signed_pack: require_signed,
        previous: previous.iter().map(Vec::as_slice).collect(),
        ..Default::default()
    });
    let args = VerifyArgs {
        record: s.write(&format!("{id}.record"), record),
        trust_store: s.write(&format!("{id}.store.json"), store),
        at: Some(Timestamp::parse(at).unwrap()),
        previous: previous.iter().enumerate().map(|(i, p)| s.write(&format!("{id}.previous-{i}.json"), p)).collect(),
        require_lineage: false,
        policy_pack: Some(s.write(&format!("{id}.pack.json"), pack)),
        authority_store: authorities.map(|a| s.write(&format!("{id}.authorities.json"), a)),
        require_signed_pack: require_signed,
        json: true,
    };
    match (vmr_cli::verify_cmd::run(&args), answer.get("report_json").and_then(|r| r.as_str())) {
        (Ok(out), Some(report)) => assert_eq!(out.stdout, format!("{report}\n"), "{id}"),
        (Err(e), None) => {
            let refusal = answer["refusal"]["id"].as_str().unwrap();
            assert!(e.message.contains(&format!("cannot be used: {refusal}: ")), "{id}: vmr-check refused {refusal}, vmr said: {}", e.message);
        }
        (Ok(_), None) => panic!("{id}: vmr verified, vmr-check refused: {answer}"),
        (Err(e), Some(_)) => panic!("{id}: vmr-check verified, vmr refused: {}", e.message),
    }
}

#[test]
fn every_policy_vector_gives_vmrs_report_through_vmr_check() {
    let s = Scratch::new("policy");
    let store = vector_store("ts-basic");
    let mut n = 0;
    for c in cases("policy/cases.json") {
        let id = c["id"].as_str().unwrap();
        let text = c["record"]["text"].as_str().unwrap();
        let record = if c["verifiable"] == true {
            let mut r = vmr_record::Record::from_json(text).unwrap();
            reissue_with(&mut r, KEY_A);
            r.to_json().unwrap()
        } else {
            text.to_string()
        };
        let previous: Vec<Vec<u8>> = c["context"]["predecessors"]
            .as_array()
            .map(|ps| ps.iter().map(|p| p["text"].as_str().unwrap().as_bytes().to_vec()).collect())
            .unwrap_or_default();
        let pack = c["pack"]["text"].as_str().unwrap().as_bytes();
        agree(&s, id, record.as_bytes(), &store, c["evaluation_time"].as_str().unwrap(), pack, None, false, &previous);
        n += 1;
    }
    assert!(n >= 200, "{n}");
}

#[test]
fn every_pack_signature_and_pack_loader_vector_gives_vmrs_answer_through_vmr_check() {
    let s = Scratch::new("pack");
    let base = base_case();
    let record = input_bytes(&base["input"]);
    let t = base["evaluation_time"].as_str().unwrap();
    for c in vector_file("policy/pack-signature.json")["cases"].as_array().unwrap() {
        let authorities = c["authority_store"]["text"].as_str().map(str::as_bytes);
        agree(
            &s,
            c["id"].as_str().unwrap(),
            &record,
            c["trust_store"]["text"].as_str().unwrap().as_bytes(),
            c["evaluation_time"].as_str().unwrap(),
            c["pack"]["text"].as_str().unwrap().as_bytes(),
            authorities,
            c["require_signed_pack"].as_bool().unwrap(),
            &[],
        );
    }
    let store = vector_store("ts-basic");
    for c in vector_file("policy/pack-loader.json")["cases"].as_array().unwrap() {
        // The CLI reads a file of at most 1 MiB and names an oversized one
        // without reading it; the loader refuses the same bytes as
        // policy_pack.size.
        agree(&s, c["id"].as_str().unwrap(), &record, &store, t, &input_bytes(&c["pack"]), None, false, &[]);
    }
}

#[test]
fn store_for_embedded_key_writes_what_trust_store_add_writes() {
    let s = Scratch::new("store");
    let base = input_bytes(&base_case()["input"]);
    let general = general_vector().to_json().unwrap().into_bytes();
    for (name, record) in [("vector", base), ("general", general)] {
        let r = vmr_check::inspect::read_record(&record).unwrap();
        let key_file = vmr_cli::keys::PublicKeyFile::of(&r.issuer.public_key.to_verifying_key().unwrap());
        for (level, arg) in [(None, AttestationArg::SelfAttested), (Some("hardware"), AttestationArg::Hardware)] {
            let store = s.0.join(format!("{name}-{arg:?}.json"));
            vmr_cli::trust_store_cmd::add(&TrustStoreAddArgs {
                trust_store: store.clone(),
                public_key: s.write(&format!("{name}.pub.json"), serde_json::to_string_pretty(&key_file).unwrap()),
                issuer_id: r.issuer.issuer_id.clone(),
                issuer_name: r.issuer.issuer_name.clone(),
                attestation_level: arg,
                valid_from: Timestamp::parse(&r.issued_at).unwrap(),
                valid_until: None,
            })
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
            let ours = api::store_for_embedded_key(&record, &r.issuer.public_key.fingerprint(), level);
            assert_eq!(ours["trust_store"].as_str().unwrap(), std::fs::read_to_string(&store).unwrap(), "{name} {level:?}");
        }
    }
}

#[test]
fn the_ids_vmr_check_shares_with_vmr_are_vmrs() {
    use vmr_check::{pack, refusal};
    assert_eq!(refusal::AUTHORITY_STORE_ISSUERS, vmr_cli::verify_cmd::AUTHORITY_STORE_ISSUERS);
    assert_eq!(refusal::AUTHORITY_STORE_ISSUER_KEY, vmr_cli::verify_cmd::AUTHORITY_STORE_ISSUER_KEY);
    assert_eq!(pack::UNSIGNED_REFUSED, vmr_cli::policy_pack::UNSIGNED_REFUSED);
    assert_eq!(pack::NOT_CHECKED_REFUSED, vmr_cli::policy_pack::NOT_CHECKED_REFUSED);
}
