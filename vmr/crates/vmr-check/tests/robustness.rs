// tests/robustness.rs — no input makes vmr-check panic (a trap in the
// browser): random and mutated records, stores, packs and requests always
// give JSON, either the call's result or the fail shape.
//
// The mutation approach of vmr-verify/tests/robustness.rs, at the byte level:
// flips, interesting bytes, insertions, deletions, truncations and
// duplications, from seeds that are the published vectors' own inputs, with
// a fixed-seed LCG (Law 1). js/test/api.test.mjs runs the same kind of
// inputs through the built module.

mod common;

use common::*;
use serde_json::Value;
use vmr_check::api;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: [u8; 16] = [0x00, 0xff, b'"', b'{', b'}', b'[', b']', b',', b':', b'\\', 0x84, 0xd2, 0x5b, 0x9b, 0x7f, 0x80];

fn mutate(rng: &mut Lcg, mut b: Vec<u8>) -> Vec<u8> {
    let len = b.len();
    match rng.below(6) {
        0 if len > 0 => {
            let i = rng.below(len);
            b[i] ^= 1 << rng.below(8);
        }
        1 if len > 0 => {
            let i = rng.below(len);
            b[i] = INTERESTING[rng.below(INTERESTING.len())];
        }
        2 => {
            let i = rng.below(len + 1);
            b.insert(i, INTERESTING[rng.below(INTERESTING.len())]);
        }
        3 if len > 0 => {
            let i = rng.below(len);
            let n = 1 + rng.below((len - i).min(16));
            b.drain(i..i + n);
        }
        4 => b.truncate(rng.below(len + 1)),
        _ if len > 0 => {
            let i = rng.below(len);
            let n = 1 + rng.below((len - i).min(32));
            let copy = b[i..i + n].to_vec();
            let at = rng.below(len + 1);
            b.splice(at..at, copy);
        }
        _ => b.push(INTERESTING[rng.below(INTERESTING.len())]),
    }
    b
}

/// An answer is JSON, and either the call's result or the fail shape.
fn shaped(bytes: &[u8], result_member: &str) -> Value {
    let v: Value = serde_json::from_slice(bytes).expect("every answer is JSON");
    assert!(
        v.get(result_member).is_some() || v["refusal"]["id"].is_string(),
        "neither a result nor a refusal: {v}"
    );
    v
}

fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

#[test]
fn mutated_records_stores_and_packs_never_panic() {
    let base = base_case();
    let record = input_bytes(&base["input"]);
    let general = general_vector().to_json().unwrap().into_bytes();
    let store = vector_store("ts-basic");
    let pack = std::fs::read(repo().join("specs/policy-packs/khalm-reading-eu-ai-act-2026.json")).unwrap();
    let at = unix(base["evaluation_time"].as_str().unwrap());
    let files = format!(
        "{{\"files\":[{{\"name\":\"weights.bin\",\"sha256\":\"sha256:{}\",\"size\":4}}]}}",
        "00".repeat(32)
    );
    let mut rng = Lcg(0x5EED_C4EC);
    let (mut current, mut current_store, mut current_pack) = (record.clone(), store.clone(), pack.clone());
    let mut reports = 0;
    for i in 0..3_000 {
        if i % 10 == 0 {
            current = if rng.below(2) == 0 { record.clone() } else { general.clone() };
            current_store = store.clone();
            current_pack = pack.clone();
        }
        current = mutate(&mut rng, current);
        match rng.below(4) {
            0 => current_store = mutate(&mut rng, current_store),
            1 => current_pack = mutate(&mut rng, current_pack),
            _ => {}
        }
        let header = format!("{{\"at\":{at},\"previous\":0,\"pack\":true,\"authority_store\":false}}");
        let v = shaped(
            &api::call(api::OP_VERIFY, &framed(&[header.as_bytes(), &current, &current_store, &current_pack])),
            "report",
        );
        reports += usize::from(v.get("report").is_some());
        shaped(&api::call(api::OP_INSPECT, &framed(&[b"{}", &current])), "integrity_against_embedded_key");
        let v = api::call(api::OP_STORE_FOR_EMBEDDED_KEY, &framed(&[b"{\"attestation_level\":\"software\",\"expected_fingerprint\":\"HyoP YysS FOQ5 d6x6 4H8_ pHdd\"}", &current]));
        shaped(&v, "trust_store");
        shaped(&api::call(api::OP_CHECK_FILES, &framed(&[files.as_bytes(), &current])), "model_hash");
    }
    assert!(reports > 300, "the harness reaches verification ({reports} reports)");
}

#[test]
fn random_requests_never_panic() {
    let mut rng = Lcg(0x00F4_A3E5);
    let seed = framed(&[b"{\"at\":0,\"previous\":1}", b"{", b"{}", b"x"]);
    let mut current = seed.clone();
    for i in 0..5_000 {
        if i % 16 == 0 {
            current = seed.clone();
        }
        current = mutate(&mut rng, current);
        let op = rng.below(7) as u32;
        let v: Value = serde_json::from_slice(&api::call(op, &current)).expect("every answer is JSON");
        assert!(v.is_object(), "{v}");
    }
}
