// tests/robustness.rs — the robustness bar for the audit-log parsers: every
// parser of a stranger's document is fed mutated seeds and never panics.
//
// The seeds are specs/test-vectors/audit-log/cases.json, and what a target
// accepts holds its oracle:
//
//   entry       entry::validate_entry on a line's JSON, as a log and the
//               proofs read it. An accepted line is the JCS form of its value.
//   log         log::read_log over a mutated file's bytes. A log that reads
//               has one leaf per line and the root vmr_record::merkle computes
//               over the lines.
//   checkpoint  checkpoint::verify_checkpoint. Accepted claims are a seed's.
//   inclusion   proof::verify_inclusion_proof. A proven entry is a seed's.
//   consistency proof::verify_consistency_proof. Proven sizes are a seed's.
//
// The lanes read the core profile where a kind is not the point, and the
// khalm-vmr.enforcer profile where the seeds are its entries.
//
// Debug runs are small; the release bar (>= 1 000 000 mutations per parser) is
// the ignored test at the end:
//
//     cargo test --release -p vmr-audit-log --test robustness -- --ignored

mod common;

use common::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use vmr_audit_log::profile::CORE;
use vmr_audit_log::profiles::khalm_enforcer::PROFILE;
use vmr_audit_log::vmr_record::canonical::jcs;
use vmr_audit_log::{checkpoint, entry, json, log, proof};

const RELEASE_RUN: usize = 1_000_000;
const RELEASE_LOG_RUN: usize = 100_000;

// ---------------------------------------------------------------------------
//  The generator and the mutators
// ---------------------------------------------------------------------------

/// Knuth's MMIX LCG: explicit, seeded, platform-independent.
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
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const INTERESTING: [u8; 16] = [
    0x00, 0xff, b'"', b'{', b'}', b'[', b']', b',', b':', b'\\', b'\n', b'0', b'-', 0x7f, 0x80, 0xc3,
];

fn byte_mutation(rng: &mut Lcg, mut b: Vec<u8>) -> Vec<u8> {
    let len = b.len();
    match rng.below(7) {
        0 if len > 0 => {
            let i = rng.below(len);
            b[i] ^= 1 << rng.below(8);
        }
        1 if len > 0 => {
            let i = rng.below(len);
            b[i] = if rng.below(2) == 0 { *rng.pick(&INTERESTING) } else { rng.next() as u8 };
        }
        2 => b.truncate(rng.below(len + 1)),
        3 => {
            let i = rng.below(len + 1);
            let n = 1 + rng.below(8);
            let insert: Vec<u8> = (0..n).map(|_| *rng.pick(&INTERESTING)).collect();
            b.splice(i..i, insert);
        }
        4 if len > 0 => {
            let (i, n) = (rng.below(len), 1 + rng.below(64));
            let slice: Vec<u8> = b[i..(i + n).min(len)].to_vec();
            let at = rng.below(len + 1);
            b.splice(at..at, slice);
        }
        5 if len > 0 => {
            let (i, n) = (rng.below(len), 1 + rng.below(64));
            b.drain(i..(i + n).min(len));
        }
        _ => {
            for _ in 0..3 {
                if !b.is_empty() {
                    let i = rng.below(b.len());
                    b[i] ^= 1 << rng.below(8);
                }
            }
        }
    }
    b
}

/// Every object in a JSON value, by pointer.
fn objects(v: &Value, at: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            out.push(at.to_string());
            for (k, c) in m {
                objects(c, &format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")), out);
            }
        }
        Value::Array(items) => {
            for (i, c) in items.iter().enumerate() {
                objects(c, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// Strings a document's formats almost accept.
const NEAR_MISSES: [&str; 16] = [
    "",
    "::ffff:203.0.113.7",
    "203.0.113.007",
    "0.0.0.0",
    "2001:DB8::1",
    "2026-02-30T00:00:00Z",
    "2026-09-14T10:00:00.5Z",
    "sha256:ABCDEF",
    "urn:uuid:44444444-4444-4444-8444-44444444444G",
    "urn:ietf:params:oauth:jwk-thumbprint:sha-256:",
    "base64url:",
    "ES256 ",
    "tcp ",
    "\u{202e}\u{1b}[2J",
    "export.granted",
    "0.1",
];

fn json_mutation(rng: &mut Lcg, seed: &[u8]) -> Vec<u8> {
    let Ok(mut v) = serde_json::from_slice::<Value>(seed) else {
        return byte_mutation(rng, seed.to_vec());
    };
    let mut objs = Vec::new();
    objects(&v, "", &mut objs);
    if objs.is_empty() {
        return byte_mutation(rng, seed.to_vec());
    }
    let at = rng.pick(&objs).clone();
    let Some(obj) = v.pointer_mut(&at).and_then(Value::as_object_mut) else {
        return byte_mutation(rng, seed.to_vec());
    };
    let keys: Vec<String> = obj.keys().cloned().collect();
    let key = if keys.is_empty() { "x".to_string() } else { rng.pick(&keys).clone() };
    let mut text_edit: Option<String> = None;
    let needle = serde_json::to_string(&key).unwrap() + ":";
    match rng.below(10) {
        0 => {
            obj.remove(&key);
        }
        1 => {
            // Repeat a member, written into the text (a Value cannot).
            let text = serde_json::to_string(&v).unwrap();
            if let Some(i) = text.find(&needle) {
                let repeat = if rng.below(2) == 0 { "null".to_string() } else { "\"0.1\"".to_string() };
                text_edit = Some(format!("{}{needle}{repeat},{}", &text[..i], &text[i..]));
            }
        }
        2 => {
            let old = obj.get(&key).cloned().unwrap_or(Value::Null);
            let new = match old {
                Value::String(_) => Value::from(1),
                Value::Number(_) => Value::from("1"),
                Value::Object(_) => Value::Array(vec![]),
                Value::Array(_) => Value::Object(Default::default()),
                Value::Bool(b) => Value::from(u8::from(b)),
                Value::Null => Value::Bool(true),
            };
            obj.insert(key, new);
        }
        3 => {
            obj.insert(key, Value::from("A".repeat(100_000)));
        }
        4 => {
            obj.insert(key, Value::from("\u{1b}[2J\u{0}\r\n\u{202e}\u{7f}\u{85}"));
        }
        5 => {
            let text = serde_json::to_string(&v).unwrap();
            if let Some(i) = text.find(&needle) {
                let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
                text_edit = Some(format!("{}\"deep\":{deep},{}", &text[..i], &text[i..]));
            }
        }
        6 => {
            let text = serde_json::to_string(&v).unwrap();
            let spelling = *rng.pick(&["1e400", "18446744073709551616", "-1", "12.0", "9007199254740992", "-0", "1E1", "00"]);
            if let Some(i) = text.find(&needle) {
                text_edit = Some(format!("{}{needle}{spelling},{}", &text[..i], &text[i..]));
            }
        }
        7 => {
            obj.insert(format!("injected_{}", rng.below(1000)), Value::Bool(true));
        }
        8 => {
            let near = *rng.pick(&NEAR_MISSES);
            obj.insert(key, Value::from(near));
        }
        _ => {
            if let Some(val) = obj.get(&key).cloned() {
                obj.insert(key, Value::Array(vec![val]));
            }
        }
    }
    text_edit.unwrap_or_else(|| serde_json::to_string(&v).unwrap()).into_bytes()
}

/// A JSON mutant or a byte mutant, evenly.
fn mutate(rng: &mut Lcg, seed: &[u8]) -> Vec<u8> {
    if rng.below(2) == 0 {
        json_mutation(rng, seed)
    } else {
        byte_mutation(rng, seed.to_vec())
    }
}

// ---------------------------------------------------------------------------
//  Seeds and oracles
// ---------------------------------------------------------------------------

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors/audit-log/cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn audit_key() -> p256::ecdsa::VerifyingKey {
    *key(AUDIT_KEY).verifying_key()
}

fn section<'a>(doc: &'a Value, name: &str) -> &'a [Value] {
    doc[name].as_array().map(Vec::as_slice).unwrap_or_else(|| panic!("no {name} array"))
}

/// A case's document bytes: its `raw` text, else its `member` value.
fn case_bytes(case: &Value, member: &str) -> Vec<u8> {
    match case.get("raw") {
        Some(raw) => raw.as_str().unwrap().as_bytes().to_vec(),
        None => serde_json::to_vec(&case[member]).unwrap(),
    }
}

/// The text a `&str` parser is given for a mutant's bytes.
fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Run `f`; a panic fails the test and names the input.
fn no_panic<T>(what: &str, input: &[u8], f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => panic!("{what}: the parser PANICKED on input {}", hex::encode(input)),
    }
}

/// A refusal names an id of one of `namespaces` and carries no raw control
/// character.
fn check_refusal(e: &vmr_audit_log::Error, namespaces: &[&str], what: &str) {
    let id = e.id();
    assert!(namespaces.iter().any(|ns| id.starts_with(ns)), "{what}: refused with {id}, not one of {namespaces:?}: {e}");
    let text = e.to_string();
    assert!(!text.chars().any(char::is_control), "{what}: a raw control character in the refusal {text:?}");
}

fn run_entry_target(iterations: usize, seed_value: u64) -> usize {
    let doc = vectors();
    let mut seeds: Vec<Vec<u8>> =
        doc["environment"]["log_lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().as_bytes().to_vec()).collect();
    for case in section(&doc, "logs") {
        seeds.extend(case["raw"].as_str().unwrap().split('\n').filter(|l| !l.is_empty()).map(|l| l.as_bytes().to_vec()));
    }
    for case in section(&doc, "inclusion_proofs") {
        if let Some(entry) = case["proof"]["entry"].as_str() {
            seeds.push(entry.as_bytes().to_vec());
        }
    }

    let mut rng = Lcg(seed_value);
    let mut accepted = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds).clone();
        let mutant = mutate(&mut rng, &seed);
        let text = text_of(&mutant);
        let what = format!("entry mutant {i}");
        let outcome = no_panic(&what, &mutant, || json::parse_json_bounded(&text).map(|v| (entry::validate_entry(&v, &text, &PROFILE), v)));
        match outcome {
            Err(_not_json) => {}
            Ok((Ok(entry), value)) => {
                assert_eq!(jcs(&value), text, "{what}: accepted a line that is not the JCS form of its value");
                assert_eq!(entry.canonical, text, "{what}");
                assert!(vmr_audit_log::profiles::khalm_enforcer::KINDS.contains(&entry.kind.as_str()), "{what}: kind {}", entry.kind);
                accepted += 1;
            }
            Ok((Err(e), _)) => check_refusal(&e, &["audit_entry."], &what),
        }
    }
    accepted
}

fn run_log_target(iterations: usize, seed_value: u64) -> usize {
    let doc = vectors();
    let mut seeds: Vec<Vec<u8>> = section(&doc, "logs").iter().map(|c| c["raw"].as_str().unwrap().as_bytes().to_vec()).collect();
    let env_lines: Vec<&str> = doc["environment"]["log_lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect();
    seeds.push((env_lines.join("\n") + "\n").into_bytes());

    let mut rng = Lcg(seed_value);
    let mut accepted = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds).clone();
        let mutant = mutate(&mut rng, &seed);
        let what = format!("log mutant {i}");
        match no_panic(&what, &mutant, || log::read_log(&mutant, &CORE)) {
            Ok(entries) => {
                assert!(mutant.is_empty() || mutant.ends_with(b"\n"), "{what}: read a log with a torn tail");
                let leaves: Vec<&[u8]> = mutant.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
                assert_eq!(entries.len(), leaves.len(), "{what}");
                assert_eq!(
                    vmr_audit_log::tree::root_of(&log::leaves_of(&entries)),
                    vmr_audit_log::vmr_record::merkle::merkle_root(&leaves),
                    "{what}: the root is not RFC 9162's over the lines"
                );
                accepted += 1;
            }
            Err(e) => check_refusal(&e, &["audit_entry.", "audit_log."], &what),
        }
    }
    accepted
}

fn checkpoint_seeds(doc: &Value) -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = section(doc, "checkpoints").iter().map(|c| case_bytes(c, "checkpoint")).collect();
    seeds.push(serde_json::to_vec(&doc["environment"]["checkpoint"]).unwrap());
    for case in section(doc, "inclusion_proofs") {
        if case["proof"]["checkpoint"].is_object() {
            seeds.push(serde_json::to_vec(&case["proof"]["checkpoint"]).unwrap());
        }
    }
    for case in section(doc, "consistency_proofs") {
        for end in ["from", "to"] {
            if case["proof"][end].is_object() {
                seeds.push(serde_json::to_vec(&case["proof"][end]).unwrap());
            }
        }
    }
    seeds
}

fn run_checkpoint_target(iterations: usize, seed_value: u64) -> usize {
    let doc = vectors();
    let seeds = checkpoint_seeds(&doc);
    let audit = audit_key();
    let claims = |c: checkpoint::CheckpointClaims| (c.log_id, c.tree_size, c.root_hash);
    let genuine: BTreeSet<(String, u64, String)> =
        seeds.iter().filter_map(|s| checkpoint::verify_checkpoint(s, &audit).ok()).map(claims).collect();
    assert!(!genuine.is_empty(), "no checkpoint seed verifies");

    let mut rng = Lcg(seed_value);
    let mut accepted = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds).clone();
        let mutant = mutate(&mut rng, &seed);
        let what = format!("checkpoint mutant {i}");
        match no_panic(&what, &mutant, || checkpoint::verify_checkpoint(&mutant, &audit)) {
            Ok(c) => {
                assert!(genuine.contains(&claims(c)), "{what}: claims the audit key did not sign: {}", hex::encode(&mutant));
                accepted += 1;
            }
            Err(e) => check_refusal(&e, &["checkpoint."], &what),
        }
    }
    accepted
}

fn run_inclusion_target(iterations: usize, seed_value: u64) -> usize {
    let doc = vectors();
    let seeds: Vec<Vec<u8>> = section(&doc, "inclusion_proofs").iter().map(|c| case_bytes(c, "proof")).collect();
    let audit = audit_key();
    let genuine: BTreeSet<String> =
        seeds.iter().filter_map(|s| proof::verify_inclusion_proof(s, &audit, &PROFILE).ok()).map(|e| e.canonical).collect();
    assert!(!genuine.is_empty(), "no inclusion seed verifies");

    let mut rng = Lcg(seed_value);
    let mut accepted = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds).clone();
        let mutant = mutate(&mut rng, &seed);
        let what = format!("inclusion mutant {i}");
        match no_panic(&what, &mutant, || proof::verify_inclusion_proof(&mutant, &audit, &PROFILE)) {
            Ok(entry) => {
                assert!(genuine.contains(&entry.canonical), "{what}: proved an entry no seed proves: {}", hex::encode(&mutant));
                accepted += 1;
            }
            Err(e) => check_refusal(&e, &["audit_proof.", "checkpoint.", "audit_entry."], &what),
        }
    }
    accepted
}

fn run_consistency_target(iterations: usize, seed_value: u64) -> usize {
    let doc = vectors();
    let seeds: Vec<Vec<u8>> = section(&doc, "consistency_proofs").iter().map(|c| case_bytes(c, "proof")).collect();
    let audit = audit_key();
    let genuine: BTreeSet<(u64, u64)> = seeds.iter().filter_map(|s| proof::verify_consistency_proof(s, &audit).ok()).collect();
    assert!(!genuine.is_empty(), "no consistency seed verifies");

    let mut rng = Lcg(seed_value);
    let mut accepted = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds).clone();
        let mutant = mutate(&mut rng, &seed);
        let what = format!("consistency mutant {i}");
        match no_panic(&what, &mutant, || proof::verify_consistency_proof(&mutant, &audit)) {
            Ok(sizes) => {
                assert!(genuine.contains(&sizes), "{what}: proved sizes {sizes:?} no seed proves: {}", hex::encode(&mutant));
                accepted += 1;
            }
            Err(e) => check_refusal(&e, &["audit_proof.", "checkpoint."], &what),
        }
    }
    accepted
}

// ---------------------------------------------------------------------------
//  Normal runs (debug; skipped by CI by name) and the release bar
// ---------------------------------------------------------------------------

#[test]
fn audit_entry_mutants_never_panic_and_accept_only_canonical_lines() {
    let accepted = run_entry_target(20_000, 0x5338_0003);
    eprintln!("entry: {accepted} of 20000 mutants accepted, each canonical");
}

#[test]
fn audit_log_mutants_never_panic_and_replay_to_the_merkle_root() {
    let accepted = run_log_target(2_000, 0x5338_0004);
    eprintln!("log: {accepted} of 2000 mutated logs read, each at its RFC 9162 root");
}

#[test]
fn checkpoint_mutants_never_panic_and_never_pass_unsigned_claims() {
    let accepted = run_checkpoint_target(20_000, 0x5338_0005);
    eprintln!("checkpoint: {accepted} of 20000 mutants verified, each signed claims");
}

#[test]
fn inclusion_proof_mutants_never_panic_and_prove_only_logged_entries() {
    let accepted = run_inclusion_target(20_000, 0x5338_0006);
    eprintln!("inclusion: {accepted} of 20000 mutants verified, each a logged entry");
}

#[test]
fn consistency_proof_mutants_never_panic_and_prove_only_signed_trees() {
    let accepted = run_consistency_target(20_000, 0x5338_0007);
    eprintln!("consistency: {accepted} of 20000 mutants verified, each signed sizes");
}

#[test]
#[ignore = "the doctrine's release bar: >= 1 000 000 mutations per parser; run with --release -- --ignored"]
fn one_million_mutations_per_parser() {
    std::thread::scope(|s| {
        let runs = [
            s.spawn(|| ("entry", run_entry_target(RELEASE_RUN, 0x5339_0003))),
            s.spawn(|| ("log", run_log_target(RELEASE_LOG_RUN, 0x5339_0004))),
            s.spawn(|| ("checkpoint", run_checkpoint_target(RELEASE_RUN, 0x5339_0005))),
            s.spawn(|| ("inclusion", run_inclusion_target(RELEASE_RUN, 0x5339_0006))),
            s.spawn(|| ("consistency", run_consistency_target(RELEASE_RUN, 0x5339_0007))),
        ];
        for run in runs {
            let (name, accepted) = run.join().expect("a target failed; its panic is printed above");
            eprintln!("{name}: {accepted} mutants accepted, every oracle held");
        }
    });
}
