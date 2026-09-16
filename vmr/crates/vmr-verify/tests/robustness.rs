// tests/robustness.rs — a deterministic mutation harness on stable Rust
// (Phase 4 task 4.8, decision D8 option B: this gates Gate 4; coverage-guided
// cargo-fuzz is a later, time-boxed pre-release task). DEV_PLAN §5.7: "a
// malformed record must never crash the verifier".
//
// Seeds: every input of the committed verification vectors (JSON and COSE,
// positive and negative) and every trust store (verification stores and
// loader cases). Mutators: bit flips, byte overwrites, truncation,
// insertion, duplication and deletion; structure-aware JSON edits (drop or
// duplicate a member, change a type, huge and control-character strings,
// 100 000-deep nesting, huge numbers, an object written as the array of its
// values); CBOR edits (major-type flips, 2^62 declared lengths, 10 000-deep
// arrays, tags). The generator is an explicit LCG with fixed seeds (no
// `rand`): every run tries the same inputs.
//
// Oracles: never a panic; every call returns a well-formed report; a mutated
// input that PASSES carries a signed payload some trusted key really signed
// (its recomputed hash is one of the vectors' records); a mutated COSE
// input that passes is byte-identical to its record's canonical envelope;
// a mutated JSON input that passes, as a record or as a predecessor, is
// the document its record re-derives (QA QT-01: no object read from an
// array); a trust store with an object written as the array of its values
// never loads (QA QT-01 QJ-03). A self-test runs the two JSON targets against
// a verifier that reads a record from such an array, and requires the
// re-derivation oracle to fail both runs.
//
// Normal run: 20 000 mutations per target (the four targets run as parallel
// tests). Release bar (Doctrine L3, >= 1 M per parser):
//     cargo test --release -p vmr-verify --test robustness -- --ignored

mod common;
#[path = "common/generate.rs"]
mod generate;

use generate::input_bytes;
use serde_json::Value;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::BTreeSet;
use vmr_record::timestamp::Timestamp;
use vmr_record::Record;
use vmr_verify::report::{Outcome, Verdict};
use vmr_verify::{TrustStore, Verifier, VerifyOptions};

const NORMAL_RUN: usize = 20_000;
const RELEASE_RUN: usize = 1_000_000;

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

fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors")
}

fn cases(rel: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(vectors_dir().join(rel)).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

fn store(name: &str) -> TrustStore {
    let text = std::fs::read_to_string(vectors_dir().join(format!("verify/trust-stores/{name}.json"))).unwrap();
    TrustStore::from_json(text.as_bytes()).unwrap()
}

/// A seed: bytes, its form, the store and time of its case.
struct Seed {
    bytes: Vec<u8>,
    cose: bool,
    store: String,
    t: String,
}

fn seeds() -> Vec<Seed> {
    let mut out = Vec::new();
    for c in cases("verify/cases.json") {
        let mut add = |input: &Value| {
            out.push(Seed {
                bytes: input_bytes(input),
                cose: input["form"] == "cose",
                store: c["trust_store"].as_str().unwrap().to_string(),
                t: c["evaluation_time"].as_str().unwrap().to_string(),
            })
        };
        add(&c["input"]);
        for p in c["previous"].as_array().unwrap() {
            add(p);
        }
    }
    out.retain(|s| s.bytes.len() <= 64 * 1024); // the oversized case is its own test
    out
}

/// The signed-payload hash of every record in the vectors: the only
/// payloads a trusted key ever signed. A passing mutant must carry one.
fn genuine_payload_hashes() -> BTreeSet<String> {
    seeds()
        .iter()
        .filter_map(|s| {
            let p = if s.cose {
                Record::from_cose(&s.bytes).ok()
            } else {
                std::str::from_utf8(&s.bytes)
                    .ok()
                    .map(|t| t.trim_start_matches('\u{feff}'))
                    .and_then(|t| Record::from_json(t).ok())
            };
            p.and_then(|p| p.signed_payload_hash().ok())
        })
        .collect()
}

// ---------------------------------------------------------------------------
//  Mutators
// ---------------------------------------------------------------------------

const INTERESTING: [u8; 16] = [
    0x00, 0xff, b'"', b'{', b'}', b'[', b']', b',', b':', b'\\', 0x84, 0xd2, 0x5b, 0x9b, 0x7f, 0x80,
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
            // Several small mutations at once.
            for _ in 0..3 {
                if let Some(i) = (len > 0).then(|| rng.below(b.len().max(1))) {
                    if i < b.len() {
                        b[i] ^= 1 << rng.below(8);
                    }
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
                objects(c, &format!("{at}/{k}"), out);
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

fn json_mutation(rng: &mut Lcg, seed: &[u8]) -> Vec<u8> {
    json_edit(rng, seed).0
}

/// [`json_mutation`]'s mutant, and whether it wrote an object as the array of
/// its values.
fn json_edit(rng: &mut Lcg, seed: &[u8]) -> (Vec<u8>, bool) {
    let Ok(mut v) = serde_json::from_slice::<Value>(seed) else {
        return (byte_mutation(rng, seed.to_vec()), false);
    };
    let mut objs = Vec::new();
    objects(&v, "", &mut objs);
    let at = rng.pick(&objs).clone();
    let obj = v.pointer_mut(&at).unwrap().as_object_mut().unwrap();
    let keys: Vec<String> = obj.keys().cloned().collect();
    let key = if keys.is_empty() { "x".to_string() } else { rng.pick(&keys).clone() };
    let deep = || format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    let mut text_edit: Option<String> = None;
    let mut respelled = false;
    match rng.below(10) {
        0 => {
            obj.remove(&key);
        }
        9 => {
            // QA QT-01: the object as the array of its values - in declaration
            // order (the order serde's derive reads a struct in) when it is a
            // record object, half the time, else in its members' order
            // rotated.
            let kind = at.split('/').map(|s| if s.parse::<usize>().is_ok() { "*" } else { s }).collect::<Vec<_>>().join("/");
            let declared = common::OBJECT_FIELDS.iter().find(|(k, _)| *k == kind).map(|(_, fields)| *fields);
            let values: Vec<Value> = match declared {
                Some(fields) if rng.below(2) == 0 => fields.iter().filter_map(|f| obj.get(*f).cloned()).collect(),
                _ => {
                    let mut all: Vec<Value> = obj.values().cloned().collect();
                    let shift = rng.below(all.len());
                    all.rotate_left(shift);
                    all
                }
            };
            *v.pointer_mut(&at).unwrap() = Value::Array(values);
            respelled = true;
        }
        1 => {
            // Duplicate a member: written textually (serde_json cannot).
            let text = serde_json::to_string(&v).unwrap();
            let needle = format!("\"{key}\":");
            if let Some(i) = text.find(&needle) {
                let dup = format!("\"{key}\":null,");
                text_edit = Some(format!("{}{}{}", &text[..i], dup, &text[i..]));
            }
        }
        2 => {
            let old = obj.get(&key).cloned().unwrap_or(Value::Null);
            let new = match old {
                Value::String(_) => Value::from(1),
                Value::Number(_) => Value::from("1"),
                Value::Object(_) => Value::Array(vec![]),
                Value::Array(_) => Value::Object(Default::default()),
                Value::Bool(b) => Value::from(if b { 1 } else { 0 }),
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
            let needle = format!("\"{key}\":");
            if let Some(i) = text.find(&needle) {
                text_edit = Some(format!("{}\"deep\":{},{}", &text[..i], deep(), &text[i..]));
            }
        }
        6 => {
            let text = serde_json::to_string(&v).unwrap();
            let needle = format!("\"{key}\":");
            let huge = *rng.pick(&["1e400", "18446744073709551616", "-1", "12.0", "9007199254740992", "-0"]);
            if let Some(i) = text.find(&needle) {
                text_edit = Some(format!("{}\"{key}\":{huge},{}", &text[..i], &text[i..]));
            }
        }
        7 => {
            obj.insert(format!("injected_{}", rng.below(1000)), Value::Bool(true));
        }
        _ => {
            if let Some(val) = obj.get(&key).cloned() {
                obj.insert(key, Value::Array(vec![val]));
            }
        }
    }
    (text_edit.unwrap_or_else(|| serde_json::to_string(&v).unwrap()).into_bytes(), respelled)
}

fn cbor_mutation(rng: &mut Lcg, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    let len = b.len();
    if len == 0 {
        return vec![0x84];
    }
    let i = rng.below(len);
    match rng.below(5) {
        0 => b[i] ^= 0xe0 & (rng.next() as u8), // flip the major type bits of a byte
        1 => {
            // A 2^62 length head for a byte string, array or map.
            let head = *rng.pick(&[0x5bu8, 0x7b, 0x9b, 0xbb]);
            b.splice(i..i, [head, 0x40, 0, 0, 0, 0, 0, 0, 0]);
        }
        2 => {
            let deep = vec![0x81u8; 10_000];
            b.splice(i..i, deep);
        }
        3 => {
            let tag = *rng.pick(&[0xd2u8, 0xc0, 0xd8, 0xdb]);
            b.splice(i..i, [tag, 0x12]);
        }
        _ => return byte_mutation(rng, b),
    }
    b
}

// ---------------------------------------------------------------------------
//  Targets
// ---------------------------------------------------------------------------

/// How the targets have the verifier read an input: as it does, or, in the
/// oracles' self-test only, as a verifier with the fault QA QT-01 fixed did.
#[derive(Clone, Copy)]
enum Reading<'a> {
    Verifier,
    /// A JSON text the record reader refuses, but serde_json's derive reads
    /// as a record, is verified as that record's object form: what a
    /// verifier that reads a struct from the array of its values reports. The
    /// cell counts such texts.
    Lenient(&'a Cell<usize>),
}

/// The bytes the verifier is given for `input` under `reading`.
fn as_read<'a>(input: &'a [u8], cose: bool, reading: Reading) -> Cow<'a, [u8]> {
    let Reading::Lenient(count) = reading else { return Cow::Borrowed(input) };
    let object_form = std::str::from_utf8(input)
        .ok()
        .filter(|text| !cose && Record::from_json(text).is_err())
        .and_then(|text| serde_json::from_str::<Record>(text).ok())
        .and_then(|record| record.to_json().ok());
    match object_form {
        Some(text) => {
            count.set(count.get() + 1);
            Cow::Owned(text.into_bytes())
        }
        None => Cow::Borrowed(input),
    }
}

/// Check every oracle on one mutant; `what` identifies it on failure.
fn check_report(
    verifier: &Verifier,
    input: &[u8],
    cose: bool,
    t: Timestamp,
    genuine: &BTreeSet<String>,
    what: &str,
    reading: Reading,
) -> bool {
    let opts = VerifyOptions::new(t);
    let read = as_read(input, cose, reading);
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let explicit = if cose { verifier.verify_cose(&read, &opts) } else { verifier.verify_json(&read, &opts) };
        let detected = verifier.verify(&read, &opts);
        (explicit, detected)
    }));
    let (report, detected) = match run {
        Ok(r) => r,
        Err(_) => panic!("{what}: the verifier PANICKED on input {}", hex::encode(input)),
    };
    for r in [&report, &detected] {
        assert!(!r.checks.is_empty(), "{what}");
        assert_eq!(r.verdict == Verdict::Fail, r.failure.is_some(), "{what}");
        assert!(r.to_json().is_ok(), "{what}");
        if r.verdict == Verdict::Pass {
            assert!(r.checks.iter().all(|c| c.outcome == Outcome::Pass || c.outcome == Outcome::NotEvaluated));
            let hash = r.record.as_ref().and_then(|p| p.signed_payload_hash.clone()).unwrap();
            assert!(genuine.contains(&hash), "{what}: a mutant passed with a payload no trusted key signed: {}", hex::encode(input));
        }
    }
    if report.verdict == Verdict::Pass && cose {
        let canonical = Record::from_cose(input).unwrap().to_cose().unwrap();
        assert_eq!(canonical, input, "{what}: a passing COSE mutant is not the canonical envelope");
    }
    if report.verdict == Verdict::Pass && !cose {
        assert_rederives(input, what);
    }
    report.verdict == Verdict::Pass
}

/// A JSON record that verified is the document its record re-derives
/// (QA QT-01): every object of the text is an object, so the signed payload
/// was re-derived from what the text says, not from another JSON shape. A
/// text the record reader refuses re-derives nothing, and fails too.
fn assert_rederives(input: &[u8], what: &str) {
    let text = std::str::from_utf8(input).unwrap_or_default();
    let written = serde_json::from_str::<Value>(text).ok();
    let rederived = Record::from_json(text).ok().and_then(|record| serde_json::to_value(record).ok());
    assert!(
        rederived.is_some() && written == rederived,
        "{what}: a passing JSON mutant is not the document its record re-derives: {text}"
    );
}

/// Returns how many mutants passed (they must all carry genuine payloads).
fn run_record_target(cose: bool, iterations: usize, seed_value: u64, reading: Reading) -> usize {
    let seeds: Vec<Seed> = seeds().into_iter().filter(|s| s.cose == cose).collect();
    assert!(!seeds.is_empty());
    let genuine = genuine_payload_hashes();
    let names: BTreeSet<String> = seeds.iter().map(|s| s.store.clone()).collect();
    let verifiers: std::collections::BTreeMap<String, Verifier> =
        names.into_iter().map(|n| (n.clone(), Verifier::new(store(&n)))).collect();
    let mut rng = Lcg(seed_value);
    let mut passed = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds);
        let mutant = match (cose, rng.below(3)) {
            (false, 0) => json_mutation(&mut rng, &seed.bytes),
            (true, 0) => cbor_mutation(&mut rng, &seed.bytes),
            _ => byte_mutation(&mut rng, seed.bytes.clone()),
        };
        let t = Timestamp::parse(&seed.t).unwrap();
        if check_report(&verifiers[&seed.store], &mutant, cose, t, &genuine, &format!("iteration {i}"), reading) {
            passed += 1;
        }
    }
    passed
}

fn store_seeds() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = std::fs::read_dir(vectors_dir().join("verify/trust-stores"))
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    out.sort();
    for c in cases("trust-store/cases.json") {
        let bytes = input_bytes(&c["input"]);
        if bytes.len() <= 64 * 1024 {
            out.push(bytes);
        }
    }
    out
}

/// Returns how many mutants wrote an object as the array of its values (none
/// may load).
fn run_trust_store_target(iterations: usize, seed_value: u64) -> usize {
    let seeds = store_seeds();
    let mut rng = Lcg(seed_value);
    let mut respellings = 0;
    for i in 0..iterations {
        let seed = rng.pick(&seeds);
        let (mutant, respelled) =
            if rng.below(2) == 0 { json_edit(&mut rng, seed) } else { (byte_mutation(&mut rng, seed.clone()), false) };
        respellings += usize::from(respelled);
        let loaded = std::panic::catch_unwind(|| TrustStore::from_json(&mutant).map(|s| s.sha256().to_string()));
        match loaded {
            Err(_) => panic!("iteration {i}: the loader PANICKED on {}", hex::encode(&mutant)),
            Ok(Ok(hash)) => {
                // QA QT-01 QJ-03 (trust-store format §3 kind 4): a store with
                // an object written as the array of its values never loads.
                assert!(
                    !respelled,
                    "iteration {i}: a store with an object written as an array loaded: {}",
                    String::from_utf8_lossy(&mutant)
                );
                // Loading is deterministic.
                assert_eq!(TrustStore::from_json(&mutant).unwrap().sha256(), hash, "iteration {i}");
            }
            Ok(Err(e)) => assert!(e.to_string().starts_with("trust_store."), "iteration {i}: {e}"),
        }
    }
    respellings
}

fn run_chain_target(iterations: usize, seed_value: u64, reading: Reading) {
    // The lineage path: a fixed head (P2) with a mutated predecessor.
    let p1 = common::vector();
    let p2 = generate::successor(&p1, generate::U2, "2026-09-10T12:00:00Z", "training-update", common::KEY_A);
    let head = common::json_of(&p2);
    let p1_bytes = [common::json_of(&p1), p1.to_cose().unwrap()];
    let p1_hash = p1.signed_payload_hash().unwrap();
    let verifier = Verifier::new(store("ts-basic"));
    let t = Timestamp::parse(common::T).unwrap();
    let mut rng = Lcg(seed_value);
    for i in 0..iterations {
        let k = rng.below(2);
        let mutant = if k == 0 { json_mutation(&mut rng, &p1_bytes[0]) } else { cbor_mutation(&mut rng, &p1_bytes[1]) };
        let read = as_read(&mutant, k == 1, reading);
        let previous: [&[u8]; 1] = [&read];
        let opts = VerifyOptions::new(t).with_previous(&previous).require_complete_lineage(true);
        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verifier.verify(&head, &opts)))
            .unwrap_or_else(|_| panic!("iteration {i}: PANIC on predecessor {}", hex::encode(&mutant)));
        if report.verdict == Verdict::Pass {
            let links = &report.lineage.as_ref().unwrap().verified_links;
            assert_eq!(links[0].signed_payload_hash, p1_hash, "iteration {i}");
            if k == 0 {
                assert_rederives(&mutant, &format!("iteration {i}, the predecessor"));
            }
        }
    }
}

#[test]
fn the_seeds_include_general_records_in_both_forms() {
    // Task 10.11b: records in the general model description (spec §7.3)
    // seed the JSON and the COSE targets, here and in the release runs, as the
    // verification vectors carry them; so do their predecessors.
    let seeds = seeds();
    for cose in [false, true] {
        let general = seeds
            .iter()
            .filter(|s| s.cose == cose && s.bytes.windows(b"safetensors".len()).any(|w| w == b"safetensors"))
            .count();
        assert!(general >= 1, "no general record among the {} seeds", if cose { "COSE" } else { "JSON" });
    }
}

#[test]
fn json_mutants_never_panic_and_never_pass_unsigned_content() {
    let passed = run_record_target(false, NORMAL_RUN, 0x4b48_414c_4d01, Reading::Verifier);
    // Re-serializations of passing seeds do pass: the "genuine payload"
    // oracle is exercised, not vacuous.
    assert!(passed > 0, "no JSON mutant passed: the pass oracle never ran");
    eprintln!("json: {passed} of {NORMAL_RUN} mutants passed, all with genuine payloads");
}

/// Runs `run` against a verifier that reads a record from the array of its
/// values ([`Reading::Lenient`]): how many texts it read so, and the message
/// the run failed with, if it failed.
fn run_lenient(run: impl FnOnce(Reading)) -> (usize, Option<String>) {
    let lenient_reads = Cell::new(0);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(Reading::Lenient(&lenient_reads))));
    let failure = outcome.err().map(|payload| payload.downcast_ref::<String>().cloned().unwrap_or_default());
    (lenient_reads.get(), failure)
}

#[test]
fn the_rederivation_oracle_fails_a_verifier_that_reads_a_record_from_an_array() {
    // QA QT-01 QJ-03. A JSON record or predecessor with an object written as
    // the array of its values carries a genuine signed payload, so of this
    // harness's oracles only the re-derivation oracle notices a verifier that
    // reads one. Both JSON targets run here, with their normal seeds, against
    // such a verifier: the respelling strategy must write records it reads,
    // and the oracle must fail each run on the first that passes.
    for (target, (lenient_reads, failure)) in [
        (
            "the JSON target",
            run_lenient(|reading| {
                run_record_target(false, NORMAL_RUN, 0x4b48_414c_4d01, reading);
            }),
        ),
        ("the chain target", run_lenient(|reading| run_chain_target(NORMAL_RUN / 10, 0x4b48_414c_4d04, reading))),
    ] {
        assert!(
            lenient_reads > 0,
            "{target}: no text the record reader refuses was read as a record by serde_json's derive: \
             no respelling was written, or the record reader reads one"
        );
        let failure = failure.unwrap_or_else(|| {
            panic!("{target}: a verifier that reads a record from an array passed the run: the re-derivation oracle did not fire")
        });
        assert!(failure.contains("is not the document its record re-derives"), "{target} failed otherwise: {failure}");
    }
}

#[test]
fn cose_mutants_never_panic_and_never_pass_non_canonical_envelopes() {
    let passed = run_record_target(true, NORMAL_RUN, 0x4b48_414c_4d02, Reading::Verifier);
    eprintln!("cose: {passed} of {NORMAL_RUN} mutants passed, all canonical and genuine");
}

#[test]
fn trust_store_mutants_never_panic() {
    let respelled = run_trust_store_target(NORMAL_RUN, 0x4b48_414c_4d03);
    // The respelling oracle ran (QA QT-01 QJ-03).
    assert!(respelled > 0, "no store was written with an object as an array: the oracle never ran");
    eprintln!("trust store: {respelled} of {NORMAL_RUN} mutants wrote an object as an array, and none loaded");
}

#[test]
fn chain_mutants_never_panic_and_never_link_unsigned_content() {
    run_chain_target(NORMAL_RUN / 10, 0x4b48_414c_4d04, Reading::Verifier);
}

#[test]
fn the_oversized_and_the_deepest_inputs_are_rejected_cheaply() {
    let verifier = Verifier::new(store("ts-basic"));
    let t = Timestamp::parse(common::T).unwrap();
    let genuine = genuine_payload_hashes();
    let huge = vec![b' '; 8 * 1024 * 1024];
    check_report(&verifier, &huge, false, t, &genuine, "8 MiB of spaces", Reading::Verifier);
    let deep = format!("{{\"a\":{}{}}}", "[".repeat(1_000_000), "]".repeat(1_000_000)).into_bytes();
    check_report(&verifier, &deep, false, t, &genuine, "1 000 000-deep JSON", Reading::Verifier);
    let deep_cbor = [vec![0x84], vec![0x81; 1_000_000]].concat();
    check_report(&verifier, &deep_cbor, true, t, &genuine, "1 000 000-deep CBOR", Reading::Verifier);
}

#[test]
#[ignore = "the Doctrine L3 release bar: >= 1 000 000 mutations per target; run with --release -- --ignored"]
fn one_million_mutations_per_target() {
    run_record_target(false, RELEASE_RUN, 0x4c33_0001, Reading::Verifier);
    run_record_target(true, RELEASE_RUN, 0x4c33_0002, Reading::Verifier);
    assert!(run_trust_store_target(RELEASE_RUN, 0x4c33_0003) > 0, "no store was written with an object as an array");
    run_chain_target(RELEASE_RUN / 10, 0x4c33_0004, Reading::Verifier);
}
