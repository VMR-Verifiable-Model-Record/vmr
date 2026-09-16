// tests/robustness.rs — a deterministic mutation harness over vmr-policy's
// two entry points, `load_pack` and `evaluate` (QA Q6-04). A pack is a
// document from a stranger, and so is the record it is evaluated against:
// neither may crash the evaluator, and no mutant may break a promise the
// crate makes about its answers. Modelled on vmr-verify/tests/robustness.rs
// (Phase 4, D8) and adapted from the Phase 6 QA's stand-in,
// QA/repro/p6qa_robust.rs. DEV_PLAN §5.7 names fuzz_policy_eval; the
// doctrine's bar is >= 1 000 000 iterations per parser.
//
// The generator is an explicit LCG with fixed seeds (no `rand`): every run
// tries the same inputs.
//
// Loader target. Seeds: the five committed reference packs, a pack covering
// all seven rule types, and that pack signed. Mutators: bit flips, byte
// overwrites, truncation, insertion, duplication and deletion; structural
// JSON edits (a member dropped, duplicated or retyped, a 100 000-character
// or control-character string, 127- to 100 000-deep nesting, an injected
// member, a value wrapped in an array); number spellings in
// `minimum_chain_length`; words in `severity` and `minimum_level`; rule
// lists duplicated or emptied; flags; format versions; a byte order mark;
// one object (the pack, its authority, its signature section or a rule)
// written as the array of its values (QA QT-01 QJ-03).
// Oracles: never a panic; a refusal carries a message, with no raw
// character a terminal acts on or hides (QA Q6-10); a pack with an object
// written as the array of its values is refused as refusal 2, since every
// seed loads and it breaks nothing else (QA QT-01 QJ-03); an accepted pack
// reloads identically; its JCS form (the bytes an authority signs) reloads
// as the same pack with the same payload hash; a mutant whose signature
// still verifies is the seed's pack; every accepted pack evaluates under
// every evaluation oracle below, against the conformance record, the
// Gate 5 record and `null`, and its converted section validates against
// the record schema.
//
// Evaluator target. Seeds: the conformance record and the Gate 5
// record, against the five reference packs and two synthetic packs that
// cover all seven rule types. Mutators: a member a rule reads removed, or
// replaced by a value of every JSON type; the structural edits above; the
// whole record replaced by a non-object. Oracles: never a panic; the
// evaluation is deterministic; one result per rule, in the pack's order,
// naming its rule; every `evidence_hash` is the SHA-256 of the JCS form of
// the P6-3 pointer values, the lists written out again here (absent = null);
// the overall status is the mandatory-only aggregation; `indeterminate`
// lists exactly the indeterminate rules; `to_policy_compliance` carries
// exactly the decided ones; a member is called "not declared" only when it
// is absent, of another JSON type, or empty; data_residency,
// source_screening and attestation_level give the status P6-3's table
// gives, recomputed here; removing a member a rule reads never turns a pass
// into a fail; a record that is not an object decides no rule.
//
// Normal run: 20 000 mutations per target (two tests, run in parallel).
// Release bar:
//     cargo test --release -p vmr-policy --test robustness -- --ignored

mod common;

use common::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use vmr_policy::vmr_record::canonical::jcs;
use vmr_policy::vmr_record::encoding::b64url_encode;
use vmr_policy::vmr_record::hash::{format_hash, sha256};
use vmr_policy::vmr_record::record::Record;
use vmr_policy::vmr_record::timestamp::Timestamp;
use vmr_policy::vmr_record::{jwk, sign};
use vmr_policy::{
    load_pack, signing, Evaluation, EvaluationContext, LineageContext, LineageOutcome, LoadedPack, PolicyPack, Refusal,
    Rule, Severity, Status, VerifiedPredecessor,
};

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

// ---------------------------------------------------------------------------
//  What a run saw
// ---------------------------------------------------------------------------

/// Counts, and every oracle that failed with its first few samples. A target
/// runs to the end and reports every kind of failure at once.
#[derive(Default)]
struct Findings {
    counts: BTreeMap<String, u64>,
    failures: BTreeMap<String, (u64, Vec<String>)>,
}

impl Findings {
    fn count(&mut self, what: &str) {
        *self.counts.entry(what.to_string()).or_default() += 1;
    }

    fn counted(&self, what: &str) -> u64 {
        self.counts.get(what).copied().unwrap_or(0)
    }

    fn fail(&mut self, oracle: &str, sample: String) {
        let entry = self.failures.entry(oracle.to_string()).or_default();
        entry.0 += 1;
        if entry.1.len() < 3 {
            entry.1.push(sample);
        }
    }

    fn summary(&self, title: &str) -> String {
        let mut out = format!("{title}\ncounts:\n");
        for (k, v) in &self.counts {
            out.push_str(&format!("  {v:>9}  {k}\n"));
        }
        out.push_str(&format!("oracle failures:{}\n", if self.failures.is_empty() { " none" } else { "" }));
        for (k, (n, samples)) in &self.failures {
            out.push_str(&format!("  {n:>9}  {k}\n"));
            for s in samples {
                out.push_str(&format!("             e.g. {s}\n"));
            }
        }
        out
    }

    fn assert_clean(&self, title: &str) {
        let summary = self.summary(title);
        eprintln!("{summary}");
        assert!(self.failures.is_empty(), "{summary}");
    }
}

/// `s` safe to print: terminal-unsafe characters, CR, LF and TAB as
/// `\u{..}`, cut at `max` characters.
fn shown(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push_str(&format!("...[{} chars]", s.chars().count()));
            break;
        }
        if is_terminal_unsafe(c) {
            out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------------------
//  Seeds
// ---------------------------------------------------------------------------

fn authority_key() -> p256::ecdsa::SigningKey {
    sign::signing_key_from_secret(&sha256(b"vmr-policy robustness authority key")).expect("a derived test key")
}

/// One rule of each of the seven types.
fn all_rule_types() -> Value {
    json!([
        {"type":"documentation_declared","rule_id":"all-dd","description":"d","severity":"mandatory","reference":"robustness 7","document":"data_governance"},
        {"type":"data_residency","rule_id":"all-dr","description":"d","severity":"mandatory","reference":"robustness 1","allowed_jurisdictions":["PH","US"]},
        {"type":"source_screening","rule_id":"all-ss","description":"d","severity":"recommended","reference":"robustness 2","restricted_list":["CN","scraped"]},
        {"type":"export_control","rule_id":"all-ec","description":"d","severity":"mandatory","reference":"robustness 3","require_air_gapped":true,"require_egress_denied":true},
        {"type":"audit_integrity","rule_id":"all-ai","description":"d","severity":"informational","reference":"robustness 4","minimum_chain_length":2,"require_tamper_evident":true,"require_input_committed":true,"require_ordered_record":true,"require_verified_lineage":true},
        {"type":"execution_integrity","rule_id":"all-ei","description":"d","severity":"mandatory","reference":"robustness 5","require_learned_state_components":true,"require_environment_pinned":true,"require_tee":true,"require_state_kept":true},
        {"type":"attestation_level","rule_id":"all-al","description":"d","severity":"recommended","reference":"robustness 6","minimum_level":"hardware"}
    ])
}

/// The same seven types with other severities and the weakest settings a
/// loaded pack may hold.
fn relaxed_rule_types() -> Value {
    json!([
        {"type":"documentation_declared","rule_id":"r-dd","description":"d","severity":"informational","reference":"robustness","document":"human_oversight"},
        {"type":"data_residency","rule_id":"r-dr","description":"d","severity":"recommended","reference":"robustness","allowed_jurisdictions":["ZZ"]},
        {"type":"source_screening","rule_id":"r-ss","description":"d","severity":"mandatory","reference":"robustness","restricted_list":["sensor_stream"]},
        {"type":"export_control","rule_id":"r-ec","description":"d","severity":"informational","reference":"robustness","require_egress_denied":true},
        {"type":"audit_integrity","rule_id":"r-ai","description":"d","severity":"mandatory","reference":"robustness","minimum_chain_length":1,"require_verified_lineage":true},
        {"type":"execution_integrity","rule_id":"r-ei","description":"d","severity":"recommended","reference":"robustness","require_tee":true,"require_state_kept":true},
        {"type":"attestation_level","rule_id":"r-al","description":"d","severity":"mandatory","reference":"robustness","minimum_level":"software"}
    ])
}

fn synthetic_pack(pack_id: &str, rules: Value) -> Value {
    let mut document = pack_document(rules);
    document["pack_id"] = json!(pack_id);
    document
}

/// `document` signed by the authority key over vmr-policy's signed payload
/// (the document without `/signature`, JCS).
fn signed(mut document: Value) -> Value {
    if let Some(o) = document.as_object_mut() {
        o.remove("signature");
    }
    let k = authority_key();
    let payload = signing::signed_payload(&document);
    let signature = sign::sign(&k, payload.as_bytes()).expect("ES256");
    document["signature"] = json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", b64url_encode(&signature.to_bytes())),
        "signed_payload_hash": signing::payload_hash(&document),
        "signing_key_id": jwk::key_id(k.verifying_key()),
    });
    document
}

fn conformance() -> Record {
    serde_json::from_value(conformance_record()).expect("the conformance record")
}

/// The committed Gate 5 artifact, read only.
fn gate5() -> Record {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../vmr-cli/tests/data/gate5/model.vmr");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Record::from_cose(&bytes).expect("the Gate 5 artifact is a record")
}

/// The general description's conformance record (task 10.11b), read only:
/// a model of four synthetic files, not-held training records.
fn general() -> Record {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../specs/test-vectors/record/example-general-v0.1.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let file: Value = serde_json::from_str(&text).unwrap();
    serde_json::from_value(file["record"].clone()).expect("the general conformance record")
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

/// Every object in a JSON value, by RFC 6901 pointer.
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

const SPELLINGS: [&str; 16] = [
    "0",
    "1",
    "-0",
    "1e2",
    "1E2",
    "1.0",
    "100.0",
    "-1",
    "9007199254740991",
    "9007199254740992",
    "9007199254740993",
    "18446744073709551615",
    "18446744073709551616",
    "1e400",
    "0.5",
    "\"1\"",
];
const WORDS: [&str; 10] =
    ["mandatory", "Mandatory", "recommended", "informational", "self", "software", "hardware", "root", "", "\u{1b}[31m"];
const PLACEHOLDER: &str = "__ROBUSTNESS_PLACEHOLDER_NUMBER__";

/// A structural edit of a JSON value; returns the text to use.
fn generic_json(rng: &mut Lcg, v: &mut Value) -> String {
    let mut objs = Vec::new();
    objects(v, "", &mut objs);
    if objs.is_empty() {
        return serde_json::to_string(v).unwrap();
    }
    let at = rng.pick(&objs).clone();
    let choice = rng.below(9);
    let mut textual: Option<(String, &str)> = None; // (member name, "dup" or "deep")
    {
        let Some(obj) = v.pointer_mut(&at).and_then(Value::as_object_mut) else {
            return serde_json::to_string(v).unwrap();
        };
        let keys: Vec<String> = obj.keys().cloned().collect();
        let key = if keys.is_empty() { "x".to_string() } else { rng.pick(&keys).clone() };
        match choice {
            0 => {
                obj.remove(&key);
            }
            1 => textual = Some((key, "dup")),
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
                obj.insert(key, Value::from("\u{1b}[2J\u{0}\r\n\u{202e}\u{7f}\u{85}\u{2028}\u{feff}"));
            }
            5 => textual = Some((key, "deep")),
            6 => {
                obj.insert(key, Value::from(PLACEHOLDER));
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
    }
    let text = serde_json::to_string(v).unwrap();
    if choice == 6 {
        return text.replacen(&format!("\"{PLACEHOLDER}\""), rng.pick(&SPELLINGS), 1);
    }
    if let Some((key, kind)) = textual {
        let needle = format!("\"{key}\":");
        if let Some(i) = text.find(&needle) {
            return if kind == "dup" {
                format!("{}\"{key}\":null,{}", &text[..i], &text[i..])
            } else {
                let depth = *rng.pick(&[127usize, 128, 129, 100_000]);
                format!("{}\"deep\":{}{},{}", &text[..i], "[".repeat(depth), "]".repeat(depth), &text[i..])
            };
        }
    }
    text
}

/// Each object kind of a pack with its members in the schema's `properties`
/// order, which is the structs' declaration order: the order a reader that
/// takes a record from the array of its fields reads them in. A rule's are its
/// `type` and then every rule member, in `RuleMembers`' order.
const PACK_OBJECT_FIELDS: [(&str, &[&str]); 4] = [
    ("", &["version", "pack_id", "pack_version", "jurisdiction", "description", "disclaimer", "authority", "rules", "signature"]),
    ("/authority", &["authority_id", "authority_name"]),
    ("/signature", &["algorithm", "signature", "signed_payload_hash", "signing_key_id"]),
    (
        "/rules/*",
        &[
            "type",
            "rule_id",
            "description",
            "severity",
            "reference",
            "allowed_jurisdictions",
            "restricted_list",
            "require_air_gapped",
            "require_egress_denied",
            "minimum_chain_length",
            "require_tamper_evident",
            "require_input_committed",
            "require_ordered_record",
            "require_verified_lineage",
            "require_learned_state_components",
            "require_environment_pinned",
            "require_tee",
            "require_state_kept",
            "minimum_level",
            "document",
        ],
    ),
];

/// QA QT-01 QJ-03: one object of `v` written as the array of its values, in
/// the declared order half the time, otherwise in its members' order rotated.
fn respell(rng: &mut Lcg, v: &mut Value) {
    let mut objs = Vec::new();
    objects(v, "", &mut objs);
    if objs.is_empty() {
        return;
    }
    let at = rng.pick(&objs).clone();
    let kind = at.split('/').map(|s| if s.parse::<usize>().is_ok() { "*" } else { s }).collect::<Vec<_>>().join("/");
    let declared = PACK_OBJECT_FIELDS.iter().find(|(k, _)| *k == kind).map(|(_, fields)| *fields);
    let Some(object) = v.pointer_mut(&at).and_then(Value::as_object_mut) else { return };
    let values: Vec<Value> = match declared {
        Some(fields) if rng.below(2) == 0 => fields.iter().filter_map(|f| object.get(*f).cloned()).collect(),
        _ => {
            let mut all: Vec<Value> = object.values().cloned().collect();
            let shift = rng.below(all.len());
            all.rotate_left(shift);
            all
        }
    };
    if let Some(slot) = v.pointer_mut(&at) {
        *slot = Value::Array(values);
    }
}

/// A mutant of `seed`, and whether it is `seed` with one object written as the
/// array of its values.
fn pack_mutation(rng: &mut Lcg, seed: &[u8]) -> (Vec<u8>, bool) {
    let Ok(mut v) = serde_json::from_slice::<Value>(seed) else {
        return (byte_mutation(rng, seed.to_vec()), false);
    };
    let rules_len = v.get("rules").and_then(Value::as_array).map_or(0, Vec::len);
    let mutant = match rng.below(14) {
        0..=8 => generic_json(rng, &mut v).into_bytes(),
        9 if rules_len > 0 => {
            let i = rng.below(rules_len);
            v["rules"][i]["minimum_chain_length"] = Value::from(PLACEHOLDER);
            let text = serde_json::to_string(&v).unwrap();
            text.replacen(&format!("\"{PLACEHOLDER}\""), rng.pick(&SPELLINGS), 1).into_bytes()
        }
        10 if rules_len > 0 => {
            let i = rng.below(rules_len);
            let member = if rng.below(2) == 0 { "severity" } else { "minimum_level" };
            v["rules"][i][member] = Value::from(*rng.pick(&WORDS));
            serde_json::to_vec(&v).unwrap()
        }
        11 if rules_len > 0 => {
            let i = rng.below(rules_len);
            match rng.below(4) {
                0 => {
                    let r = v["rules"][i].clone();
                    v["rules"].as_array_mut().unwrap().push(r);
                }
                1 => v["rules"] = Value::Array(vec![]),
                2 => {
                    let flag = *rng.pick(&[
                        "require_air_gapped",
                        "require_egress_denied",
                        "require_tamper_evident",
                        "require_input_committed",
                        "require_ordered_record",
                        "require_verified_lineage",
                        "require_learned_state_components",
                        "require_environment_pinned",
                        "require_tee",
                        "require_state_kept",
                    ]);
                    v["rules"][i][flag] = Value::Bool(rng.below(2) == 0);
                }
                _ => v["version"] = Value::from(*rng.pick(&["0.1", "0.10", "0.2", "", "0.1 "])),
            }
            serde_json::to_vec(&v).unwrap()
        }
        13 => {
            respell(rng, &mut v);
            return (serde_json::to_vec(&v).unwrap(), true);
        }
        _ => {
            let mut b = vec![0xef, 0xbb, 0xbf];
            b.extend(serde_json::to_vec_pretty(&v).unwrap());
            if rng.below(2) == 0 {
                b.drain(..3);
            }
            b
        }
    };
    (mutant, false)
}

/// Every record member a rule may read (P6-3, P6-17 and task 10.11a),
/// written out again.
const READ_POINTERS: [&str; 26] = [
    "/data_governance",
    "/human_oversight",
    "/learning_provenance/training_input_provenance/data_residency",
    "/learning_provenance/training_input_provenance/data_residency_countries",
    "/learning_provenance/training_input_disclosure",
    "/model_identity/model_hash",
    "/learning_provenance/training_input_provenance/source_type",
    "/deployment_context/inference_boundary/type",
    "/deployment_context/inference_boundary/egress_allowed",
    "/deployment_context/inference_boundary/allowed_egress_destinations",
    "/lineage/lineage_chain_length",
    "/lineage/previous_record_hash",
    "/learning_provenance/training_input_merkle_root",
    "/model_identity/learned_state_hash",
    "/model_identity/learned_state_components",
    "/learning_provenance/training_environment/training_software",
    "/learning_provenance/training_environment/software_hash",
    "/learning_provenance/training_environment/tee_measurement",
    "/issuer/attestation_level",
    "/learning_provenance/training_input_count",
    "/learning_provenance/training_started_at",
    "/learning_provenance/training_ended_at",
    "/learning_provenance/training_input_provenance/collection_period/start",
    "/learning_provenance/training_input_provenance/collection_period/end",
    "/issued_at",
    "/lineage/lineage_type",
];

/// The members E2 makes declared when empty (P6-17): "" is a signed
/// declaration of absence, which fails a requirement for the member.
const EMPTY_IS_DECLARED: [&str; 3] = [
    "/learning_provenance/training_environment/training_software",
    "/learning_provenance/training_environment/software_hash",
    "/learning_provenance/training_environment/tee_measurement",
];

fn junk(rng: &mut Lcg) -> Value {
    match rng.below(25) {
        0 => Value::from(""),
        1 => Value::from(" "),
        2 => Value::from("\u{1b}[2J\u{202e}\u{85}"),
        3 => Value::from("A".repeat(100_000)),
        4 => Value::from(-1),
        5 => Value::from(1.5),
        6 => Value::from(u64::MAX),
        7 => Value::from(0),
        8 => Value::Null,
        9 => Value::Bool(rng.below(2) == 0),
        10 => Value::Array(vec![]),
        11 => json!(["x", 1, null]),
        12 => json!({}),
        13 => {
            let mut d = Value::from(1);
            for _ in 0..120 {
                d = Value::Array(vec![d]);
            }
            d
        }
        14 => Value::from(format!("sha256:{}", "0".repeat(64))),
        15 => Value::from(format!("SHA256:{}", "A".repeat(64))),
        16 => Value::from("air-gapped"),
        17 => Value::from("hardware"),
        18 => Value::from("PH"),
        // A short string that is declared, and one that is declared but can
        // match nothing a pack lists (packs list upper-case codes).
        19 => Value::from("x"),
        20 => Value::from("ph"),
        // P6-17: a time that reorders the record, a state-keeping lineage
        // type, and the empty tree's root.
        21 => Value::from("2026-09-30T00:00:00Z"),
        22 => Value::from(if rng.below(2) == 0 { "deployment" } else { "policy-change" }),
        23 => Value::from(format_hash(&vmr_policy::vmr_record::merkle::empty_root())),
        _ => json!([{"name": "afferent_H", "hash": "x", "size_bytes": 0}, {"size_bytes": -1}]),
    }
}

/// A verification context a library caller could hand in: every outcome,
/// zero to two predecessors, each the seed, the seed with another learned
/// state, or junk.
fn context_mutant(rng: &mut Lcg, seed: &Value) -> EvaluationContext {
    let outcome = *rng.pick(&[
        LineageOutcome::Initial,
        LineageOutcome::Complete,
        LineageOutcome::Partial,
        LineageOutcome::NotChecked,
    ]);
    let predecessors = (0..rng.below(3))
        .map(|_| {
            let record = match rng.below(5) {
                0 => seed.clone(),
                1 => {
                    let mut other = seed.clone();
                    if let Some(slot) = other.pointer_mut("/model_identity/learned_state_hash") {
                        *slot = json!(format!("sha256:{:064x}", rng.next()));
                    }
                    other
                }
                2 => json!(7),
                3 => Value::Null,
                _ => {
                    // Past the depth bound (128) or within it.
                    let mut deep = json!("sha256:");
                    for _ in 0..(120 + rng.below(20)) {
                        deep = Value::Array(vec![deep]);
                    }
                    json!({"model_identity": {"learned_state_hash": deep}})
                }
            };
            VerifiedPredecessor { signed_payload_hash: format!("sha256:{:064x}", rng.next()), record }
        })
        .collect();
    EvaluationContext { lineage: LineageContext { outcome, predecessors } }
}

/// How a record mutant was made.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// A member a rule reads was removed.
    Removed,
    /// A member a rule reads was replaced by junk.
    Replaced,
    /// A structural edit anywhere.
    Structural,
    /// An E2 member was set to "" (P6-17).
    Emptied,
    /// The seed made a successor: a longer chain, a predecessor hash, a
    /// lineage type, sometimes another learned state (P6-17).
    Successor,
    /// The whole record is not an object.
    NotAnObject,
}

fn record_mutation(rng: &mut Lcg, seed: &Value) -> (Value, Mode, Option<&'static str>) {
    let mut v = seed.clone();
    match rng.below(14) {
        12 | 13 => {
            // Both seeds are initial records, so without this no rule that
            // reads the lineage would meet a chain it has to have verified.
            let kind = *rng.pick(&["training-update", "fine-tune", "quantization", "deployment", "policy-change"]);
            let length = 2 + rng.below(4) as u64;
            let previous_hash = format!("sha256:{:064x}", rng.next());
            let other_state = format!("sha256:{:064x}", rng.next());
            let change_state = rng.below(2) == 0;
            if let Some(lineage) = v.pointer_mut("/lineage").and_then(Value::as_object_mut) {
                lineage.insert("lineage_type".into(), json!(kind));
                lineage.insert("lineage_chain_length".into(), json!(length));
                lineage.insert("previous_record_hash".into(), json!(previous_hash));
                lineage.insert("previous_record_id".into(), json!("urn:uuid:00000000-0000-4000-8000-00000000abcd"));
            }
            if change_state {
                for p in ["/model_identity/learned_state_hash", "/model_identity/model_hash"] {
                    if let Some(slot) = v.pointer_mut(p) {
                        *slot = json!(other_state);
                    }
                }
            }
            (v, Mode::Successor, None)
        }
        9 | 10 => {
            let p = *rng.pick(&EMPTY_IS_DECLARED);
            if let Some(slot) = v.pointer_mut(p) {
                *slot = json!("");
            }
            (v, Mode::Emptied, Some(p))
        }
        0..=3 => {
            let p = *rng.pick(&READ_POINTERS);
            let (parent, key) = p.rsplit_once('/').unwrap();
            if let Some(o) = v.pointer_mut(parent).and_then(Value::as_object_mut) {
                o.remove(key);
            }
            (v, Mode::Removed, Some(p))
        }
        4..=6 => {
            let p = *rng.pick(&READ_POINTERS);
            let j = junk(rng);
            if let Some(slot) = v.pointer_mut(p) {
                *slot = j;
            }
            (v, Mode::Replaced, None)
        }
        7 | 8 => {
            let text = generic_json(rng, &mut v);
            match serde_json::from_str::<Value>(&text) {
                Ok(parsed) => (parsed, Mode::Structural, None),
                Err(_) => (v, Mode::Structural, None),
            }
        }
        _ => {
            let j = match rng.below(4) {
                0 => Value::Null,
                1 => json!([]),
                2 => json!("record"),
                _ => json!(42),
            };
            (j, Mode::NotAnObject, None)
        }
    }
}

// ---------------------------------------------------------------------------
//  Oracles, written from P6-2 and P6-3 rather than read back from the crate
// ---------------------------------------------------------------------------

/// P6-3's "Reads" column as P6-17 extends it, in hash order.
fn p6_3_pointers(rule_type: &str) -> &'static [&'static str] {
    match rule_type {
        "data_residency" => &[
            "/learning_provenance/training_input_provenance/data_residency",
            "/learning_provenance/training_input_provenance/data_residency_countries",
        ],
        "source_screening" => &[
            "/learning_provenance/training_input_provenance/source_type",
            "/learning_provenance/training_input_provenance/data_residency",
            "/learning_provenance/training_input_provenance/data_residency_countries",
        ],
        "export_control" => &[
            "/deployment_context/inference_boundary/type",
            "/deployment_context/inference_boundary/egress_allowed",
            "/deployment_context/inference_boundary/allowed_egress_destinations",
        ],
        "audit_integrity" => &[
            "/lineage/lineage_chain_length",
            "/lineage/previous_record_hash",
            "/learning_provenance/training_input_merkle_root",
            "/learning_provenance/training_input_count",
            "/learning_provenance/training_started_at",
            "/learning_provenance/training_ended_at",
            "/learning_provenance/training_input_provenance/collection_period/start",
            "/learning_provenance/training_input_provenance/collection_period/end",
            "/issued_at",
            "/learning_provenance/training_input_disclosure",
        ],
        "execution_integrity" => &[
            "/model_identity/learned_state_hash",
            "/model_identity/learned_state_components",
            "/learning_provenance/training_environment/training_software",
            "/learning_provenance/training_environment/software_hash",
            "/learning_provenance/training_environment/tee_measurement",
            "/lineage/lineage_type",
            "/model_identity/model_hash",
        ],
        "attestation_level" => &["/issuer/attestation_level"],
        // Task 10.11a (D11-4): both members, whichever one a rule names.
        "documentation_declared" => &["/data_governance", "/human_oversight"],
        _ => &[],
    }
}

/// Task 10.11a (D11-4), written out from the plan rather than read back
/// from the crate: a record that is not an object, or a read nested past
/// 128 levels, is indeterminate; the named member absent from an object
/// record fails; present but not an object, or without a declared string
/// `documentation_hash`, indeterminate; a hash string (lower-case `sha256:`,
/// 64 hex digits in either case) passes, any other string fails.
fn documentation_status(document: &str, record: &Value) -> Status {
    let Some(object) = record.as_object() else { return Status::Indeterminate };
    if p6_3_pointers("documentation_declared").iter().any(|p| record.pointer(p).is_some_and(|v| nesting(v) > 128)) {
        return Status::Indeterminate;
    }
    let Some(member) = object.get(document) else { return Status::Fail };
    let Some(hash) = member.get("documentation_hash").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Status::Indeterminate;
    };
    let is_hash = hash.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if is_hash {
        Status::Pass
    } else {
        Status::Fail
    }
}

/// P6-2: one pointer hashes its value, several the array of their values,
/// and a pointer that resolves to nothing contributes `null`. P6-17: the two
/// context-reading types add the context slot - `null` without context;
/// `audit_integrity`'s the outcome word and each predecessor's signed-payload
/// hash; `execution_integrity`'s the immediate predecessor's `model_hash`
/// (task 10.12a).
fn p6_2_evidence_hash(record: &Value, rule_type: &str, context: Option<&EvaluationContext>) -> String {
    // Only a context that adds something to the record fills the slot.
    let context = context.filter(|c| context_applies(c, record));
    let mut values: Vec<Value> =
        p6_3_pointers(rule_type).iter().map(|p| record.pointer(p).cloned().unwrap_or(Value::Null)).collect();
    let word = |o: LineageOutcome| match o {
        LineageOutcome::Initial => "initial",
        LineageOutcome::Complete => "complete",
        LineageOutcome::Partial => "partial",
        LineageOutcome::NotChecked => "not_checked",
    };
    match rule_type {
        "audit_integrity" => values.push(match context {
            None => Value::Null,
            Some(c) => {
                let mut slot = vec![json!(word(c.lineage.outcome))];
                slot.extend(c.lineage.predecessors.iter().map(|p| json!(p.signed_payload_hash)));
                Value::Array(slot)
            }
        }),
        // A value nested past 128 levels is not read (QA Q6-04).
        "execution_integrity" => values.push(
            context
                .and_then(|c| c.lineage.predecessors.first())
                .and_then(|p| p.record.pointer("/model_identity/model_hash"))
                .filter(|v| nesting(v) <= 128)
                .cloned()
                .unwrap_or(Value::Null),
        ),
        _ => {}
    }
    let value = if values.len() == 1 { values[0].clone() } else { Value::Array(values) };
    format_hash(&sha256(jcs(&value).as_bytes()))
}

/// How many levels of arrays and objects `v` nests, itself counting as one.
/// Recursive: the harness only builds values a few hundred levels deep.
fn nesting(v: &Value) -> usize {
    match v {
        Value::Array(items) => 1 + items.iter().map(nesting).max().unwrap_or(0),
        Value::Object(members) => 1 + members.values().map(nesting).max().unwrap_or(0),
        _ => 0,
    }
}

/// Whether the member at `pointer` is declared in the sense of P6-3: present,
/// of the JSON type the rule reads it as, and not empty where emptiness means
/// "not said". P6-17 (E2): an empty environment member is declared.
fn declared(pointer: &str, value: Option<&Value>) -> bool {
    let Some(v) = value else { return false };
    match pointer {
        "/deployment_context/inference_boundary/egress_allowed" => v.is_boolean(),
        "/deployment_context/inference_boundary/allowed_egress_destinations" => v.is_array(),
        "/model_identity/learned_state_components" => v.as_array().is_some_and(|a| !a.is_empty()),
        "/learning_provenance/training_input_provenance/data_residency_countries" => {
            v.as_array().is_some_and(|a| !a.is_empty() && a.iter().all(|c| c.as_str().is_some_and(|s| !s.is_empty())))
        }
        "/lineage/lineage_chain_length" | "/learning_provenance/training_input_count" => count(Some(v)).is_some(),
        p if EMPTY_IS_DECLARED.contains(&p) => v.is_string(),
        _ => v.as_str().is_some_and(|s| !s.is_empty()),
    }
}

/// P6-17, made normative on 2026-09-13: a context adds something to a
/// record only with an outcome other than initial, for a record whose
/// `lineage_chain_length` is a count of 2 or more. On every verified record
/// a chain of 1 is exactly an initial record (spec §6.5, check 20), so any
/// other context adds nothing, and is neither hashed nor read.
fn context_applies(c: &EvaluationContext, record: &Value) -> bool {
    c.lineage.outcome != LineageOutcome::Initial
        && count(record.pointer("/lineage/lineage_chain_length")).is_some_and(|n| n >= 2)
}

/// A count as the format document's §5 defines it: a JSON integer from 0 to
/// 2^53 - 1 (QA Q7-05 S2, the owner, 2026-09-13). Written out here rather
/// than taken from the library.
fn count(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).filter(|n| *n <= 9_007_199_254_740_991)
}

/// P6-17: a setting that reads context passes only on what verification
/// established. `require_verified_lineage` needs the outcome initial or
/// complete, or, with no context, a chain of one; `require_state_kept` on a
/// deployment or policy-change record needs a verified immediate
/// predecessor with the same learned state. Returns the setting when a pass
/// is not allowed by that.
fn pass_without_what_verification_established(
    rule: &Rule,
    record: &Value,
    context: Option<&EvaluationContext>,
) -> Option<&'static str> {
    let context = context.filter(|c| context_applies(c, record));
    match rule {
        Rule::AuditIntegrity(r) if r.require_verified_lineage => {
            let length = count(record.pointer("/lineage/lineage_chain_length"));
            let allowed = match context {
                Some(c) => matches!(c.lineage.outcome, LineageOutcome::Initial | LineageOutcome::Complete),
                None => length == Some(1),
            };
            (!allowed).then_some("require_verified_lineage")
        }
        Rule::ExecutionIntegrity(r) if r.require_state_kept => {
            let kind = record.pointer("/lineage/lineage_type").and_then(Value::as_str);
            if !matches!(kind, Some("deployment") | Some("policy-change")) {
                return None;
            }
            let own = record.pointer("/model_identity/model_hash").and_then(Value::as_str);
            let theirs = context
                .and_then(|c| c.lineage.predecessors.first())
                .and_then(|p| p.record.pointer("/model_identity/model_hash"))
                .and_then(Value::as_str);
            let same = matches!((own, theirs), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b));
            (!same).then_some("require_state_kept")
        }
        _ => None,
    }
}

/// The status P6-3's table gives, for the three rule types whose answer
/// depends neither on flags nor on the order of their checks.
fn p6_3_status(rule: &Rule, record: &Value) -> Option<Status> {
    let string = |p: &str| record.pointer(p).and_then(Value::as_str).filter(|s| !s.is_empty());
    let rank = |level: &str| ["self", "software", "hardware"].iter().position(|l| *l == level);
    // Task 10.12a (D12a-4): the residency is the one code and each code of
    // the countries list. A list is read when it is an array: empty, or
    // holding anything but a non-empty string, it said nothing checkable.
    let residency = || -> Option<Vec<&str>> {
        let mut codes: Vec<&str> = string("/learning_provenance/training_input_provenance/data_residency").into_iter().collect();
        if let Some(list) = record.pointer("/learning_provenance/training_input_provenance/data_residency_countries").and_then(Value::as_array) {
            if list.is_empty() {
                return None;
            }
            for code in list {
                codes.push(code.as_str().filter(|s| !s.is_empty())?);
            }
        }
        (!codes.is_empty()).then_some(codes)
    };
    match rule {
        Rule::DataResidency(r) => Some(match residency() {
            None => Status::Indeterminate,
            Some(codes) if codes.iter().all(|d| r.allowed_jurisdictions.iter().any(|a| a == d)) => Status::Pass,
            Some(_) => Status::Fail,
        }),
        Rule::SourceScreening(r) => Some(
            match (string("/learning_provenance/training_input_provenance/source_type"), residency()) {
                (Some(t), Some(codes)) if r.restricted_list.iter().any(|x| x == t || codes.contains(&x.as_str())) => Status::Fail,
                (Some(_), Some(_)) => Status::Pass,
                _ => Status::Indeterminate,
            },
        ),
        Rule::AttestationLevel(r) => Some(match (string("/issuer/attestation_level").and_then(rank), rank(&r.minimum_level)) {
            (Some(have), Some(want)) if have >= want => Status::Pass,
            (Some(_), Some(_)) => Status::Fail,
            _ => Status::Indeterminate,
        }),
        _ => None,
    }
}

/// Mandatory rules only: any fail is a fail, else any indeterminate is
/// indeterminate, else a pass.
fn mandatory_only(pack: &PolicyPack, e: &Evaluation) -> Status {
    let mut indeterminate = false;
    for (rule, r) in pack.rules.iter().zip(&e.results) {
        if rule.common().severity != Severity::Mandatory {
            continue;
        }
        match r.status {
            Status::Fail => return Status::Fail,
            Status::Indeterminate => indeterminate = true,
            Status::Pass => {}
        }
    }
    if indeterminate {
        Status::Indeterminate
    } else {
        Status::Pass
    }
}

/// Evaluate `record` twice, in `context` when there is one, under every
/// evaluation oracle; returns the evaluation when there was one.
fn check_evaluation(
    f: &mut Findings,
    loaded: &LoadedPack,
    record: &Value,
    context: Option<&EvaluationContext>,
    t: Timestamp,
    what: &str,
) -> Option<Evaluation> {
    let once = || match context {
        Some(c) => loaded.evaluate_in_context(record, c, t),
        None => loaded.evaluate(record, t),
    };
    let run = catch_unwind(AssertUnwindSafe(|| (once(), once())));
    let Ok((e, again)) = run else {
        f.fail("evaluate panicked", format!("{what}: pack {}", shown(&loaded.pack_id, 60)));
        return None;
    };
    check_results(f, loaded.pack(), record, context, &e, &again, what);
    Some(e)
}

/// Every evaluation oracle on `e`, which `pack` gave for `record` in
/// `context` (and `again`, the same evaluation run a second time).
fn check_results(
    f: &mut Findings,
    pack: &PolicyPack,
    record: &Value,
    context: Option<&EvaluationContext>,
    e: &Evaluation,
    again: &Evaluation,
    what: &str,
) {
    f.count("evaluations");
    if e != again {
        f.fail("the evaluation is deterministic", what.to_string());
    }
    if e.results.len() != pack.rules.len() {
        f.fail("one result per rule", what.to_string());
        return;
    }
    for (rule, r) in pack.rules.iter().zip(&e.results) {
        if r.rule_id != rule.rule_id() || r.rule_type != rule.rule_type() || r.severity != rule.common().severity {
            f.fail("results come in the pack's order, naming their rule", format!("{what}: {}", shown(&r.rule_id, 60)));
        }
        if r.evidence_hash != p6_2_evidence_hash(record, rule.rule_type(), context) {
            f.fail("evidence_hash is the P6-2 hash of the P6-3 pointers", format!("{what}: {}", rule.rule_type()));
        }
        if r.status == Status::Pass {
            if let Some(setting) = pass_without_what_verification_established(rule, record, context) {
                f.fail(
                    "a context-reading setting passes only on what verification established (P6-17)",
                    format!("{what}: {} passed under {setting}: {}", rule.rule_type(), shown(&r.detail, 120)),
                );
            }
        }
        if r.detail.is_empty() {
            f.fail("every result says why", what.to_string());
        }
        for pointer in p6_3_pointers(rule.rule_type()) {
            if r.detail == format!("{pointer} is not declared, or is empty") && declared(pointer, record.pointer(pointer)) {
                f.fail(
                    "\"not declared\" is said only of an absent, other-typed or empty member",
                    format!("{what}: {} at {pointer}: {}", rule.rule_type(), shown(&record.pointer(pointer).map(Value::to_string).unwrap_or_default(), 80)),
                );
            }
            // E2: a signed "" in an environment member is a declaration.
            if r.detail == format!("{pointer} is not declared")
                && EMPTY_IS_DECLARED.contains(pointer)
                && record.pointer(pointer).is_some_and(Value::is_string)
            {
                f.fail(
                    "an empty environment member is declared, not absent (P6-17, E2)",
                    format!("{what}: {} at {pointer}", rule.rule_type()),
                );
            }
        }
        if let Rule::DocumentationDeclared(d) = rule {
            let expected = documentation_status(&d.document, record);
            if r.status != expected {
                f.fail(
                    "documentation_declared gives the status of task 10.11a D11-4",
                    format!("{what}: {} gave {} where D11-4 gives {}: {}", d.document, r.status.id(), expected.id(), shown(&r.detail, 120)),
                );
            }
        }
        if let Some(expected) = p6_3_status(rule, record) {
            if r.status != expected {
                f.fail(
                    "data_residency, source_screening and attestation_level give P6-3's status",
                    format!("{what}: {} gave {} where P6-3 gives {}: {}", rule.rule_type(), r.status.id(), expected.id(), shown(&r.detail, 120)),
                );
            }
        }
        f.count(&format!("status {} {}", rule.rule_type(), r.status.id()));
    }
    if e.overall != mandatory_only(pack, e) {
        f.fail("the overall status is the mandatory-only aggregation", what.to_string());
    }
    let indeterminate: Vec<String> =
        e.results.iter().filter(|r| r.status == Status::Indeterminate).map(|r| r.rule_id.clone()).collect();
    if e.indeterminate != indeterminate {
        f.fail("indeterminate lists exactly the indeterminate rules", what.to_string());
    }
    let section = e.to_policy_compliance();
    let decided = e.results.iter().filter(|r| r.status != Status::Indeterminate).count();
    if section.results.len() != decided || section.overall_status != e.overall.overall_id() || section.policy_pack_id != e.pack_id {
        f.fail("to_policy_compliance carries exactly the decided rules", what.to_string());
    }
    if !record.is_object() && e.results.iter().any(|r| r.status != Status::Indeterminate) {
        f.fail("a record that is not an object decides no rule", what.to_string());
    }
}

// ---------------------------------------------------------------------------
//  Targets
// ---------------------------------------------------------------------------

fn run_loader_target(iterations: usize, seed_value: u64) -> Findings {
    let mut f = Findings::default();
    let t = now();
    let mut seeds: Vec<Vec<u8>> = REFERENCE_PACKS.iter().map(|id| pack_text(id).into_bytes()).collect();
    seeds.push(serde_json::to_vec_pretty(&synthetic_pack("robustness-all-types", all_rule_types())).unwrap());
    let signed_seed = serde_json::to_vec_pretty(&signed(synthetic_pack("robustness-signed", all_rule_types()))).unwrap();
    let signed_loaded = load_pack(std::str::from_utf8(&signed_seed).unwrap()).expect("the signed seed loads");
    let verifying = *authority_key().verifying_key();
    signed_loaded.verify_signature(&verifying).expect("the signed seed verifies");
    seeds.push(signed_seed);

    let vector = conformance();
    let records: [(&str, Value); 3] = [
        ("conformance", serde_json::to_value(&vector).unwrap()),
        ("gate5", serde_json::to_value(gate5()).unwrap()),
        ("null", Value::Null),
    ];
    let mut rng = Lcg(seed_value);
    for i in 0..iterations {
        let seed = rng.pick(&seeds).clone();
        let (mutant, respelled) =
            if rng.below(3) == 0 { (byte_mutation(&mut rng, seed), false) } else { pack_mutation(&mut rng, &seed) };
        let Ok(text) = std::str::from_utf8(&mutant) else {
            f.count("loader: not UTF-8 (a caller refuses it before load_pack)");
            continue;
        };
        let what = format!("loader iteration {i}");
        let loaded = match catch_unwind(|| load_pack(text)) {
            Err(_) => {
                f.fail("load_pack panicked", format!("{what}: {}", shown(text, 300)));
                continue;
            }
            Ok(Err(e)) => {
                let debug = format!("{e:?}");
                let variant: String = debug.chars().take_while(|c| c.is_alphanumeric()).collect();
                f.count(&format!("loader refused: {variant}"));
                if respelled {
                    if e.refusal() == Some(Refusal::Structure) {
                        f.count("loader: objects written as arrays refused as refusal 2");
                    } else {
                        f.fail(
                            "a pack with an object written as the array of its values is refusal 2 (QA QT-01)",
                            format!("{what}: {}: {}", e.refusal().map_or("no refusal", Refusal::id), shown(text, 300)),
                        );
                    }
                }
                let message = e.to_string();
                if message.is_empty() {
                    f.fail("a refusal carries a message", what);
                } else if message.chars().any(is_terminal_unsafe) {
                    f.fail(
                        "a refusal message carries no raw terminal-unsafe character (QA Q6-10)",
                        format!("{variant}: {}", shown(&message, 160)),
                    );
                }
                continue;
            }
            Ok(Ok(pack)) => {
                if respelled {
                    f.fail(
                        "a pack with an object written as the array of its values is refusal 2 (QA QT-01)",
                        format!("{what}: it loaded: {}", shown(text, 300)),
                    );
                }
                pack
            }
        };
        f.count("loader accepted");
        match load_pack(text) {
            Ok(again) if again == loaded => {}
            _ => f.fail("an accepted pack reloads identically", what.clone()),
        }
        let canonical = jcs(loaded.document());
        match load_pack(&canonical) {
            Ok(c) if c.pack() == loaded.pack() && c.payload_hash() == loaded.payload_hash() => {}
            Ok(_) => f.fail(
                "the JCS form reloads as the same pack (the signed bytes identify the pack)",
                format!("{what}: {}", shown(&canonical, 400)),
            ),
            Err(e) => f.fail(
                "the JCS form reloads (the signed bytes are a pack)",
                format!("{what}: {} :: {}", shown(&e.to_string(), 120), shown(&canonical, 300)),
            ),
        }
        if loaded.pack().signature.is_some() {
            if let Ok(Ok(())) = catch_unwind(AssertUnwindSafe(|| loaded.verify_signature(&verifying))) {
                f.count("mutant signature still verifies");
                if loaded.pack() != signed_loaded.pack() {
                    f.fail("a signature that verifies is the signed pack's", format!("{what}: {}", shown(text, 400)));
                }
            }
        }
        for (name, record) in &records {
            if let Some(e) = check_evaluation(&mut f, &loaded, record, None, t, &format!("{what} x {name}")) {
                if *name == "conformance" {
                    let mut with = vector.clone();
                    with.policy_compliance = e.to_policy_compliance();
                    if with.validate_format().is_err() {
                        f.fail("the converted section validates against the record schema", what.clone());
                    }
                }
            }
        }
        if (i + 1) % 200_000 == 0 {
            eprintln!("  loader: {} iterations", i + 1);
        }
    }
    f
}

fn run_evaluator_target(iterations: usize, seed_value: u64) -> Findings {
    let mut f = Findings::default();
    let t = now();
    let mut packs: Vec<LoadedPack> = REFERENCE_PACKS.iter().map(|id| reference_pack(id)).collect();
    packs.push(load_pack(&synthetic_pack("robustness-all-types", all_rule_types()).to_string()).unwrap());
    packs.push(load_pack(&synthetic_pack("robustness-relaxed", relaxed_rule_types()).to_string()).unwrap());

    // A third seed declares both documentation members (task 10.11a), so
    // documentation_declared rules pass as well as fail and abstain.
    let mut documented = serde_json::to_value(conformance()).unwrap();
    documented["data_governance"] = json!({"documentation_hash": format_hash(&sha256(b"robustness: data governance"))});
    documented["human_oversight"] = json!({"documentation_hash": format_hash(&sha256(b"robustness: human oversight"))});
    // A fourth is a record in the general model description (task 10.11b):
    // components that are files, "" commitments, no times, no residency.
    let seeds: Vec<Value> = vec![
        serde_json::to_value(conformance()).unwrap(),
        serde_json::to_value(gate5()).unwrap(),
        documented,
        serde_json::to_value(general()).unwrap(),
    ];
    let seed_evaluations: Vec<Vec<Evaluation>> =
        seeds.iter().map(|s| packs.iter().map(|p| p.evaluate(s, t)).collect()).collect();
    let mut rng = Lcg(seed_value);
    for i in 0..iterations {
        let si = rng.below(seeds.len());
        let (mutant, mode, changed) = record_mutation(&mut rng, &seeds[si]);
        // A context is handed in only where the oracles below do not compare
        // with the seed's context-free evaluation.
        let context = match mode {
            Mode::Removed | Mode::Emptied => None,
            Mode::Successor if rng.below(2) == 0 => None,
            _ if rng.below(3) == 0 => None,
            _ => Some(context_mutant(&mut rng, &seeds[si])),
        };
        if context.is_some() {
            f.count("evaluations in a context");
        }
        if mode == Mode::Successor && context.is_none() {
            f.count("successors evaluated without context");
        }
        for (pi, pack) in packs.iter().enumerate() {
            let what = format!("evaluator iteration {i}, pack {}", pack.pack_id);
            let Some(e) = check_evaluation(&mut f, pack, &mutant, context.as_ref(), t, &what) else { continue };
            if context.as_ref().is_some_and(|c| !context_applies(c, &mutant)) {
                f.count("evaluations whose context adds nothing");
                let bare = catch_unwind(AssertUnwindSafe(|| pack.evaluate(&mutant, t)));
                if bare.as_ref().ok() != Some(&e) {
                    f.fail(
                        "a context that adds nothing to the record changes nothing (P6-17)",
                        format!("{what}: outcome {}", context.as_ref().map_or("?", |c| c.lineage.outcome.id())),
                    );
                }
            }
            let seed_results = &seed_evaluations[si][pi].results;
            if mode == Mode::Removed {
                for ((rule, before), after) in pack.rules.iter().zip(seed_results).zip(&e.results) {
                    // Task 10.11a (D11-4), the one exception: removing the
                    // optional documentation member a rule names is the
                    // record saying it pins no such document, and fails.
                    if let Rule::DocumentationDeclared(d) = rule {
                        if changed.is_some_and(|p| p.strip_prefix('/') == Some(d.document.as_str())) {
                            if before.status == Status::Pass && after.status != Status::Fail {
                                f.fail(
                                    "removing the documentation member a passing rule names fails it (10.11a D11-4)",
                                    format!("{what}: rule {}: {}", before.rule_id, after.status.id()),
                                );
                            }
                            if before.status == Status::Pass {
                                f.count("removed documentation members checked against a passing rule");
                            }
                            continue;
                        }
                    }
                    if before.status == Status::Pass && after.status == Status::Fail {
                        f.fail(
                            "removing a member a rule reads never turns a pass into a fail",
                            format!("{what}: rule {} after removing {}", before.rule_id, changed.unwrap_or("?")),
                        );
                    }
                }
            }
            if mode == Mode::Emptied {
                // E2: emptying a member a passing rule requires turns the
                // pass into a fail. The steps before it saw the same values.
                let member = changed.unwrap_or("?");
                for ((rule, before), after) in pack.rules.iter().zip(seed_results).zip(&e.results) {
                    let Rule::ExecutionIntegrity(r) = rule else { continue };
                    let requires = if member.ends_with("tee_measurement") {
                        r.require_tee
                    } else {
                        r.require_environment_pinned
                    };
                    if requires && before.status == Status::Pass && after.status != Status::Fail {
                        f.fail(
                            "an emptied member a passing rule requires fails it (P6-17, E2)",
                            format!("{what}: rule {} after emptying {member}: {}", before.rule_id, after.status.id()),
                        );
                    }
                    if requires && before.status == Status::Pass {
                        f.count("emptied members checked against a passing rule");
                    }
                }
            }
            if mode == Mode::NotAnObject && e.results.iter().any(|r| r.status != Status::Indeterminate) {
                f.fail("a junk record decides no rule", what);
            }
        }
        if (i + 1) % 200_000 == 0 {
            eprintln!("  evaluator: {} iterations", i + 1);
        }
    }
    f
}

/// The loader oracles ran on something: mutants were accepted, some kept a
/// signature that verifies, and some wrote an object as an array.
fn assert_loader_oracles_ran(f: &Findings) {
    assert!(f.counted("loader accepted") > 0, "no mutant loaded: the acceptance oracles never ran");
    assert!(
        f.counted("loader: objects written as arrays refused as refusal 2") > 0,
        "no mutant wrote an object as an array: the refusal 2 oracle never ran (QA QT-01)"
    );
    assert!(
        f.counted("mutant signature still verifies") > 0,
        "no mutant kept a valid signature: the signature oracle never ran"
    );
}

/// The evaluation oracles ran on every answer: each rule type passed, failed
/// and was indeterminate at least once.
fn assert_every_status_was_seen(f: &Findings) {
    for rule_type in vmr_policy::pack::RULE_TYPES {
        for status in [Status::Pass, Status::Fail, Status::Indeterminate] {
            let key = format!("status {rule_type} {}", status.id());
            assert!(f.counted(&key) > 0, "never seen: {key}");
        }
    }
}

/// The P6-17 oracles ran where they can bite: evaluations in a context, and
/// successors evaluated without one, where no lineage rule may pass.
fn assert_context_oracles_ran(f: &Findings) {
    for what in ["evaluations in a context", "successors evaluated without context", "evaluations whose context adds nothing"] {
        assert!(f.counted(what) > 0, "never seen: {what}");
    }
}

#[test]
fn the_oracles_catch_a_rule_that_stops_reading_a_declared_member() {
    // The regression a harness exists for, without touching the library: the
    // answer `rules::declared_string` would give if it returned None for
    // "x", a declared data_residency "x" reported as not declared. The honest
    // evaluation passes every oracle; the doctored one must trip both the
    // P6-3 status oracle and the "not declared" oracle.
    let pack = load_pack(&synthetic_pack("robustness-all-types", all_rule_types()).to_string()).unwrap();
    let pointer = "/learning_provenance/training_input_provenance/data_residency";
    let mut record = serde_json::to_value(conformance()).unwrap();
    *record.pointer_mut(pointer).expect("the member") = json!("x");

    let honest = pack.evaluate(&record, now());
    let mut clean = Findings::default();
    check_results(&mut clean, pack.pack(), &record, None, &honest, &honest, "the honest evaluation");
    assert!(clean.failures.is_empty(), "{}", clean.summary("the honest evaluation"));

    let mut doctored = honest.clone();
    for r in doctored.results.iter_mut().filter(|r| r.rule_type == "data_residency") {
        assert_eq!(r.status, Status::Fail, "\"x\" is not an allowed jurisdiction");
        r.status = Status::Indeterminate;
        r.detail = format!("{pointer} is not declared, or is empty");
    }
    let mut f = Findings::default();
    check_results(&mut f, pack.pack(), &record, None, &doctored, &doctored, "the doctored evaluation");
    for oracle in [
        "data_residency, source_screening and attestation_level give P6-3's status",
        "\"not declared\" is said only of an absent, other-typed or empty member",
    ] {
        assert!(f.failures.contains_key(oracle), "did not fire: {oracle}\n{}", f.summary("the doctored evaluation"));
    }
}

#[test]
fn pack_mutants_never_panic_and_keep_every_loader_oracle() {
    let f = run_loader_target(NORMAL_RUN, 0x5036_0001);
    f.assert_clean(&format!("loader target, {NORMAL_RUN} mutants"));
    assert_loader_oracles_ran(&f);
}

#[test]
fn record_mutants_never_panic_and_keep_every_evaluation_oracle() {
    let f = run_evaluator_target(NORMAL_RUN, 0x5036_0002);
    f.assert_clean(&format!("evaluator target, {NORMAL_RUN} mutants"));
    assert_every_status_was_seen(&f);
    assert_context_oracles_ran(&f);
    assert!(
        f.counted("removed documentation members checked against a passing rule") > 0,
        "never seen: a documentation member removed under a rule it passed"
    );
}

#[test]
#[ignore = "the doctrine's release bar: >= 1 000 000 mutations per target; run with --release -- --ignored"]
fn one_million_mutations_per_target() {
    let loader = run_loader_target(RELEASE_RUN, 0x5136_0001);
    loader.assert_clean(&format!("loader target, {RELEASE_RUN} mutants"));
    assert_loader_oracles_ran(&loader);
    let evaluator = run_evaluator_target(RELEASE_RUN, 0x5136_0002);
    evaluator.assert_clean(&format!("evaluator target, {RELEASE_RUN} mutants"));
    assert_every_status_was_seen(&evaluator);
    assert_context_oracles_ran(&evaluator);
}
