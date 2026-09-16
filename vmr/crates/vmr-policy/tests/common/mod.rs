// tests/common/mod.rs — what every vmr-policy test needs: the committed
// reference packs, the committed conformance record, and a way to build a
// one-rule pack inline so a rule can be exercised without inventing a
// standard to put it in.
//
// Nothing here reads a clock or the environment: the evaluation time is a
// fixed value, as it is everywhere in this project.

#![allow(dead_code)] // each test file uses part of this

use serde_json::{json, Value};
use vmr_policy::{load_pack, Error, LoadedPack};
use vmr_policy::vmr_record::timestamp::Timestamp;

/// The evaluation time every test uses unless it says otherwise.
pub const NOW: &str = "2026-09-11T00:00:00Z";

/// The five committed reference packs, by id.
pub const REFERENCE_PACKS: [&str; 5] = [
    "khalm-reading-eu-ai-act-2026",
    "khalm-reading-nist-ai-rmf-1.0",
    "khalm-reading-iso-42001-2023",
    "khalm-reading-c2pa-ai-disclosure-2.2",
    "khalm-reading-rats-rfc9334-v0.1",
];

/// `<repo>/specs`, from this crate's manifest directory.
pub fn specs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs")
}

/// The text of a committed reference pack.
pub fn pack_text(pack_id: &str) -> String {
    let path = specs_dir().join(format!("policy-packs/{pack_id}.json"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A committed reference pack, loaded.
pub fn reference_pack(pack_id: &str) -> LoadedPack {
    load_pack(&pack_text(pack_id)).unwrap_or_else(|e| panic!("{pack_id}: {e}"))
}

/// The EU AI Act reference pack, which Gate 6 evaluates against.
pub fn eu_pack() -> LoadedPack {
    reference_pack("khalm-reading-eu-ai-act-2026")
}

/// The published policy-pack schema.
pub fn schema() -> Value {
    let path = specs_dir().join("policy-pack-schema/v0.1.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

/// The committed conformance vector's record, as a JSON value.
pub fn conformance_record() -> Value {
    let path = specs_dir().join("test-vectors/record/example-v0.1.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let file: Value = serde_json::from_str(&text).unwrap();
    file["record"].clone()
}

/// The evaluation time as a `Timestamp`.
pub fn now() -> Timestamp {
    Timestamp::parse(NOW).unwrap()
}

/// `t` as a `Timestamp`.
pub fn at(t: &str) -> Timestamp {
    Timestamp::parse(t).unwrap()
}

/// A pack document around `rules`, with every other member filled in.
pub fn pack_document(rules: Value) -> Value {
    json!({
        "version": "0.1",
        "pack_id": "test-pack",
        "pack_version": "1.0.0",
        "jurisdiction": "test",
        "description": "A pack built by a test.",
        "disclaimer": "A test fixture, not legal advice.",
        "authority": {
            "authority_id": "vmr-policy-tests",
            "authority_name": "vmr-policy tests"
        },
        "rules": rules,
    })
}

/// A pack holding exactly `rule`, loaded. Panics if it does not load: a test
/// fixture that does not load is a broken test, not a finding.
pub fn one_rule_pack(rule: Value) -> LoadedPack {
    let document = pack_document(json!([rule]));
    load_pack(&document.to_string()).unwrap_or_else(|e| panic!("fixture pack: {e}\n{document:#}"))
}

/// Load a pack holding exactly `rule`, keeping the error.
pub fn try_one_rule_pack(rule: Value) -> Result<LoadedPack, Error> {
    load_pack(&pack_document(json!([rule])).to_string())
}

/// The status of the single rule of a one-rule pack, against `record`.
pub fn status_of(rule: Value, record: &Value) -> (vmr_policy::Status, String) {
    let pack = one_rule_pack(rule);
    let evaluation = pack.evaluate(record, now());
    let result = evaluation.results.first().expect("one rule, one result").clone();
    (result.status, result.detail)
}

/// A record payload holding only the members a test cares about; every
/// rule reads by JSON pointer, so an incomplete payload is exactly the
/// "field not declared" case the rules must answer with Indeterminate.
pub fn payload(members: Value) -> Value {
    members
}

/// Whether a terminal acts on `c` or hides it: every C0 control (TAB, LF and
/// CR included), DEL, the C1 controls, U+2028 and U+2029, every
/// Default_Ignorable code point of Unicode 16.0.0, and every noncharacter.
/// Written out again from `vmr-verify/src/text.rs` (`DEFAULT_IGNORABLE`),
/// the table `QA/repro/p5_scan_unsafe.py` also uses, so a test here does not
/// take the library's own copy on trust.
pub fn is_terminal_unsafe(c: char) -> bool {
    const IGNORABLE: [(u32, u32); 17] = [
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x061C, 0x061C),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFF8),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    ];
    let code = u32::from(c);
    code < 0x20
        || (0x7f..=0x9f).contains(&code)
        || code == 0x2028
        || code == 0x2029
        || IGNORABLE.iter().any(|&(lo, hi)| (lo..=hi).contains(&code))
        || (0xFDD0..=0xFDEF).contains(&code)
        || code & 0xFFFE == 0xFFFE
}
