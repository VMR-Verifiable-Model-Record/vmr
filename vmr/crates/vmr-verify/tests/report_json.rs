// tests/report_json.rs — the report's JSON reaches terminals (`vmr record
// verify --json` prints it byte for byte), so it must carry no character a
// terminal acts on or hides. serde_json escapes C0 controls, `"` and `\`, but
// writes DEL, C1 controls (U+009B is CSI to many terminals), bidi controls,
// invisible characters and noncharacters raw: every character display_safe
// escapes is written as a JSON \u escape instead, and the JSON still parses
// to exactly the same values (Phase 5 review).

mod common;

use common::*;
use serde_json::Value;
use vmr_verify::VerificationReport;

/// An issuer_name with one character of every class serde_json leaves raw
/// that display_safe escapes, plus characters that must stay as they are.
const HOSTILE: &str =
    "Evil\u{7f}\u{9b}32m\u{202e}\u{200b}\u{2028}\u{feff}\u{e0041}\u{ffff}\u{1fffe} \u{e9} \u{4e2d} \u{1f600}";

fn hostile_report() -> (String, VerificationReport) {
    let mut p = vector();
    p.issuer.issuer_name = HOSTILE.into();
    reissue_with(&mut p, KEY_F);
    let report = verify_basic(&p);
    (report.to_json().unwrap(), report)
}

/// Characters display_safe would escape, other than the newlines and
/// backslashes JSON itself needs.
fn raw_unsafe(text: &str) -> Vec<char> {
    text.chars()
        .filter(|&c| c != '\n' && c != '\\' && vmr_verify::display_safe(&c.to_string()) != c.to_string())
        .collect()
}

#[test]
fn the_report_json_carries_no_character_a_terminal_acts_on() {
    let (json, report) = hostile_report();
    assert_eq!(
        report.record.as_ref().map(|p| p.issuer_name.as_str()),
        Some(HOSTILE),
        "the claim is in the report, raw"
    );
    let raw = raw_unsafe(&json);
    assert!(raw.is_empty(), "raw {raw:?} in the report JSON");
    // Each class escaped: \uXXXX within the BMP, a UTF-16 pair beyond it.
    for escaped in [
        "\\u007f", "\\u009b", "\\u202e", "\\u200b", "\\u2028", "\\ufeff", "\\udb40\\udc41", "\\uffff", "\\ud83f\\udffe",
    ] {
        assert!(json.contains(escaped), "{escaped} missing from the report JSON");
    }
    for kept in ["\u{e9}", "\u{4e2d}", "\u{1f600}"] {
        assert!(json.contains(kept), "{kept} is written as it is");
    }
}

#[test]
fn the_escaped_report_json_parses_to_the_same_values() {
    let (json, report) = hostile_report();
    let parsed: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["record"]["issuer_name"], HOSTILE);
    assert_eq!(parsed, serde_json::to_value(&report).unwrap(), "the same report, only spelled differently");
}

#[test]
fn a_report_without_such_characters_is_what_serde_json_writes() {
    // The golden reports pin this too; stated here as the rule.
    let report = verify_basic(&vector());
    assert_eq!(report.to_json().unwrap(), serde_json::to_string_pretty(&report).unwrap());
}

#[test]
fn the_report_names_the_model_by_its_model_hash_and_model_format() {
    // QA QC-02 (the reviewer's decision): model_hash is a model's identity
    // under both descriptions (spec §7.3, §7.4), and what an enforcer binds
    // since task 8.10, so the report's record summary carries it and the
    // model_format it is read under, beside learned_state_hash.
    let general = general_vector();
    let report = verify_basic(&general);
    assert_passes(&report);
    let json: Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    let identity = &general.model_identity;
    assert_eq!(json["record"]["model_hash"], identity.model_hash.as_str());
    assert_eq!(json["record"]["model_format"], identity.model_format.as_str());
    assert_eq!(json["record"]["learned_state_hash"], identity.learned_state_hash.as_str());
}
