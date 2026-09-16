//! The stable identifiers of a policy pack's refusals
//! (`specs/policy-pack-format-v0.1.md` §3), and how the reference loader tells
//! apart the refusals one parser error can stand for.
// ============================================================================
//  refusal.rs — `policy_pack.*` ids (docs/TASKS.md 6.16; docs/dev/task-6.16.md
//  A16-20, A16-21)
//
//  The format document's §3 lists twelve refusals. The reference loader's
//  typed errors do not line up with them one for one: serde_json refuses
//  refusals 2, 3, 4, some of 5 and some of 7 alike (`Error::PackParse`), and
//  the schema's value check refuses 5, 7 and 8 alike (`Error::PackSchema`). A
//  stable id lets a test, a vector and another implementation name the
//  refusal without matching any wording.
//
//  Nothing here changes what is refused, or how: the loader parses exactly as
//  before, and only when a parse FAILS is its text looked at again, to say
//  which refusal the failure is. When a text breaks several rules any of them
//  may be named, since §3 fixes no order - with two exceptions: refusal 1
//  first, then refusal 12, counted over the bytes before anything else is
//  looked at (A16-21; QA16-02: `nests_past_bound`, `load_pack_bytes`).
//
//  A number no double holds (`1e400`, an integer of 400 digits) is refused by
//  the first parse, which reads every number as a value, before the typed
//  parse that reads how it is written. So that parse's failure is looked at
//  for a `minimum_chain_length` too, and named by its spelling (QA16-03).
// ============================================================================

use crate::pack::Severity;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// The deepest a pack text may nest arrays and objects, the outermost counting
/// as the first level (§3 refusal 12). It is serde_json's own limit: deeper
/// text is refused while it is read.
pub const MAX_TEXT_NESTING: usize = 127;

/// One refusal of the format document's §3, in the table's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Refusal {
    /// 1: the document is larger than the loader's bound.
    Size,
    /// 2: not JSON; a member unknown, missing, `null` or of the wrong JSON
    /// type, at any level; a rule `type` that is not one of the seven.
    Structure,
    /// 3: a member name twice in one object.
    DuplicateMember,
    /// 4: `minimum_chain_length` negative, or not written as a plain integer.
    IntegerSpelling,
    /// 5: `minimum_chain_length` above 2^53 − 1.
    IntegerRange,
    /// 6: `version` is not `"0.1"`.
    Version,
    /// 7: a value rule of the schema is broken.
    Value,
    /// 8: an `allowed_jurisdictions` entry is not two upper-case ASCII letters.
    Jurisdiction,
    /// 9: `rules` is empty.
    EmptyRules,
    /// 10: two rules share a `rule_id`.
    DuplicateRuleId,
    /// 11: a rule states no requirement a record can fail.
    NoRequirement,
    /// 12: the text nests arrays and objects more than 127 levels deep.
    Nesting,
}

impl Refusal {
    /// Every refusal, in the table's order.
    pub const ALL: [Refusal; 12] = [
        Refusal::Size,
        Refusal::Structure,
        Refusal::DuplicateMember,
        Refusal::IntegerSpelling,
        Refusal::IntegerRange,
        Refusal::Version,
        Refusal::Value,
        Refusal::Jurisdiction,
        Refusal::EmptyRules,
        Refusal::DuplicateRuleId,
        Refusal::NoRequirement,
        Refusal::Nesting,
    ];

    /// Its number in the §3 table.
    pub fn number(self) -> u8 {
        match self {
            Refusal::Size => 1,
            Refusal::Structure => 2,
            Refusal::DuplicateMember => 3,
            Refusal::IntegerSpelling => 4,
            Refusal::IntegerRange => 5,
            Refusal::Version => 6,
            Refusal::Value => 7,
            Refusal::Jurisdiction => 8,
            Refusal::EmptyRules => 9,
            Refusal::DuplicateRuleId => 10,
            Refusal::NoRequirement => 11,
            Refusal::Nesting => 12,
        }
    }

    /// Its stable id, e.g. `policy_pack.structure`: what the vectors and a
    /// refusal message name.
    pub fn id(self) -> &'static str {
        match self {
            Refusal::Size => "policy_pack.size",
            Refusal::Structure => "policy_pack.structure",
            Refusal::DuplicateMember => "policy_pack.duplicate_member",
            Refusal::IntegerSpelling => "policy_pack.integer_spelling",
            Refusal::IntegerRange => "policy_pack.integer_range",
            Refusal::Version => "policy_pack.version",
            Refusal::Value => "policy_pack.value",
            Refusal::Jurisdiction => "policy_pack.jurisdiction",
            Refusal::EmptyRules => "policy_pack.empty_rules",
            Refusal::DuplicateRuleId => "policy_pack.duplicate_rule_id",
            Refusal::NoRequirement => "policy_pack.no_requirement",
            Refusal::Nesting => "policy_pack.nesting",
        }
    }
}

/// The refusal a failed parse of `text` into a JSON value is, in order:
///
/// 1. 12 when the text nests past [`MAX_TEXT_NESTING`] levels, which the
///    parser stops at;
/// 2. 4 or 5 when the text is JSON and an `audit_integrity` rule's
///    `minimum_chain_length` writes a number no double holds, which the parser
///    refuses as it reads it ([`chain_length_beyond_a_double`]);
/// 3. else 2 (not JSON, a byte order mark, data after the value, a `\u`
///    escape of an unpaired surrogate).
pub(crate) fn of_value_parse(text: &str) -> Refusal {
    match nesting_or_structure(text) {
        Refusal::Structure => chain_length_beyond_a_double(text).unwrap_or(Refusal::Structure),
        refusal => refusal,
    }
}

/// 12 when `text` nests past [`MAX_TEXT_NESTING`] levels, else 2.
fn nesting_or_structure(text: &str) -> Refusal {
    if nests_past(text.as_bytes(), MAX_TEXT_NESTING) {
        Refusal::Nesting
    } else {
        Refusal::Structure
    }
}

/// When `text` is JSON, the refusal of the first `minimum_chain_length` of an
/// `audit_integrity` rule, in document order, whose number no double holds
/// (`1e400`, `-1e400`, an integer of 400 digits): 4 or 5 by how it is written
/// ([`integer_refusal`]). The text breaks nothing else for it; the parser
/// refused it only because it reads every number as a value (QA16-03).
/// `None` for a text that is not JSON, which breaks refusal 2 whatever numbers
/// it holds, and for one whose chain lengths a double holds.
fn chain_length_beyond_a_double(text: &str) -> Option<Refusal> {
    // RFC 8259's grammar alone: skipping a value checks its syntax, not the
    // range of a number or the code point of a `\u` escape, and it does not
    // recurse.
    serde_json::from_str::<serde::de::IgnoredAny>(text).ok()?;
    let scan = scan(text);
    scan.chain_lengths
        .iter()
        .filter(|(index, _)| scan.rule_types.get(index).is_some_and(|rule_type| rule_type == "audit_integrity"))
        .find(|(_, token)| !token.parse::<f64>().is_ok_and(f64::is_finite))
        .and_then(|(_, token)| integer_refusal(token))
}

/// The refusal a failed typed parse of `text` is, `value` being the JSON value
/// the same text parsed into (so the text is JSON, at most 127 levels deep).
/// In order:
///
/// 1. a member name twice in one object, names compared as decoded: 3;
/// 2. an `audit_integrity` rule's `minimum_chain_length` written negative or
///    with a fraction or an exponent: 4; written as a plain integer too large
///    for the parser's integers: 5 (a smaller one parses, and the schema's
///    `maximum` refuses it);
/// 3. a rule `severity` that is a string outside its enum: 7;
/// 4. anything else: 2.
pub(crate) fn of_typed_parse(text: &str, value: &Value) -> Refusal {
    let scan = scan(text);
    if scan.duplicate_member {
        return Refusal::DuplicateMember;
    }
    let rules = value.get("rules").and_then(Value::as_array);
    let rule_type = |index: usize| {
        rules.and_then(|r| r.get(index)).and_then(|r| r.get("type")).and_then(Value::as_str)
    };
    for (index, token) in &scan.chain_lengths {
        if rule_type(*index) == Some("audit_integrity") {
            if let Some(refusal) = integer_refusal(token) {
                return refusal;
            }
        }
    }
    let severity_outside_enum = rules.is_some_and(|rules| {
        rules.iter().any(|rule| {
            rule.get("severity")
                .and_then(Value::as_str)
                .is_some_and(|word| !Severity::ALL.iter().any(|s| s.id() == word))
        })
    });
    if severity_outside_enum {
        Refusal::Value
    } else {
        Refusal::Structure
    }
}

/// The refusal a `minimum_chain_length` number token is (§2: digits only, no
/// `-0`, fraction or exponent), or `None` for a plain integer the parser reads
/// (at most 2^64 − 1).
fn integer_refusal(token: &str) -> Option<Refusal> {
    if token.starts_with('-') || token.contains(['.', 'e', 'E']) {
        Some(Refusal::IntegerSpelling)
    } else if token.parse::<u64>().is_ok() {
        None
    } else {
        Some(Refusal::IntegerRange)
    }
}

/// Whether `bytes` reach a depth of [`MAX_TEXT_NESTING`] + 1 by the count of
/// the format document's §3, refusal 12, which it decides after the size and
/// before anything else (QA16-02). One pass over every byte, first to last:
/// outside a string, `[` and `{` raise the depth and `]` and `}` lower it,
/// never below 0, and `"` opens a string; inside one, `\` skips the byte after
/// it and `"` closes it. Nothing else the bytes hold is looked at: a byte
/// order mark, bytes that are not UTF-8, a syntax error before or after the
/// level that reaches 128. For JSON text the count is the depth of its arrays
/// and objects, the outermost counting as the first.
pub fn nests_past_bound(bytes: &[u8]) -> bool {
    nests_past(bytes, MAX_TEXT_NESTING)
}

/// Whether `json` opens more than `max` levels of arrays and objects. One
/// pass, no recursion: outside strings `[` and `{` open a level and `]` and
/// `}` close one; inside a string a backslash escapes the byte after it.
/// UTF-8 continuation bytes never equal these ASCII bytes.
fn nests_past(json: &[u8], max: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in json {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// What [`scan`] finds in a JSON text.
#[derive(Debug, Default)]
struct Scan {
    /// Some object holds one member name twice.
    duplicate_member: bool,
    /// Every number token at `/rules/<index>/minimum_chain_length`, as written.
    chain_lengths: Vec<(usize, String)>,
    /// The string at `/rules/<index>/type`, as decoded, by index. For a name
    /// written twice, the last, which is the one a parsed value keeps.
    rule_types: BTreeMap<usize, String>,
}

/// An open array or object while scanning.
enum Frame {
    /// An object: the member names seen, and the one whose value is being read.
    Object { names: BTreeSet<String>, member: Option<String> },
    /// An array: the index of the element being read.
    Array { index: usize },
}

/// Walk `text`, already known to be JSON at most 127 levels deep, once and
/// without recursion: the member names of every object, as decoded; the
/// number tokens of `minimum_chain_length` members of `rules` elements, as
/// written (a parsed number no longer says how it was written); and the
/// `type` strings of `rules` elements.
fn scan(text: &str) -> Scan {
    let bytes = text.as_bytes();
    let mut out = Scan::default();
    let mut stack: Vec<Frame> = Vec::new();
    let mut expect_name = false;
    let mut at = 0usize;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'{' => {
                stack.push(Frame::Object { names: BTreeSet::new(), member: None });
                expect_name = true;
                at += 1;
            }
            b'[' => {
                stack.push(Frame::Array { index: 0 });
                expect_name = false;
                at += 1;
            }
            b'}' | b']' => {
                stack.pop();
                expect_name = false;
                at += 1;
            }
            b',' => {
                match stack.last_mut() {
                    Some(Frame::Object { .. }) => expect_name = true,
                    Some(Frame::Array { index }) => *index += 1,
                    None => {}
                }
                at += 1;
            }
            b'"' => {
                let end = string_end(bytes, at);
                let decoded =
                    || serde_json::from_str::<String>(text.get(at..end).unwrap_or_default()).unwrap_or_default();
                if expect_name {
                    let name = decoded();
                    if let Some(Frame::Object { names, member }) = stack.last_mut() {
                        if !names.insert(name.clone()) {
                            out.duplicate_member = true;
                        }
                        *member = Some(name);
                    }
                    expect_name = false;
                } else if let [Frame::Object { member: Some(top), .. }, Frame::Array { index }, Frame::Object { member: Some(name), .. }] =
                    stack.as_slice()
                {
                    if top == "rules" && name == "type" {
                        out.rule_types.insert(*index, decoded());
                    }
                }
                at = end;
            }
            b'-' | b'0'..=b'9' => {
                let start = at;
                while bytes.get(at).is_some_and(|b| matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')) {
                    at += 1;
                }
                if let [Frame::Object { member: Some(top), .. }, Frame::Array { index }, Frame::Object { member: Some(name), .. }] =
                    stack.as_slice()
                {
                    if top == "rules" && name == "minimum_chain_length" {
                        out.chain_lengths.push((*index, text.get(start..at).unwrap_or_default().to_string()));
                    }
                }
            }
            _ => at += 1,
        }
    }
    out
}

/// The index just past the closing quote of the string whose opening quote is
/// at `start`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut at = start + 1;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'\\' => at += 2,
            b'"' => return at + 1,
            _ => at += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_depth_count_skips_brackets_inside_strings() {
        assert!(!nests_past(br#"{"a":"[[[[[\"[[[["}"#, 2));
        assert!(nests_past(b"[[[", 2));
        assert!(!nests_past(b"[[]]", 2));
    }

    #[test]
    fn the_scan_finds_duplicates_by_decoded_name_and_chain_length_tokens_as_written() {
        let s = scan(r#"{"a":1,"a":2}"#);
        assert!(s.duplicate_member);
        let s = scan(r#"{"a":{"b":1},"c":{"b":2},"rules":[{"x":[1,2]},{"minimum_chain_length":1.0e1}]}"#);
        assert!(!s.duplicate_member, "a name repeated in two objects is not a duplicate");
        assert_eq!(s.chain_lengths, vec![(1, "1.0e1".to_string())]);
    }

    #[test]
    fn the_scan_reads_the_type_of_each_rule_and_nothing_else_called_type() {
        let s = scan(
            r#"{"type":"top","rules":[{"type":"audit_integrity","minimum_chain_length":1e400},{"type":"x","type":"attestation_level","inner":{"type":"deeper"},"list":["type"]}]}"#,
        );
        let types: Vec<(usize, &str)> = s.rule_types.iter().map(|(i, t)| (*i, t.as_str())).collect();
        assert_eq!(types, vec![(0, "audit_integrity"), (1, "attestation_level")], "the last of a name written twice");
        assert_eq!(s.chain_lengths, vec![(0, "1e400".to_string())]);
    }

    #[test]
    fn an_integer_token_is_a_spelling_a_range_or_readable() {
        assert_eq!(integer_refusal("-0"), Some(Refusal::IntegerSpelling));
        assert_eq!(integer_refusal("1E0"), Some(Refusal::IntegerSpelling));
        assert_eq!(integer_refusal("18446744073709551615"), None);
        assert_eq!(integer_refusal("18446744073709551616"), Some(Refusal::IntegerRange));
    }

    #[test]
    fn only_json_text_has_its_chain_lengths_classified_after_a_failed_value_parse() {
        let pack = |number: &str| {
            format!(r#"{{"rules":[{{"type":"audit_integrity","minimum_chain_length":{number}}}],"version":"0.1"}}"#)
        };
        assert_eq!(chain_length_beyond_a_double(&pack("1e400")), Some(Refusal::IntegerSpelling));
        assert_eq!(chain_length_beyond_a_double(&pack("1e308")), None, "a double holds it");
        assert_eq!(chain_length_beyond_a_double(&format!("{} x", pack("1e400"))), None, "not JSON");
        assert_eq!(chain_length_beyond_a_double(&pack("01e400")), None, "not JSON: a leading zero");
    }
}
