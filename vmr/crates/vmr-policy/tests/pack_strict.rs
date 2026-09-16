// tests/pack_strict.rs — P6-9: a compliance format must not silently ignore
// a constraint. One test per refusal, each asserting the typed Error variant
// and that the message names the member at fault. If any of these ever
// loads instead of failing, a pack could carry a rule this build does not
// apply and still be reported as evaluated.

mod common;

use common::*;
use serde_json::{json, Value};
use vmr_policy::vmr_record::canonical::jcs;
use vmr_policy::{load_pack, Error, Refusal, MAX_PACK_BYTES, PACK_FORMAT_VERSION};

/// A well-formed pack document a test then breaks in one place.
fn good() -> Value {
    pack_document(json!([{
        "type": "attestation_level",
        "rule_id": "attest",
        "description": "The issuer attests.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, pack_strict.rs",
        "minimum_level": "software"
    }]))
}

fn load(document: &Value) -> Result<vmr_policy::LoadedPack, Error> {
    load_pack(&document.to_string())
}

fn edit(f: impl FnOnce(&mut Value)) -> Result<vmr_policy::LoadedPack, Error> {
    let mut d = good();
    f(&mut d);
    load(&d)
}

#[test]
fn the_fixture_itself_loads() {
    let pack = load(&good()).expect("the unbroken fixture loads");
    assert_eq!(pack.pack_id, "test-pack");
    assert_eq!(pack.version, PACK_FORMAT_VERSION);
    assert_eq!(pack.rules.len(), 1);
}

#[test]
fn an_unknown_member_is_refused_at_every_level() {
    for at in ["", "/authority", "/rules/0"] {
        let err = edit(|d| {
            let target = if at.is_empty() { d } else { d.pointer_mut(at).unwrap() };
            target.as_object_mut().unwrap().insert("surprise".into(), json!(true));
        })
        .expect_err(at);
        assert!(matches!(err, Error::PackParse { .. }), "{at}: {err}");
        assert!(err.to_string().contains("surprise"), "{at}: {err}");
    }
}

#[test]
fn an_unknown_rule_type_is_refused() {
    // The tagged enum is what refuses it, and the message lists what this
    // build does know, so a pack author sees the version mismatch.
    let err = edit(|d| d["rules"][0]["type"] = json!("thermal_limits")).expect_err("unknown type");
    assert!(matches!(err, Error::PackParse { .. }), "{err}");
    let text = err.to_string();
    assert!(text.contains("thermal_limits"), "{text}");
    assert!(text.contains("data_residency"), "{text}");
}

#[test]
fn a_rule_parameter_of_another_rule_type_is_refused() {
    // The clearest way a constraint goes unapplied: it is written under the
    // wrong type and silently dropped.
    let err = edit(|d| d["rules"][0]["require_tee"] = json!(true)).expect_err("foreign parameter");
    assert!(matches!(err, Error::PackParse { .. }), "{err}");
    assert!(err.to_string().contains("require_tee"), "{err}");
}

#[test]
fn a_missing_member_is_refused() {
    for member in ["version", "pack_id", "disclaimer", "authority", "rules"] {
        let err = edit(|d| {
            d.as_object_mut().unwrap().remove(member);
        })
        .expect_err(member);
        assert!(matches!(err, Error::PackParse { .. }), "{member}: {err}");
        assert!(err.to_string().contains(member), "{member}: {err}");
    }
    let err = edit(|d| {
        d["rules"][0].as_object_mut().unwrap().remove("reference");
    })
    .expect_err("reference");
    assert!(err.to_string().contains("reference"), "{err}");
}

#[test]
fn a_rule_without_its_required_parameter_is_refusal_2() {
    // QA QT-01 QJ-02: `Rule`'s reader checks each type's required parameter
    // itself, where serde's derive refused a missing member. A check that
    // defaulted the parameter instead would pass the rule on to the value
    // rules, and refusal 7 would name it, not refusal 2 (the format document's
    // §3). The other three types have no required parameter: each of their
    // settings defaults.
    let every = rules_with_every_member();
    for (rule_type, parameter) in [
        ("data_residency", "allowed_jurisdictions"),
        ("source_screening", "restricted_list"),
        ("attestation_level", "minimum_level"),
        ("documentation_declared", "document"),
    ] {
        let members = &every.iter().find(|(t, _)| *t == rule_type).expect("a rule type").1;
        let (mut rule, _) = rule_and_array(rule_type, members);
        try_one_rule_pack(rule.clone()).unwrap_or_else(|e| panic!("{rule_type}, every member: {e}"));
        rule.as_object_mut().unwrap().remove(parameter).expect("the parameter");
        let err = try_one_rule_pack(rule).map(|_| ()).expect_err(parameter);
        assert!(matches!(err, Error::PackParse { .. }), "{rule_type}: {err}");
        assert_eq!(err.refusal(), Some(Refusal::Structure), "{rule_type}: {err}");
        assert!(err.to_string().contains(&format!("missing field `{parameter}`")), "{rule_type}: {err}");
    }
}

#[test]
fn a_null_optional_member_is_refused() {
    // Optional members are omitted, never null - the record's rule.
    let err = edit(|d| d["signature"] = Value::Null).expect_err("null signature");
    assert!(matches!(err, Error::PackParse { .. }), "{err}");
}

#[test]
fn a_duplicate_member_is_refused() {
    // serde_json rejects a repeated key before any of this crate sees it;
    // pinned here because a pack with two `rules` members could otherwise be
    // read differently by two implementations.
    let text = good().to_string().replacen("\"rules\":", "\"rules\": [], \"rules\":", 1);
    let err = load_pack(&text).expect_err("duplicate member");
    assert!(matches!(err, Error::PackParse { .. }), "{err}");
}

#[test]
fn another_format_version_is_refused() {
    let err = edit(|d| d["version"] = json!("0.2")).expect_err("version 0.2");
    assert!(matches!(&err, Error::UnsupportedVersion(v) if v == "0.2"), "{err}");
}

#[test]
fn an_empty_rule_list_is_refused() {
    let err = edit(|d| d["rules"] = json!([])).expect_err("no rules");
    assert!(matches!(err, Error::PackEmpty), "{err}");
}

#[test]
fn a_duplicate_rule_id_is_refused() {
    let err = edit(|d| {
        let rule = d["rules"][0].clone();
        d["rules"] = json!([rule.clone(), rule]);
    })
    .expect_err("two rules, one id");
    assert!(matches!(&err, Error::DuplicateRuleId(id) if id == "attest"), "{err}");
}

#[test]
fn a_rule_that_states_no_requirement_is_refused() {
    // The mirror of P6-3's "always Indeterminate poisons the pack": a rule
    // that asks for nothing is decoration, and a pack of them would report
    // "compliant" while checking nothing. P6-17 adds two: a lineage check
    // alone (it never fails), and minimum_level "self" (every record that
    // declares a level meets it). The hint names only settings that can fail.
    let cases: [(&str, Value, &str); 6] = [
        ("export_control", json!({}), "require_air_gapped"),
        (
            "audit_integrity",
            json!({"minimum_chain_length": 0, "require_tamper_evident": false}),
            "minimum_chain_length",
        ),
        ("audit_integrity", json!({"require_verified_lineage": true}), "require_ordered_record"),
        ("execution_integrity", json!({"require_tee": false}), "require_tee"),
        ("execution_integrity", json!({}), "require_state_kept"),
        ("attestation_level", json!({"minimum_level": "self"}), "minimum_level"),
    ];
    for (rule_type, params, mentions) in cases {
        let mut rule = json!({
            "type": rule_type,
            "rule_id": "vacuous",
            "description": "Asks for nothing.",
            "severity": "mandatory",
            "reference": "vmr-policy tests, pack_strict.rs"
        });
        for (k, v) in params.as_object().unwrap() {
            rule.as_object_mut().unwrap().insert(k.clone(), v.clone());
        }
        let err = try_one_rule_pack(rule).expect_err(rule_type);
        assert!(
            matches!(&err, Error::RuleWithoutRequirement { rule_id, .. } if rule_id == "vacuous"),
            "{rule_type}: {err}"
        );
        assert!(err.to_string().contains(mentions), "{rule_type}: {err}");
    }
}

#[test]
fn a_broken_value_rule_is_refused_with_its_pointer() {
    type Break = fn(&mut Value);
    let cases: [(&str, Break, &str); 6] = [
        ("empty pack_id", |d| d["pack_id"] = json!(""), "/pack_id"),
        ("pack_version 1.0", |d| d["pack_version"] = json!("1.0"), "/pack_version"),
        ("empty disclaimer", |d| d["disclaimer"] = json!(""), "/disclaimer"),
        (
            "empty authority_name",
            |d| d["authority"]["authority_name"] = json!(""),
            "/authority/authority_name",
        ),
        ("empty reference", |d| d["rules"][0]["reference"] = json!(""), "/rules/0/reference"),
        (
            "unknown minimum_level",
            |d| d["rules"][0]["minimum_level"] = json!("quantum"),
            "/rules/0/minimum_level",
        ),
    ];
    for (what, break_it, pointer) in cases {
        let err = edit(break_it).expect_err(what);
        assert!(matches!(err, Error::PackSchema(_)), "{what}: {err}");
        assert!(err.to_string().contains(pointer), "{what}: {err}");
    }
}

#[test]
fn a_documentation_rule_names_one_of_the_two_documents() {
    // Task 10.11a (D11-4): `document` is required and is `data_governance`
    // or `human_oversight` (the schema's enum). Another word is refused with
    // its pointer; a missing or mistyped member does not parse.
    let base = json!({
        "type": "documentation_declared",
        "rule_id": "documentation",
        "description": "The record pins a document.",
        "severity": "recommended",
        "reference": "vmr-policy tests, pack_strict.rs"
    });
    let with_document = |value: Value| {
        let mut rule = base.clone();
        rule["document"] = value;
        rule
    };
    for document in ["data_governance", "human_oversight"] {
        try_one_rule_pack(with_document(json!(document))).unwrap_or_else(|e| panic!("{document}: {e}"));
    }
    for bad in ["risk_management", "Data_Governance", "data governance", ""] {
        let err = try_one_rule_pack(with_document(json!(bad))).expect_err(bad);
        assert!(
            matches!(&err, Error::PackSchema(v) if v.pointer == "/rules/0/document" && v.rule == "enum"),
            "{bad:?}: {err}"
        );
    }
    let err = try_one_rule_pack(base.clone()).expect_err("no document");
    assert!(matches!(&err, Error::PackParse { detail, .. } if detail.contains("missing field `document`")), "{err}");
    for (value, what) in [(Value::Null, "null"), (json!(["data_governance"]), "an array"), (json!(1), "a number")] {
        let err = try_one_rule_pack(with_document(value)).expect_err(what);
        assert!(matches!(err, Error::PackParse { .. }), "{what}: {err}");
    }
}

/// An `audit_integrity` rule asking for `minimum_chain_length` written as
/// `number` (the JSON text, so a spelling can be tried as well as a value).
fn chain_length_pack(number: &str) -> String {
    let rule = json!({
        "type": "audit_integrity",
        "rule_id": "chain",
        "description": "Asks for a chain length.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, pack_strict.rs",
        "minimum_chain_length": "__NUMBER__"
    });
    pack_document(json!([rule])).to_string().replacen("\"__NUMBER__\"", number, 1)
}

#[test]
fn an_integer_a_record_could_not_carry_is_refused_with_its_pointer() {
    // A pack is signed over its JCS form, and JCS writes a number as the
    // double it denotes: above 2^53 - 1 two different packs would share one
    // signed payload and one signature (QA Q6-03). No record's
    // lineage_chain_length can exceed 2^53 - 1 either.
    for number in ["9007199254740992", "9007199254740993", "18446744073709551615"] {
        match load_pack(&chain_length_pack(number)) {
            Err(Error::PackSchema(v)) => {
                assert_eq!(v.pointer, "/rules/0/minimum_chain_length", "{number}");
                assert_eq!(v.rule, "maximum", "{number}");
            }
            other => panic!("{number}: expected a PackSchema refusal, got {other:?}"),
        }
    }
}

#[test]
fn the_largest_accepted_integer_survives_its_canonical_form() {
    // The boundary itself: 2^53 - 1 is written exactly by JCS, so the signed
    // bytes reload as the same pack with the same payload hash.
    let pack = load_pack(&chain_length_pack("9007199254740991")).expect("2^53 - 1 loads");
    let canonical = load_pack(&jcs(pack.document())).expect("its canonical form loads");
    assert_eq!(canonical.pack(), pack.pack());
    assert_eq!(canonical.payload_hash(), pack.payload_hash());
    assert!(matches!(
        &pack.rules[0],
        vmr_policy::Rule::AuditIntegrity(r) if r.minimum_chain_length == 9_007_199_254_740_991
    ));
}

#[test]
fn an_integer_has_one_spelling() {
    // The schema says so in its description; JSON Schema alone would accept
    // 1.0 as an integer. A negative number is below the schema's minimum.
    for number in ["1.0", "1e0", "1E0", "-0", "-1", "0.5"] {
        let err = load_pack(&chain_length_pack(number)).expect_err(number);
        assert!(matches!(err, Error::PackParse { .. }), "{number}: {err}");
        assert!(err.to_string().contains("u64"), "{number}: {err}");
    }
    load_pack(&chain_length_pack("1")).expect("the one spelling of 1");
}

#[test]
fn a_chain_length_beyond_a_doubles_range_is_named_by_how_it_is_written() {
    // QA16-03: serde_json refuses a number beyond a double's range while it
    // reads the document into a value, before the typed parse that reads the
    // number's spelling. The text is JSON, and its refusal is the one its
    // spelling breaks (the format document's §3, refusals 4 and 5), never 2.
    let four_hundred_digits = format!("1{}", "0".repeat(399));
    let minus_four_hundred_digits = format!("-{four_hundred_digits}");
    for (number, expected) in [
        ("1e400", Refusal::IntegerSpelling),
        ("-1e400", Refusal::IntegerSpelling),
        ("1E+400", Refusal::IntegerSpelling),
        ("1.5e400", Refusal::IntegerSpelling),
        (minus_four_hundred_digits.as_str(), Refusal::IntegerSpelling),
        (four_hundred_digits.as_str(), Refusal::IntegerRange),
    ] {
        let err = load_pack(&chain_length_pack(number)).expect_err(number);
        assert_eq!(err.refusal(), Some(expected), "{}: {err}", &number[..number.len().min(12)]);
    }
    // Numbers a double holds are unchanged: the typed parse names them.
    assert_eq!(load_pack(&chain_length_pack("1e-400")).unwrap_err().refusal(), Some(Refusal::IntegerSpelling));
    assert_eq!(load_pack(&chain_length_pack("1e308")).unwrap_err().refusal(), Some(Refusal::IntegerSpelling));
    // Only an audit_integrity rule has a minimum_chain_length: on another rule
    // type the member is unknown, refusal 2, however it is written (as
    // `each_refusal_is_named_by_its_id_whichever_error_carries_it` holds for
    // 1.0).
    let err = load_pack(&with_literal(attestation_rule(), "minimum_chain_length", "1e400")).unwrap_err();
    assert_eq!(err.refusal(), Some(Refusal::Structure), "{err}");
    // A number beyond a double's range anywhere else breaks refusal 2 alone.
    let err = load_pack(&with_literal(audit_rule(), "surprise", "1e400")).unwrap_err();
    assert_eq!(err.refusal(), Some(Refusal::Structure), "{err}");
    // Text that is not JSON is not classified by a number it holds.
    let not_json = chain_length_pack("1e400").replacen("\"severity\":", "\"severity\" ", 1);
    assert_eq!(load_pack(&not_json).unwrap_err().refusal(), Some(Refusal::Structure));
}

#[test]
fn a_jurisdiction_no_record_can_declare_is_refused() {
    // A record's data_residency is two upper-case ASCII letters, so an
    // allowed entry of any other shape can never match: the rule would fail
    // every record while looking like it allows one more place (QA Q6-09).
    for bad in ["ph", "PHL", "P", "P1", "\u{00c9}S", " PH"] {
        let rule = json!({
            "type": "data_residency",
            "rule_id": "residency",
            "description": "Training data stays in an allowed place.",
            "severity": "mandatory",
            "reference": "vmr-policy tests, pack_strict.rs",
            "allowed_jurisdictions": ["US", bad]
        });
        match try_one_rule_pack(rule) {
            Err(Error::PackSchema(v)) => {
                assert_eq!(v.pointer, "/rules/0/allowed_jurisdictions/1", "{bad:?}");
                assert_eq!(v.rule, "pattern", "{bad:?}");
            }
            other => panic!("{bad:?}: expected a PackSchema refusal, got {other:?}"),
        }
    }
}

#[test]
fn a_pack_version_with_a_leading_zero_is_refused() {
    // One version, one spelling: 01.00.000 and 1.0.0 would otherwise name
    // the same pack text two ways (QA Q6-09).
    for bad in ["01.00.000", "01.0.0", "1.00.0", "1.0.00"] {
        let err = edit(|d| d["pack_version"] = json!(bad)).expect_err(bad);
        assert!(
            matches!(&err, Error::PackSchema(v) if v.pointer == "/pack_version" && v.rule == "pattern"),
            "{bad}: {err}"
        );
    }
    for good in ["0.0.0", "1.0.0", "10.20.30", "2.3.4"] {
        edit(|d| d["pack_version"] = json!(good)).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
}

#[test]
fn a_refusal_message_carries_no_raw_control_character() {
    // serde echoes an unknown member name, or an unknown word, as it was
    // written: a pack from a stranger could put terminal escapes, a bidi
    // override or an invisible filler into every caller's error output
    // (QA Q6-10). The message still names the member, escaped.
    let hostile = "\u{1b}[2J\u{0}\r\n\u{7f}\u{85}\u{9b}\u{202e}\u{2028}\u{feff}\u{3164}";
    let mut unknown_member = good();
    unknown_member.as_object_mut().unwrap().insert(hostile.to_string(), json!(true));
    let mut unknown_word = good();
    unknown_word["rules"][0]["severity"] = json!(hostile);
    for (what, document) in [("an unknown member", unknown_member), ("an unknown severity", unknown_word)] {
        let err = load(&document).expect_err(what);
        assert!(matches!(err, Error::PackParse { .. }), "{what}: {err}");
        let message = err.to_string();
        let raw: Vec<String> =
            message.chars().filter(|c| is_terminal_unsafe(*c)).map(|c| format!("U+{:04X}", u32::from(c))).collect();
        assert!(raw.is_empty(), "{what}: raw {raw:?} in {message:?}");
        assert!(message.starts_with("policy pack parse failed: "), "{what}: {message:?}");
        assert!(message.contains("\\u{001b}[2J\\u{0000}"), "{what}: {message:?}");
    }
}

#[test]
fn a_hangul_filler_in_pack_text_reaches_no_refusal_or_detail_raw() {
    // U+3164 HANGUL FILLER is a letter to Rust's {:?}, which leaves it raw,
    // and blank on a terminal: two ids that look identical can differ by one
    // (QA Q6-10, the residual). Every refusal that quotes pack text, and a
    // rule detail that quotes record text, must escape it.
    const FILLER: &str = "\u{3164}";
    let mut member_name = good();
    member_name.as_object_mut().unwrap().insert(format!("rules{FILLER}"), json!([]));
    let mut duplicate = good();
    duplicate["rules"][0]["rule_id"] = json!(format!("attest{FILLER}"));
    duplicate["rules"] = json!([duplicate["rules"][0].clone(), duplicate["rules"][0].clone()]);
    let asks_for_nothing = pack_document(json!([{
        "type": "export_control",
        "rule_id": format!("vacuous{FILLER}"),
        "description": "Asks for nothing.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, pack_strict.rs"
    }]));
    let mut version = good();
    version["version"] = json!(format!("0.1{FILLER}"));
    let mut schema_value = good();
    schema_value["pack_version"] = json!(format!("1.0.0{FILLER}"));

    let cases: [(&str, Value); 5] = [
        ("a member name", member_name),
        ("a duplicate rule_id", duplicate),
        ("a rule that asks for nothing", asks_for_nothing),
        ("a format version", version),
        ("a schema value", schema_value),
    ];
    for (what, document) in cases {
        let message = load(&document).expect_err(what).to_string();
        assert!(!message.chars().any(is_terminal_unsafe), "{what}: raw character in {message:?}");
        assert!(message.contains("\\u{3164}"), "{what}: the filler is not shown escaped: {message:?}");
    }

    let rule = json!({
        "type": "attestation_level",
        "rule_id": "attest",
        "description": "The issuer attests.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, pack_strict.rs",
        "minimum_level": "software"
    });
    let record = json!({"issuer": {"attestation_level": format!("software{FILLER}")}});
    let (_, detail) = status_of(rule, &record);
    assert!(!detail.chars().any(is_terminal_unsafe), "raw character in the detail {detail:?}");
    assert!(detail.contains("\\u{3164}"), "{detail:?}");
}

#[test]
fn an_empty_list_parameter_is_refused() {
    for (rule_type, member, extra) in [
        ("data_residency", "allowed_jurisdictions", json!([])),
        ("source_screening", "restricted_list", json!([])),
    ] {
        let rule = json!({
            "type": rule_type,
            "rule_id": "empty-list",
            "description": "Lists nothing.",
            "severity": "mandatory",
            "reference": "vmr-policy tests, pack_strict.rs",
            member: extra
        });
        let err = try_one_rule_pack(rule).expect_err(rule_type);
        assert!(matches!(err, Error::PackSchema(_)), "{rule_type}: {err}");
        assert!(err.to_string().contains(member), "{rule_type}: {err}");
    }
}

#[test]
fn a_document_over_the_size_bound_is_refused_before_it_is_parsed() {
    let big = "x".repeat(MAX_PACK_BYTES + 1);
    let err = load_pack(&big).expect_err("over the bound");
    assert!(
        matches!(err, Error::PackTooLarge { bytes, limit } if bytes == MAX_PACK_BYTES + 1 && limit == MAX_PACK_BYTES),
        "{err}"
    );
}

#[test]
fn text_that_is_not_json_is_refused() {
    for text in ["", "{", "[]", "null", "{\"version\": \"0.1\"} trailing"] {
        let err = load_pack(text).expect_err(text);
        assert!(matches!(err, Error::PackParse { .. }), "{text:?}: {err}");
    }
}

#[test]
fn a_pack_nested_past_the_parsers_depth_limit_is_refused_with_a_typed_error() {
    // QA Q7-12 and Q7-13 S9 (the reviewer, 2026-09-13): a pack text that nests
    // arrays and objects more than 127 levels deep, the outermost counting as
    // the first, is refused (the format document's section 3, refusal 12), as
    // the reference parser refuses it: a typed PackParse, never a panic or a
    // stack overflow. At 127 levels the text still parses, and is refused for
    // what it holds, not for its depth.
    let nested = |levels: usize| format!("{}{}", "[".repeat(levels), "]".repeat(levels));
    for (arrays, refused_for_depth) in [(126usize, false), (127, true), (200, true), (100_000, true)] {
        // The pack object is the first level; its description holds the rest.
        let levels = arrays + 1;
        let text = format!("{{\"description\":{}}}", nested(arrays));
        let err = load_pack(&text).map(|_| ()).expect_err("not a pack");
        let Error::PackParse { detail: message, .. } = &err else {
            panic!("{levels} levels: {err:?}");
        };
        assert_eq!(message.contains("recursion limit exceeded"), refused_for_depth, "{levels} levels: {message}");
        let expected = if refused_for_depth { Refusal::Nesting } else { Refusal::Structure };
        assert_eq!(err.refusal(), Some(expected), "{levels} levels: {err}");
    }
}

#[test]
fn a_pack_file_is_refused_for_its_size_then_its_depth_whatever_else_its_bytes_break() {
    // QA16-02 (the format document's §3): refusal 1 first; then refusal 12,
    // counted over the bytes with strings skipped, whatever else they break;
    // then the rest. load_pack_bytes is the loader on a file's bytes, and
    // load_pack names the same refusal for every such text it can take.
    use vmr_policy::load_pack_bytes;
    let base = good().to_string();
    let close = base.rfind('}').unwrap();
    // `arrays` arrays in a member the format lacks: arrays + 1 levels.
    let deep = |arrays: usize| format!("{},\"surprise\":{}{}}}", &base[..close], "[".repeat(arrays), "]".repeat(arrays));
    let not_utf8 = |text: &str| {
        let at = text.find("\"version\":\"0.1\"").unwrap() + "\"version\":\"".len();
        let mut bytes = text.as_bytes().to_vec();
        bytes[at] = 0xff;
        bytes
    };
    let bom = |text: &str| [&[0xef, 0xbb, 0xbf][..], text.as_bytes()].concat();
    let mut padded = deep(127).into_bytes();
    padded.resize(MAX_PACK_BYTES + 1, b' ');
    let cases: Vec<(&str, Vec<u8>, Refusal)> = vec![
        ("over 1 MiB and 128 levels", padded, Refusal::Size),
        ("128 levels", deep(127).into_bytes(), Refusal::Nesting),
        ("a byte order mark, then 128 levels", bom(&deep(127)), Refusal::Nesting),
        ("a UTF-16 byte order mark, then 128 levels", [&[0xff, 0xfe][..], deep(127).as_bytes()].concat(), Refusal::Nesting),
        ("a byte that is not UTF-8, then 128 levels", not_utf8(&deep(127)), Refusal::Nesting),
        ("a syntax error, then 128 levels", deep(127).replacen('{', "{\"x\":tru,", 1).into_bytes(), Refusal::Nesting),
        ("128 levels, then a syntax error", format!("{},]", deep(127)).into_bytes(), Refusal::Nesting),
        ("128 levels never closed", format!("{},\"surprise\":{}", &base[..close], "[".repeat(127)).into_bytes(), Refusal::Nesting),
        ("a byte order mark and 127 levels", bom(&deep(126)), Refusal::Structure),
        ("a byte that is not UTF-8", not_utf8(&base), Refusal::Structure),
        ("200 [ in a string never closed", format!("{}\"{}", &base[..close], "[".repeat(200)).into_bytes(), Refusal::Structure),
    ];
    for (what, bytes, expected) in &cases {
        let err = load_pack_bytes(bytes).map(|_| ()).expect_err(what);
        assert_eq!(err.refusal(), Some(*expected), "{what}: {err}");
        if let Ok(text) = std::str::from_utf8(bytes) {
            let by_text = load_pack(text).map(|_| ()).expect_err(what);
            assert_eq!(by_text.refusal(), Some(*expected), "{what}: load_pack: {by_text}");
        }
    }
    // 200 brackets in a string at depth 1, after an escaped quotation mark,
    // open no level: the pack loads, by bytes and by text alike.
    let mut doc = good();
    doc["description"] = json!(format!("\"{}", "[".repeat(200)));
    let text = doc.to_string();
    let by_bytes = load_pack_bytes(text.as_bytes()).expect("brackets in a string open no level");
    assert_eq!(by_bytes.payload_hash(), load_pack(&text).unwrap().payload_hash());
}

// ---------------------------------------------------------------------------
//  Stable refusal ids (docs/TASKS.md 6.16; docs/dev/task-6.16.md A16-20 and
//  A16-21): each refusal of the format document's §3 has one, whichever Error
//  variant and whatever wording carry it.
// ---------------------------------------------------------------------------

#[test]
fn the_twelve_refusals_have_stable_ids_in_the_tables_order() {
    let table = [
        (1, "policy_pack.size"),
        (2, "policy_pack.structure"),
        (3, "policy_pack.duplicate_member"),
        (4, "policy_pack.integer_spelling"),
        (5, "policy_pack.integer_range"),
        (6, "policy_pack.version"),
        (7, "policy_pack.value"),
        (8, "policy_pack.jurisdiction"),
        (9, "policy_pack.empty_rules"),
        (10, "policy_pack.duplicate_rule_id"),
        (11, "policy_pack.no_requirement"),
        (12, "policy_pack.nesting"),
    ];
    assert_eq!(Refusal::ALL.len(), table.len());
    for (refusal, (number, id)) in Refusal::ALL.iter().zip(table) {
        assert_eq!((refusal.number(), refusal.id()), (number, id), "{refusal:?}");
    }
}

/// A one-rule pack whose rule is `rule` with `member` set to the JSON text
/// `literal`, written as it stands.
fn with_literal(rule: Value, member: &str, literal: &str) -> String {
    let mut rule = rule;
    rule[member] = json!("__LITERAL__");
    pack_document(json!([rule])).to_string().replacen("\"__LITERAL__\"", literal, 1)
}

fn attestation_rule() -> Value {
    good()["rules"][0].clone()
}

fn audit_rule() -> Value {
    json!({
        "type": "audit_integrity",
        "rule_id": "chain",
        "description": "Asks for a chain length.",
        "severity": "mandatory",
        "reference": "vmr-policy tests, pack_strict.rs"
    })
}

#[test]
fn each_refusal_is_named_by_its_id_whichever_error_carries_it() {
    let base = good().to_string();
    let edited = |f: &dyn Fn(&mut Value)| {
        let mut d = good();
        f(&mut d);
        d.to_string()
    };
    // The pack object is the first level, so `arrays` arrays in one of its
    // members reach level arrays + 1; the member is one the format lacks.
    let nested = |arrays: usize| {
        edited(&|d| d["surprise"] = json!("__DEEP__"))
            .replacen("\"__DEEP__\"", &format!("{}{}", "[".repeat(arrays), "]".repeat(arrays)), 1)
    };
    let signature = |algorithm: &str| {
        edited(&|d| {
            d["signature"] = json!({
                "algorithm": algorithm,
                "signature": format!("base64url:{}", "A".repeat(86)),
                "signed_payload_hash": format!("sha256:{}", "0".repeat(64)),
                "signing_key_id": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg"
            })
        })
    };
    let mut export_control = attestation_rule();
    export_control["type"] = json!("export_control");
    export_control.as_object_mut().unwrap().remove("minimum_level");
    let mut residency = attestation_rule();
    residency["type"] = json!("data_residency");
    residency.as_object_mut().unwrap().remove("minimum_level");
    residency["allowed_jurisdictions"] = json!(["ph"]);
    let mut screening = attestation_rule();
    screening["type"] = json!("source_screening");
    screening.as_object_mut().unwrap().remove("minimum_level");
    screening["restricted_list"] = json!([]);

    let cases: Vec<(&str, String, Refusal)> = vec![
        ("1 MiB and one byte", format!("{base}{}", " ".repeat(MAX_PACK_BYTES + 1 - base.len())), Refusal::Size),
        ("not JSON", "{".to_string(), Refusal::Structure),
        ("an unknown member", edited(&|d| d["surprise"] = json!(true)), Refusal::Structure),
        ("a missing member", edited(&|d| drop(d.as_object_mut().unwrap().remove("disclaimer"))), Refusal::Structure),
        ("a null member", edited(&|d| d["signature"] = Value::Null), Refusal::Structure),
        ("an unknown rule type", edited(&|d| d["rules"][0]["type"] = json!("thermal_limits")), Refusal::Structure),
        ("a severity of the wrong JSON type", edited(&|d| d["rules"][0]["severity"] = json!(3)), Refusal::Structure),
        ("a chain length written as a string", with_literal(audit_rule(), "minimum_chain_length", "\"5\""), Refusal::Structure),
        (
            "a chain length on a rule type without one, written 1.0",
            with_literal(attestation_rule(), "minimum_chain_length", "1.0"),
            Refusal::Structure,
        ),
        ("a byte order mark", format!("\u{feff}{base}"), Refusal::Structure),
        ("a member name twice", base.replacen("\"version\":", "\"version\":\"0.1\",\"version\":", 1), Refusal::DuplicateMember),
        ("a rule member twice", base.replacen("\"rule_id\":", "\"rule_id\":\"attest\",\"rule_id\":", 1), Refusal::DuplicateMember),
        ("a member name twice, once escaped", base.replacen("\"pack_id\":", "\"pack_\\u0069d\":\"x\",\"pack_id\":", 1), Refusal::DuplicateMember),
        ("a chain length written 1.0", with_literal(audit_rule(), "minimum_chain_length", "1.0"), Refusal::IntegerSpelling),
        ("a chain length written 1e0", with_literal(audit_rule(), "minimum_chain_length", "1e0"), Refusal::IntegerSpelling),
        ("a chain length written -0", with_literal(audit_rule(), "minimum_chain_length", "-0"), Refusal::IntegerSpelling),
        ("a negative chain length", with_literal(audit_rule(), "minimum_chain_length", "-1"), Refusal::IntegerSpelling),
        (
            "a negative chain length past the parser's integers",
            with_literal(audit_rule(), "minimum_chain_length", "-99999999999999999999"),
            Refusal::IntegerSpelling,
        ),
        ("a chain length of 2^53", with_literal(audit_rule(), "minimum_chain_length", "9007199254740992"), Refusal::IntegerRange),
        (
            "a chain length of 2^64, past the parser's integers",
            with_literal(audit_rule(), "minimum_chain_length", "18446744073709551616"),
            Refusal::IntegerRange,
        ),
        ("version 0.2", edited(&|d| d["version"] = json!("0.2")), Refusal::Version),
        ("pack_version 1.0", edited(&|d| d["pack_version"] = json!("1.0")), Refusal::Value),
        ("an empty description", edited(&|d| d["description"] = json!("")), Refusal::Value),
        ("a severity outside its enum", edited(&|d| d["rules"][0]["severity"] = json!("critical")), Refusal::Value),
        ("a minimum_level outside its enum", edited(&|d| d["rules"][0]["minimum_level"] = json!("quantum")), Refusal::Value),
        ("an empty restricted_list", pack_document(json!([screening])).to_string(), Refusal::Value),
        ("a signature algorithm other than ES256", signature("ES384"), Refusal::Value),
        ("a jurisdiction in lower case", pack_document(json!([residency])).to_string(), Refusal::Jurisdiction),
        ("no rules", edited(&|d| d["rules"] = json!([])), Refusal::EmptyRules),
        (
            "two rules with one rule_id",
            edited(&|d| {
                let r = d["rules"][0].clone();
                d["rules"] = json!([r.clone(), r]);
            }),
            Refusal::DuplicateRuleId,
        ),
        ("a rule that asks for nothing", pack_document(json!([export_control])).to_string(), Refusal::NoRequirement),
        ("127 levels, in a member the format lacks", nested(126), Refusal::Structure),
        ("128 levels, in a member the format lacks", nested(127), Refusal::Nesting),
    ];
    assert!(signature("ES256").len() > 1 && load_pack(&signature("ES256")).is_ok(), "the signature fixture is well formed");
    let mut seen = std::collections::BTreeSet::new();
    for (what, text, expected) in cases {
        let err = load_pack(&text).map(|_| ()).expect_err(what);
        assert_eq!(err.refusal(), Some(expected), "{what}: {err}");
        assert_eq!(err.refusal_id(), expected.id(), "{what}: {err}");
        seen.insert(expected);
    }
    assert_eq!(seen.len(), Refusal::ALL.len(), "every refusal is reached");
}

// ---------------------------------------------------------------------------
//  An object written as the array of its values (QA QT-01; the format
//  document's §3 refusal 2: a member "of the wrong JSON type, at any level")
// ---------------------------------------------------------------------------

/// Each rule type with every one of its own members written, in its struct's
/// declaration order, and a value for each that loads.
fn rules_with_every_member() -> Vec<(&'static str, Vec<(&'static str, Value)>)> {
    vec![
        ("data_residency", vec![("allowed_jurisdictions", json!(["PH"]))]),
        ("source_screening", vec![("restricted_list", json!(["web_crawl"]))]),
        ("export_control", vec![("require_air_gapped", json!(true)), ("require_egress_denied", json!(false))]),
        (
            "audit_integrity",
            vec![
                ("minimum_chain_length", json!(1)),
                ("require_tamper_evident", json!(true)),
                ("require_input_committed", json!(false)),
                ("require_ordered_record", json!(false)),
                ("require_verified_lineage", json!(false)),
            ],
        ),
        (
            "execution_integrity",
            vec![
                ("require_learned_state_components", json!(false)),
                ("require_environment_pinned", json!(true)),
                ("require_tee", json!(false)),
                ("require_state_kept", json!(false)),
            ],
        ),
        ("attestation_level", vec![("minimum_level", json!("software"))]),
        ("documentation_declared", vec![("document", json!("data_governance"))]),
    ]
}

/// A rule of `rule_type` holding `members`, and the same rule as the array
/// serde's derive for an internally tagged enum read as it: the tag, then the
/// values in declaration order.
fn rule_and_array(rule_type: &str, members: &[(&str, Value)]) -> (Value, Value) {
    let common = [
        ("rule_id", json!("respelled")),
        ("description", json!("A rule of a test.")),
        ("severity", json!("mandatory")),
        ("reference", json!("vmr-policy tests, pack_strict.rs")),
    ];
    let mut rule = json!({"type": rule_type});
    let mut values = vec![json!(rule_type)];
    for (name, value) in common.iter().chain(members) {
        rule[*name] = value.clone();
        values.push(value.clone());
    }
    (rule, Value::Array(values))
}

#[test]
fn an_object_written_as_the_array_of_its_values_is_refusal_2_at_every_level() {
    // serde's derive reads a struct from the array of its values in
    // declaration order: each text below read as the pack. The loader reads
    // strictly, so the pack itself, its authority and its signature section
    // are each refused as refusal 2.
    let mut signed = good();
    signed["signature"] = json!({
        "algorithm": "ES256",
        "signature": format!("base64url:{}", "A".repeat(86)),
        "signed_payload_hash": format!("sha256:{}", "0".repeat(64)),
        "signing_key_id": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg"
    });
    let expected = load(&signed).expect("the signed fixture loads").pack().clone();
    let objects: [(&str, &[&str]); 3] = [
        ("", &["version", "pack_id", "pack_version", "jurisdiction", "description", "disclaimer", "authority", "rules", "signature"]),
        ("/authority", &["authority_id", "authority_name"]),
        ("/signature", &["algorithm", "signature", "signed_payload_hash", "signing_key_id"]),
    ];
    for (pointer, fields) in objects {
        let mut respelled = signed.clone();
        let object = respelled.pointer_mut(pointer).unwrap();
        assert_eq!(object.as_object().unwrap().len(), fields.len(), "{pointer}: every member, in declaration order");
        let values: Vec<Value> = fields.iter().map(|f| object[*f].clone()).collect();
        *object = Value::Array(values);
        let text = respelled.to_string();
        assert_eq!(serde_json::from_str::<vmr_policy::PolicyPack>(&text).unwrap(), expected, "{pointer}: serde_json reads it as the pack");
        let err = load_pack(&text).map(|_| ()).expect_err(pointer);
        assert_eq!(err.refusal(), Some(Refusal::Structure), "{pointer}: {err}");
        assert!(err.to_string().contains("invalid type: sequence, expected "), "{pointer}: {err}");
    }
    // A rule of each type: the object loads, and the array serde's internally
    // tagged derive read as the same rule (the tag first) is refused.
    let every = rules_with_every_member();
    assert_eq!(every.len(), vmr_policy::pack::RULE_TYPES.len());
    for (rule_type, members) in &every {
        let (rule, array) = rule_and_array(rule_type, members);
        let pack = try_one_rule_pack(rule).unwrap_or_else(|e| panic!("{rule_type}: {e}"));
        assert_eq!(pack.rules[0].rule_type(), *rule_type);
        let err = try_one_rule_pack(array).map(|_| ()).expect_err(rule_type);
        assert_eq!(err.refusal(), Some(Refusal::Structure), "{rule_type}: {err}");
        assert!(err.to_string().contains("invalid type: sequence, expected struct Rule"), "{rule_type}: {err}");
    }
}

#[test]
fn a_rule_is_read_member_by_member_and_refused_as_the_derive_refused_it() {
    // QA QT-01: a rule is read without a buffer, from a closed struct of every
    // rule member, then checked against its type. It accepts and refuses the
    // rules serde's derive for the internally tagged enum did, arrays aside,
    // and a refused rule keeps its refusal id, refusal 2. The messages are
    // serde's; a rule that breaks one rule of the format is refused naming the
    // member or type at fault, as below. Where a rule breaks several, the
    // words and the position may differ from the derive's: wording is not part
    // of v0.1 (the format document's §3; QA QT-01 QJ-01).
    let read = |rule: Value| serde_json::from_value::<vmr_policy::Rule>(rule);
    for (rule_type, members) in rules_with_every_member() {
        let (rule, _) = rule_and_array(rule_type, &members);
        let parsed = read(rule.clone()).unwrap_or_else(|e| panic!("{rule_type}: {e}"));
        assert_eq!(parsed.rule_type(), rule_type);
        // `type` may come after every other member: the text is read whole
        // before the type is looked up.
        let text = rule.to_string();
        let member = format!("\"type\":\"{rule_type}\"");
        let without = text.replacen(&format!("{member},"), "", 1).replacen(&format!(",{member}"), "", 1);
        assert!(!without.contains(&member), "{rule_type}: {without}");
        let type_last = format!("{},{member}}}", &without[..without.len() - 1]);
        assert_eq!(serde_json::from_str::<vmr_policy::Rule>(&type_last).unwrap(), parsed, "{rule_type}: type last");
    }
    let attestation = || {
        json!({"type": "attestation_level", "rule_id": "attest", "description": "d", "severity": "mandatory", "reference": "r", "minimum_level": "software"})
    };
    // Refused when read, and refused by the loader as refusal 2.
    let refused = |edit: &dyn Fn(&mut Value)| {
        let mut rule = attestation();
        edit(&mut rule);
        let err = try_one_rule_pack(rule.clone()).map(|_| ()).expect_err("the loader refuses it");
        assert_eq!(err.refusal(), Some(Refusal::Structure), "{rule}: {err}");
        read(rule).expect_err("refused").to_string()
    };
    assert_eq!(
        refused(&|r| r["type"] = json!("thermal_limits")),
        "unknown variant `thermal_limits`, expected one of `data_residency`, `source_screening`, `export_control`, \
         `audit_integrity`, `execution_integrity`, `attestation_level`, `documentation_declared`"
    );
    assert_eq!(
        refused(&|r| r["require_tee"] = json!(true)),
        "unknown field `require_tee`, expected one of `rule_id`, `description`, `severity`, `reference`, `minimum_level`"
    );
    assert_eq!(refused(&|r| drop(r.as_object_mut().unwrap().remove("type"))), "missing field `type`");
    assert_eq!(refused(&|r| drop(r.as_object_mut().unwrap().remove("reference"))), "missing field `reference`");
    assert_eq!(refused(&|r| drop(r.as_object_mut().unwrap().remove("minimum_level"))), "missing field `minimum_level`");
    assert!(refused(&|r| r["surprise"] = json!(true)).starts_with("unknown field `surprise`"));
    assert!(refused(&|r| r["minimum_level"] = Value::Null).starts_with("invalid type: null"));
    assert!(refused(&|r| r["type"] = Value::Null).starts_with("invalid type: null"));
    // Rules that break more than one rule, or a member's type: refused, as
    // refusal 2, whatever their words (the QA's four families, QJ-01).
    for (what, edit) in [
        ("a member of another type, null", Box::new(|r: &mut Value| r["require_tee"] = Value::Null) as Box<dyn Fn(&mut Value)>),
        ("a member of another type, wrongly typed", Box::new(|r| r["require_tee"] = json!("yes"))),
        ("an unknown type beside an unknown member", Box::new(|r| {
            r["type"] = json!("thermal_limits");
            r["surprise"] = json!(true);
        })),
        ("no type beside an unknown member", Box::new(|r| {
            r.as_object_mut().unwrap().remove("type");
            r["surprise"] = json!(true);
        })),
        ("a severity that is not a string", Box::new(|r| r["severity"] = json!(1))),
    ] {
        assert!(!refused(&*edit).is_empty(), "{what}");
    }
    let mut tee_null = json!({"type": "execution_integrity", "rule_id": "e", "description": "d", "severity": "mandatory", "reference": "r", "require_tee": null});
    assert!(read(tee_null.take()).is_err(), "a defaulted member is never null");
    let duplicate = attestation().to_string().replacen("\"type\":\"attestation_level\"", "\"type\":\"attestation_level\",\"type\":\"attestation_level\"", 1);
    assert!(serde_json::from_str::<vmr_policy::Rule>(&duplicate).unwrap_err().to_string().starts_with("duplicate field `type`"));
    assert!(read(json!("attestation_level")).is_err(), "a rule is an object");
}
