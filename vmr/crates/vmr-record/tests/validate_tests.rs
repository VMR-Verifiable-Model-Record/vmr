// tests/validate_tests.rs — the schema's string rules as hand-written
// matchers (Phase 4, decisions D3/D4): UTC-seconds timestamps with calendar
// validity, and one matcher per schema `pattern`, checked against the
// `regex` crate (a dev-dependency; never on a verification path).

use vmr_record::timestamp::Timestamp;
use vmr_record::validate::Pattern;

// ---------------------------------------------------------------------------
//  Timestamps: YYYY-MM-DDTHH:MM:SSZ, proleptic Gregorian, calendar-validated
// ---------------------------------------------------------------------------

/// Known answers computed independently with Python's calendar.timegm (and,
/// for year 0000, as 0001-01-01 minus the 366 days of the leap year 0).
const KNOWN: [(&str, i64); 13] = [
    ("1970-01-01T00:00:00Z", 0),
    ("1969-12-31T23:59:59Z", -1),
    ("2026-09-10T00:00:00Z", 1_788_998_400),
    ("2026-09-11T00:00:00Z", 1_789_084_800),
    ("2000-02-29T23:59:59Z", 951_868_799),
    ("2024-02-29T12:00:00Z", 1_709_208_000),
    ("2100-02-28T23:59:59Z", 4_107_542_399),
    ("2100-03-01T00:00:00Z", 4_107_542_400),
    ("2038-01-19T03:14:08Z", 2_147_483_648),
    ("1900-03-01T00:00:00Z", -2_203_891_200),
    ("0001-01-01T00:00:00Z", -62_135_596_800),
    ("0000-01-01T00:00:00Z", -62_167_219_200),
    ("9999-12-31T23:59:59Z", 253_402_300_799),
];

#[test]
fn timestamps_have_the_known_unix_seconds() {
    for (text, secs) in KNOWN {
        let t = Timestamp::parse(text).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(t.unix_seconds(), secs, "{text}");
    }
}

#[test]
fn timestamps_round_trip_through_text_and_seconds() {
    for (text, secs) in KNOWN {
        let t = Timestamp::parse(text).unwrap();
        assert_eq!(t.to_string(), text);
        assert_eq!(Timestamp::from_unix_seconds(secs), Some(t), "{text}");
    }
    // Outside years 0000..=9999 there is no profile text, hence no Timestamp.
    assert_eq!(Timestamp::from_unix_seconds(-62_167_219_201), None);
    assert_eq!(Timestamp::from_unix_seconds(253_402_300_800), None);
    assert_eq!(Timestamp::from_unix_seconds(i64::MIN), None);
    assert_eq!(Timestamp::from_unix_seconds(i64::MAX), None);
}

#[test]
fn timestamps_validate_the_calendar() {
    // Leap years: divisible by 4, except centuries, except every 400th.
    for ok in ["2000-02-29T00:00:00Z", "2024-02-29T00:00:00Z", "0000-02-29T00:00:00Z"] {
        assert!(Timestamp::parse(ok).is_ok(), "{ok}");
    }
    for bad in [
        "2100-02-29T00:00:00Z", // century, not a leap year
        "1900-02-29T00:00:00Z",
        "2023-02-29T00:00:00Z",
        "2024-02-30T00:00:00Z", // no Feb 30, ever
        "2026-04-31T00:00:00Z", // April has 30 days
        "2026-09-00T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-13-10T00:00:00Z",
        "2026-09-32T00:00:00Z",
    ] {
        let err = Timestamp::parse(bad).expect_err(bad);
        assert_eq!(err.rule, "timestamp", "{bad}");
    }
}

#[test]
fn timestamps_accept_only_the_utc_seconds_profile() {
    // The last second of the day is 23:59:59; 24:00:00 and a leap second 60
    // are not in the profile. Nor are lower-case t/z, offsets, fractions,
    // missing or extra characters, look-alike digits, or whitespace.
    assert!(Timestamp::parse("2026-09-10T23:59:59Z").is_ok());
    for bad in [
        "2026-09-10T24:00:00Z",
        "2026-09-10T23:60:00Z",
        "2026-09-10T23:59:60Z",
        "2026-09-10t00:00:00Z",
        "2026-09-10T00:00:00z",
        "2026-09-10T00:00:00+00:00",
        "2026-09-10T00:00:00.5Z",
        "2026-09-10T00:00:00",
        "2026-09-10 00:00:00Z",
        "2026-9-10T00:00:00Z",
        "26-09-10T00:00:00Z",
        "+2026-09-10T00:00:00Z",
        "2026-09-10T00:00:00ZZ",
        " 2026-09-10T00:00:00Z",
        "2026-09-10T00:00:00Z\n",
        "２026-09-10T00:00:00Z",  // FULLWIDTH DIGIT TWO
        "2026-09-1\u{661}T00:00:00Z", // ARABIC-INDIC DIGIT ONE
        "",
        "yesterday",
    ] {
        assert!(Timestamp::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn timestamps_order_chronologically_and_lexically() {
    let mut texts: Vec<&str> = KNOWN.iter().map(|(t, _)| *t).collect();
    texts.sort_unstable();
    let parsed: Vec<Timestamp> = texts.iter().map(|t| Timestamp::parse(t).unwrap()).collect();
    for pair in parsed.windows(2) {
        assert!(pair[0] < pair[1], "{} < {}", pair[0], pair[1]);
        assert!(pair[0].unix_seconds() < pair[1].unix_seconds());
    }
}

#[test]
fn a_format_violation_says_where_and_why() {
    let err = Timestamp::parse("2024-02-30T00:00:00Z").unwrap_err();
    assert_eq!(err.pointer, "");
    assert_eq!(err.rule, "timestamp");
    let text = err.to_string();
    assert!(text.contains("2024-02-30") && text.contains("calendar"), "{text}");
}

// ---------------------------------------------------------------------------
//  The schema's patterns: hand-written matchers vs. the regex crate
// ---------------------------------------------------------------------------

/// Valid seeds per pattern (the vector's values where it has one).
fn seeds(p: Pattern) -> Vec<String> {
    let v = |s: &str| s.to_string();
    match p {
        Pattern::Timestamp => vec![v("2026-09-10T00:00:00Z"), v("2024-02-29T23:59:59Z")],
        Pattern::UuidUrn => vec![v("urn:uuid:2b6a0c48-9f21-4f3a-8c51-1d0b4a7e9c00")],
        Pattern::Hash => vec![v(
            "sha256:ca124043b83197f265fddd74ea89492026d824e26af356786c50972fbf594435",
        )],
        Pattern::OptionalHash => vec![
            v(""),
            v("sha256:a98e5dba0e01b88a3fc6f74132a1307fda4f3a1ed515e0dd135e588da905a352"),
        ],
        Pattern::Did => vec![
            v("did:web:factory-operator.ph"),
            v("did:web:example.com%3A8443:user:alice"),
            v("did:key:z6Mk_9.x-Y"),
            v("did:a:b"),
        ],
        Pattern::JwkCoordinate => vec![
            v("lhRE8GZODXHnOx5CcKu3icCMv-8OK7jXabfTHjK03qw"),
            v("ec-95I6PGCrVpTShOPyuo1pTUSqlRSQ_zTGxchcyiPY"),
        ],
        Pattern::KeyId => vec![v(
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:HyoPYysSFOQ5d6x64H8_pHddcHp7E91G5SZbdiaeWJg",
        )],
        Pattern::Signature => vec![v(
            "base64url:dBB294VwlFntfR2YZbhRo1OioleRnRm1-Y2kiFaZM7FVsJt42g9-jwZKNnJ0wWpu5YACkCkuq9mgIybQJ98-Zw",
        )],
        Pattern::CountryCode => vec![v("PH"), v("ZZ")],
        Pattern::StatementFormat => vec![v("oms-v1"), v("org.example.model-card-v1"), v("a0.9-")],
    }
}

/// Every single-character substitution, deletion and insertion over
/// `alphabet`, at every position, plus the seed itself: a deterministic
/// corpus around the pattern's boundary (lengths ±1 included).
fn corpus(seed: &str, alphabet: &[char]) -> Vec<String> {
    let chars: Vec<char> = seed.chars().collect();
    let mut out = vec![seed.to_string(), String::new()];
    for i in 0..=chars.len() {
        for &c in alphabet {
            let mut ins = chars.clone();
            ins.insert(i, c);
            out.push(ins.into_iter().collect());
            if i < chars.len() {
                let mut sub = chars.clone();
                sub[i] = c;
                out.push(sub.into_iter().collect());
            }
        }
        if i < chars.len() {
            let mut del = chars.clone();
            del.remove(i);
            out.push(del.into_iter().collect());
        }
    }
    out
}

/// Boundary characters of every pattern's classes, plus look-alikes: the
/// Cyrillic а/е/о, Greek ο, full-width and Arabic-Indic digits, a soft
/// hyphen, and the whitespace a `$` in a line-oriented engine would forgive.
const ALPHABET: [char; 44] = [
    '0', '1', '4', '8', '9', 'a', 'f', 'g', 'z', 'A', 'E', 'F', 'G', 'Q', 'Z', 'c', 'w', 'y',
    'T', '-', '_', ':', '.', '%', '=', '+', '/', ' ', '\n', '\r', '\t', '\0', 'é', 'а', 'е',
    'о', 'ο', '０', '١', '\u{ad}', '\u{200b}', '~', '#', '@',
];

#[test]
fn pattern_differential() {
    // The regex crate is the oracle for every schema pattern: same answer
    // on every string of the corpus. The timestamp matcher may be stricter
    // (calendar validation): there, matcher => regex, and every string the
    // regex alone accepts must be a date that does not exist.
    let mut checked = 0usize;
    for p in Pattern::ALL {
        let re = regex::Regex::new(p.regex()).unwrap_or_else(|e| panic!("{p:?}: {e}"));
        for seed in seeds(p) {
            assert!(p.matches(&seed), "{p:?} rejects its own seed {seed:?}");
            for s in corpus(&seed, &ALPHABET) {
                let (mine, oracle) = (p.matches(&s), re.is_match(&s));
                if p == Pattern::Timestamp {
                    assert!(!mine || oracle, "timestamp matcher accepts {s:?}, regex does not");
                    if oracle && !mine {
                        assert!(!calendar_date_exists(&s), "{s:?} is a real date");
                    }
                } else {
                    assert_eq!(mine, oracle, "{p:?} on {s:?}");
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 50_000, "corpus too small: {checked}");
}

/// Independent calendar check for a string the timestamp regex accepted.
fn calendar_date_exists(s: &str) -> bool {
    let y: u32 = s[0..4].parse().unwrap();
    let m: u32 = s[5..7].parse().unwrap();
    let d: u32 = s[8..10].parse().unwrap();
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let len = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    d <= len[(m - 1) as usize]
}

#[test]
fn did_matcher_follows_did_core() {
    for ok in [
        "did:web:factory-operator.ph",
        "did:web:example.com%3A8443",
        "did:example:123:456",
        "did:example::x", // an empty segment between colons is allowed
        "did:0:x",
    ] {
        assert!(Pattern::Did.matches(ok), "{ok}");
    }
    for bad in [
        "did:web:",           // empty method-specific id
        "did:web:a:",         // may not end in ':'
        "did:Web:a",          // method names are lower-case
        "did::a",             // empty method name
        "did:web:a%2",        // truncated escape
        "did:web:a%zz",       // not hex
        "did:web:f\u{430}ctory", // look-alike Unicode
        "did:web:a b",
        "DID:web:a",
        "did:web",
    ] {
        assert!(!Pattern::Did.matches(bad), "{bad}");
    }
}

// ---------------------------------------------------------------------------
//  The rule table (task 4.3a): RULES == the schema, both directions; every
//  value rule enforced by validate_format; spec §7 by check_consistency.
// ---------------------------------------------------------------------------

use serde_json::{json, Value};
use vmr_record::hash::{format_hash, sha256};
use vmr_record::named_set::named_set_digest;
use vmr_record::record::Record;
use vmr_record::validate::{ModelDescription, RuleKind, KHALM_ENGINE_PROFILE, RULES};

fn load_json(rel: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs").join(rel);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn vector_value() -> Value {
    load_json("test-vectors/record/example-v0.1.json")["record"].clone()
}

fn vector_record() -> Record {
    serde_json::from_value(vector_value()).unwrap()
}

/// Every `(pointer, keyword, JSON value)` rule of a schema node and its
/// children (`*` = array items); any keyword outside the implemented set
/// fails, so the schema cannot grow a rule the code does not know.
fn schema_rules(node: &Value, pointer: &str, out: &mut Vec<(String, String, String)>) {
    const ANNOTATIONS: [&str; 4] = ["$schema", "$id", "title", "description"];
    const KEYWORDS: [&str; 12] = [
        "type", "const", "enum", "pattern", "format", "minimum", "maximum", "minItems",
        "maxItems", "minLength", "required", "additionalProperties",
    ];
    for (k, v) in node.as_object().unwrap() {
        if KEYWORDS.contains(&k.as_str()) {
            out.push((pointer.to_string(), k.clone(), serde_json::to_string(v).unwrap()));
        } else if k == "properties" {
            for (name, sub) in v.as_object().unwrap() {
                schema_rules(sub, &format!("{pointer}/{name}"), out);
            }
        } else if k == "items" {
            schema_rules(v, &format!("{pointer}/*"), out);
        } else {
            assert!(ANNOTATIONS.contains(&k.as_str()), "unsupported schema keyword {k} at {pointer:?}");
        }
    }
}

#[test]
fn schema_sync() {
    let mut from_schema = Vec::new();
    schema_rules(&load_json("record-schema/v0.1.json"), "", &mut from_schema);
    from_schema.sort();
    let mut from_code: Vec<(String, String, String)> = RULES
        .iter()
        .map(|r| (r.pointer.to_string(), r.kind.keyword().to_string(), r.kind.value().to_string()))
        .collect();
    from_code.sort();
    for rule in &from_schema {
        assert!(from_code.contains(rule), "schema rule missing from RULES: {rule:?}");
    }
    for rule in &from_code {
        assert!(from_schema.contains(rule), "RULES entry not in the schema: {rule:?}");
    }
    assert_eq!(from_code.len(), from_schema.len(), "no duplicates in RULES");
}

#[test]
fn the_vector_satisfies_every_rule() {
    let p = vector_record();
    p.validate_format().unwrap();
    p.check_consistency().unwrap();
}

/// `pointer` with `*` replaced by index 0.
fn concrete(pointer: &str) -> String {
    pointer.replace('*', "0")
}

/// The vector with every optional member present, each with a value that
/// every value rule accepts, so that a rule under an optional member has a
/// value to break (tasks 10.11a, 10.11b and 10.11e). It is not consistent
/// (spec §7): only `validate_format` is run on it.
fn vector_with_every_optional_member() -> Value {
    let mut v = vector_value();
    let hash = |label: &str| format_hash(&sha256(label.as_bytes()));
    v["data_governance"] = json!({"documentation_hash": hash("data governance")});
    v["human_oversight"] = json!({"documentation_hash": hash("human oversight")});
    v["model_identity"]["derived_from"] = json!([{"model_hash": hash("base"), "name": "base", "relation": "fine-tune"}]);
    v["model_identity"]["statement_references"] = json!([{"format": "oms-v1", "digest": hash("an in-toto statement")}]);
    v["learning_provenance"]["training_environment"]["accelerator"] = json!("CPU");
    v["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = json!(["PH", "SG"]);
    v["learning_provenance"]["training_input_format"] = json!("khalmtrn-frame-v1");
    v["learning_provenance"]["training_input_disclosure"] = json!("not-held");
    v
}

/// [`vector_with_every_optional_member`] with the value at `pointer`
/// replaced.
fn vector_with(pointer: &str, value: Value) -> Record {
    let mut v = vector_with_every_optional_member();
    let (parent, name) = pointer.rsplit_once('/').unwrap();
    match v.pointer_mut(parent).unwrap_or_else(|| panic!("{pointer}: no parent")) {
        Value::Object(m) => {
            m.insert(name.to_string(), value);
        }
        Value::Array(items) => items[name.parse::<usize>().unwrap()] = value,
        other => panic!("{other}"),
    }
    serde_json::from_value(v).unwrap_or_else(|e| panic!("{pointer}: {e}"))
}

#[test]
fn every_value_rule_rejects_a_violation() {
    // One violation per value rule of the table (the parser enforces type,
    // required and additionalProperties; the signature section is checked
    // by the signature checks, not here). Each must fail validate_format at
    // exactly that pointer, with exactly that rule.
    let mut exercised = 0;
    for rule in RULES {
        if rule.pointer.starts_with("/signature") || rule.kind.enforced_by_parser() {
            continue;
        }
        let at = concrete(rule.pointer);
        let bad = match &rule.kind {
            RuleKind::Const(_) => vector_with(&at, json!("x")),
            RuleKind::Enum(_) => vector_with(&at, json!("root")),
            // A space fails every pattern, a statement format's included
            // (task 10.11e: "not-matching" is a valid format name).
            RuleKind::Pattern(_) => vector_with(&at, json!("not matching")),
            RuleKind::Format(_) => vector_with(&at, json!("yesterday")),
            RuleKind::MinLength(_) => vector_with(&at, json!("")),
            RuleKind::Minimum(0) => continue, // an unsigned integer cannot go below 0
            RuleKind::Minimum(n) => vector_with(&at, json!(n - 1)),
            RuleKind::Maximum(_) => {
                // The parser refuses > 2^53 - 1, so build it in memory.
                let mut p: Record = serde_json::from_value(vector_with_every_optional_member()).unwrap();
                let field = match rule.pointer {
                    "/model_identity/parameter_count" => p.model_identity.parameter_count.as_mut().unwrap(),
                    "/model_identity/learned_state_components/*/size_bytes" => {
                        &mut p.model_identity.learned_state_components[0].size_bytes
                    }
                    "/learning_provenance/training_input_count" => {
                        &mut p.learning_provenance.training_input_count
                    }
                    "/learning_provenance/training_epochs" => p.learning_provenance.training_epochs.as_mut().unwrap(),
                    "/lineage/lineage_chain_length" => &mut p.lineage.lineage_chain_length,
                    other => panic!("no field for {other}"),
                };
                *field = 1u64 << 53;
                p
            }
            RuleKind::MinItems(n) => {
                // One item fewer than the minimum.
                let mut v = vector_with_every_optional_member();
                v.pointer_mut(rule.pointer).unwrap().as_array_mut().unwrap().truncate(*n as usize - 1);
                serde_json::from_value(v).unwrap()
            }
            RuleKind::MaxItems(n) => {
                // One item more than the maximum.
                let mut v = vector_with_every_optional_member();
                let items = v.pointer_mut(rule.pointer).unwrap().as_array_mut().unwrap();
                while items.len() as u64 <= *n {
                    items.push(items[0].clone());
                }
                serde_json::from_value(v).unwrap()
            }
            other => panic!("unexpected value rule {other:?}"),
        };
        let err = bad
            .validate_format()
            .expect_err(&format!("{} {} must reject", rule.pointer, rule.kind.keyword()));
        let expected_at = match &rule.kind {
            RuleKind::MinItems(_) | RuleKind::MaxItems(_) => rule.pointer.to_string(),
            _ => at.clone(),
        };
        assert_eq!(err.pointer, expected_at, "{err}");
        // A timestamp field has two rules (`format` and the profile
        // `pattern`) that reject the same values; the table reports the
        // first. Every other rule is the only one at its pointer.
        let timestamp_rule = matches!(rule.kind, RuleKind::Format(_) | RuleKind::Pattern(Pattern::Timestamp));
        if timestamp_rule {
            assert!(["format", "pattern"].contains(&err.rule), "{err}");
        } else {
            assert_eq!(err.rule, rule.kind.keyword(), "{err}");
        }
        exercised += 1;
    }
    assert!(exercised >= 40, "only {exercised} value rules exercised");
}

#[test]
fn a_documentation_hash_is_a_lower_case_sha256_hash() {
    // Task 10.11a, D11-1: `documentation_hash` has the pattern of every hash
    // string (spec §2 rule 5), and no "" form: an absent member already says
    // that no document is declared.
    let good = format!("sha256:{}", "ab".repeat(32));
    let bad = [
        String::new(),
        "sha256:".to_string(),
        format!("sha256:{}", "AB".repeat(32)),
        format!("SHA256:{}", "ab".repeat(32)),
        format!("sha256:{}", "ab".repeat(31)),
        "none".to_string(),
    ];
    for member in ["data_governance", "human_oversight"] {
        let at = format!("/{member}/documentation_hash");
        vector_with(&at, json!(good)).validate_format().unwrap();
        for value in &bad {
            let err = vector_with(&at, json!(value)).validate_format().expect_err(value);
            assert_eq!((err.pointer.as_str(), err.rule), (at.as_str(), "pattern"), "{value:?}");
        }
    }
}

#[test]
fn calendar_invalid_timestamps_fail_the_format_rules() {
    // The regex accepts 2026-02-30; the rule (spec §2 rule 7) does not.
    let bad = vector_with("/issued_at", json!("2026-02-30T00:00:00Z"));
    let err = bad.validate_format().unwrap_err();
    assert_eq!(err.pointer, "/issued_at");
}

#[test]
fn format_rules_leave_the_signature_section_to_the_signature_checks() {
    let mut p = vector_record();
    p.signature.algorithm = "none".into();
    p.signature.signature = "not base64url".into();
    p.validate_format().unwrap();
}

#[test]
fn lineage_chain_length_zero_is_rejected() {
    // Schema minimum 1; a u64 parses 0, and nothing checked it before.
    let bad = vector_with("/lineage/lineage_chain_length", json!(0));
    let err = bad.validate_format().unwrap_err();
    assert_eq!((err.pointer.as_str(), err.rule), ("/lineage/lineage_chain_length", "minimum"));
}

// ---------------------------------------------------------------------------
//  Task 10.11b: the general description, the profile's selection, the
//  training commitment, residency and derived models (spec §7, §8; plan §4.3)
// ---------------------------------------------------------------------------

fn h(bytes: &[u8]) -> String {
    format_hash(&sha256(bytes))
}

/// A general record (spec §7.3) of the model of spec §7.2's example, two
/// files, from a party that holds them and not their training records
/// (§8.4), and deploys nothing. Not signed: only the format rules run on it.
fn general_value() -> Value {
    let mut v = vector_value();
    let digest = "sha256:bcd9ed61d08e582e69d37afb23dbf37c69b14a3e26d1751a7d6ac6f12803c6d3";
    v["model_identity"] = json!({
        "model_hash": digest,
        "model_format": "safetensors",
        "parameter_count": 2,
        "architecture": {"type": "transformer", "topology": "decoder-only", "precision": "bfloat16"},
        "learned_state_hash": digest,
        "learned_state_components": [
            {"name": "config.json", "hash": h(b"{}"), "size_bytes": 2},
            {"name": "weights.bin", "hash": h(&[0u8; 4]), "size_bytes": 4}
        ]
    });
    v["learning_provenance"] = json!({
        "training_input_digest": "",
        "training_input_merkle_root": "",
        "training_input_count": 0,
        "training_environment": {"hardware_id": "", "tee_measurement": "", "software_hash": "", "training_software": ""},
        "training_input_provenance": {"source_type": "", "source_description": ""},
        "training_input_disclosure": "not-held"
    });
    v.as_object_mut().unwrap().remove("deployment_context");
    v
}

fn edited(mut v: Value, edit: impl FnOnce(&mut Value)) -> Record {
    edit(&mut v);
    serde_json::from_value(v).unwrap()
}

/// The pointer of `p`'s first consistency violation.
fn inconsistent_at(p: &Record) -> String {
    let e = p.check_consistency().expect_err("inconsistent");
    assert_eq!(e.rule, "consistency", "{e}");
    e.pointer
}

#[test]
fn a_general_record_is_consistent() {
    let p: Record = serde_json::from_value(general_value()).unwrap();
    assert_eq!(p.model_description(), ModelDescription::General);
    p.validate_format().unwrap();
    p.check_consistency().unwrap();
    assert!(p.deployment_context.is_none() && p.learning_provenance.training_epochs.is_none());
    let v = vector_record();
    assert_eq!((v.model_identity.model_format.as_str(), v.model_description()), (KHALM_ENGINE_PROFILE, ModelDescription::KhalmEngineProfile));
}

#[test]
fn editing_only_model_format_fails_consistency_both_ways() {
    // Spec §7.1: one signed value selects the rules; editing it alone moves no
    // record from one set to the other.
    for format in ["safetensors", "SNN-compact-v1", "snn-compact-v1 ", ""] {
        let dropped = edited(vector_value(), |v| v["model_identity"]["model_format"] = json!(format));
        assert_eq!(dropped.model_description(), ModelDescription::General, "{format:?}");
        assert_eq!(inconsistent_at(&dropped), "/model_identity/learned_state_hash", "{format:?}");
    }
    let added = edited(general_value(), |v| v["model_identity"]["model_format"] = json!(KHALM_ENGINE_PROFILE));
    assert_eq!(inconsistent_at(&added), "/model_identity/learned_state_components");
}

#[test]
fn general_component_names_follow_the_name_rules_and_ascend() {
    for name in ["", "/config.json", "config.json/", "a//config.json", "./config.json", "a/../config.json"] {
        let p = edited(general_value(), |v| v["model_identity"]["learned_state_components"][0]["name"] = json!(name));
        p.validate_format().unwrap();
        assert_eq!(inconsistent_at(&p), "/model_identity/learned_state_components/0/name", "{name:?}");
    }
    let swapped = edited(general_value(), |v| v["model_identity"]["learned_state_components"].as_array_mut().unwrap().swap(0, 1));
    assert_eq!(inconsistent_at(&swapped), "/model_identity/learned_state_components/1/name");
    let repeated = edited(general_value(), |v| v["model_identity"]["learned_state_components"][1]["name"] = json!("config.json"));
    assert_eq!(inconsistent_at(&repeated), "/model_identity/learned_state_components/1/name");
}

#[test]
fn general_component_names_ascend_by_scalar_value_not_by_utf16() {
    // U+FF5E comes before U+1F600 by scalar value (spec §7.2); JCS's UTF-16
    // order (§3) puts U+1F600 first.
    let (config, weights) = (sha256(b"{}"), sha256(&[0u8; 4]));
    let by_scalar = edited(general_value(), |v| {
        let c = &mut v["model_identity"]["learned_state_components"];
        c[0]["name"] = json!("\u{ff5e}");
        c[1]["name"] = json!("\u{1f600}");
        let digest = named_set_digest(&[("\u{ff5e}", config), ("\u{1f600}", weights)]).unwrap();
        v["model_identity"]["learned_state_hash"] = json!(format_hash(&digest));
    });
    by_scalar.check_consistency().unwrap();
    let by_utf16 = edited(general_value(), |v| {
        let c = &mut v["model_identity"]["learned_state_components"];
        c[0]["name"] = json!("\u{1f600}");
        c[1]["name"] = json!("\u{ff5e}");
    });
    assert_eq!(inconsistent_at(&by_utf16), "/model_identity/learned_state_components/1/name");
}

#[test]
fn a_general_learned_state_hash_is_the_components_named_set_digest() {
    let other = edited(general_value(), |v| v["model_identity"]["learned_state_hash"] = json!(h(b"other")));
    assert_eq!(inconsistent_at(&other), "/model_identity/learned_state_hash");
    // A name is bound into the digest (D11b-2): renaming a component breaks it.
    let renamed = edited(general_value(), |v| v["model_identity"]["learned_state_components"][1]["name"] = json!("weights2.bin"));
    assert_eq!(inconsistent_at(&renamed), "/model_identity/learned_state_hash");
    let rehashed = edited(general_value(), |v| v["model_identity"]["learned_state_components"][1]["hash"] = json!(h(b"x")));
    assert_eq!(inconsistent_at(&rehashed), "/model_identity/learned_state_hash");
    // model_hash covers files a record need not carry: not checked.
    edited(general_value(), |v| v["model_identity"]["model_hash"] = json!(h(b"every file"))).check_consistency().unwrap();
    // Sizes and parameter_count are claims in general.
    edited(general_value(), |v| v["model_identity"]["parameter_count"] = json!(7_000_000_000u64)).check_consistency().unwrap();
}

#[test]
fn a_record_that_holds_no_training_records_commits_to_nothing() {
    // Spec §8.4.
    for (member, value) in [
        ("training_input_digest", json!(h(b"d"))),
        ("training_input_merkle_root", json!(h(b"r"))),
        ("training_input_count", json!(1)),
        ("training_input_format", json!("named-set-v1")),
    ] {
        let p = edited(general_value(), |v| v["learning_provenance"][member] = value);
        assert_eq!(inconsistent_at(&p), format!("/learning_provenance/{member}"));
    }
    // Without the disclosure "" commits to nothing, which is refused.
    let empty_root = edited(vector_value(), |v| v["learning_provenance"]["training_input_merkle_root"] = json!(""));
    empty_root.validate_format().unwrap();
    assert_eq!(inconsistent_at(&empty_root), "/learning_provenance/training_input_merkle_root");
    // A general record that commits records names their format.
    let commit = |v: &mut Value| {
        let l = v["learning_provenance"].as_object_mut().unwrap();
        l.remove("training_input_disclosure");
        l.insert("training_input_digest".into(), json!(h(b"d")));
        l.insert("training_input_merkle_root".into(), json!(h(b"r")));
        l.insert("training_input_count".into(), json!(3));
    };
    assert_eq!(inconsistent_at(&edited(general_value(), commit)), "/learning_provenance/training_input_format");
    edited(general_value(), |v| {
        commit(v);
        v["learning_provenance"]["training_input_format"] = json!("named-set-v1");
    })
    .check_consistency()
    .unwrap();
    // The profile's records are its frames.
    let profile = edited(vector_value(), |v| v["learning_provenance"]["training_input_format"] = json!("khalmtrn-frame-v1"));
    assert_eq!(inconsistent_at(&profile), "/learning_provenance/training_input_format");
    // Every not-disclosed record the profile issues is consistent too.
    edited(vector_value(), |v| {
        let l = v["learning_provenance"].as_object_mut().unwrap();
        l.insert("training_input_digest".into(), json!(""));
        l.insert("training_input_merkle_root".into(), json!(""));
        l.insert("training_input_count".into(), json!(0));
        l.insert("training_input_disclosure".into(), json!("not-disclosed"));
    })
    .check_consistency()
    .unwrap();
}

#[test]
fn residency_countries_replace_data_residency_and_ascend() {
    const PROVENANCE: &str = "/learning_provenance/training_input_provenance";
    let set = |countries: Value| move |v: &mut Value| v["learning_provenance"]["training_input_provenance"]["data_residency_countries"] = countries;
    let several = edited(general_value(), set(json!(["DE", "FR"])));
    several.validate_format().unwrap();
    several.check_consistency().unwrap();
    assert_eq!(inconsistent_at(&edited(vector_value(), set(json!(["PH", "SG"])))), format!("{PROVENANCE}/data_residency"));
    assert_eq!(inconsistent_at(&edited(general_value(), set(json!(["FR", "DE"])))), format!("{PROVENANCE}/data_residency_countries/1"));
    assert_eq!(inconsistent_at(&edited(general_value(), set(json!(["DE", "DE"])))), format!("{PROVENANCE}/data_residency_countries/1"));
    let one = edited(general_value(), set(json!(["DE"]))).validate_format().unwrap_err();
    assert_eq!((one.pointer, one.rule), (format!("{PROVENANCE}/data_residency_countries"), "minItems"));
    let lower = edited(general_value(), set(json!(["de", "FR"]))).validate_format().unwrap_err();
    assert_eq!((lower.pointer, lower.rule), (format!("{PROVENANCE}/data_residency_countries/0"), "pattern"));
    // Neither member: the residency is not stated, and nothing is inconsistent.
    edited(vector_value(), |v| {
        v["learning_provenance"]["training_input_provenance"].as_object_mut().unwrap().remove("data_residency");
    })
    .check_consistency()
    .unwrap();
}

#[test]
fn derived_from_entries_ascend_by_model_hash() {
    let (mut lo, mut hi) = (h(b"one base"), h(b"another base"));
    if hi < lo {
        std::mem::swap(&mut lo, &mut hi);
    }
    let bases = |first: &str, second: &str| {
        json!([{"model_hash": first, "name": "", "relation": "merge"}, {"model_hash": second, "name": "second", "relation": "merge"}])
    };
    let ok = edited(general_value(), |v| v["model_identity"]["derived_from"] = bases(&lo, &hi));
    ok.validate_format().unwrap();
    ok.check_consistency().unwrap();
    for (first, second) in [(&hi, &lo), (&lo, &lo)] {
        let p = edited(general_value(), |v| v["model_identity"]["derived_from"] = bases(first, second));
        assert_eq!(inconsistent_at(&p), "/model_identity/derived_from/1/model_hash");
    }
    let empty = edited(general_value(), |v| v["model_identity"]["derived_from"] = json!([])).validate_format().unwrap_err();
    assert_eq!((empty.pointer.as_str(), empty.rule), ("/model_identity/derived_from", "minItems"));
    let finetune = edited(general_value(), |v| {
        v["model_identity"]["derived_from"] = json!([{"model_hash": lo, "name": "", "relation": "finetune"}])
    })
    .validate_format()
    .unwrap_err();
    assert_eq!((finetune.pointer.as_str(), finetune.rule), ("/model_identity/derived_from/0/relation", "enum"));
}

#[test]
fn parameter_count_is_optional_in_general_and_required_in_the_profile() {
    // QA QB-09 (the 10.13a planner's F1): an issuer that does not know its
    // model's parameter count, or whose model has none defined, omits the
    // member in the general description (spec §7.3); the profile
    // snn-compact-v1 requires it at format.consistency (§7.4).
    let without = |v: &mut Value| {
        v["model_identity"].as_object_mut().unwrap().remove("parameter_count");
    };
    let general = edited(general_value(), without);
    assert_eq!(general.model_description(), ModelDescription::General);
    general.validate_format().unwrap();
    general.check_consistency().unwrap();
    // 0 is a statement, not "not stated": it stays a consistent claim.
    edited(general_value(), |v| v["model_identity"]["parameter_count"] = json!(0)).check_consistency().unwrap();
    let profile = edited(vector_value(), without);
    profile.validate_format().unwrap();
    let err = profile.check_consistency().expect_err("the profile requires parameter_count");
    assert_eq!((err.pointer.as_str(), err.rule), ("/model_identity/parameter_count", "consistency"), "{err}");
    assert!(err.detail.contains("requires parameter_count"), "{err}");
    // Present and wrong still fails where it did, with the detail it had.
    let wrong = edited(vector_value(), |v| v["model_identity"]["parameter_count"] = json!(24_705));
    let err = wrong.check_consistency().unwrap_err();
    assert_eq!(err.pointer, "/model_identity/parameter_count");
    assert!(err.detail.starts_with("parameter_count is 24705, not I·H + H·H + H"), "{err}");
}

#[test]
fn a_derived_from_entry_never_names_the_model_itself() {
    // QA QB-08, the reviewer's decision (spec §7.5): a model is not made from
    // itself, so an entry naming the model's own model_hash fails
    // format.consistency, whichever description model_format selects.
    let zeros = format!("sha256:{}", "0".repeat(64));
    for (description, value) in [("general", general_value()), ("profile", vector_value())] {
        let own = value["model_identity"]["model_hash"].as_str().unwrap().to_string();
        let entry = |model_hash: &str| json!({"model_hash": model_hash, "name": "", "relation": "fine-tune"});
        let alone = edited(value.clone(), |v| v["model_identity"]["derived_from"] = json!([entry(&own)]));
        alone.validate_format().unwrap();
        assert_eq!(inconsistent_at(&alone), "/model_identity/derived_from/0/model_hash", "{description}");
        let e = alone.check_consistency().unwrap_err();
        assert!(e.detail.contains("not made from itself"), "{description}: {e}");
        // Second, after a base that comes before it: reported at that entry.
        let second = edited(value.clone(), |v| v["model_identity"]["derived_from"] = json!([entry(&zeros), entry(&own)]));
        assert_eq!(inconsistent_at(&second), "/model_identity/derived_from/1/model_hash", "{description}");
        // Another base is consistent.
        edited(value.clone(), |v| v["model_identity"]["derived_from"] = json!([entry(&zeros)])).check_consistency().unwrap();
    }
}

#[test]
fn statement_references_name_a_registered_or_an_issuers_format_and_ascend_by_digest() {
    // Task 10.11e (D11e-2, D11e-3; spec §7.7): each entry is a format and a
    // digest. A format without "." is registered (v0.1: oms-v1 and
    // vmr-audit-checkpoint-v1), one with
    // "." is the issuer's own, and the entries ascend by digest, none
    // repeated: the same rules whichever description model_format selects.
    let (mut a, mut b) = (h(b"an in-toto statement"), h(b"a model card"));
    if b < a {
        std::mem::swap(&mut a, &mut b);
    }
    let refs = |entries: Value| move |v: &mut Value| v["model_identity"]["statement_references"] = entries;
    for (description, base) in [("general", general_value()), ("profile", vector_value())] {
        let one = edited(base.clone(), refs(json!([{"format": "oms-v1", "digest": a}])));
        one.validate_format().unwrap();
        one.check_consistency().unwrap();
        let two = json!([{"format": "oms-v1", "digest": a}, {"format": "org.example.model-card-v1", "digest": b}]);
        edited(base.clone(), refs(two)).check_consistency().unwrap();
        let unregistered = edited(base.clone(), refs(json!([{"format": "c2pa-manifest", "digest": a}])));
        unregistered.validate_format().unwrap();
        assert_eq!(inconsistent_at(&unregistered), "/model_identity/statement_references/0/format", "{description}");
        for entries in [
            json!([{"format": "oms-v1", "digest": b}, {"format": "oms-v1", "digest": a}]),
            json!([{"format": "oms-v1", "digest": a}, {"format": "org.example.model-card-v1", "digest": a}]),
        ] {
            let p = edited(base.clone(), refs(entries));
            assert_eq!(inconsistent_at(&p), "/model_identity/statement_references/1/digest", "{description}");
        }
    }
    // format.schema: lower-case ASCII segments joined by ".", a hash string,
    // one or more entries.
    const AT: &str = "/model_identity/statement_references";
    for format in ["", "OMS-v1", "oms\u{2010}v1", "\u{43e}ms-v1", ".oms", "oms.", "oms..v1", "-oms", "oms v1"] {
        let e = edited(general_value(), refs(json!([{"format": format, "digest": a}]))).validate_format().expect_err(format);
        assert_eq!((e.pointer, e.rule), (format!("{AT}/0/format"), "pattern"), "{format:?}");
    }
    for digest in [String::new(), a.to_uppercase(), format!("{a}0")] {
        let e = edited(general_value(), refs(json!([{"format": "oms-v1", "digest": digest}]))).validate_format().unwrap_err();
        assert_eq!((e.pointer, e.rule), (format!("{AT}/0/digest"), "pattern"));
    }
    let e = edited(general_value(), refs(json!([]))).validate_format().unwrap_err();
    assert_eq!((e.pointer.as_str(), e.rule), (AT, "minItems"));
}

#[test]
fn every_registered_statement_format_is_defined_in_a_published_format() {
    // QA QC-01 (the reviewer's decision A): a registered statement format is
    // part of record_version "0.1", so §7.7 of the record format itself states
    // which bytes each one's digest covers, and sends no reader to a document
    // that is not published with it (the commercial sovereignty format).
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/record-format-v0.1.md");
    let spec = std::fs::read_to_string(&path).unwrap();
    let start = spec.find("### 7.7 ").expect("the record format has a §7.7");
    let end = start + spec[start..].find("\n## ").expect("a section follows §7.7");
    let section = &spec[start..end];
    for format in vmr_record::validate::REGISTERED_STATEMENT_FORMATS {
        assert!(section.contains(&format!("- **`{format}`:**")), "§7.7 states no digest for the registered format {format}");
    }
    assert!(!section.contains("sovereignty-format"), "§7.7 defines a registered format by the sovereignty format:\n{section}");
    let checkpoint = &section[section.find("- **`vmr-audit-checkpoint-v1`:**").unwrap()..];
    assert!(checkpoint.contains("RFC 8785"), "§7.7 states the checkpoint's signed payload in its own terms:\n{checkpoint}");
}

#[test]
fn vmr_audit_checkpoint_v1_is_a_registered_format() {
    // Task 10.11cd (the owner, 2026-09-15, answering Phase 8's Q9(b); spec
    // §7.7): a record names an audit-log checkpoint by the SHA-256 of its
    // signed payload, format vmr-audit-checkpoint-v1, a registered format
    // beside oms-v1. The rules are §7.7's: a registered name is compared as
    // an exact string, a look-alike without "." is refused, and another
    // letter case fails the pattern.
    assert_eq!(vmr_record::validate::REGISTERED_STATEMENT_FORMATS, ["oms-v1", "vmr-audit-checkpoint-v1"]);
    let digest = h(b"a checkpoint's signed payload");
    let refs = |format: &str| {
        let entries = json!([{"format": format, "digest": digest}]);
        move |v: &mut Value| v["model_identity"]["statement_references"] = entries
    };
    for (description, base) in [("general", general_value()), ("profile", vector_value())] {
        let registered = edited(base.clone(), refs("vmr-audit-checkpoint-v1"));
        registered.validate_format().unwrap();
        registered.check_consistency().unwrap();
        let dotted = edited(base.clone(), refs("vmr.audit-checkpoint-v1"));
        dotted.check_consistency().unwrap();
        for look_alike in ["vmr-audit-checkpoint-v2", "vmr-audit-checkpoint", "vmr-checkpoint-v1"] {
            let p = edited(base.clone(), refs(look_alike));
            p.validate_format().unwrap();
            assert_eq!(inconsistent_at(&p), "/model_identity/statement_references/0/format", "{description}: {look_alike}");
        }
    }
    let e = edited(general_value(), refs("VMR-audit-checkpoint-v1")).validate_format().unwrap_err();
    assert_eq!((e.pointer.as_str(), e.rule), ("/model_identity/statement_references/0/format", "pattern"));
}

#[test]
fn new_optional_strings_are_never_empty() {
    for (at, pointer) in [
        ("accelerator", "/learning_provenance/training_environment/accelerator"),
        ("accelerator_software", "/learning_provenance/training_environment/accelerator_software"),
        ("training_input_format", "/learning_provenance/training_input_format"),
    ] {
        let err = vector_with(pointer, json!("")).validate_format().expect_err(at);
        assert_eq!((err.pointer.as_str(), err.rule), (pointer, "minLength"));
        vector_with(pointer, json!("\u{1f600}")).validate_format().unwrap();
    }
}

#[test]
fn consistency_rules_each_break_once() {
    // Spec §7 / D4 (e). The vector: I = 64, H = 128.
    type Edit = fn(&mut Record);
    let cases: [(&str, Edit, &str); 9] = [
        (
            "components reordered",
            |p| p.model_identity.learned_state_components.swap(0, 1),
            "/model_identity/learned_state_components",
        ),
        (
            "a component renamed",
            |p| p.model_identity.learned_state_components[2].name = "afferent_H".into(),
            "/model_identity/learned_state_components",
        ),
        (
            "two components",
            |p| {
                p.model_identity.learned_state_components.pop();
            },
            "/model_identity/learned_state_components",
        ),
        (
            "thresholds not 4*H",
            |p| p.model_identity.learned_state_components[2].size_bytes = 511,
            "/model_identity/learned_state_components/2/size_bytes",
        ),
        (
            "no hidden neurons",
            |p| p.model_identity.learned_state_components[2].size_bytes = 0,
            "/model_identity/learned_state_components/2/size_bytes",
        ),
        (
            "recurrent not H*H",
            |p| p.model_identity.learned_state_components[1].size_bytes = 16_385,
            "/model_identity/learned_state_components/1/size_bytes",
        ),
        (
            "afferent not I*H",
            |p| p.model_identity.learned_state_components[0].size_bytes = 8_193,
            "/model_identity/learned_state_components/0/size_bytes",
        ),
        (
            "parameter_count off by one",
            |p| *p.model_identity.parameter_count.as_mut().unwrap() += 1,
            "/model_identity/parameter_count",
        ),
        (
            "model_hash != learned_state_hash",
            |p| p.model_identity.model_hash = p.model_identity.learned_state_components[0].hash.clone(),
            "/model_identity/model_hash",
        ),
    ];
    for (what, edit, pointer) in cases {
        let mut p = vector_record();
        edit(&mut p);
        let err = p.check_consistency().expect_err(what);
        assert_eq!((err.pointer.as_str(), err.rule), (pointer, "consistency"), "{what}: {err}");
    }
    // parameter_count - 1 fails too, and the arithmetic cannot overflow.
    let mut p = vector_record();
    *p.model_identity.parameter_count.as_mut().unwrap() -= 1;
    assert!(p.check_consistency().is_err());
    let mut p = vector_record();
    p.model_identity.learned_state_components[2].size_bytes = 4 * (1u64 << 40);
    assert!(p.check_consistency().is_err());
}

#[test]
fn lineage_consistency_rules_each_break_once() {
    // Spec §6.5 (the verifier's lineage.consistency; the builder runs it
    // before signing). The vector is initial: id U0, chain length 1, its own
    // root. Each rule broken once, reported at the member that breaks it.
    const OTHER: &str = "urn:uuid:00000000-0000-4000-8000-0000000000b9";
    let hash = || Some(format!("sha256:{}", "ab".repeat(32)));
    let non_initial = |p: &mut Record| {
        p.lineage.lineage_type = "fine-tune".into();
        p.lineage.previous_record_id = Some(OTHER.into());
        p.lineage.previous_record_hash = Some(format!("sha256:{}", "cd".repeat(32)));
        p.lineage.lineage_chain_length = 2;
        p.lineage.root_record_id = OTHER.into();
    };
    let mut p = vector_record();
    p.check_lineage_consistency().unwrap();
    non_initial(&mut p);
    p.check_lineage_consistency().unwrap();

    type Edit = Box<dyn Fn(&mut Record)>;
    let cases: Vec<(&str, bool, Edit, &str)> = vec![
        ("initial naming a predecessor", false, Box::new(move |p| {
            p.lineage.previous_record_id = Some(OTHER.into());
            p.lineage.previous_record_hash = hash();
        }), "/lineage/previous_record_id"),
        ("initial, previous id alone", false, Box::new(|p| p.lineage.previous_record_id = Some(OTHER.into())), "/lineage/previous_record_hash"),
        ("initial, previous hash alone", false, Box::new(move |p| p.lineage.previous_record_hash = hash()), "/lineage/previous_record_id"),
        ("initial of chain length 3", false, Box::new(|p| p.lineage.lineage_chain_length = 3), "/lineage/lineage_chain_length"),
        ("initial with another root", false, Box::new(|p| p.lineage.root_record_id = OTHER.into()), "/lineage/root_record_id"),
        ("non-initial naming no predecessor", true, Box::new(|p| {
            p.lineage.previous_record_id = None;
            p.lineage.previous_record_hash = None;
        }), "/lineage/previous_record_id"),
        ("non-initial, previous id alone", true, Box::new(|p| p.lineage.previous_record_hash = None), "/lineage/previous_record_hash"),
        ("non-initial, previous hash alone", true, Box::new(|p| p.lineage.previous_record_id = None), "/lineage/previous_record_id"),
        ("non-initial of chain length 1", true, Box::new(|p| p.lineage.lineage_chain_length = 1), "/lineage/lineage_chain_length"),
        ("non-initial as its own root", true, Box::new(|p| p.lineage.root_record_id = p.record_id.clone()), "/lineage/root_record_id"),
        ("non-initial as its own predecessor", true, Box::new(|p| p.lineage.previous_record_id = Some(p.record_id.clone())), "/lineage/previous_record_id"),
    ];
    for (what, from_non_initial, edit, pointer) in cases {
        let mut p = vector_record();
        if from_non_initial {
            non_initial(&mut p);
        }
        edit(&mut p);
        let err = p.check_lineage_consistency().expect_err(what);
        assert_eq!((err.pointer.as_str(), err.rule), (pointer, "lineage"), "{what}: {err}");
    }
}

#[test]
fn the_record_schema_is_identified_at_verifiablemodel_org() {
    // Task 10.11cd (D11cd-4, D11cd-5): the schema is the Verifiable Model
    // Record's, identified at the address the standard's site reserves; a
    // schema is served from there exactly as tagged, so its $id is that path.
    let schema = load_json("record-schema/v0.1.json");
    assert_eq!(schema["$id"], "https://verifiablemodel.org/schemas/record/v0.1.json");
    assert_eq!(schema["title"], "Verifiable Model Record v0.1");
    assert_eq!(schema["properties"]["record_version"]["const"], "0.1");
    assert!(!serde_json::to_string(&schema).unwrap().contains("passport"), "the schema names no passport");
}
