// tests/pack_schema.rs — specs/policy-pack-schema/v0.1.json and
// vmr_policy::schema::SCHEMA_RULES are the same rules, in both directions
// (P6-10, Phase 4's D3). The published schema is what a pack author
// validates against; the table is what this build enforces. If they drift,
// an authority writes a pack the evaluator reads differently, which is the
// one failure this format cannot afford.
//
// The `regex` crate is a DEV-dependency oracle only: it checks that each
// hand-written matcher agrees with the `pattern` text the schema publishes.
// No evaluation path ever runs a regular expression.

mod common;

use common::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use vmr_policy::pack::RULE_TYPES;
use vmr_policy::schema::{Kind, Pattern, Scope, SCHEMA_RULES};

/// (scope label, pointer, keyword) -> the keyword's value.
type Rules = BTreeMap<(String, String, String), Value>;

/// The ten keywords the table can express. A schema keyword outside this
/// set makes `from_schema` fail, so the schema cannot grow a rule the code
/// silently ignores.
const KEYWORDS: [&str; 10] = [
    "type",
    "required",
    "additionalProperties",
    "const",
    "enum",
    "pattern",
    "minLength",
    "minItems",
    "minimum",
    "maximum",
];

/// The keys the walker steps over: metadata and the places handled apart.
const SKIPPED: [&str; 7] = ["$schema", "$id", "title", "description", "$defs", "properties", "items"];

fn from_table() -> Rules {
    let mut out = Rules::new();
    for rule in SCHEMA_RULES {
        let scopes: Vec<String> = match rule.scope {
            Scope::Pack => vec!["pack".to_string()],
            // Every rule object repeats these, once per $defs entry.
            Scope::EveryRule => RULE_TYPES.iter().map(|t| t.to_string()).collect(),
            Scope::Rule(t) => vec![t.to_string()],
        };
        for scope in scopes {
            let key = (scope, rule.pointer.to_string(), rule.kind.keyword().to_string());
            let previous = out.insert(key.clone(), rule.kind.value());
            assert!(previous.is_none(), "SCHEMA_RULES states {key:?} twice");
        }
    }
    out
}

/// Walk a subschema, emitting every keyword it states under `scope`.
fn walk(scope: &str, pointer: &str, schema: &Value, out: &mut Rules) {
    let object = schema.as_object().unwrap_or_else(|| panic!("{scope}{pointer} is not an object"));
    for (key, value) in object {
        if SKIPPED.contains(&key.as_str()) {
            continue;
        }
        if key == "oneOf" {
            // The rule union; each branch is walked as its own $defs entry.
            continue;
        }
        assert!(
            KEYWORDS.contains(&key.as_str()),
            "{scope}{pointer}: the schema states {key:?}, which SCHEMA_RULES cannot express"
        );
        let inserted =
            out.insert((scope.to_string(), pointer.to_string(), key.clone()), value.clone());
        assert!(inserted.is_none(), "{scope}{pointer}: {key} twice");
    }
    if let Some(properties) = object.get("properties").and_then(Value::as_object) {
        for (name, sub) in properties {
            walk(scope, &format!("{pointer}/{name}"), sub, out);
        }
    }
    if let Some(items) = object.get("items") {
        if items.get("oneOf").is_none() {
            walk(scope, &format!("{pointer}/*"), items, out);
        }
    }
}

fn from_schema() -> Rules {
    let schema = schema();
    let mut out = Rules::new();
    walk("pack", "", &schema, &mut out);
    let defs = schema["$defs"].as_object().expect("$defs");
    assert_eq!(defs.len(), RULE_TYPES.len(), "one $defs entry per rule type");
    for rule_type in RULE_TYPES {
        let def = defs.get(rule_type).unwrap_or_else(|| panic!("$defs/{rule_type}"));
        walk(rule_type, "", def, &mut out);
    }
    out
}

#[test]
fn the_schema_and_the_rule_table_agree_in_both_directions() {
    let table = from_table();
    let schema = from_schema();
    let missing: Vec<_> = schema.keys().filter(|k| !table.contains_key(*k)).collect();
    let extra: Vec<_> = table.keys().filter(|k| !schema.contains_key(*k)).collect();
    assert!(missing.is_empty(), "in the schema, not in SCHEMA_RULES: {missing:#?}");
    assert!(extra.is_empty(), "in SCHEMA_RULES, not in the schema: {extra:#?}");
    for (key, value) in &schema {
        assert_eq!(table.get(key), Some(value), "{key:?} differs");
    }
    // A floor, so a future edit that empties the table cannot pass.
    assert!(table.len() >= 90, "{} rules", table.len());
}

#[test]
fn the_rule_union_names_every_rule_type_once() {
    let schema = schema();
    let branches = schema["properties"]["rules"]["items"]["oneOf"].as_array().expect("oneOf");
    let named: Vec<&str> =
        branches.iter().map(|b| b["$ref"].as_str().expect("$ref")).collect();
    let expected: Vec<String> =
        RULE_TYPES.iter().map(|t| format!("#/$defs/{t}")).collect();
    assert_eq!(named, expected);
}

#[test]
fn every_pattern_matcher_agrees_with_the_text_the_schema_publishes() {
    // The corpus is deterministic and covers the boundaries of each pattern.
    let corpus: Vec<String> = [
        "", "0.0.0", "1.0.0", "1.0", "1.0.0.0", "01.2.3", "1.2.3 ", " 1.2.3", "1.2.x", "v1.2.3",
        "10.20.30", "1..3", ".1.2", "1.2.", "1.02.3", "1.2.03", "00.0.0", "100.200.300",
        "PH", "ph", "Ph", "P", "PHL", "P1", " PH", "PH ", "PH\n", "\u{00c9}S", "ZZ",
        "sha256:", "sha256:00", "ES256", "base64url:", "not a pattern at all",
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:", "\u{00e9}.0.0",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain(std::iter::once(format!("sha256:{}", "ab".repeat(32))))
    .chain(std::iter::once(format!("base64url:{}A", "a".repeat(85))))
    .chain(std::iter::once(format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}A",
        "a".repeat(42)
    )))
    .collect();

    for pattern in [
        Pattern::PackVersion,
        Pattern::Hash,
        Pattern::Signature,
        Pattern::KeyId,
        Pattern::CountryCode,
    ] {
        let oracle = regex::Regex::new(pattern.regex())
            .unwrap_or_else(|e| panic!("{:?}: {e}", pattern.regex()));
        for case in &corpus {
            assert_eq!(
                pattern.matches(case),
                oracle.is_match(case),
                "{pattern:?} disagrees with {} on {case:?}",
                pattern.regex()
            );
        }
    }
}

#[test]
fn the_parser_enforced_rules_are_exactly_the_structural_ones() {
    for rule in SCHEMA_RULES {
        let structural = matches!(rule.kind, Kind::Type(_) | Kind::Required(_) | Kind::Closed);
        assert_eq!(rule.kind.enforced_by_parser(), structural, "{rule:?}");
    }
}

#[test]
fn every_committed_reference_pack_satisfies_the_schema() {
    for pack_id in REFERENCE_PACKS {
        // Loading runs the parser (type, required, additionalProperties) and
        // then every value rule; a pack that loads satisfies the schema.
        let pack = reference_pack(pack_id);
        assert_eq!(pack.pack_id, pack_id, "pack_id must equal its file name");
        let document: Value = serde_json::from_str(&pack_text(pack_id)).unwrap();
        assert_eq!(pack.document(), &document, "the document is kept as received");
        assert_eq!(document["version"], json!("0.1"));
    }
}
