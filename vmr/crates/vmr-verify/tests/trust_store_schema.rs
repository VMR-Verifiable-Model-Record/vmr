// tests/trust_store_schema.rs — the trust-store schema v0.1 is closed and
// reuses the record's rules (Phase 4 task 4.0d, decision D7).

use serde_json::Value;

fn spec_file(rel: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs").join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("valid JSON")
}

fn store_schema() -> Value {
    spec_file("trust-store-schema/v0.1.json")
}

fn record_schema() -> Value {
    spec_file("record-schema/v0.1.json")
}

#[test]
fn trust_store_schema_closes_every_object() {
    // Same strictness as records (QA P3-01): a member the loader dropped
    // would sit in the file unread. Seven object kinds: the store; an issuer,
    // its key and that key's JWK; a policy authority, its key and that key's
    // JWK (6.16).
    fn closed_objects(node: &Value) -> usize {
        match node {
            Value::Object(map) => {
                let here = map.get("type") == Some(&Value::from("object"));
                if here {
                    assert_eq!(map.get("additionalProperties"), Some(&Value::Bool(false)), "{map:?}");
                }
                usize::from(here) + map.values().map(closed_objects).sum::<usize>()
            }
            Value::Array(items) => items.iter().map(closed_objects).sum(),
            _ => 0,
        }
    }
    assert_eq!(closed_objects(&store_schema()), 7);
}

#[test]
fn a_policy_authority_reuses_the_issuer_key_and_the_pack_authority_rules() {
    // P6-14, docs/dev/task-6.16.md A16-1: an authority's keys are an issuer's
    // key objects, byte for byte, and its authority_id is held to the rule a
    // pack's own authority.authority_id is. The list is optional and may be
    // empty, so every earlier store stays valid.
    let store = store_schema();
    let pack = spec_file("policy-pack-schema/v0.1.json");
    let authorities = &store["properties"]["policy_authorities"];
    assert_eq!(authorities["type"], "array");
    assert!(authorities.get("minItems").is_none(), "an empty list is allowed");
    let required = store["required"].as_array().unwrap();
    assert!(!required.contains(&Value::from("policy_authorities")), "optional");
    let entry = &authorities["items"];
    let issuer = &store["properties"]["issuers"]["items"];
    assert_eq!(entry["required"], serde_json::json!(["authority_id", "authority_name", "keys"]));
    assert_eq!(entry["additionalProperties"], false);
    assert_eq!(entry["properties"]["authority_id"], pack["properties"]["authority"]["properties"]["authority_id"]);
    assert_eq!(entry["properties"]["authority_name"], issuer["properties"]["issuer_name"]);
    assert_eq!(entry["properties"]["keys"], issuer["properties"]["keys"]);
}

#[test]
fn trust_store_schema_reuses_the_record_rules() {
    // An entry holds the key "exactly as in the record" and names the
    // issuer in the record's syntax: the rules must be the same bytes, so
    // the two schemas cannot drift apart.
    let store = store_schema();
    let record = record_schema();
    let issuer = &store["properties"]["issuers"]["items"];
    let key = &issuer["properties"]["keys"]["items"];
    let p_issuer = &record["properties"]["issuer"];

    assert_eq!(issuer["properties"]["issuer_id"], p_issuer["properties"]["issuer_id"]);
    assert_eq!(key["properties"]["key_id"], p_issuer["properties"]["key_id"]);
    assert_eq!(key["properties"]["public_key"], p_issuer["properties"]["public_key"]);
    assert_eq!(key["properties"]["attestation_level"], p_issuer["properties"]["attestation_level"]);
    for when in ["valid_from", "valid_until"] {
        assert_eq!(key["properties"][when], record["properties"]["issued_at"], "{when}");
    }
    assert_eq!(key["properties"]["revoked"]["type"], "boolean");
    assert_eq!(issuer["properties"]["keys"]["minItems"], 1);
    assert_eq!(store["properties"]["trust_store_version"]["const"], "0.1");
    // valid_until is the only optional member of the whole store.
    let required = key["required"].as_array().unwrap();
    let props = key["properties"].as_object().unwrap();
    let optional: Vec<&String> =
        props.keys().filter(|k| !required.contains(&Value::from(k.as_str()))).collect();
    assert_eq!(optional, ["valid_until"]);
}
