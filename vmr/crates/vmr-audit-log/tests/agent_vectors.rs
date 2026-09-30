// tests/agent_vectors.rs — the vmr.agent profile's vectors and schema
// (specs/audit-profile-agent-v0.1.md §6).
//
// The committed specs/test-vectors/audit-profile-agent/cases.json is written
// only by agent_generate/ (every expected result declared by hand), and
// agent_vectors_are_reproducible fails if the committed bytes differ. Every
// case is replayed through this build; the cases are held to cover every kind,
// every §4.6 rule and every listed member's out-of-list value; and the schema
// specs/audit-profile-agent-schema/v0.1.json is held to the Rust profile, kind
// by kind and member by member.

mod agent_generate;

use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use vmr_audit_log::entry::validate_entry;
use vmr_audit_log::json::parse_json_bounded;
use vmr_audit_log::log::read_log;
use vmr_audit_log::profile::CORE;
use vmr_audit_log::profiles::vmr_agent::digest::{json_content, label, ContentSecret};
use vmr_audit_log::profiles::vmr_agent::{members, MemberType, KINDS, PROFILE, TOOL_KINDS};
use vmr_audit_log::vmr_record::hash::sha256;

fn specs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs")
}

fn read_cases() -> Value {
    let path = specs_dir().join("test-vectors/audit-profile-agent/cases.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn cases<'a>(doc: &'a Value, key: &str) -> &'a Vec<Value> {
    doc[key].as_array().unwrap_or_else(|| panic!("no {key} array"))
}

// ---------------------------------------------------------------------------
//  Reproducibility (the writer is the only ignored test)
// ---------------------------------------------------------------------------

#[test]
fn agent_vectors_are_reproducible() {
    for (rel, contents) in agent_generate::generate() {
        let path = specs_dir().join("test-vectors").join(&rel);
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (regenerate with VMR_WRITE_VECTORS=1)", path.display()));
        assert!(
            committed == contents,
            "{rel} differs from a fresh generation: regenerate with VMR_WRITE_VECTORS=1, in its own commit"
        );
    }
}

#[test]
#[ignore = "writes specs/test-vectors/audit-profile-agent/; run with VMR_WRITE_VECTORS=1 -- --ignored, in its own commit"]
fn write_agent_vectors() {
    // The crate's clippy.toml forbids env reads; this writer says why.
    #[allow(clippy::disallowed_methods)]
    let write = std::env::var("VMR_WRITE_VECTORS").is_ok();
    if !write {
        eprintln!("set VMR_WRITE_VECTORS=1 to write the vectors");
        return;
    }
    for (rel, contents) in agent_generate::generate() {
        let path = specs_dir().join("test-vectors").join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        eprintln!("wrote {}", path.display());
    }
}

// ---------------------------------------------------------------------------
//  Replaying the cases
// ---------------------------------------------------------------------------

#[test]
fn every_entry_case_gives_its_expected_result() {
    let doc = read_cases();
    assert_eq!(doc["profile"], "vmr.agent");
    for case in cases(&doc, "entries") {
        let id = case["id"].as_str().unwrap();
        let text = case["raw"].as_str().unwrap();
        let want = case["expect"].as_str().unwrap();
        // Read as a log of one entry (core §4.4), under the profile.
        let result = read_log(format!("{text}\n").as_bytes(), &PROFILE);
        match want {
            "accept" => {
                result.unwrap_or_else(|e| panic!("{id}: expected accept, got {e}"));
                let value = parse_json_bounded(text).unwrap();
                validate_entry(&value, text, &PROFILE).unwrap_or_else(|e| panic!("{id}: {e}"));
            }
            want => {
                let got = result.unwrap_err();
                assert_eq!(got.id(), want, "{id}: expected {want}, got {got}");
                // The message names the kind, and never a member's value.
                let kind = parse_json_bounded(text).unwrap()["kind"].as_str().unwrap().to_string();
                assert!(got.to_string().contains(&kind), "{id}: the message names the kind: {got}");
            }
        }
        // Every case is an entry of the core: only the profile refuses it.
        read_log(format!("{text}\n").as_bytes(), &CORE).unwrap_or_else(|e| panic!("{id}: the core refused it: {e}"));
    }
}

#[test]
fn every_digest_case_gives_its_keys_and_digest() {
    let doc = read_cases();
    for case in cases(&doc, "digests") {
        let id = case["id"].as_str().unwrap();
        let s = |m: &str| case[m].as_str().unwrap_or_else(|| panic!("{id}: {m}"));
        // The secret is derived from its label, as the case says.
        let secret_bytes = sha256(s("content_secret_label").as_bytes());
        assert_eq!(hex::encode(secret_bytes), s("content_secret"), "{id}: the secret is sha256 of its label");
        let secret = ContentSecret::from_bytes(secret_bytes);
        let index = case["index"].as_u64().unwrap();
        assert_eq!(label(s("kind"), s("member"), index), s("label"), "{id}: the label");
        let content = match (case.get("content_text"), case.get("content_json")) {
            (Some(text), None) => text.as_str().unwrap().as_bytes().to_vec(),
            (None, Some(value)) => json_content(value),
            _ => panic!("{id}: exactly one of content_text and content_json"),
        };
        assert_eq!(hex::encode(&content), s("content_hex"), "{id}: the content's bytes");
        let session_key = secret.session_key(s("session_id"));
        assert_eq!(hex::encode(session_key.as_bytes()), s("session_key"), "{id}: the session key");
        let item_key = session_key.item_key(s("kind"), s("member"), index);
        assert_eq!(hex::encode(item_key.as_bytes()), s("item_key"), "{id}: the item key");
        assert_eq!(item_key.digest(&content), s("digest"), "{id}: the digest");
    }
}

#[test]
fn the_cases_cover_every_kind_every_rule_and_every_listed_value() {
    let doc = read_cases();
    let entries = cases(&doc, "entries");
    let kind_of = |case: &Value| -> String {
        parse_json_bounded(case["raw"].as_str().unwrap()).unwrap()["kind"].as_str().unwrap().to_string()
    };
    let accepted: BTreeSet<String> =
        entries.iter().filter(|c| c["expect"] == "accept").map(kind_of).collect();
    let all: BTreeSet<String> = KINDS.iter().map(|k| k.to_string()).collect();
    assert_eq!(accepted, all, "an accepting case for every kind");

    let rules: BTreeSet<u64> = entries.iter().filter_map(|c| c["rule"].as_u64()).collect();
    assert_eq!(rules, (1..=6).collect::<BTreeSet<u64>>(), "a refusing case for every rule of section 4.6");
    for case in entries {
        assert_eq!(case["expect"] == "accept", case.get("rule").is_none(), "{}: a rule exactly when refused", case["id"]);
    }

    // Each listed member (§4's quoted values) has a case where its value is
    // outside the list.
    for kind in KINDS {
        for member in members(kind).unwrap() {
            let MemberType::OneOf(values) = member.ty else { continue };
            let covered = entries.iter().any(|case| {
                let detail = &parse_json_bounded(case["raw"].as_str().unwrap()).unwrap()["detail"];
                case["expect"] != "accept"
                    && kind_of(case) == kind
                    && detail[member.name].as_str().is_some_and(|v| !values.contains(&v))
            });
            assert!(covered, "{kind}: no case puts {:?} outside its list", member.name);
        }
    }

    // The person type (§2) as identity providers issue it: a `|` and the
    // base64 characters accepted; an `@` refused, also inside such an id.
    // And policy.refused inside a session (its session_id is optional).
    let detail_of = |case: &Value| parse_json_bounded(case["raw"].as_str().unwrap()).unwrap()["detail"].clone();
    let people = |expect_accept: bool, has: &dyn Fn(&str) -> bool| {
        entries.iter().any(|case| {
            let detail = detail_of(case);
            (case["expect"] == "accept") == expect_accept
                && ["approver", "stopped_by"].iter().any(|m| detail[*m].as_str().is_some_and(has))
        })
    };
    assert!(people(true, &|p| p.contains('|')), "an accepted person with |");
    assert!(people(true, &|p| p.contains('+') && p.contains('/') && p.contains('=')), "an accepted base64 person");
    assert!(people(false, &|p| p.contains('|') && p.contains('@')), "a refused provider id holding an address");
    assert!(
        entries.iter().any(|c| c["expect"] == "accept" && kind_of(c) == "policy.refused" && detail_of(c).get("session_id").is_some()),
        "an accepted policy.refused with session_id"
    );
}

// ---------------------------------------------------------------------------
//  Schema sync: the schema and the Rust profile agree, kind by kind
// ---------------------------------------------------------------------------

/// The Rust type a schema property stands for, or the list of strings it
/// allows.
#[derive(Debug, PartialEq)]
enum SchemaType {
    Type(MemberType),
    List(Vec<String>),
}

fn schema_type(defs: &Map<String, Value>, property: &Value) -> SchemaType {
    if let Some(reference) = property.get("$ref").and_then(Value::as_str) {
        let name = reference.strip_prefix("#/$defs/").unwrap();
        return SchemaType::Type(match name {
            "uuid_urn" => MemberType::Uuid,
            "hash" => MemberType::Hash,
            "integer" => MemberType::Integer { min: 0 },
            "positive_integer" => MemberType::Integer { min: 1 },
            "u64_string" => MemberType::U64,
            "refusal_id" => MemberType::Refusal,
            "text" | "short_text" => MemberType::Text { max_bytes: defs[name]["maxLength"].as_u64().unwrap() as usize },
            "name" => MemberType::Name,
            "gate" => MemberType::Gate,
            "digest" => MemberType::Digest,
            "person" => MemberType::Person,
            other => panic!("the schema refers to $defs.{other}, which this test does not map"),
        });
    }
    assert_eq!(property["type"], "string", "a listed member is a string: {property}");
    SchemaType::List(
        property["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("a property with neither $ref nor enum: {property}"))
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
    )
}

#[test]
fn the_schema_and_the_profile_agree_on_every_kind_and_member() {
    let path = specs_dir().join("audit-profile-agent-schema/v0.1.json");
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        schema["$id"], "https://verifiablemodel.org/schemas/audit-profile-agent/v0.1.json",
        "the $id the spec names"
    );
    let defs = schema["$defs"].as_object().expect("$defs");

    // The type definitions say what the spec's types say.
    assert_eq!(defs["name"]["pattern"], "^[A-Za-z0-9_./:-]{1,128}$");
    assert_eq!(defs["gate"]["pattern"], "^[a-z][a-z_]{0,63}$");
    assert_eq!(defs["digest"]["pattern"], "^hmac-sha256:[0-9a-f]{64}$");
    assert_eq!(defs["person"]["pattern"], "^[A-Za-z0-9_.:|+=/-]{1,128}$");

    // The entry: the core's members, the profile's kinds, one detail per kind.
    let entry = &defs["vmr_agent_entry"];
    let mut entry_members: Vec<&str> = entry["properties"].as_object().unwrap().keys().map(String::as_str).collect();
    entry_members.sort_unstable();
    assert_eq!(entry_members, ["detail", "index", "kind", "log_version", "previous_root", "recorded_at"]);
    assert_eq!(entry["additionalProperties"], false);
    let kinds: Vec<&str> =
        entry["properties"]["kind"]["enum"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
    assert_eq!(kinds, KINDS, "the kinds, in section 4's order");

    let branches = entry["allOf"].as_array().unwrap();
    assert_eq!(branches.len(), KINDS.len(), "one detail branch per kind");
    for (branch, kind) in branches.iter().zip(KINDS) {
        assert_eq!(branch["if"]["properties"]["kind"]["const"], kind, "the branches in the kinds' order");
        let reference = branch["then"]["properties"]["detail"]["$ref"].as_str().unwrap();
        let detail = &defs[reference.strip_prefix("#/$defs/").unwrap()];
        assert_eq!(detail["type"], "object", "{kind}");
        assert_eq!(detail["additionalProperties"], false, "{kind}: the detail is closed");

        let rust = members(kind).unwrap();
        let properties = detail["properties"].as_object().unwrap_or_else(|| panic!("{kind}: properties"));
        let schema_names: BTreeSet<&str> = properties.keys().map(String::as_str).collect();
        let rust_names: BTreeSet<&str> = rust.iter().map(|m| m.name).collect();
        assert_eq!(schema_names, rust_names, "{kind}: the members");

        let required: BTreeSet<&str> = detail["required"]
            .as_array()
            .map(|r| r.iter().map(|v| v.as_str().unwrap()).collect())
            .unwrap_or_default();
        let rust_required: BTreeSet<&str> = rust.iter().filter(|m| m.required).map(|m| m.name).collect();
        assert_eq!(required, rust_required, "{kind}: the required members");

        for member in rust {
            let want = match member.ty {
                MemberType::OneOf(values) => SchemaType::List(values.iter().map(|v| v.to_string()).collect()),
                ty => SchemaType::Type(ty),
            };
            assert_eq!(schema_type(defs, &properties[member.name]), want, "{kind}.{}", member.name);
        }

        // Rule 4 in the schema: exactly one of tool and tool_digest.
        let one_of = detail.get("oneOf");
        if TOOL_KINDS.contains(&kind) {
            let one_of = one_of.unwrap_or_else(|| panic!("{kind}: the schema holds rule 4 with oneOf"));
            assert_eq!(one_of, &serde_json::json!([{ "required": ["tool"] }, { "required": ["tool_digest"] }]), "{kind}");
        } else {
            assert!(one_of.is_none(), "{kind}: no oneOf");
        }
    }

    // Rules 5 and 6 in the schema.
    assert!(defs["detail_gate_decided"].get("if").is_some(), "rule 5: refusal exactly when refused");
    assert_eq!(defs["detail_session_started"]["dependentRequired"]["parent_call"], serde_json::json!(["parent_session_id"]));
    assert!(defs["detail_session_ended"].get("if").is_some(), "rule 6: stopped_by only when stopped");
}
