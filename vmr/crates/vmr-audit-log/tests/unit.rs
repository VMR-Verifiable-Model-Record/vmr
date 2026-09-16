// tests/unit.rs — the tree and the strict JSON reading, checked directly.
//
// These were the unit tests inside the enforcer's audit.rs before task 10.13's
// split; they belong with the code, which is now this crate's.

use serde_json::{json, Value};
use vmr_audit_log::json::parse_document;
use vmr_audit_log::tree::root_of;
use vmr_audit_log::vmr_record;
use vmr_audit_log::vmr_record::hash::DIGEST_LEN;
use vmr_audit_log::vmr_record::merkle::{empty_root, hash_leaf};


#[test]
fn the_tree_matches_vmr_record_merkle_for_sizes_0_to_300() {
    // The log's tree is the record's §8 tree for every non-empty size.
    for n in 0..=300usize {
        let datas: Vec<Vec<u8>> = (0..n).map(|i| format!("entry-{i}").into_bytes()).collect();
        let leaves: Vec<[u8; DIGEST_LEN]> = datas.iter().map(|d| hash_leaf(d)).collect();
        let mine = root_of(&leaves);
        let theirs = vmr_record::merkle::merkle_root(&datas);
        assert_eq!(mine, theirs, "root differs at size {n}");
    }
}

#[test]
fn the_empty_root_is_the_record_empty_root() {
    assert_eq!(root_of(&[]), empty_root());
}

#[test]
fn parse_document_reads_as_serde_json_and_records_where_a_member_repeats() {
    // Without a repeat, the value is serde_json's own, numbers and escapes
    // included.
    for text in [
        r#"{"a":1,"b":[1,-2,3.5,"xA\n",null,true,{"c":{}}]}"#,
        r#"{"big":18446744073709551615,"small":-9223372036854775808,"f":1e300,"z":-0}"#,
        "[]",
        "0",
        r#""s""#,
        " {\"a\" : [ ] } ",
    ] {
        let parsed = parse_document(text).unwrap();
        assert_eq!(parsed.value, serde_json::from_str::<Value>(text).unwrap(), "{text}");
        assert!(!parsed.has_repeated_member(), "{text}");
    }

    // A repeat in the outermost object keeps the last value, as serde_json does.
    let top = parse_document(r#"{"a":1,"b":{},"a":2}"#).unwrap();
    assert_eq!(top.value, json!({ "a": 2, "b": {} }));
    assert!(top.has_repeated_member() && top.repeats_at_top());
    assert!(!top.repeats_inside("a") && !top.repeats_inside("b"));

    // A repeat deep inside a member's value is that member's.
    let inner = parse_document(r#"{"a":{"x":[{"y":1,"y":1}]},"b":{"y":1}}"#).unwrap();
    assert!(inner.has_repeated_member() && !inner.repeats_at_top());
    assert!(inner.repeats_inside("a") && !inner.repeats_inside("b"));

    // Inside an outermost array: a repeat, but no member's.
    let array = parse_document(r#"[{"a":1,"a":1}]"#).unwrap();
    assert!(array.has_repeated_member() && !array.repeats_at_top() && !array.repeats_inside("a"));

    // One name spelled with an escape is the same member.
    assert!(parse_document(r#"{"a":1,"a":1}"#).unwrap().repeats_at_top());

    // Not JSON, trailing data, and nesting past the bound are errors.
    assert!(parse_document("{").is_err());
    assert!(parse_document("{} {}").is_err());
    assert!(parse_document(&format!("{}{}", "[".repeat(128), "]".repeat(128))).is_err());
    assert!(parse_document(&format!("{}{}", "[".repeat(127), "]".repeat(127))).is_ok());
}
