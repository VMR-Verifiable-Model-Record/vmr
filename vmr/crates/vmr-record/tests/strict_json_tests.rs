// tests/strict_json_tests.rs — the strict reader of closed JSON formats (QA
// QT-01, docs/dev/fix-json-object-shape.md). A JSON array is read only where
// a sequence was asked for; everything else reads as serde_json reads it,
// errors included.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use vmr_record::strict_json;

#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    x: u64,
    y: String,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Wrapper(Point);

#[derive(Debug, PartialEq, Deserialize)]
struct Pair(u64, u64);

#[derive(Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nested {
    point: Point,
    points: Vec<Point>,
    #[serde(default)]
    maybe: Option<Point>,
    wrapped: Wrapper,
    by_name: BTreeMap<String, Point>,
    tags: Vec<String>,
    tuple: (u64, String),
    pair: Pair,
}

/// A conforming `Nested`, compact, members in declaration order.
const GOOD: &str = r#"{"point":{"x":1,"y":"a"},"points":[{"x":2,"y":"b"}],"maybe":{"x":3,"y":"c"},"wrapped":{"x":4,"y":"d"},"by_name":{"k":{"x":5,"y":"e"}},"tags":["t"],"tuple":[6,"f"],"pair":[7,8]}"#;

/// `GOOD` with its one occurrence of `from` replaced by `to`.
fn good_with(from: &str, to: &str) -> String {
    assert_eq!(GOOD.matches(from).count(), 1, "{from}");
    GOOD.replacen(from, to, 1)
}

#[test]
fn conforming_text_reads_exactly_as_serde_json_reads_it() {
    let pretty = serde_json::to_string_pretty(&serde_json::from_str::<Value>(GOOD).unwrap()).unwrap();
    for text in [
        GOOD.to_string(),
        pretty,
        good_with(r#""maybe":{"x":3,"y":"c"},"#, ""),
        good_with(r#""maybe":{"x":3,"y":"c"}"#, r#""maybe":null"#),
        good_with(r#""y":"a""#, r#""y":"a""#),
        format!("  {GOOD}\n"),
    ] {
        let strict: Nested = strict_json::from_str(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
        let lenient: Nested = serde_json::from_str(&text).unwrap();
        assert_eq!(strict, lenient, "{text}");
        assert_eq!(strict_json::from_slice::<Nested>(text.as_bytes()).unwrap(), lenient, "{text}");
    }
}

#[test]
fn a_struct_written_as_the_array_of_its_values_is_refused_at_every_depth() {
    // Each respelling is serde's sequence form of the struct, so serde_json
    // reads it as the struct; the strict reader refuses it, wherever it is.
    let root = r#"[{"x":1,"y":"a"},[{"x":2,"y":"b"}],{"x":3,"y":"c"},{"x":4,"y":"d"},{"k":{"x":5,"y":"e"}},["t"],[6,"f"],[7,8]]"#;
    let cases = [
        ("a member", good_with(r#"{"x":1,"y":"a"}"#, r#"[1,"a"]"#), "struct Point"),
        ("an array element", good_with(r#"{"x":2,"y":"b"}"#, r#"[2,"b"]"#), "struct Point"),
        ("an option's value", good_with(r#"{"x":3,"y":"c"}"#, r#"[3,"c"]"#), "struct Point"),
        ("a newtype's value", good_with(r#"{"x":4,"y":"d"}"#, r#"[4,"d"]"#), "struct Point"),
        ("a map's value", good_with(r#"{"x":5,"y":"e"}"#, r#"[5,"e"]"#), "struct Point"),
        ("the document", root.to_string(), "struct Nested"),
    ];
    for (place, text, expected) in cases {
        assert!(serde_json::from_str::<Nested>(&text).is_ok(), "{place}: serde_json reads the respelling");
        let err = strict_json::from_str::<Nested>(&text).expect_err(place);
        assert!(
            err.to_string().starts_with(&format!("invalid type: sequence, expected {expected}")),
            "{place}: {err}"
        );
        assert_eq!(err.to_string(), strict_json::from_slice::<Nested>(text.as_bytes()).unwrap_err().to_string());
    }
}

#[test]
fn the_refusal_names_where_the_array_is() {
    let text = good_with(r#"{"x":2,"y":"b"}"#, r#"[2,"b"]"#);
    let err = strict_json::from_str::<Nested>(&text).unwrap_err();
    let start = text.find(r#"[2,"b"]"#).unwrap() + 1; // 1-based column of '['
    assert_eq!(err.line(), 1);
    assert!((start..=start + r#"[2,"b"]"#.len()).contains(&err.column()), "column {} for '[' at {start}", err.column());
}

#[test]
fn sequences_are_read_where_a_sequence_is_asked_for() {
    // Vec, tuple, tuple struct and bytes are sequences in JSON.
    assert_eq!(strict_json::from_str::<Vec<Vec<u64>>>("[[1],[2,3],[]]").unwrap(), vec![vec![1], vec![2, 3], vec![]]);
    assert_eq!(strict_json::from_str::<(u64, String)>(r#"[1,"a"]"#).unwrap(), (1, "a".to_string()));
    assert_eq!(strict_json::from_str::<Pair>("[1,2]").unwrap(), Pair(1, 2));
    assert_eq!(strict_json::from_str::<[u8; 2]>("[1,2]").unwrap(), [1, 2]);
    #[derive(Debug, PartialEq, Deserialize)]
    struct Bytes(#[serde(with = "bytes")] Vec<u8>);
    mod bytes {
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("bytes")
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                    let mut out = Vec::new();
                    while let Some(b) = seq.next_element()? {
                        out.push(b);
                    }
                    Ok(out)
                }
            }
            d.deserialize_byte_buf(V)
        }
    }
    assert_eq!(strict_json::from_str::<Bytes>("[1,2,255]").unwrap(), Bytes(vec![1, 2, 255]));
}

#[test]
fn a_skipped_value_may_hold_arrays() {
    // A member a struct does not know, when it does not deny unknown members,
    // and IgnoredAny, read nothing into anything.
    #[derive(Debug, PartialEq, Deserialize)]
    struct Open {
        x: u64,
    }
    let text = r#"{"extra":[[1],{"a":[2]}],"x":1}"#;
    assert_eq!(strict_json::from_str::<Open>(text).unwrap(), Open { x: 1 });
    assert!(strict_json::from_str::<serde::de::IgnoredAny>("[1,[2,{\"a\":[]}]]").is_ok());
}

#[test]
fn every_other_error_is_serde_json_s_own() {
    // Same text, same position: a conforming reader of these formats sees
    // no difference except the refusal of an array.
    for text in [
        r#"{"x":1,"y":"a","z":2}"#,
        r#"{"x":1}"#,
        r#"{"x":1,"x":2,"y":"a"}"#,
        "null",
        r#""a""#,
        "1",
        r#"{"x":"1","y":"a"}"#,
        r#"{"x":-1,"y":"a"}"#,
        r#"{"x":1.5,"y":"a"}"#,
        r#"{"x":1,"y":"a"} x"#,
        r#"{"x":1,"y":"a""#,
        r#"{"x":1,"y":"a",}"#,
        r#"{"x":1,"y":"\ud800"}"#,
        r#"{"x":1,"y":null}"#,
        "",
    ] {
        let lenient = serde_json::from_str::<Point>(text).expect_err(text).to_string();
        let strict = strict_json::from_str::<Point>(text).expect_err(text).to_string();
        assert_eq!(strict, lenient, "{text}");
        let strict_bytes = strict_json::from_slice::<Point>(text.as_bytes()).expect_err(text).to_string();
        assert_eq!(strict_bytes, serde_json::from_slice::<Point>(text.as_bytes()).unwrap_err().to_string(), "{text}");
    }
    let bad_utf8 = b"{\"x\":1,\"y\":\"\xff\"}";
    assert_eq!(
        strict_json::from_slice::<Point>(bad_utf8).unwrap_err().to_string(),
        serde_json::from_slice::<Point>(bad_utf8).unwrap_err().to_string()
    );
}

#[derive(Debug, PartialEq, Deserialize)]
enum External {
    Unit,
    New(Point),
    Tuple(u64, u64),
    Held(Point, u64),
    Record { x: u64 },
}

#[test]
fn an_enum_s_variants_keep_their_shapes() {
    for (text, value) in [
        (r#""Unit""#, External::Unit),
        (r#"{"New":{"x":1,"y":"a"}}"#, External::New(Point { x: 1, y: "a".into() })),
        (r#"{"Tuple":[1,2]}"#, External::Tuple(1, 2)),
        (r#"{"Held":[{"x":1,"y":"a"},2]}"#, External::Held(Point { x: 1, y: "a".into() }, 2)),
        (r#"{"Record":{"x":1}}"#, External::Record { x: 1 }),
    ] {
        assert_eq!(strict_json::from_str::<External>(text).unwrap(), value, "{text}");
    }
    // A tuple variant is a sequence, so its elements are read under the rule
    // too: a struct inside one, written as an array, is refused (QA QT-01
    // QJ-08).
    for (text, expected) in [
        (r#"{"New":[1,"a"]}"#, "struct Point"),
        (r#"{"Held":[[1,"a"],2]}"#, "struct Point"),
        (r#"{"Record":[1]}"#, "struct variant External::Record"),
    ] {
        assert!(serde_json::from_str::<External>(text).is_ok(), "serde_json reads {text}");
        let err = strict_json::from_str::<External>(text).unwrap_err().to_string();
        assert!(err.starts_with(&format!("invalid type: sequence, expected {expected}")), "{text}: {err}");
    }
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Tagged {
    Dot(Point),
    Holder { point: Point },
    Listed { items: Vec<u64> },
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(untagged)]
enum Untagged {
    Point(Point),
    Number(u64),
}

#[derive(Debug, PartialEq, Deserialize)]
struct Free {
    v: Value,
}

#[test]
fn a_buffered_type_never_holds_an_array() {
    // serde buffers these through deserialize_any and reads their structs
    // from the buffer, which accepts a sequence (TaggedContentVisitor even
    // takes the tag from an array's first element). Through the strict
    // reader the buffer never holds an array.
    assert_eq!(
        strict_json::from_str::<Tagged>(r#"{"y":"a","type":"dot","x":1}"#).unwrap(),
        Tagged::Dot(Point { x: 1, y: "a".into() })
    );
    assert_eq!(
        strict_json::from_str::<Tagged>(r#"{"type":"holder","point":{"x":1,"y":"a"}}"#).unwrap(),
        Tagged::Holder { point: Point { x: 1, y: "a".into() } }
    );
    assert_eq!(strict_json::from_str::<Untagged>(r#"{"x":1,"y":"a"}"#).unwrap(), Untagged::Point(Point { x: 1, y: "a".into() }));
    assert_eq!(strict_json::from_str::<Untagged>("7").unwrap(), Untagged::Number(7));
    assert_eq!(strict_json::from_str::<Free>(r#"{"v":{"a":"b"}}"#).unwrap(), Free { v: json!({"a": "b"}) });

    for (what, text) in [
        ("an internally tagged enum as [tag, values...]", r#"["dot",1,"a"]"#),
        ("a struct inside a tagged variant", r#"{"type":"holder","point":[1,"a"]}"#),
    ] {
        assert!(serde_json::from_str::<Tagged>(text).is_ok(), "{what}: serde_json reads {text}");
        let err = strict_json::from_str::<Tagged>(text).expect_err(what).to_string();
        assert!(err.starts_with("invalid type: sequence, expected "), "{what}: {err}");
    }
    // An untagged enum tries each variant on the buffer, and serde reports
    // only that none matched: none can, because the buffer was refused.
    assert!(serde_json::from_str::<Untagged>(r#"[1,"a"]"#).is_ok(), "serde_json reads an untagged struct as an array");
    let err = strict_json::from_str::<Untagged>(r#"[1,"a"]"#).unwrap_err().to_string();
    assert!(err.starts_with("invalid type: sequence, expected ") || err.starts_with("data did not match any variant"), "{err}");

    // The price, by design: a buffered type or a free-form value whose
    // documents hold arrays is refused on every document, so no loader can
    // read one through this reader by accident.
    assert!(serde_json::from_str::<Tagged>(r#"{"type":"listed","items":[1]}"#).is_ok());
    assert!(strict_json::from_str::<Tagged>(r#"{"type":"listed","items":[1]}"#).is_err());
    assert!(strict_json::from_str::<Free>(r#"{"v":[1]}"#).is_err());
    assert!(strict_json::from_str::<Free>(r#"{"v":{"a":[1]}}"#).is_err());
}

#[test]
fn over_a_value_the_reader_refuses_what_from_value_reads() {
    let respelled = json!([1, "a"]);
    assert_eq!(serde_json::from_value::<Point>(respelled.clone()).unwrap(), Point { x: 1, y: "a".into() });
    let err = strict_json::deserialize::<Point, _>(&respelled).unwrap_err();
    assert!(err.to_string().starts_with("invalid type: sequence, expected struct Point"), "{err}");
    let object = json!({"x": 1, "y": "a"});
    assert_eq!(strict_json::deserialize::<Point, _>(&object).unwrap(), Point { x: 1, y: "a".into() });
    let nested: Value = serde_json::from_str(GOOD).unwrap();
    assert_eq!(strict_json::deserialize::<Nested, _>(&nested).unwrap(), serde_json::from_str::<Nested>(GOOD).unwrap());
}
