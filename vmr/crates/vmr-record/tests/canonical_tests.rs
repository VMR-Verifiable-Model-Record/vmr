// tests/canonical_tests.rs — JCS conformance: the RFC 8785 §3.2.2 and
// §3.2.3 samples, plus hand-written cases. Every expected output was
// cross-checked with V8 (node 22): JSON.stringify for numbers and strings,
// Object.keys().sort() (UTF-16 code-unit order) for member order. The RFC's
// full test suite is not vendored (offline build; QA P3-09).

use serde_json::json;
use vmr_record::canonical::jcs;

#[test]
fn rfc8785_example_numbers_and_strings() {
    // RFC 8785 §3.2.2 sample (number expectations V8-verified).
    let input = json!({
        "numbers": [
            333333333.3333333,
            1E30,
            4.50,
            2e-3,
            0.000000000000000000000000001
        ],
        "string": "\u{20ac}$\u{000f}\u{000a}A'\u{0042}\u{0022}\u{005c}\\\"/",
        "literals": [null, true, false]
    });
    // The input value is: € $ U+000F U+000A A ' B " \ \ " /
    let expected = r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#;
    assert_eq!(jcs(&input), expected);
}

#[test]
fn number_edges_match_v8() {
    // Doubles at the edges of ECMAScript Number::toString: subnormal and
    // maximal magnitudes, the 1e21 and 1e-7 notation switches, shortest
    // round-trip digits. Expected strings are V8's JSON.stringify output.
    let cases: [(f64, &str); 17] = [
        (5e-324, "5e-324"),
        (-5e-324, "-5e-324"),
        (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"),
        (-1.797_693_134_862_315_7e308, "-1.7976931348623157e+308"),
        (9_007_199_254_740_992.0, "9007199254740992"),
        (999_999_999_999_999_900_000.0, "999999999999999900000"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (0.000_001, "0.000001"),
        (0.1 + 0.2, "0.30000000000000004"),
        (1.5e-9, "1.5e-9"),
        (123e-20, "1.23e-18"),
        (1e23, "1e+23"),
        (9.999_999_999_999_997e22, "9.999999999999997e+22"),
        (295_147_905_179_352_830_000.0, "295147905179352830000"),
        (1_424_953_923_781_206.2, "1424953923781206.2"),
        (-0.000_003_333_333_333_333_333_3, "-0.0000033333333333333333"),
    ];
    for (v, expected) in cases {
        assert_eq!(jcs(&json!(v)), expected, "{v:e}");
    }
}

#[test]
fn integers_beyond_2_53_follow_ecmascript() {
    // QA P3-10: RFC 8785 numbers are IEEE-754 doubles. An integer outside
    // +/-(2^53 - 1) is serialized as the double it denotes, exactly as a JS
    // implementation (JSON.parse then JSON.stringify) would. Expected strings
    // from V8 (node 22). The canonicalizer used to print the exact digits.
    let cases: [(&str, &str); 6] = [
        ("9007199254740991", "9007199254740991"), // 2^53 - 1: still exact
        ("9007199254740993", "9007199254740992"),
        ("-9007199254740993", "-9007199254740992"),
        ("18446744073709551615", "18446744073709552000"),
        ("-9223372036854775808", "-9223372036854776000"),
        ("9223372036854775807", "9223372036854776000"),
    ];
    for (input, expected) in cases {
        let v: serde_json::Value = serde_json::from_str(input).unwrap();
        assert_eq!(jcs(&v), expected, "{input}");
    }
}

#[test]
fn rfc8785_object_sorting() {
    // RFC 8785 §3.2.3: members sorted by their names as UTF-16 code units.
    let input = json!({"b":"b","a":"a"});
    assert_eq!(jcs(&input), r#"{"a":"a","b":"b"}"#);
}

#[test]
fn rfc8785_sorting_sample_utf16_code_units() {
    // QA P3-03: the RFC's own sorting test data (§3.2.3), given here in the
    // RFC's escaped JSON form. It exists to separate UTF-16 code-unit order
    // from code-point (= UTF-8 byte) order: U+1F600 is the surrogate pair
    // 0xD83D 0xDE00, which sorts BEFORE U+FB33 in UTF-16 but after it by
    // code point. Expected bytes cross-checked with V8 (node 22), whose
    // default Array.prototype.sort compares UTF-16 code units.
    let text = r#"{
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "\ufb33": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "\ud83d\ude00": "Emoji: Grinning Face",
        "\u0080": "Control",
        "\u00f6": "Latin Small Letter O With Diaeresis"
    }"#;
    let input: serde_json::Value = serde_json::from_str(text).unwrap();
    let out = jcs(&input);
    let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
                    \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
                    \"\u{1f600}\":\"Emoji: Grinning Face\",\
                    \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
    assert_eq!(out, expected);
    // The RFC states the expected result as the order of the values.
    let order: Vec<&str> = [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]
    .to_vec();
    let mut pos: Vec<usize> = order.iter().map(|v| out.find(v).unwrap()).collect();
    let sorted = {
        let mut p = pos.clone();
        p.sort_unstable();
        p
    };
    assert_eq!(pos, sorted, "values must appear in the RFC's order");
    pos.dedup();
    assert_eq!(pos.len(), order.len());
}

#[test]
fn supplementary_plane_sorts_before_the_top_of_the_bmp() {
    // Minimal pair (QA PROBE 1): U+10000 = 0xD800 0xDC00 < U+E000 in UTF-16.
    let input: serde_json::Value = serde_json::from_str(r#"{"\ue000":1,"\ud800\udc00":2}"#).unwrap();
    assert_eq!(jcs(&input), "{\"\u{10000}\":2,\"\u{e000}\":1}");
}

#[test]
fn nested_structures() {
    let input = json!({
        "z": [1, {"y": 2, "x": 3}, []],
        "a": {"nested": {"deep": {"value": null}}}
    });
    let expected = r#"{"a":{"nested":{"deep":{"value":null}}},"z":[1,{"x":3,"y":2},[]]}"#;
    assert_eq!(jcs(&input), expected);
}

#[test]
fn no_whitespace_anywhere() {
    // Whitespace inside string VALUES is content and must be preserved;
    // whitespace outside strings must not exist. Use a space-free value so
    // the whole output is whitespace-free.
    let input = json!({"a": [1, 2], "b": {"c": "xy"}});
    let out = jcs(&input);
    assert!(!out.contains(' ') && !out.contains('\n') && !out.contains('\t'));
    assert_eq!(out, r#"{"a":[1,2],"b":{"c":"xy"}}"#);

    // A space inside a string value survives verbatim.
    let spaced = json!({"msg": "x y"});
    assert_eq!(jcs(&spaced), r#"{"msg":"x y"}"#);
}

#[test]
fn determinism_across_construction_orders() {
    // serde_json maps sort keys anyway; the canonicalizer must not depend
    // on insertion order.
    let v1: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
    let v2: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
    assert_eq!(jcs(&v1), jcs(&v2));
}

#[test]
fn strings_are_scalar_values_so_jcs_never_writes_a_surrogate() {
    // QA P4-03, spec §2 rule 1: record strings are sequences of Unicode
    // scalar values (RFC 8785 §3.1). The issuer side cannot break this: a
    // Rust `char` / `str` holds scalar values only, so the JCS writer (and
    // therefore the builder, which signs JCS output) can never emit an
    // unpaired surrogate - raw or as a \u escape - that a verifier rejects.
    for code in [0xd800, 0xdbff, 0xdc00, 0xdfff] {
        assert!(char::from_u32(code).is_none(), "U+{code:04X} is not a char");
    }
    assert!(String::from_utf8(vec![0xed, 0xa0, 0x80]).is_err(), "no surrogate in UTF-8");
    for lone in [r#""\ud800""#, r#""\udc00""#, r#""\ud800A""#, r#""\udc00\ud800""#] {
        assert!(serde_json::from_str::<String>(lone).is_err(), "{lone} is no string");
    }
    // Noncharacters ARE scalar values: JCS writes them as they are (only
    // controls below U+0020, the quote and the backslash are escaped), and
    // their \u spellings parse to the same string.
    let nonchars = "\u{fdd0}\u{fdef}\u{fffe}\u{ffff}\u{1fffe}\u{10ffff}";
    assert_eq!(jcs(&json!(nonchars)), format!("\"{nonchars}\""));
    let escaped: String = serde_json::from_str(&format!("\"{}\"", r"\ufdd0\uFDEF\ufffe\uffff\ud83f\udffe\udbff\udfff")).unwrap();
    assert_eq!(escaped, nonchars);
}
