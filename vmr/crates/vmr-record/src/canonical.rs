//! JSON Canonicalization Scheme (RFC 8785) over `serde_json::Value`.
// ============================================================================
//  canonical.rs — JSON Canonicalization Scheme (JCS, RFC 8785) — TASKS 3.3
//
//  Deterministic serialization of a JSON value, byte-identical across
//  implementations:
//
//    * object members sorted by property name, compared as UTF-16 code
//      units (RFC 8785 §3.2.3 — not code points);
//    * string escaping identical to ECMAScript JSON.stringify;
//    * numbers formatted exactly as ECMAScript Number::toString would
//      (no trailing ".0", no leading zeros, scientific notation for
//      exponents outside (-6, 21));
//    * no insignificant whitespace.
//
//  JCS is a serialization rule, not cryptography (Doctrine Refusal 4 does
//  not apply). Coverage, stated exactly (QA P3-09): tests/canonical_tests.rs
//  runs the RFC's §3.2.2 primitive sample and §3.2.3 sorting sample plus
//  hand-written cases (number edges, escaping, nesting) whose expected bytes
//  were cross-checked with V8 (node 22). The RFC's full test suite
//  (cyberphone/json-canonicalization) is not vendored: the build is offline.
//
//  Number formatting: serde_json's own number formatting differs from
//  ECMAScript (it prints "1.0" for float 1.0, full digit strings for 1e21,
//  "1e21" instead of "1e+21"), so numbers are formatted here explicitly.
//  Float formatting uses ryu-js, the reference implementation of ECMAScript
//  Number::toString — byte-identical with JSON.stringify on every double,
//  including the rare shortest-representation ties where Rust's own
//  formatter differs. Integers within +/-(2^53 - 1) are printed exactly;
//  larger ones are serialized as the double they denote, as ECMAScript
//  would (QA P3-10). Record integers are limited to 2^53 - 1, so they are
//  always exact.
//
//  Strings (QA P4-03, record spec §2 rule 1): a Rust `str` holds Unicode
//  scalar values only, so this writer - and the builder that signs its
//  output - can never emit an unpaired surrogate, raw or escaped; a verifier
//  rejects one at json.structure. Noncharacters (U+FDD0-U+FDEF,
//  U+xFFFE/U+xFFFF) are scalar values and are written as they are, like
//  every other character from U+0020 up except `"` and `\`.
// ============================================================================

use serde_json::Value;

/// Serialize `value` in its JCS canonical form.
pub fn jcs(value: &Value) -> String {
    let mut out = String::new();
    write_jcs(value, &mut out);
    out
}

// Cannot panic (plan §5.8): serde_json's serializer has no error path for a
// `str` (to_string of a string only fails for non-string map keys and I/O,
// neither possible here), and `map[*key]` indexes with a key just taken from
// that same map.
#[allow(clippy::expect_used)]
fn write_jcs(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&number_str(n)),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string serialization")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: sort members by property name compared as
            // arrays of UTF-16 code units. Rust's `str` order is UTF-8 byte
            // order = code-point order, which differs exactly when a
            // supplementary character (a surrogate pair, 0xD800-0xDBFF
            // first) meets one in U+E000-U+FFFF (QA P3-03). serde_json's Map
            // is a BTreeMap in str order, so the sort must be explicit.
            let mut keys: Vec<(Vec<u16>, &String)> =
                map.keys().map(|k| (k.encode_utf16().collect(), k)).collect();
            keys.sort_unstable();
            let keys: Vec<&String> = keys.into_iter().map(|(_, k)| k).collect();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key.as_str()).expect("key serialization"));
                out.push(':');
                write_jcs(&map[*key], out);
            }
            out.push('}');
        }
    }
}

// ---------------------------------------------------------------------------
//  ECMAScript number formatting
// ---------------------------------------------------------------------------

/// The largest integer an IEEE-754 double represents exactly together with
/// all smaller integers: 2^53 - 1 (ECMAScript `Number.MAX_SAFE_INTEGER`).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Format a serde_json number the way ECMAScript's JSON.stringify would.
// Cannot panic (plan §5.8): without serde_json's `arbitrary_precision`
// feature (not enabled in this workspace) a Number is always i64, u64 or f64,
// so `as_f64` is `Some` whenever the two branches above did not return. The
// verifier never reaches it anyway: record and trust-store JCS input holds
// only u64 integers.
#[allow(clippy::expect_used)]
fn number_str(n: &serde_json::Number) -> String {
    // RFC 8785 numbers are doubles (QA P3-10). Integers within +/-(2^53 - 1)
    // are exact doubles below 1e21, which ECMAScript prints in plain
    // decimal; beyond that range the value is the nearest double (Rust's
    // `as f64` rounds to nearest, ties to even, as JSON.parse does) and is
    // formatted like any other double. Records never get here: their
    // integers are limited to 2^53 - 1 when built and when parsed.
    if let Some(i) = n.as_i64() {
        if i.unsigned_abs() <= MAX_SAFE_INTEGER {
            return i.to_string();
        }
        return float_str(i as f64);
    }
    if let Some(u) = n.as_u64() {
        if u <= MAX_SAFE_INTEGER {
            return u.to_string();
        }
        return float_str(u as f64);
    }
    let f = n.as_f64().expect("serde_json number is i64, u64, or f64");
    float_str(f)
}

/// Format an f64 exactly the way ECMAScript Number::toString does.
fn float_str(f: f64) -> String {
    let mut buf = ryu_js::Buffer::new();
    buf.format(f).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn number_formatting_matches_ecmascript() {
        // Verified against V8 (node 22): JSON.stringify of each value.
        assert_eq!(number_str(json!(1.0).as_number().unwrap()), "1");
        assert_eq!(number_str(json!(4.50).as_number().unwrap()), "4.5");
        assert_eq!(number_str(json!(0.002).as_number().unwrap()), "0.002");
        assert_eq!(number_str(json!(1e30).as_number().unwrap()), "1e+30");
        assert_eq!(number_str(json!(1e-27).as_number().unwrap()), "1e-27");
        assert_eq!(number_str(json!(1e21).as_number().unwrap()), "1e+21");
        assert_eq!(number_str(json!(1e20).as_number().unwrap()), "100000000000000000000");
        assert_eq!(number_str(json!(-0.0).as_number().unwrap()), "0");
        assert_eq!(
            number_str(json!(333333333.3333333).as_number().unwrap()),
            "333333333.3333333"
        );
        assert_eq!(number_str(json!(0.000001).as_number().unwrap()), "0.000001");
        assert_eq!(number_str(json!(-2.5).as_number().unwrap()), "-2.5");
        assert_eq!(number_str(json!(42).as_number().unwrap()), "42");
        assert_eq!(number_str(json!(-42).as_number().unwrap()), "-42");
    }

    #[test]
    fn key_sorting_and_structure() {
        let v = json!({"b": 1, "a": {"d": null, "c": [3, 2, 1]}, "z": true});
        assert_eq!(
            jcs(&v),
            r#"{"a":{"c":[3,2,1],"d":null},"b":1,"z":true}"#
        );
    }

    #[test]
    fn string_escaping_matches_json_stringify() {
        let v = json!({"q": "a\"b\\c\nd\te\u{1}\u{1f}"});
        assert_eq!(jcs(&v), r#"{"q":"a\"b\\c\nd\te\u0001\u001f"}"#);
    }
}
