//! Every string of a JSON value through `display_safe`.

use serde_json::{Map, Value};
use vmr_verify::display_safe;

/// `value` with every string in it, member names included, passed through
/// vmr-verify's [`display_safe`]: the characters a screen would act on or
/// hide (controls, bidi overrides, invisible characters, noncharacters) are
/// written as visible `\u{..}` escapes, and a backslash is doubled. Numbers,
/// booleans and nulls are kept.
pub fn display_safe_value(value: Value) -> Value {
    match value {
        Value::String(s) => Value::String(display_safe(&s)),
        Value::Array(items) => Value::Array(items.into_iter().map(display_safe_value).collect()),
        Value::Object(members) => Value::Object(
            members.into_iter().map(|(k, v)| (display_safe(&k), display_safe_value(v))).collect::<Map<_, _>>(),
        ),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_string_and_member_name_is_escaped_and_nothing_else_changes() {
        let v = json!({"a\u{202e}": ["x\u{0007}", 1, true, null, {"k": "back\\slash"}], "n": 2.5});
        assert_eq!(
            display_safe_value(v),
            json!({"a\\u{202e}": ["x\\u{0007}", 1, true, null, {"k": "back\\\\slash"}], "n": 2.5})
        );
    }
}
