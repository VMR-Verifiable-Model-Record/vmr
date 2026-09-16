// ============================================================================
//  json.rs — reading a document's text as §2 rules 3 and 4 read it.
//
//  serde_json keeps the last of a repeated member without a word, and its
//  recursion limit is far higher than this format's, so the nesting is counted
//  on the text and every repeat is recorded while the value is built.
// ============================================================================

//! Strict JSON reading: a bounded parse, and a parse that records where a
//! member appears twice (`specs/audit-log-format-v0.1.md` §2 rules 3 and 4).

use crate::error::display_safe;
use crate::MAX_NESTING_DEPTH;
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Parse JSON, refusing a document nested past [`MAX_NESTING_DEPTH`] before it
/// is otherwise read (§2 rule 3). serde_json's recursion limit is far higher,
/// so the depth is counted here on the text.
/// The message is terminal-safe (QA QR-33): this module is public and
/// re-exported, so a third party that calls it directly and prints the `Err`
/// gets no control character serde_json copied out of the document.
pub fn parse_json_bounded(text: &str) -> Result<Value, String> {
    check_nesting(text)?;
    serde_json::from_str(text).map_err(|e| display_safe(&e.to_string()))
}

/// A document's text read as §2 rules 3 and 4 read it: its JSON value, and
/// every place a member appears twice. serde_json keeps the last of a repeated
/// member without a word, and a [`Value`] cannot hold two, so the repeats are
/// recorded while the value is built ([`parse_document`]).
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDocument {
    /// The value. A repeated member holds its last value, as serde_json reads it.
    pub value: Value,
    repeats: Vec<Repeat>,
}

/// Where a repeated member was found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Repeat {
    /// In the outermost object itself.
    Outermost,
    /// In an object inside the value of the outermost object's member of this
    /// name, at any depth.
    Inside(String),
    /// In an object inside an outermost array.
    InArray,
}

impl ParsedDocument {
    /// Whether any object of the document repeats a member.
    pub fn has_repeated_member(&self) -> bool {
        !self.repeats.is_empty()
    }

    /// Whether the outermost object itself repeats a member.
    pub fn repeats_at_top(&self) -> bool {
        self.repeats.contains(&Repeat::Outermost)
    }

    /// Whether an object inside the value of the outermost object's member
    /// `name`, at any depth, repeats a member.
    pub fn repeats_inside(&self, name: &str) -> bool {
        self.repeats.iter().any(|r| matches!(r, Repeat::Inside(n) if n == name))
    }
}

/// Read a document's text: refuse it past [`MAX_NESTING_DEPTH`] (§2 rule 3),
/// read one JSON value with nothing after it, and record every repeated
/// member (§2 rule 4). An `Err` is the caller's syntax refusal. A repeat is
/// not an `Err`: a document's version is read first (§2 rule 10), and the
/// caller then refuses the repeat with the structure id of the document the
/// repeating object belongs to.
pub fn parse_document(text: &str) -> Result<ParsedDocument, String> {
    check_nesting(text)?;
    let mut repeats = Vec::new();
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = ValueSeed { repeats: &mut repeats, at: At::Outermost }
        .deserialize(&mut deserializer)
        .map_err(|e| display_safe(&e.to_string()))?;
    deserializer.end().map_err(|e| display_safe(&e.to_string()))?;
    Ok(ParsedDocument { value, repeats })
}

/// Where the value being read sits, to record a repeat against.
#[derive(Clone, Copy)]
enum At<'n> {
    Outermost,
    InsideMember(&'n str),
    InsideArray,
}

/// Builds a [`Value`] exactly as serde_json's own `Value` reader does, and
/// records a member met twice in one object.
struct ValueSeed<'r, 'n> {
    repeats: &'r mut Vec<Repeat>,
    at: At<'n>,
}

impl<'de> DeserializeSeed<'de> for ValueSeed<'_, '_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_, '_> {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_f64<E>(self, n: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(n).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_owned()))
    }

    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let at = match self.at {
            At::Outermost => At::InsideArray,
            inner => inner,
        };
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(ValueSeed { repeats: &mut *self.repeats, at })? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let value = {
                let at = match self.at {
                    At::Outermost => At::InsideMember(name.as_str()),
                    inner => inner,
                };
                map.next_value_seed(ValueSeed { repeats: &mut *self.repeats, at })?
            };
            if members.contains_key(&name) {
                self.repeats.push(match self.at {
                    At::Outermost => Repeat::Outermost,
                    At::InsideMember(outer) => Repeat::Inside(outer.to_string()),
                    At::InsideArray => Repeat::InArray,
                });
            }
            members.insert(name, value);
        }
        Ok(Value::Object(members))
    }
}

fn check_nesting(text: &str) -> Result<(), String> {
    let mut depth = 0usize;
    let mut max = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &b in text.as_bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
                if max > MAX_NESTING_DEPTH {
                    return Err(format!("nests deeper than {MAX_NESTING_DEPTH} levels"));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
