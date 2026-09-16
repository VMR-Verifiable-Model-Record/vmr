//! A strict reader for closed JSON formats: a JSON array is read only where a
//! sequence was asked for, never as a struct (QA QT-01).
// ============================================================================
//  strict_json.rs — closed objects stay objects (QA QT-01;
//  docs/dev/fix-json-object-shape.md)
//
//  serde's derived `Deserialize` for a struct reads two JSON shapes: an
//  object, and an array of the field values in declaration order
//  (`deny_unknown_fields` does not turn the second off). Every document the
//  workspace reads is a closed format whose objects are JSON objects, and a
//  record's signed payload is re-derived from the parsed struct (spec §3):
//  a signed record with an object respelled as the array of its values
//  would verify.
//
//  The rule, at every depth: a JSON array reaches a visitor only through a
//  request for a sequence (`deserialize_seq`, `deserialize_tuple`,
//  `deserialize_tuple_struct`, and `deserialize_bytes` /
//  `deserialize_byte_buf`, which JSON spells as arrays of numbers) or for a
//  value to skip (`deserialize_ignored_any`). Any other request that meets an
//  array - a struct, a map, an enum, `deserialize_any`, the value inside an
//  option or a newtype - fails with serde's own "invalid type: sequence,
//  expected ...". Every deserializer, access and seed a visitor is handed is
//  wrapped the same way, so the rule needs no list of structs.
//
//  Buffered types. serde's derive reads internally tagged, adjacently tagged
//  and untagged enums, and `flatten`, through `deserialize_any` into a buffer
//  whose structs accept a buffered sequence. Through this reader no buffer
//  ever holds an array: a buffered type whose documents contain arrays is
//  refused on every document, conforming ones included, so it cannot be read
//  here by accident.
//
//  A conforming document never meets the refusal, and every other error is
//  serde_json's, at serde_json's position in text order.
// ============================================================================

use serde::de::{
    self, Deserialize, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, Unexpected,
    VariantAccess, Visitor,
};
use std::fmt;

/// Parse `text` as one `T`, as [`serde_json::from_str`] does (the same
/// errors, and nothing but whitespace after the value), except that a JSON
/// array is read only where `T` asks for a sequence (this module's rule).
pub fn from_str<'a, T: Deserialize<'a>>(text: &'a str) -> serde_json::Result<T> {
    let mut reader = serde_json::Deserializer::from_str(text);
    let value = T::deserialize(Strict(&mut reader))?;
    reader.end()?;
    Ok(value)
}

/// [`from_str`] over bytes, as [`serde_json::from_slice`] reads them.
pub fn from_slice<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> serde_json::Result<T> {
    let mut reader = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(Strict(&mut reader))?;
    reader.end()?;
    Ok(value)
}

/// Deserialize a `T` from any `deserializer` under this module's rule. Over a
/// `&serde_json::Value`, it refuses the array in a struct's place that
/// [`serde_json::from_value`] reads.
pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
    T::deserialize(Strict(deserializer))
}

/// A deserializer under the rule.
struct Strict<D>(D);

/// A visitor under the rule: `sequence` says whether its request asked for a
/// sequence (or for a value to skip), the only requests an array may answer.
struct StrictVisitor<V> {
    visitor: V,
    sequence: bool,
}

/// The visitor of a request that did not ask for a sequence.
fn no_sequence<V>(visitor: V) -> StrictVisitor<V> {
    StrictVisitor { visitor, sequence: false }
}

/// The visitor of a request for a sequence, or for a value to skip.
fn sequence<V>(visitor: V) -> StrictVisitor<V> {
    StrictVisitor { visitor, sequence: true }
}

/// `deserialize_*` methods that take only a visitor, forwarded with it
/// wrapped by `$wrap`.
macro_rules! forward_requests {
    ($($method:ident: $wrap:ident),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.0.$method($wrap(visitor))
        }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Strict<D> {
    type Error = D::Error;

    forward_requests! {
        deserialize_any: no_sequence,
        deserialize_bool: no_sequence,
        deserialize_i8: no_sequence,
        deserialize_i16: no_sequence,
        deserialize_i32: no_sequence,
        deserialize_i64: no_sequence,
        deserialize_i128: no_sequence,
        deserialize_u8: no_sequence,
        deserialize_u16: no_sequence,
        deserialize_u32: no_sequence,
        deserialize_u64: no_sequence,
        deserialize_u128: no_sequence,
        deserialize_f32: no_sequence,
        deserialize_f64: no_sequence,
        deserialize_char: no_sequence,
        deserialize_str: no_sequence,
        deserialize_string: no_sequence,
        deserialize_option: no_sequence,
        deserialize_unit: no_sequence,
        deserialize_map: no_sequence,
        deserialize_identifier: no_sequence,
        deserialize_seq: sequence,
        // JSON writes bytes as an array of numbers.
        deserialize_bytes: sequence,
        deserialize_byte_buf: sequence,
        // A skipped value is read into nothing.
        deserialize_ignored_any: sequence,
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(self, name: &'static str, visitor: V) -> Result<V::Value, D::Error> {
        self.0.deserialize_unit_struct(name, no_sequence(visitor))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(self, name: &'static str, visitor: V) -> Result<V::Value, D::Error> {
        self.0.deserialize_newtype_struct(name, no_sequence(visitor))
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, D::Error> {
        self.0.deserialize_tuple(len, sequence(visitor))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_tuple_struct(name, len, sequence(visitor))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_struct(name, fields, no_sequence(visitor))
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, D::Error> {
        self.0.deserialize_enum(name, variants, no_sequence(visitor))
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }
}

/// `visit_*` methods that take a plain value, forwarded unchanged.
macro_rules! forward_values {
    ($($method:ident($ty:ty)),* $(,)?) => {$(
        fn $method<E: de::Error>(self, v: $ty) -> Result<V::Value, E> {
            self.visitor.$method(v)
        }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for StrictVisitor<V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.visitor.expecting(formatter)
    }

    forward_values! {
        visit_bool(bool),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_i128(i128),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
        visit_u128(u128),
        visit_f32(f32),
        visit_f64(f64),
        visit_char(char),
        visit_str(&str),
        visit_borrowed_str(&'de str),
        visit_string(String),
        visit_bytes(&[u8]),
        visit_borrowed_bytes(&'de [u8]),
        visit_byte_buf(Vec<u8>),
    }

    fn visit_none<E: de::Error>(self) -> Result<V::Value, E> {
        self.visitor.visit_none()
    }

    fn visit_unit<E: de::Error>(self) -> Result<V::Value, E> {
        self.visitor.visit_unit()
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<V::Value, D::Error> {
        self.visitor.visit_some(Strict(deserializer))
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<V::Value, D::Error> {
        self.visitor.visit_newtype_struct(Strict(deserializer))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<V::Value, A::Error> {
        if self.sequence {
            self.visitor.visit_seq(StrictSeq(seq))
        } else {
            // The one refusal (QT-01), in serde's own words: the deserializer
            // adds where the array is.
            Err(de::Error::invalid_type(Unexpected::Seq, &self))
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<V::Value, A::Error> {
        self.visitor.visit_map(StrictMap(map))
    }

    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<V::Value, A::Error> {
        self.visitor.visit_enum(StrictEnum(data))
    }
}

/// A sequence whose elements are read under the rule.
struct StrictSeq<A>(A);

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for StrictSeq<A> {
    type Error = A::Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>, A::Error> {
        self.0.next_element_seed(StrictSeed(seed))
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

/// A map whose keys and values are read under the rule.
struct StrictMap<A>(A);

impl<'de, A: MapAccess<'de>> MapAccess<'de> for StrictMap<A> {
    type Error = A::Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>, A::Error> {
        self.0.next_key_seed(StrictSeed(seed))
    }

    fn next_value_seed<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.0.next_value_seed(StrictSeed(seed))
    }

    fn next_entry_seed<K: DeserializeSeed<'de>, S: DeserializeSeed<'de>>(
        &mut self,
        key: K,
        value: S,
    ) -> Result<Option<(K::Value, S::Value)>, A::Error> {
        self.0.next_entry_seed(StrictSeed(key), StrictSeed(value))
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

/// An enum whose variant name and content are read under the rule.
struct StrictEnum<A>(A);

impl<'de, A: EnumAccess<'de>> EnumAccess<'de> for StrictEnum<A> {
    type Error = A::Error;
    type Variant = StrictVariant<A::Variant>;

    fn variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<(S::Value, Self::Variant), A::Error> {
        let (value, variant) = self.0.variant_seed(StrictSeed(seed))?;
        Ok((value, StrictVariant(variant)))
    }
}

/// A variant's content, read under the rule: a tuple variant is a sequence,
/// a struct variant is not.
struct StrictVariant<A>(A);

impl<'de, A: VariantAccess<'de>> VariantAccess<'de> for StrictVariant<A> {
    type Error = A::Error;

    fn unit_variant(self) -> Result<(), A::Error> {
        self.0.unit_variant()
    }

    fn newtype_variant_seed<S: DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, A::Error> {
        self.0.newtype_variant_seed(StrictSeed(seed))
    }

    fn tuple_variant<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value, A::Error> {
        self.0.tuple_variant(len, sequence(visitor))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, A::Error> {
        self.0.struct_variant(fields, no_sequence(visitor))
    }
}

/// A seed that reads its value under the rule.
struct StrictSeed<S>(S);

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for StrictSeed<S> {
    type Value = S::Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<S::Value, D::Error> {
        self.0.deserialize(Strict(deserializer))
    }
}
