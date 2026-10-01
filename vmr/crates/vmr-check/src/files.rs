//! `checkFiles`: the files a reader holds, against the files a record lists,
//! and the record's two digests over them (spec §7.2–7.3).
// ============================================================================
//  files.rs — names, digests and the two hashes, nothing read from a disk
//
//  The reader's page hashes each file (`fileHasher`) and passes its name,
//  digest and size. A name is the file's path relative to the model folder,
//  with "/" separators, compared exactly: no case folding, no Unicode
//  normalisation (§7.2). The record's two digests are compared where spec
//  §7.3 puts them:
//
//    "learned_state_hash is the named-set digest (§7.2) of the components,
//     each a member named by its name whose SHA-256 is its hash."
//    "model_hash is the named-set digest of every file the model is
//     distributed as. When the components are every file, it equals
//     learned_state_hash."
//    "model_hash covers files a record need not carry: only a holder of
//     exactly those files, knowing which they are, can check it."
//
//  So:
//    - `learned_state_hash.computed` is the named-set digest of the listed
//      components, each named by its name with the digest of the GIVEN file
//      of that name; `null` when a listed file is missing or given twice, or
//      when the record's own names are not a set;
//    - `model_hash.computed` is the named-set digest of every file the reader
//      gave: the reader is the holder §7.3 names, and the files given are the
//      ones they hold. `null` when a given name is refused (§7.2 refuses a
//      set holding such a name). An extra file changes it, as it changes the
//      folder; `extra` names each one;
//    - each listed component (`files`, in the record's order) is `match`
//      (same digest and size), `mismatch`, `missing`, or `duplicate` (its
//      name was given twice: neither copy is used);
//    - every entry carries `name` (exact, for matching), `shown` (through
//      `display_safe`, for showing) and `index` (its position in the given
//      list; for a listed file, its position in the record, with
//      `given_index` the given file it was compared with);
//    - a given name §7.2 refuses goes into `refused_names` with §7.2's reason
//      (vmr-record's `NameError::id`); a name given twice is refused at every
//      place it was given as `not-ascending`, with `indexes`; a name that is
//      not a sequence of Unicode scalar values (a lone surrogate, which a
//      JavaScript string can hold) is refused as `not-unicode`, which §7.2
//      requires a tool to refuse but gives no reason name for.
//
//  A record in a registered profile (snn-compact-v1) is refused as
//  unsupported: its model hash is the engine state's, not a digest of files.
// ============================================================================

use crate::refusal::{Refusal, CHECK_FILES_DIGEST, CHECK_FILES_SIZE, CHECK_FILES_UNSUPPORTED_PROFILE};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use vmr_record::hash::{format_hash, parse_hash, DIGEST_LEN};
use vmr_record::named_set::{validate_name, NameError, NamedSetDigest};
use vmr_record::validate::KHALM_ENGINE_PROFILE;
use vmr_record::Record;
use vmr_verify::display_safe;

/// The largest size a record can state (2^53 - 1, spec §2).
const MAX_SIZE: u64 = (1 << 53) - 1;

/// The reason a name that is not Unicode is refused with: §7.2 refuses such
/// a name but names no reason for it.
pub const NOT_UNICODE: &str = "not-unicode";

/// A given file's name as the page passes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GivenName {
    /// A name of Unicode scalar values.
    Text(String),
    /// A name that is not: its UTF-16 code units, a lone surrogate among them.
    NotUnicode(Vec<u16>),
}

/// One file the reader holds, as the page passes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GivenFile {
    /// Its path relative to the model folder, `/`-separated.
    pub name: GivenName,
    /// `sha256:` and 64 lower-case hex digits (`fileHasher().finish()`).
    pub sha256: String,
    /// Its size in bytes; `None` when the page passed something that is not
    /// a whole number from 0 to 2^53 - 1.
    pub size: Option<u64>,
}

impl GivenFile {
    /// A file with a Unicode name.
    pub fn named(name: &str, sha256: &str, size: u64) -> Self {
        GivenFile { name: GivenName::Text(name.to_string()), sha256: sha256.to_string(), size: Some(size) }
    }
}

/// `checkFiles` for `record` and the files the reader holds.
pub fn check_files(record: &Record, given: &[GivenFile]) -> Value {
    match checked(record, given) {
        Ok(value) => value,
        Err(refusal) => refusal.to_value(),
    }
}

/// A held file: its index, its digest's bytes and text, its size.
type Held<'a> = (usize, [u8; DIGEST_LEN], &'a str, u64);

fn checked(record: &Record, given: &[GivenFile]) -> Result<Value, Refusal> {
    let identity = &record.model_identity;
    if identity.model_format == KHALM_ENGINE_PROFILE {
        return Err(Refusal::new(
            CHECK_FILES_UNSUPPORTED_PROFILE,
            "record",
            format!(
                "the record's model_format is {KHALM_ENGINE_PROFILE}, a registered profile whose model_hash is the \
                 engine state's hash, not a digest of files (spec §7.4): its files cannot be checked here"
            ),
        ));
    }

    // Every digest and size well-formed, or the call is refused.
    let mut parsed = Vec::with_capacity(given.len());
    for (i, file) in given.iter().enumerate() {
        let digest = digest_of(&file.sha256).ok_or_else(|| {
            Refusal::new(
                CHECK_FILES_DIGEST,
                "files",
                format!("files[{i}].sha256 is not sha256: followed by 64 lower-case hex digits"),
            )
        })?;
        let size = file.size.filter(|s| *s <= MAX_SIZE).ok_or_else(|| {
            Refusal::new(CHECK_FILES_SIZE, "files", format!("files[{i}].size is not a whole number from 0 to 2^53 - 1"))
        })?;
        parsed.push((digest, size));
    }

    // Each name's places in the given list, and the names refused.
    let mut places: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut refused: Vec<(usize, Value)> = Vec::new();
    for (i, file) in given.iter().enumerate() {
        match &file.name {
            GivenName::NotUnicode(units) => refused.push((
                i,
                json!({ "index": i, "name": null, "shown": shown_units(units), "reason": NOT_UNICODE }),
            )),
            GivenName::Text(name) => match validate_name(name) {
                Err(e) => refused.push((i, entry(i, name, Some(e.id())))),
                Ok(()) => places.entry(name.as_str()).or_default().push(i),
            },
        }
    }
    let mut held: BTreeMap<&str, Held<'_>> = BTreeMap::new();
    for (name, at) in &places {
        match (at.as_slice(), at.first()) {
            ([_], Some(&i)) => {
                if let (Some((digest, size)), Some(file)) = (parsed.get(i), given.get(i)) {
                    held.insert(name, (i, *digest, &file.sha256, *size));
                }
            }
            _ => {
                for &i in at {
                    refused.push((i, with(entry(i, name, Some(NameError::NotAscending.id())), "indexes", json!(at))));
                }
            }
        }
    }
    refused.sort_by_key(|(i, _)| *i);

    // The listed components, in the record's order.
    let mut statuses = Vec::new();
    let mut learned = Some(NamedSetDigest::new());
    for (index, component) in identity.learned_state_components.iter().enumerate() {
        let name = component.name.as_str();
        let (status, given_index) = match held.get(name) {
            Some((i, bytes, text, size)) => {
                if let Some(d) = learned.as_mut() {
                    if d.push(name, bytes).is_err() {
                        // The record's own names are not a set (§7.2).
                        learned = None;
                    }
                }
                let status = if *text == component.hash && *size == component.size_bytes { "match" } else { "mismatch" };
                (status, Some(*i))
            }
            None => {
                learned = None;
                (if places.contains_key(name) { "duplicate" } else { "missing" }, None)
            }
        };
        let e = with(entry(index, name, None), "status", json!(status));
        statuses.push(with(e, "given_index", json!(given_index)));
    }

    // Every file given: the holder's set (BTreeMap order is §7.2's order).
    let model = if refused.is_empty() {
        let mut d = NamedSetDigest::new();
        held.iter().all(|(name, (_, bytes, _, _))| d.push(name, bytes).is_ok()).then(|| format_hash(&d.finish()))
    } else {
        None
    };
    let learned = learned.map(|d| format_hash(&d.finish()));

    let listed: Vec<&str> = identity.learned_state_components.iter().map(|c| c.name.as_str()).collect();
    let extra: Vec<Value> = held
        .iter()
        .filter(|(name, _)| !listed.contains(name))
        .map(|(name, (i, _, _, _))| entry(*i, name, None))
        .collect();
    Ok(json!({
        "learned_state_hash": compared(&identity.learned_state_hash, learned),
        "model_hash": compared(&identity.model_hash, model),
        "files": statuses,
        "extra": extra,
        "refused_names": refused.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
    }))
}

/// `{index, name, shown}`, and `reason` when one is given.
fn entry(index: usize, name: &str, reason: Option<&str>) -> Value {
    let e = json!({ "index": index, "name": name, "shown": display_safe(name) });
    match reason {
        Some(reason) => with(e, "reason", json!(reason)),
        None => e,
    }
}

/// `object` with the member `key` set to `value`.
fn with(mut object: Value, key: &str, value: Value) -> Value {
    if let Value::Object(members) = &mut object {
        members.insert(key.to_string(), value);
    }
    object
}

/// The record's value, the one computed from the files, and whether they are
/// the same.
fn compared(listed: &str, computed: Option<String>) -> Value {
    let matches = computed.as_deref() == Some(listed);
    json!({ "listed": display_safe(listed), "computed": computed, "matches": matches })
}

/// A name that is not Unicode, shown: each lone surrogate as visible
/// `\u{..}` text, everything else through `display_safe`.
fn shown_units(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|unit| match unit {
            Ok(c) => display_safe(c.encode_utf8(&mut [0; 4])),
            Err(e) => format!("\\u{{{:04x}}}", e.unpaired_surrogate()),
        })
        .collect()
}

/// The digest `text` names, when it is exactly `sha256:` and 64 lower-case
/// hex digits.
fn digest_of(text: &str) -> Option<[u8; DIGEST_LEN]> {
    let hex = text.strip_prefix("sha256:")?;
    if hex.len() != 2 * DIGEST_LEN || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    parse_hash(text).ok()
}
