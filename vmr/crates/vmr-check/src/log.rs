//! `logVerifier()` and `checkItem()`: an audit log checked on the reader's
//! own computer (`docs/BROWSER.md`, "Audit logs").
// ============================================================================
//  log.rs — the audit-log checks of `vmr log verify` and `vmr log check-item`
//
//  Every rule and every statement is vmr-audit-log's (`verify`, the
//  `EntryFinder` and the vmr.agent digest check), the code `vmr` runs: this
//  module only reads the request's bytes and writes the answer as JSON. The
//  log streams in: a `LogSession` holds the reader's line in progress and the
//  tree's frontier, the root at each checkpoint's size, and a profile's pass
//  within its caps, never the log.
//
//  What an answer says is what was checked (audit-log format §5.1, a MUST).
//  Without an audit key or a checkpoint the outcome is `chain_only`, and the
//  statements say no signature was checked; under the core profile they say
//  nothing about what the entries mean was checked. A profile's summary and
//  notes are the writer's statements, labelled so, and never change the
//  outcome.
//
//  Strings from a log reach the answer through `display_safe`: the format's
//  refusal messages and the vmr.agent notes' messages are escaped once by
//  the library (as `vmr` prints them), and everything else here.
// ============================================================================

use crate::refusal::{
    Refusal, AUDIT_KEY_UNUSABLE, CHECKPOINT_HISTORY_EMPTY, CHECK_ITEM_ITEM_KEY, CHECK_ITEM_NO_DIGEST,
    CHECK_ITEM_NO_ENTRY, PROFILE_UNKNOWN, REQUEST_MALFORMED,
};
use crate::safe::display_safe_value;
use serde::Deserialize;
use serde_json::{json, Value};
use vmr_audit_log::log::{EntryFinder, Found};
use vmr_audit_log::profile::CORE;
use vmr_audit_log::profiles::vmr_agent::digest::{self, ItemKey};
use vmr_audit_log::verify::{
    self, check_checkpoint, history_lines, CheckedCheckpoint, HistoryChecker, LogFailure, LogVerifier, ProfileRow,
    Verified,
};
use vmr_record::record::JwkPublicKey;
use vmr_verify::display_safe;

/// The largest audit key file read, in bytes: `vmr`'s cap for a public key
/// file.
pub const MAX_KEY_FILE_BYTES: usize = 64 * 1024;

/// The most of a log read in one step: a step holds the entries its bytes
/// complete.
pub const PIECE: usize = 1024 * 1024;

/// What the statements call the checkpoints given one by one: `checkpoints[i]`.
fn checkpoint_source(i: usize) -> String {
    format!("checkpoints[{i}]")
}

/// What the statements call the checkpoint history.
const HISTORY_SOURCE: &str = "checkpointsJsonl";

/// The arguments of `logVerifier`.
#[derive(Debug, Clone, Default)]
pub struct LogRequest<'a> {
    /// The profile's name; `core` when absent.
    pub profile: Option<&'a str>,
    /// The audit key's public key file (`vmr key export`'s).
    pub audit_key: Option<&'a [u8]>,
    /// Checkpoints, one document each.
    pub checkpoints: Vec<&'a [u8]>,
    /// A checkpoint history, one checkpoint a line (`checkpoints.jsonl`).
    pub checkpoints_jsonl: Option<&'a [u8]>,
}

/// A public key file: `{"key_id": ..., "public_key": {JWK}}`, both objects
/// closed (`vmr key export`'s, docs/CLI.md §4.2).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyFile {
    key_id: String,
    public_key: JwkPublicKey,
}

/// The audit key of a public key file, refused as `vmr` refuses one: not a
/// closed `{key_id, public_key}`, not a P-256 point, or a `key_id` that is not
/// the key's RFC 7638 thumbprint (an edited id cannot pass one key off as
/// another).
pub fn audit_key(bytes: &[u8]) -> Result<(String, p256::ecdsa::VerifyingKey), Refusal> {
    let refuse = |why: String| Refusal::new(AUDIT_KEY_UNUSABLE, "audit_key", why);
    if bytes.len() > MAX_KEY_FILE_BYTES {
        return Err(refuse(format!("it is {} bytes; a public key file is at most 64 KiB", bytes.len())));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) || bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        return Err(refuse("it starts with a byte order mark, which a public key file may not have (it is UTF-8 JSON)".into()));
    }
    let file: PublicKeyFile = vmr_record::strict_json::from_slice(bytes)
        .map_err(|e| refuse(format!("not a public key file ({{\"key_id\": ..., \"public_key\": {{...}}}}): {e}")))?;
    let key = file.public_key.to_verifying_key().map_err(|e| refuse(format!("its public_key is not a P-256 key ({e})")))?;
    let derived = file.public_key.key_id();
    if file.key_id != derived {
        return Err(refuse(format!(
            "its key_id {} is not the RFC 7638 thumbprint of its public_key ({derived}): the file was altered",
            file.key_id
        )));
    }
    Ok((derived, key))
}

/// A log being checked as it arrives (`logVerifier()`).
pub struct LogSession {
    state: State,
}

enum State {
    /// The answer is known before the log: an input that cannot be used, or
    /// a checkpoint refused first (the log is then not read, as `vmr` does
    /// not read it).
    Answered(Value),
    /// The log is being read.
    Reading { verifier: Box<LogVerifier>, key_id: Option<String> },
}

impl std::fmt::Debug for LogSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.state {
            State::Answered(_) => "LogSession(answered)",
            State::Reading { .. } => "LogSession(reading)",
        })
    }
}

/// The answer of a log or checkpoint the checks refused.
fn failed(row: &ProfileRow, entries: Option<u64>, refusal: &verify::Refusal) -> Value {
    json!({
        "outcome": "failed",
        "profile": row.name,
        "entries": entries,
        "root": null,
        "checkpoints": [],
        "uncovered": null,
        "checked": [format!("Profile: {}: {}", row.name, row.checks)],
        // The library's message is terminal-safe already: never escaped twice.
        "refusal": { "id": display_safe(refusal.id), "detail": refusal.message },
        "summary": null,
        "notes": [],
    })
}

impl LogSession {
    /// A session whose answer is `answer` whatever the log: a request that
    /// could not be read.
    pub fn answered(answer: Value) -> LogSession {
        LogSession { state: State::Answered(answer) }
    }

    /// A session over the request's key and checkpoints, before the log's
    /// first byte: the key and every checkpoint are checked now, in the order
    /// `vmr log verify` checks them.
    pub fn new(req: &LogRequest<'_>) -> LogSession {
        LogSession { state: Self::start(req).unwrap_or_else(State::Answered) }
    }

    fn start(req: &LogRequest<'_>) -> Result<State, Value> {
        let name = req.profile.unwrap_or("core");
        let row = verify::profile_row(name).ok_or_else(|| {
            let names: Vec<&str> = verify::PROFILES.iter().map(|r| r.name).collect();
            Refusal::new(
                PROFILE_UNKNOWN,
                "profile",
                format!("{name} is not a profile this build reads a log under: {}", names.join(", ")),
            )
            .to_value()
        })?;
        let key = match req.audit_key {
            Some(bytes) => Some(audit_key(bytes).map_err(|r| r.to_value())?),
            None => None,
        };
        let Some((key_id, key)) = key else {
            if !req.checkpoints.is_empty() || req.checkpoints_jsonl.is_some() {
                return Err(Refusal::new(REQUEST_MALFORMED, "request", "checkpoints were given without an audit key")
                    .to_value());
            }
            return Ok(State::Reading { verifier: Box::new(LogVerifier::new(row, Vec::new(), None)), key_id: None });
        };
        let mut checked: Vec<CheckedCheckpoint> = Vec::with_capacity(req.checkpoints.len());
        for (i, bytes) in req.checkpoints.iter().enumerate() {
            checked.push(check_checkpoint(&checkpoint_source(i), bytes, &key).map_err(|r| failed(row, None, &r))?);
        }
        let history = match req.checkpoints_jsonl {
            None => None,
            Some(bytes) => {
                let mut history = HistoryChecker::new(HISTORY_SOURCE, &key);
                for line in history_lines(bytes) {
                    history.line(line).map_err(|r| failed(row, None, &r))?;
                }
                Some(history.finish().ok_or_else(|| {
                    Refusal::new(CHECKPOINT_HISTORY_EMPTY, "checkpoints_jsonl", "the checkpoint history holds no checkpoint")
                        .to_value()
                })?)
            }
        };
        Ok(State::Reading { verifier: Box::new(LogVerifier::new(row, checked, history)), key_id: Some(key_id) })
    }

    /// Read the next bytes of the log: `true` while the log is still wanted,
    /// `false` once the answer is known (a refusal), when the rest need not
    /// be read.
    pub fn update(&mut self, chunk: &[u8]) -> bool {
        match &mut self.state {
            State::Answered(_) => false,
            State::Reading { verifier, .. } => verifier.feed(chunk),
        }
    }

    /// The answer: the log's result, or the fail shape for an input that
    /// cannot be used.
    pub fn finish(self) -> Value {
        match self.state {
            State::Answered(answer) => answer,
            State::Reading { verifier, key_id } => {
                let row = verifier.row();
                match verifier.finish() {
                    Ok(verified) => verified_answer(&verified, key_id.as_deref()),
                    Err(LogFailure::Refused { accepted, refusal }) => failed(row, Some(accepted), &refusal),
                    Err(LogFailure::Internal(message)) => Refusal::new(REQUEST_MALFORMED, "log", message).to_value(),
                }
            }
        }
    }
}

/// The answer of a log that verified (or whose chain did, with no
/// checkpoint): its statements as `vmr log verify` prints them.
fn verified_answer(v: &Verified, key_id: Option<&str>) -> Value {
    let mut checked = vec![
        format!("Profile: {}", v.profile_statement()),
        format!("Checked: {}", v.checked_statement()),
        format!("Entries: {}", v.entries_statement()),
        match key_id {
            Some(key_id) if !v.signed() => format!("Audit key: {key_id}; no checkpoint was checked under it"),
            Some(key_id) => format!("Audit key: {key_id}"),
            None => "Audit key: none given".to_string(),
        },
    ];
    checked.extend(v.checkpoint_statements().into_iter().map(|(label, value)| format!("{label}: {value}")));
    let checkpoints: Vec<Value> = v
        .all_checkpoints()
        .into_iter()
        .map(|(source, tree_size, issued_at)| {
            json!({
                "source": source,
                "tree_size": tree_size,
                "issued_at": issued_at.as_deref().map(display_safe),
                "covers_whole_log": tree_size == v.entries,
            })
        })
        .collect();
    let (summary, notes) = match &v.notes {
        None => (Value::Null, Vec::new()),
        Some(pass) => {
            let mut summary = display_safe_value(pass.summary_value());
            if let Value::Object(members) = &mut summary {
                members.insert("statements_of".into(), json!("the log's writer"));
                members.insert("heading".into(), json!(verify::WRITER_STATEMENTS));
                // Terminal-safe already (the library's lines, as vmr prints them).
                let lines: Vec<Value> =
                    pass.lines().into_iter().map(|(label, value)| json!({ "label": label, "value": value })).collect();
                members.insert("lines".into(), Value::Array(lines));
            }
            let notes = pass
                .notes_values()
                .into_iter()
                .map(|mut note| {
                    // The message is terminal-safe already; the session id is
                    // the log's.
                    if let Some(session) = note.get_mut("session_id") {
                        if let Some(text) = session.as_str() {
                            *session = Value::String(display_safe(text));
                        }
                    }
                    note
                })
                .collect();
            (summary, notes)
        }
    };
    json!({
        "outcome": if v.signed() { "verified" } else { "chain_only" },
        "profile": v.row.name,
        "headline": v.headline(),
        "entries": v.entries,
        "root": v.root,
        "audit_key": key_id,
        "checkpoints": checkpoints,
        "uncovered": v.uncovered().map(|(from, to)| json!({ "from": from, "to": to })),
        "checked": checked,
        "refusal": null,
        "summary": summary,
        "notes": notes,
    })
}

/// The arguments of `checkItem`.
#[derive(Debug, Clone)]
pub struct CheckItemRequest<'a> {
    /// The log's bytes, at least up to the entry.
    pub log: &'a [u8],
    /// The entry's index.
    pub index: u64,
    /// The digest member's name.
    pub member: &'a str,
    /// The item key, 64 hexadecimal characters.
    pub item_key: &'a str,
    /// The disclosed content's bytes.
    pub content: &'a [u8],
}

/// `checkItem`: whether the content under the item key gives the digest
/// entry `index` carries in `member` (`vmr log check-item`), every line of
/// the log up to the entry checked under the core profile.
pub fn check_item(req: &CheckItemRequest<'_>) -> Value {
    let Some(item_key) = ItemKey::from_hex(req.item_key) else {
        return Refusal::new(CHECK_ITEM_ITEM_KEY, "item_key", "the item key is not 64 hexadecimal characters").to_value();
    };
    // The core profile: the digest's check needs no vocabulary, and a log of
    // any profile carries its digests the same way.
    // In pieces, so that no more than a piece's entries are held at once.
    let mut finder = EntryFinder::new(&CORE, req.index);
    for piece in req.log.chunks(PIECE) {
        if finder.feed(piece) {
            break;
        }
    }
    let entry = match finder.finish() {
        Found::Entry(entry) => entry,
        Found::Refused(refused) => {
            let refusal = verify::Refusal::of(&refused, None);
            return Refusal::new(refusal.id, "log", format!("the log was refused before entry {}: {}", req.index, refusal.message))
                .to_value_safe_detail();
        }
        Found::Missing { held } => {
            return Refusal::new(CHECK_ITEM_NO_ENTRY, "index", format!("the log holds {held} entries: it has no entry {}", req.index))
                .to_value();
        }
    };
    let Some(checked) = digest::check_item(&entry, req.member, &item_key, req.content) else {
        return Refusal::new(
            CHECK_ITEM_NO_DIGEST,
            "member",
            format!("entry {} ({}) has no digest member {}", entry.index, entry.kind, req.member),
        )
        .to_value();
    };
    json!({
        "matches": checked.matches,
        "index": entry.index,
        "kind": display_safe(&entry.kind),
        "label": display_safe(&checked.label),
        "in_entry": display_safe(&checked.carried),
        "computed": checked.computed,
        "not_checked": format!("whether a signed checkpoint covers entry {}: logVerifier checks that", entry.index),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/examples/agent-log").join(name))
            .unwrap()
    }

    #[test]
    fn the_example_key_loads_and_an_altered_one_is_refused() {
        let bytes = example("audit-key.pub.json");
        let (key_id, _) = audit_key(&bytes).unwrap();
        assert!(key_id.ends_with("elV0CTLmHeLGMWHUivanSFU2fHPeuotOxKxCFKQPl8c"));
        let altered = String::from_utf8(bytes.clone()).unwrap().replace("elV0", "xlV0");
        assert_eq!(audit_key(altered.as_bytes()).unwrap_err().id, AUDIT_KEY_UNUSABLE);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&bytes);
        assert_eq!(audit_key(&bom).unwrap_err().id, AUDIT_KEY_UNUSABLE);
        assert_eq!(audit_key(b"{\"key_id\":\"x\",\"public_key\":{},\"extra\":1}").unwrap_err().id, AUDIT_KEY_UNUSABLE);
    }

    #[test]
    fn an_unknown_profile_and_an_empty_history_are_input_refusals() {
        let unknown = LogSession::new(&LogRequest { profile: Some("acme.other"), ..LogRequest::default() }).finish();
        assert_eq!(unknown["refusal"]["id"], PROFILE_UNKNOWN);
        let key = example("audit-key.pub.json");
        let mut empty = LogSession::new(&LogRequest {
            audit_key: Some(&key),
            checkpoints_jsonl: Some(b""),
            ..LogRequest::default()
        });
        assert!(!empty.update(&example("log.jsonl")));
        assert_eq!(empty.finish()["refusal"]["input"], "checkpoints_jsonl");
    }
}
