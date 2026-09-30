//! `vmr log init` and `vmr log seal` — start a log's directory, and write the
//! events a runtime sends to it.
// ============================================================================
//  log_seal.rs — the Community tool's audit log writer
//  (specs/audit-log-format-v0.1.md; specs/audit-profile-agent-v0.1.md)
//
//  Why it exists: any vendor's agent runtime, in any language, writes a
//  vmr.agent log with free software by starting `vmr log seal` and writing
//  one JSON object per line to it. The interface is the line format below
//  and docs/CLI.md's section on `log seal`; nothing in it names an engine, a
//  vendor or a model.
//
//  Orchestration, like the rest of the CLI: the file, its lock, its replay,
//  a torn tail's recovery and the durable append are vmr-audit-writer's; the
//  entry's rules and the checkpoint are vmr-audit-log's; the keyed digests
//  are the vmr.agent profile's (§3). What is here: the directory's files,
//  the input and output lines, turning content into digests, and when to
//  sign a checkpoint (§5).
//
//  Secrets: the audit key and the content secret are written once, to their
//  own files (owner-only on Unix), and never printed; content given in an
//  event is turned into its digest and written nowhere. No message quotes a
//  key, the secret or content.
//
//  Law 1 boundaries: `log init` draws the audit key and the content secret
//  from the OS random-number generator (the CLI's second randomness site,
//  beside `key generate`); `log seal` reads this machine's clock for each
//  entry's `recorded_at` and each checkpoint's `issued_at`, which the format
//  defines as the writer's clock (clock.rs).
// ============================================================================

use crate::cli::{LogInitArgs, LogSealArgs};
use crate::clock;
use crate::error::CliError;
use crate::files::{self, shown, ReadError};
use crate::keys::{self, PublicKeyFile};
use crate::names::TOOL;
use crate::output::{self, Output};
use crate::render::shown_value;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::zeroize::Zeroizing;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vmr_audit_log::json::parse_document;
use vmr_audit_log::profile::{EntryProfile, CORE};
use vmr_audit_log::profiles::vmr_agent::{self, digest::ContentSecret, MemberType};
use vmr_audit_writer::LogFile;
use vmr_record::canonical::jcs;
use vmr_record::timestamp::Timestamp;

/// The audit key: a PKCS#8 PEM private key, as `key generate` writes it.
pub const AUDIT_KEY_FILE: &str = "audit-key.pem";
/// The audit key's public key file, as `key export` writes it: what an
/// auditor pins.
pub const AUDIT_PUBLIC_KEY_FILE: &str = "audit-key.pub.json";
/// The content secret: 64 lower-case hexadecimal characters and a line feed.
pub const CONTENT_SECRET_FILE: &str = "content-secret";
/// The log.
pub const LOG_FILE: &str = "log.jsonl";
/// Every checkpoint signed, one JCS line each, in order.
pub const CHECKPOINTS_FILE: &str = "checkpoints.jsonl";
/// The latest checkpoint, replaced atomically.
pub const CHECKPOINT_FILE: &str = "checkpoint.json";

/// The longest input line, in bytes.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// The largest content-secret file read.
const MAX_SECRET_FILE_BYTES: u64 = 1024;

/// The digest members of a kind under a profile that keys content, or
/// `None` for a kind the profile does not know.
pub type DigestMembers = fn(&str) -> Option<Vec<&'static str>>;

/// A profile `log seal` writes under: the vocabulary of kinds, and what the
/// sealer does for it beyond the core.
pub struct SealProfile {
    /// The name `--profile` takes.
    pub name: &'static str,
    /// The profile.
    pub profile: &'static (dyn EntryProfile + Sync),
    /// The digest members of a kind, when the profile keys content (§3 of
    /// the vmr.agent profile): `None` for a kind the profile does not know.
    pub digests: Option<DigestMembers>,
    /// Whether a refused event is recorded as `events.dropped` with its
    /// count (the vmr.agent profile's "loss is recorded", §5).
    pub records_loss: bool,
}

/// The digest members of a `vmr.agent` kind.
fn agent_digests(kind: &str) -> Option<Vec<&'static str>> {
    vmr_agent::members(kind)
        .map(|members| members.iter().filter(|m| m.ty == MemberType::Digest).map(|m| m.name).collect())
}

/// The profiles `log seal` writes under. A later profile is one row.
pub const SEAL_PROFILES: [SealProfile; 2] = [
    SealProfile {
        name: vmr_agent::NAME,
        profile: &vmr_agent::PROFILE,
        digests: Some(agent_digests),
        records_loss: true,
    },
    SealProfile { name: "core", profile: &CORE, digests: None, records_loss: false },
];

// ---------------------------------------------------------------------------
//  log init
// ---------------------------------------------------------------------------

/// Run `log init`.
pub fn init(args: &LogInitArgs) -> Result<Output, CliError> {
    let dir = &args.dir;
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(CliError::input(format!("{} is not empty; nothing was written", shown(dir)))
                    .with_hint("give `log init` a new or empty directory: one log, one audit key, one content secret"));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir)
                .map_err(|e| CliError::input(format!("cannot create directory {}: {e}", shown(dir))))?;
        }
        Err(e) => return Err(CliError::input(format!("cannot read directory {}: {e}", shown(dir)))),
    }
    let key_path = dir.join(AUDIT_KEY_FILE);
    let public_path = dir.join(AUDIT_PUBLIC_KEY_FILE);
    let secret_path = dir.join(CONTENT_SECRET_FILE);
    let log_path = dir.join(LOG_FILE);

    // The audit key, exactly as `key generate` makes and writes one.
    let key = SigningKey::random(&mut OsRng);
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|_| CliError::input("cannot encode the new key as PKCS#8"))?;
    files::write_private_new(&key_path, pem.as_bytes(), false, "audit key")?;
    let public = PublicKeyFile::of(key.verifying_key());
    let json = serde_json::to_string_pretty(&public)
        .map_err(|e| CliError::input(format!("cannot write the public key as JSON: {e}")))?;
    files::write_public_new(&public_path, format!("{json}\n").as_bytes(), false, "public key file")?;

    // The content secret (§3): 32 bytes from the OS random-number generator.
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    let mut text = Zeroizing::new(to_hex(secret.as_ref()));
    text.push('\n');
    files::write_private_new(&secret_path, text.as_bytes(), false, "content secret")?;

    files::write_public_new(&log_path, b"", false, "audit log")?;

    let mut out = format!(
        "Started an audit log in {}\n  \
         Log:          {} (empty; `{TOOL} log seal --dir` writes to it)\n  \
         Audit key:    {} (PKCS#8 PEM, P-256: signs the log's checkpoints; keep it secret; {TOOL} never prints it)\n  \
         Public key:   {} ({}: hand this file to an auditor, who pins it)\n  \
         Secret:       {} (the content secret: keys every digest of content; keep it secret; never in the log)\n",
        shown(dir),
        shown(&log_path),
        shown(&key_path),
        shown(&public_path),
        public.key_id,
        shown(&secret_path),
    );
    for path in [&key_path, &secret_path] {
        if let Some(line) = files::private_key_permissions_note(path) {
            out.push_str(&format!("  Permissions:  {line}\n"));
        }
    }
    Ok(Output::ok(out))
}

/// Lower-case hexadecimal.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS.get(usize::from(b >> 4)).copied().unwrap_or(b'0')));
        out.push(char::from(DIGITS.get(usize::from(b & 15)).copied().unwrap_or(b'0')));
    }
    out
}

/// 32 bytes from 64 hexadecimal characters (either case).
pub(crate) fn key_from_hex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        let hi = char::from(*pair.first()?).to_digit(16)?;
        let lo = char::from(*pair.get(1)?).to_digit(16)?;
        *out.get_mut(i)? = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// Read a directory's content secret: exactly 64 lower-case hexadecimal
/// characters and a line feed. No message quotes the file.
pub(crate) fn read_content_secret(path: &Path) -> Result<ContentSecret, CliError> {
    let bytes = Zeroizing::new(files::read_bounded(path, MAX_SECRET_FILE_BYTES).map_err(|e| match e {
        ReadError::TooLarge(size) => CliError::input(format!(
            "content secret {} is {size} bytes; it is 65 (64 hexadecimal characters and a line feed), and it was not read",
            shown(path)
        )),
        ReadError::Io(e) => CliError::input(format!("cannot read content secret {}: {e}", shown(path))),
    })?);
    let text = std::str::from_utf8(&bytes).ok().and_then(|t| t.strip_suffix('\n'));
    let key = text
        .filter(|t| t.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .and_then(key_from_hex)
        .ok_or_else(|| {
            CliError::input(format!(
                "{} is not a content secret: 64 lower-case hexadecimal characters and a line feed",
                shown(path)
            ))
            .with_hint(concat!("pass the directory `", crate::tool_name!(), " log init` made"))
        })?;
    Ok(ContentSecret::from_bytes(key))
}

// ---------------------------------------------------------------------------
//  Reading a line of at most a cap
// ---------------------------------------------------------------------------

/// One line of input.
pub(crate) enum Line {
    /// Its bytes, without the line feed.
    Bytes(Vec<u8>),
    /// A line longer than the cap: its length. Its bytes were not kept.
    TooLong(u64),
}

/// Read the next line of at most `cap` bytes (a longer one is read to its end
/// and reported by its length, in the memory of `cap`), or `None` at the end
/// of the input. A last line without a line feed is a line.
pub(crate) fn read_line(input: &mut impl BufRead, cap: usize) -> std::io::Result<Option<Line>> {
    let mut line = Vec::new();
    let mut len = 0u64;
    let mut any = false;
    loop {
        let available = match input.fill_buf() {
            Ok(available) => available,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if available.is_empty() {
            if !any {
                return Ok(None);
            }
            break;
        }
        any = true;
        let (piece, used, ended) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (available.get(..i).unwrap_or(&[]), i + 1, true),
            None => (available, available.len(), false),
        };
        len += piece.len() as u64;
        if len <= cap as u64 {
            line.extend_from_slice(piece);
        } else {
            line = Vec::new();
        }
        input.consume(used);
        if ended {
            break;
        }
    }
    Ok(Some(if len > cap as u64 { Line::TooLong(len) } else { Line::Bytes(line) }))
}

// ---------------------------------------------------------------------------
//  log seal
// ---------------------------------------------------------------------------

/// Why an event was not written: a stable id and a message that quotes no
/// content.
struct Refused {
    id: &'static str,
    message: String,
}

impl Refused {
    fn new(id: &'static str, message: impl Into<String>) -> Refused {
        Refused { id, message: message.into() }
    }
}

/// An I/O failure of the log, as the command's error.
fn log_error(e: vmr_audit_log::Error) -> CliError {
    match e {
        vmr_audit_log::Error::Io(message) => CliError::input(message),
        refused => CliError::input(format!("the audit log was refused: {refused}"))
            .with_hint(concat!("`", crate::tool_name!(), " log verify --log <DIR>/log.jsonl` shows the line")),
    }
}

/// The sealer's state across events.
struct Sealer<'a> {
    row: &'a SealProfile,
    secret: Option<ContentSecret>,
    log: LogFile<'static>,
}

impl Sealer<'_> {
    /// Write one input line's event, or its refusal (and, under a profile that
    /// records loss, its `events.dropped`). `Err` is an I/O failure: stop.
    fn event(&mut self, line: Line) -> Result<(Value, bool), CliError> {
        let refused = match line {
            Line::TooLong(len) => Refused::new(
                "seal.size",
                format!("the line is {len} bytes; the cap is {MAX_LINE_BYTES}"),
            ),
            Line::Bytes(bytes) => match self.build(&bytes) {
                Err(refused) => refused,
                Ok((kind, detail)) => {
                    let now = clock::now()?;
                    match self.log.append(now, &kind, detail) {
                        Ok(entry) => {
                            let ended = entry.kind == "session.ended";
                            return Ok((json!({ "index": entry.index }), ended));
                        }
                        Err(vmr_audit_log::Error::Refused { id, message }) => Refused::new(id, message),
                        Err(e) => return Err(log_error(e)),
                    }
                }
            },
        };
        let mut answer = Map::new();
        answer.insert("refused".into(), json!(refused.id));
        answer.insert("message".into(), json!(refused.message));
        if self.row.records_loss {
            let now = clock::now()?;
            let entry = self.log.append(now, "events.dropped", json!({ "count": 1 })).map_err(log_error)?;
            answer.insert("recorded".into(), json!({ "kind": entry.kind, "index": entry.index }));
        }
        Ok((Value::Object(answer), false))
    }

    /// The entry's kind and detail from an input line, its content turned
    /// into digests; or why not.
    fn build(&self, bytes: &[u8]) -> Result<(String, Value), Refused> {
        let text = std::str::from_utf8(bytes).map_err(|_| Refused::new("seal.syntax", "the line is not UTF-8"))?;
        let parsed = parse_document(text).map_err(|e| Refused::new("seal.syntax", crate::render::bounded(&e)))?;
        if parsed.has_repeated_member() {
            return Err(Refused::new("seal.syntax", "a member appears twice"));
        }
        let Value::Object(mut event) = parsed.value else {
            return Err(Refused::new("seal.structure", "the line is not a JSON object"));
        };
        if let Some(other) = event.keys().find(|k| !["kind", "detail", "content"].contains(&k.as_str())) {
            return Err(Refused::new(
                "seal.structure",
                format!("unknown member {}: an event has kind, detail and content", shown_value(other)),
            ));
        }
        let kind = match event.remove("kind") {
            Some(Value::String(kind)) => kind,
            _ => return Err(Refused::new("seal.structure", "kind is not a string")),
        };
        // QA S4: the writer's own kind. It names bytes the sealer moved aside
        // on start; from a runtime it would name none.
        if kind == vmr_audit_writer::RECOVERED_KIND {
            return Err(Refused::new(
                "seal.reserved_kind",
                "log.recovered is written by the sealer only, when it moves a torn tail aside on start",
            ));
        }
        let mut detail = match event.remove("detail") {
            Some(Value::Object(detail)) => detail,
            _ => return Err(Refused::new("seal.structure", "detail is not an object")),
        };
        let content = match event.remove("content") {
            None => Map::new(),
            Some(Value::Object(content)) => content,
            Some(_) => return Err(Refused::new("seal.structure", "content is not an object")),
        };

        let Some(digests_of) = self.row.digests else {
            if content.is_empty() {
                return Ok((kind, Value::Object(detail)));
            }
            return Err(Refused::new(
                "seal.content",
                format!("the {} profile has no digest members: content is refused", self.row.name),
            ));
        };
        // A kind the profile does not know is its refusal, when the entry is
        // checked; content for it has no digest member to go to.
        let Some(digests) = digests_of(&kind) else {
            if content.is_empty() {
                return Ok((kind, Value::Object(detail)));
            }
            return Err(Refused::new(
                "seal.content",
                format!("kind {} is not a kind of {}: it has no digest members", shown_value(&kind), self.row.name),
            ));
        };
        if let Some(member) = digests.iter().find(|m| detail.contains_key(**m)) {
            return Err(Refused::new(
                "seal.digest_in_detail",
                format!(
                    "detail carries the digest member {member}: give the item under content, and the sealer, which \
                     holds the content secret, computes the digest"
                ),
            ));
        }
        if content.is_empty() {
            return Ok((kind, Value::Object(detail)));
        }
        let index = self.log.len();
        let Some(secret) = &self.secret else {
            return Err(Refused::new("seal.content", "no content secret is loaded"));
        };
        let session_id = match detail.get("session_id") {
            Some(Value::String(id)) => id.clone(),
            _ => {
                return Err(Refused::new(
                    "seal.content",
                    "a digest is keyed by its session: the detail has no session_id string",
                ))
            }
        };
        let session_key = secret.session_key(&session_id);
        for (member, item) in content {
            let Some(name) = digests.iter().find(|m| **m == member) else {
                return Err(Refused::new(
                    "seal.content",
                    format!(
                        "content member {} is not a digest member of {kind}; its digest members are: {}",
                        shown_value(&member),
                        if digests.is_empty() { "none".to_string() } else { digests.join(", ") }
                    ),
                ));
            };
            let bytes = content_bytes(&item).map_err(|why| Refused::new("seal.content", format!("content member {name}: {why}")))?;
            let digest = session_key.item_key(&kind, name, index).digest(&bytes);
            detail.insert((*name).to_string(), Value::String(digest));
        }
        Ok((kind, Value::Object(detail)))
    }
}

/// The bytes an item's content stands for: exactly one of `{"text": ..}`,
/// `{"base64": ..}` or `{"json": ..}`. The reason never quotes the content.
pub(crate) fn content_bytes(item: &Value) -> Result<Vec<u8>, &'static str> {
    let Some(form) = item.as_object().filter(|o| o.len() == 1) else {
        return Err("its value is not an object with exactly one of text, base64 and json");
    };
    match form.iter().next() {
        Some((k, Value::String(text))) if k == "text" => Ok(text.as_bytes().to_vec()),
        Some((k, Value::String(text))) if k == "base64" => decode_base64(text),
        Some((k, value)) if k == "json" => Ok(vmr_agent::digest::json_content(value)),
        Some((k, _)) if k == "text" || k == "base64" => Err("text and base64 take a string"),
        _ => Err("its value is not an object with exactly one of text, base64 and json"),
    }
}

/// Standard base64 (RFC 4648 §4), padded, strict: the alphabet of `A-Z`,
/// `a-z`, `0-9`, `+` and `/`, a length that is a multiple of 4, at most two
/// `=` at its end, and no bits set past the data.
pub(crate) fn decode_base64(text: &str) -> Result<Vec<u8>, &'static str> {
    if !text.len().is_multiple_of(4) {
        return Err("base64 is not standard padded base64: its length is not a multiple of 4");
    }
    let body = text.trim_end_matches('=');
    if text.len() - body.len() > 2 || body.bytes().any(|b| !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/')) {
        return Err("base64 is not standard padded base64 (A-Z, a-z, 0-9, + and /, with = only at its end)");
    }
    let url: String = body.chars().map(|c| match c {
        '+' => '-',
        '/' => '_',
        c => c,
    }).collect();
    vmr_record::encoding::b64url_decode(&url).map_err(|_| "base64 is not standard padded base64: bits are set past its data")
}

/// The directory's checkpoint files, and when the last checkpoint was made.
struct Checkpoints {
    history_path: PathBuf,
    latest_path: PathBuf,
    history: File,
    key: SigningKey,
    last_size: u64,
    last_at: Timestamp,
}

impl Checkpoints {
    /// Open `checkpoints.jsonl` for appending. A last line a crash tore (bytes
    /// no line feed ends) is moved to `checkpoints.jsonl.torn-<offset>` first,
    /// as the log's own torn tail is, so the history stays one checkpoint a
    /// line. The file is read from its end only, never whole (QA N3: it grows
    /// by a line per session): its last line feed, and the last checkpoint,
    /// whose size and time the next checkpoint is counted from (QA N4), so a
    /// restart repeats no checkpoint. `now` stands in when there is none.
    fn open(dir: &Path, key: SigningKey, now: Timestamp) -> Result<Checkpoints, CliError> {
        let history_path = dir.join(CHECKPOINTS_FILE);
        let cannot = |what: &str, e: std::io::Error| CliError::input(format!("cannot {what} {}: {e}", shown(&history_path)));
        let mut history = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&history_path)
            .map_err(|e| cannot("open", e))?;
        vmr_audit_writer::sync_parent(&history_path).map_err(log_error)?;
        let len = history.seek(SeekFrom::End(0)).map_err(|e| cannot("seek", e))?;
        let complete = line_start_before(&mut history, len, HISTORY_PIECE).map_err(|e| cannot("read", e))?;
        if len > complete {
            // As the log's own torn tail: never over an earlier torn-bytes file.
            vmr_audit_writer::move_torn_tail(&mut history, &history_path, complete).map_err(log_error)?;
        }
        let (last_size, last_at) = match last_checkpoint(&mut history, complete) {
            Ok(Some(last)) => last,
            // No checkpoint yet, or a last line this reader cannot use: log
            // verify reports a bad one; the sealer counts from its start.
            Ok(None) | Err(_) => (0, now),
        };
        history.seek(SeekFrom::End(0)).map_err(|e| cannot("seek", e))?;
        Ok(Checkpoints { latest_path: dir.join(CHECKPOINT_FILE), history_path, history, key, last_size, last_at })
    }

    /// Sign a checkpoint over the whole log, unless it is empty or the last
    /// one this run made already covers it; append it to the history (synced)
    /// and make it the latest (replaced atomically).
    fn write(&mut self, log: &LogFile<'_>) -> Result<(), CliError> {
        if log.is_empty() || log.len() == self.last_size {
            return Ok(());
        }
        let now = clock::now()?;
        let checkpoint = log.checkpoint(now, &self.key).map_err(log_error)?;
        let mut line = jcs(&checkpoint);
        line.push('\n');
        let path = &self.history_path;
        self.history
            .seek(SeekFrom::End(0))
            .and_then(|_| self.history.write_all(line.as_bytes()))
            .and_then(|()| self.history.sync_data())
            .map_err(|e| CliError::input(format!("cannot append to {}: {e}", shown(path))))?;
        self.replace_latest(line.as_bytes());
        self.last_size = log.len();
        self.last_at = now;
        Ok(())
    }

    /// Make `line` the latest checkpoint, checkpoint.json. Never fatal (QA
    /// B2): a reader may hold the file open without delete sharing (on
    /// Windows, .NET, Python and many editors open files so, and so may an
    /// antivirus scanner or an indexer), and the checkpoint is already
    /// durable in checkpoints.jsonl. So the replace is tried a few times, a
    /// little apart, and then the sealer warns on standard error and goes on:
    /// checkpoint.json lags until the next checkpoint replaces it.
    fn replace_latest(&self, line: &[u8]) {
        let mut tries = 0u64;
        loop {
            tries += 1;
            match files::replace_file(&self.latest_path, line, "checkpoint") {
                Ok(()) => return,
                Err(_) if tries < REPLACE_TRIES => std::thread::sleep(std::time::Duration::from_millis(REPLACE_PAUSE_MS * tries)),
                Err(e) => {
                    output::warning_to_stderr(&format!(
                        "{} (tried {tries} times); the checkpoint is written, and checkpoints.jsonl holds it: {} lags until the next checkpoint",
                        e.message,
                        shown(&self.latest_path)
                    ));
                    return;
                }
            }
        }
    }
}

/// How much of checkpoints.jsonl is read at a time, backwards from its end.
const HISTORY_PIECE: usize = 64 * 1024;

/// The longest checkpoint line read back (one is under 1 KiB).
const MAX_CHECKPOINT_LINE: u64 = 64 * 1024;

/// The offset just past the last line feed before `end` in `file` (0 when
/// there is none), read backwards from `end` in pieces of `piece` bytes.
pub(crate) fn line_start_before(file: &mut File, end: u64, piece: usize) -> std::io::Result<u64> {
    let mut buffer = vec![0u8; piece.max(1)];
    let mut stop = end;
    while stop > 0 {
        let start = stop.saturating_sub(buffer.len() as u64);
        let bytes = buffer.get_mut(..usize::try_from(stop - start).unwrap_or(0)).unwrap_or(&mut []);
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(bytes)?;
        if let Some(i) = bytes.iter().rposition(|&b| b == b'\n') {
            return Ok(start + i as u64 + 1);
        }
        stop = start;
    }
    Ok(0)
}

/// The tree size and time of the history's last checkpoint: the complete
/// line that ends at `complete` (just past its line feed). `None` when there
/// is no line, or it is longer than a checkpoint or not one.
fn last_checkpoint(file: &mut File, complete: u64) -> std::io::Result<Option<(u64, Timestamp)>> {
    if complete == 0 {
        return Ok(None);
    }
    let start = line_start_before(file, complete - 1, HISTORY_PIECE)?;
    let len = complete - 1 - start;
    if len > MAX_CHECKPOINT_LINE {
        return Ok(None);
    }
    let mut line = vec![0u8; usize::try_from(len).unwrap_or(0)];
    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut line)?;
    let Ok(value) = serde_json::from_slice::<Value>(&line) else { return Ok(None) };
    let size = value.get("tree_size").and_then(Value::as_u64);
    let at = value.get("issued_at").and_then(Value::as_str).and_then(|t| Timestamp::parse(t).ok());
    Ok(size.zip(at))
}

/// How many times replacing checkpoint.json is tried before the sealer warns
/// and goes on, and the pause before the n-th retry (n times this, in ms).
const REPLACE_TRIES: u64 = 5;
const REPLACE_PAUSE_MS: u64 = 20;

/// Write one answer line to standard output and flush it.
fn answer(out: &mut impl Write, value: &Value) -> Result<(), CliError> {
    let mut line = jcs(value);
    line.push('\n');
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| CliError::input(format!("cannot write to standard output: {e}")))
}

/// Run `log seal`.
pub fn seal(args: &LogSealArgs) -> Result<Output, CliError> {
    let row = SEAL_PROFILES
        .iter()
        .find(|row| row.name == args.profile)
        .ok_or_else(|| CliError::internal(format!("--profile {} is not in the profile table", shown_value(&args.profile))))?;
    let dir = &args.dir;
    let key = keys::read_signing_key(&dir.join(AUDIT_KEY_FILE))?;
    let secret = match row.digests {
        Some(_) => Some(read_content_secret(&dir.join(CONTENT_SECRET_FILE))?),
        None => None,
    };
    let log_path = dir.join(LOG_FILE);
    if !log_path.is_file() {
        return Err(CliError::input(format!("{} has no audit log {LOG_FILE}", shown(dir)))
            .with_hint(concat!("start the directory with `", crate::tool_name!(), " log init --dir <DIR>`")));
    }

    // Lock the log, replay it, and recover a torn tail (recorded as
    // log.recovered when the profile has that kind).
    let started = clock::now()?;
    let (log, recovered) = LogFile::open_recovering(&log_path, row.profile, started, &mut |_| {}).map_err(log_error)?;
    let mut checkpoints = Checkpoints::open(dir, key, started)?;
    let mut sealer = Sealer { row, secret, log };
    if !recovered.is_empty() {
        checkpoints.write(&sealer.log)?;
    }

    let every = args.checkpoint_every;
    let seconds = i64::try_from(args.checkpoint_minutes.saturating_mul(60)).unwrap_or(i64::MAX);
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        let line = match read_line(&mut input, MAX_LINE_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(e) => {
                checkpoints.write(&sealer.log)?;
                return Err(CliError::input(format!("cannot read standard input: {e}")));
            }
        };
        let (reply, ended) = sealer.event(line)?;
        // §5: after every session.ended, every N entries, and at the first
        // entry M minutes after the last checkpoint. The checkpoint is on
        // the disk before the answer that follows it.
        let now = clock::now()?;
        let due = ended
            || sealer.log.len().saturating_sub(checkpoints.last_size) >= every
            || now.unix_seconds().saturating_sub(checkpoints.last_at.unix_seconds()) >= seconds;
        if due {
            checkpoints.write(&sealer.log)?;
        }
        if let Err(e) = answer(&mut out, &reply) {
            checkpoints.write(&sealer.log)?;
            return Err(e);
        }
    }
    checkpoints.write(&sealer.log)?;
    Ok(Output::ok(String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_base64_is_read_strictly() {
        assert_eq!(decode_base64("").unwrap(), b"");
        assert_eq!(decode_base64("aGk=").unwrap(), b"hi");
        assert_eq!(decode_base64("+/8=").unwrap(), [0xfb, 0xff]);
        assert_eq!(decode_base64("AAAA").unwrap(), [0, 0, 0]);
        for bad in ["aGk", "aGk==", "-_8=", "aG=k", "aGl=", "====", "a==="] {
            assert!(decode_base64(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_content_form_is_exactly_one_of_three() {
        assert_eq!(content_bytes(&json!({ "text": "héllo" })).unwrap(), "héllo".as_bytes());
        assert_eq!(content_bytes(&json!({ "json": { "b": 1, "a": [true, null] } })).unwrap(), br#"{"a":[true,null],"b":1}"#);
        for bad in [json!("x"), json!({}), json!({ "text": "a", "json": 1 }), json!({ "text": 1 }), json!({ "hex": "00" })] {
            assert!(content_bytes(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_line_longer_than_the_cap_is_measured_not_kept() {
        let input = b"short\n0123456789\nlast";
        let mut reader = std::io::BufReader::with_capacity(4, &input[..]);
        assert!(matches!(read_line(&mut reader, 8).unwrap(), Some(Line::Bytes(b)) if b == b"short"));
        assert!(matches!(read_line(&mut reader, 8).unwrap(), Some(Line::TooLong(10))));
        assert!(matches!(read_line(&mut reader, 8).unwrap(), Some(Line::Bytes(b)) if b == b"last"));
        assert!(read_line(&mut reader, 8).unwrap().is_none());
    }

    #[test]
    fn the_last_line_feed_is_found_from_the_end_in_pieces() {
        // QA N3: checkpoints.jsonl is read backwards from its end, a piece at
        // a time; here pieces of 3 bytes, across their boundaries.
        let dir = std::env::temp_dir().join(format!("vmr-line-start-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("h.jsonl");
        std::fs::write(&path, b"first\nsecond line\ntorn").unwrap();
        let mut file = File::open(&path).unwrap();
        assert_eq!(line_start_before(&mut file, 22, 3).unwrap(), 18);
        assert_eq!(line_start_before(&mut file, 17, 3).unwrap(), 6);
        assert_eq!(line_start_before(&mut file, 5, 3).unwrap(), 0);
        assert_eq!(line_start_before(&mut file, 0, 3).unwrap(), 0);
        drop(file);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hex_round_trips() {
        let key: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        assert_eq!(key_from_hex(&to_hex(&key)), Some(key));
        assert_eq!(key_from_hex(&to_hex(&key).to_uppercase()), Some(key));
        assert_eq!(key_from_hex("00"), None);
        assert_eq!(key_from_hex(&"g".repeat(64)), None);
    }
}
