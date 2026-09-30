//! `vmr log disclose` and `vmr log check-item` — the two sides of disclosing
//! one item a `vmr.agent` log committed to by its keyed digest.
// ============================================================================
//  log_disclose.rs — disclosure, both sides
//  (specs/audit-profile-agent-v0.1.md §3, its informative paragraph)
//
//  To show that some content is what an entry committed to, the holder gives
//  the item key and the content; anyone recomputes the digest and finds it in
//  the entry. `disclose` is the holder's side: it derives one item key from
//  the directory's content secret (content secret -> session key -> item
//  key), and prints nothing else: an item key opens that one digest and no
//  other, so it is the narrowest key a holder can give. `check-item` is the
//  auditor's side: it needs no secret.
//
//  What check-item says is what it checked, and no more: that the content
//  under the item key gives the digest entry N carries, and that the log's
//  lines up to entry N are good lines of a chain. Whether a signed checkpoint
//  covers entry N is `log verify`'s answer, and the output says so.
// ============================================================================

use crate::cli::{LogCheckItemArgs, LogDiscloseArgs};
use crate::error::{CliError, EXIT_VERIFICATION_FAILED};
use crate::files::{self, shown};
use crate::log_seal::{key_from_hex, read_content_secret, to_hex, CONTENT_SECRET_FILE, LOG_FILE};
use crate::output::Output;
use crate::render::shown_value;
use serde_json::Value;
use std::io::Read;
use std::path::Path;
use vmr_audit_log::entry::AuditEntry;
use vmr_audit_log::json::parse_document;
use vmr_audit_log::log::LogReader;
use vmr_audit_log::profile::{EntryProfile, CORE};
use vmr_audit_log::profiles::vmr_agent::{self, digest, MemberType};

/// How much of the log is read at a time.
const READ_PIECE: usize = 1024 * 1024;

/// Entry `index` of the log at `path`, read under `profile` with every line
/// up to it checked: `Ok(Err(..))` is the format's refusal of a line (its id
/// and message), `Err` a file that could not be read or a log too short.
fn find_entry(
    path: &Path,
    index: u64,
    profile: &dyn EntryProfile,
) -> Result<Result<AuditEntry, vmr_audit_log::Error>, CliError> {
    let cannot = |e: std::io::Error| CliError::input(format!("cannot read audit log {}: {e}", shown(path)));
    let mut file = std::fs::File::open(path).map_err(cannot)?;
    let mut reader = LogReader::new(profile);
    let mut piece = vec![0u8; READ_PIECE];
    loop {
        let n = match file.read(&mut piece) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(cannot(e)),
        };
        match reader.feed(piece.get(..n).unwrap_or(&[])) {
            Ok(entries) => {
                if let Some(entry) = entries.into_iter().find(|e| e.index == index) {
                    return Ok(Ok(entry));
                }
            }
            Err(refused) => return Ok(Err(refused)),
        }
    }
    let held = reader.len();
    if let Err(refused) = reader.finish() {
        return Ok(Err(refused));
    }
    Err(CliError::input(format!("audit log {} holds {held} entries: it has no entry {index}", shown(path))))
}

/// The digest string entry `entry` carries in `member`, or why it has none.
fn digest_member<'e>(entry: &'e AuditEntry, member: &str) -> Result<&'e str, CliError> {
    entry
        .detail
        .get(member)
        .and_then(Value::as_str)
        .filter(|d| digest::is_digest(d))
        .ok_or_else(|| {
            CliError::input(format!(
                "entry {} ({}) has no digest member {}",
                entry.index,
                shown_value(&entry.kind),
                shown_value(member)
            ))
        })
}

/// Run `log disclose`.
pub fn disclose(args: &LogDiscloseArgs) -> Result<Output, CliError> {
    let secret = read_content_secret(&args.dir.join(CONTENT_SECRET_FILE))?;
    let log = args.dir.join(LOG_FILE);
    let entry = find_entry(&log, args.index, &vmr_agent::PROFILE)?.map_err(|refused| {
        CliError::input(format!("the audit log {} was refused: {refused}", shown(&log)))
    })?;
    // The member must be one the kind defines as a digest (§4), and the
    // entry must carry it.
    let defined = vmr_agent::members(&entry.kind)
        .is_some_and(|members| members.iter().any(|m| m.name == args.member && m.ty == MemberType::Digest));
    if !defined {
        return Err(CliError::input(format!(
            "{} is not a digest member of {} (entry {})",
            shown_value(&args.member),
            shown_value(&entry.kind),
            entry.index
        )));
    }
    digest_member(&entry, &args.member)?;
    let session_id = entry.detail.get("session_id").and_then(Value::as_str).ok_or_else(|| {
        CliError::input(format!("entry {} belongs to no session: its digests have no session key", entry.index))
    })?;
    let item_key = secret.session_key(session_id).item_key(&entry.kind, &args.member, entry.index);
    Ok(Output::ok(format!("{}\n", to_hex(item_key.as_bytes()))))
}

/// The content `check-item` was given, as bytes.
fn content_of(args: &LogCheckItemArgs) -> Result<(Vec<u8>, String), CliError> {
    if let Some(text) = &args.content_text {
        return Ok((text.as_bytes().to_vec(), "the UTF-8 bytes of --content-text".to_string()));
    }
    if let Some(path) = &args.content_file {
        let bytes = files::read_document(path, "content file")?;
        return Ok((bytes, format!("the bytes of {}", shown(path))));
    }
    if let Some(path) = &args.content_json {
        let bytes = files::read_document(path, "content JSON file")?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CliError::input(format!("{} is not UTF-8 JSON", shown(path))))?;
        let parsed = parse_document(text)
            .map_err(|e| CliError::input(format!("{} is not JSON: {}", shown(path), crate::render::bounded(&e))))?;
        if parsed.has_repeated_member() {
            return Err(CliError::input(format!(
                "{} repeats a member: its value, and so its canonical form, is ambiguous",
                shown(path)
            )));
        }
        return Ok((digest::json_content(&parsed.value), format!("the canonical JSON form of {}", shown(path))));
    }
    Err(CliError::internal("check-item was given no content"))
}

/// Run `log check-item`.
pub fn check_item(args: &LogCheckItemArgs) -> Result<Output, CliError> {
    let key = key_from_hex(&args.item_key).ok_or_else(|| {
        CliError::input("--item-key is not an item key: 64 hexadecimal characters")
            .with_hint(concat!("pass the key `", crate::tool_name!(), " log disclose` printed"))
    })?;
    let (content, what) = content_of(args)?;
    let log = shown(&args.log);
    // Read under the core profile: the digest's check needs no vocabulary,
    // and a log of any profile carries its digests the same way.
    let entry = match find_entry(&args.log, args.index, &CORE)? {
        Ok(entry) => entry,
        Err(refused) => {
            let out = format!(
                "Item NOT checked: the audit log was refused before entry {}: {refused}\n  Log:          {log}\n",
                args.index
            );
            return Ok(Output { stdout: out, rich: None, code: EXIT_VERIFICATION_FAILED });
        }
    };
    let carried = digest_member(&entry, &args.member)?;
    let computed = digest::ItemKey::from_bytes(key).digest(&content);
    let label = digest::label(&entry.kind, &args.member, entry.index);
    let matches = computed == carried;
    let mut out = if matches {
        format!(
            "Item matches: entry {}'s {} is the digest of this content under this item key\n",
            entry.index,
            shown_value(&args.member)
        )
    } else {
        format!(
            "Item does NOT match: entry {}'s {} is not the digest of this content under this item key\n",
            entry.index,
            shown_value(&args.member)
        )
    };
    let line = |out: &mut String, label: &str, value: &str| out.push_str(&format!("  {:<14}{value}\n", format!("{label}:")));
    line(&mut out, "Log", &log);
    line(&mut out, "Entry", &format!("{} ({}), label {}", entry.index, shown_value(&entry.kind), shown_value(&label)));
    line(&mut out, "Content", &what);
    line(&mut out, "In the entry", &shown_value(carried));
    line(&mut out, "Computed", &computed);
    line(
        &mut out,
        "Not checked",
        &format!(
            "whether a signed checkpoint covers entry {}: run `{} log verify --log <FILE> --audit-key <KEY> \
             --checkpoint <FILE>`",
            entry.index,
            crate::names::TOOL
        ),
    );
    Ok(Output { stdout: out, rich: None, code: if matches { 0 } else { EXIT_VERIFICATION_FAILED } })
}
