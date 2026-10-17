// ============================================================================
//  verify.rs — checking a whole log under a pinned audit key, for every reader
//  (`specs/audit-log-format-v0.1.md` §4.4, §5.1, §6).
//
//  `vmr log verify` and the browser checker (vmr-check) are two readers of
//  the same check: the profile table, the log streamed through `LogReader`,
//  each checkpoint verified under the pinned key (§6) and held to the log at
//  its `tree_size` (§6, its last paragraph), the entries no checkpoint
//  covers, and a profile's pass over the accepted entries (the vmr.agent
//  notes). Here it is once, over bytes: no clock, no file and no network. A
//  caller reads its files (or a page its `File`s) and renders the result.
//
//  What a result says is what was checked, and no more (§5.1, a MUST): the
//  statements below name the profile's own words for what it checks, under
//  the core profile that nothing about what an entry means is checked, and
//  without a checkpoint that no signature was. No profile makes an entry true:
//  a log is its writer's statement, and a checkpoint's signature binds the
//  writer's key to it. A profile's notes are the writer's statements too, and
//  never change the result.
//
//  Whose log it is does not matter here. The profiles are a table: the core,
//  and each named profile this crate carries; a later profile is one row.
// ============================================================================

//! Checking a log and its checkpoints under a pinned audit key, as every
//! reader of this repository does (`vmr log verify`, the browser checker):
//! the profile table ([`PROFILES`]), checkpoints ([`check_checkpoint`],
//! [`HistoryChecker`]), the log streamed through a [`LogVerifier`], and the
//! statements of what was checked ([`Verified`]).

use crate::checkpoint::{self, CheckpointClaims};
use crate::entry::AuditEntry;
use crate::error::{display_safe, Error};
use crate::log::LogReader;
use crate::profile::{EntryProfile, CORE};
use crate::profiles::{khalm_enforcer, vmr_agent};
use crate::tree::MerkleFrontier;
use crate::MAX_CHECKPOINT_BYTES;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use vmr_record::hash::{format_hash, parse_hash};

/// A reader's own refusal: a checkpoint that verified under the audit key is
/// not of the log given. The format asks for the check (§6, its last
/// paragraph: the log holds at least `tree_size` entries, and its root over
/// them is `root_hash`) and names no id for it; this one is the reader's, as
/// `vmr log verify` names it.
pub const CHECKPOINT_NOT_IN_LOG: &str = "log_verify.checkpoint_not_in_log";

/// A reader's own refusal: a checkpoint history whose checkpoints are not in
/// order, a line's `tree_size` smaller than the line before it. A writer's
/// history only grows (§6: a checkpoint states the log's size, and the log is
/// append only).
pub const CHECKPOINTS_OUT_OF_ORDER: &str = "log_verify.checkpoints_out_of_order";

/// The longest refusal message kept, in characters.
pub const MESSAGE_MAX_CHARS: usize = 400;

/// How many notes a profile's pass keeps; the others are counted.
pub const NOTES_SHOWN: usize = 20;

/// How many gates the vmr.agent "Calls" line names; the refusals of the
/// others are summed.
pub const GATES_SHOWN: usize = 8;

/// The heading of a profile's lines: they are the writer's statements.
pub const WRITER_STATEMENTS: &str = "What the entries say (the writer's statements, not verified facts)";

/// A profile's pass over a log's accepted entries, in order: what they record
/// across one another. The rules between entries are the writer's (a reader
/// reports where a log breaks them and never refuses it), so everything it
/// gives is the writer's statements, not verified facts.
pub trait ProfileNotes {
    /// Take in the next accepted entry.
    fn observe(&mut self, entry: &AuditEntry);
    /// The lines a reader shows after the integrity result: a label and a
    /// value, terminal-safe.
    fn lines(&self) -> Vec<(&'static str, String)>;
    /// The counts, as a JSON object whose members the profile names. Strings
    /// in it are the log's, raw: a caller that shows them escapes them.
    fn summary_value(&self) -> Value;
    /// The notes kept, in log order, each a JSON object with at least
    /// `index`, `kind` and `message` (terminal-safe).
    fn notes_values(&self) -> Vec<Value>;
}

/// A profile a log is read under (§5).
pub struct ProfileRow {
    /// The name a reader takes (`--profile`).
    pub name: &'static str,
    /// The profile.
    pub profile: &'static dyn EntryProfile,
    /// What reading under it checks of the entries themselves, beyond the
    /// core's shape and chain: the statement's words, so it never says more.
    pub checks: &'static str,
    /// The profile's pass over the accepted entries, when it has one.
    pub notes: Option<fn() -> Box<dyn ProfileNotes>>,
}

impl std::fmt::Debug for ProfileRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileRow").field("name", &self.name).field("notes", &self.notes.is_some()).finish()
    }
}

fn agent_notes() -> Box<dyn ProfileNotes> {
    Box::new(vmr_agent::notes::Notes::with_limit(NOTES_SHOWN))
}

/// The profiles a log is read under: the core (the default) and each named
/// profile this crate carries. A later profile is one row.
pub const PROFILES: [ProfileRow; 3] = [
    ProfileRow {
        name: "core",
        profile: &CORE,
        checks: "any kind the format's grammar allows, with any detail; nothing about what the entries mean is \
                 checked",
        notes: None,
    },
    ProfileRow {
        name: "khalm-vmr.enforcer",
        profile: &khalm_enforcer::PROFILE,
        checks: "each entry's kind and detail are checked against this profile's rules; not that what an entry \
                 records happened",
        notes: None,
    },
    ProfileRow {
        name: vmr_agent::NAME,
        profile: &vmr_agent::PROFILE,
        checks: "each entry's kind and detail are checked against this profile's rules; not that what an entry \
                 records happened",
        notes: Some(agent_notes),
    },
];

/// The row of the profile named `name`, if this build has it.
pub fn profile_row(name: &str) -> Option<&'static ProfileRow> {
    PROFILES.iter().find(|row| row.name == name)
}

/// A refusal of the log or of a checkpoint: the format's id (or a reader's
/// own) and a terminal-safe message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The stable id.
    pub id: &'static str,
    /// What was wrong, terminal-safe and at most [`MESSAGE_MAX_CHARS`]
    /// characters and an ellipsis.
    pub message: String,
}

impl Refusal {
    /// A refusal of this crate's; `subject`, when given, names (already
    /// terminal-safe) what the message is about.
    pub fn of(error: &Error, subject: Option<&str>) -> Refusal {
        // The message was made terminal-safe already: it is only bounded
        // here, never escaped twice.
        let (id, message) = match error {
            Error::Refused { id, message } => (*id, message.as_str()),
            Error::Io(message) => ("io", message.as_str()),
        };
        let mut cut: String = message.chars().take(MESSAGE_MAX_CHARS).collect();
        if message.chars().count() > MESSAGE_MAX_CHARS {
            cut.push('…');
        }
        let message = match subject {
            Some(subject) => format!("{subject}: {cut}"),
            None => cut,
        };
        Refusal { id, message }
    }
}

/// `1 entry`, `2 entries`.
fn plural(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `entry 4`, `entries 0 to 3`.
pub fn entries(first: u64, last: u64) -> String {
    if first == last {
        format!("entry {first}")
    } else {
        format!("entries {first} to {last}")
    }
}

/// A checkpoint that verified under the audit key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedCheckpoint {
    /// What the statements call it (a quoted file name, an argument's name),
    /// terminal-safe: the caller's.
    pub source: String,
    /// What it claims.
    pub claims: CheckpointClaims,
    /// Its `issued_at`, the writer's clock: a timestamp, as it verified.
    pub issued_at: Option<String>,
}

/// The refusal of a checkpoint of `size` bytes, over the format's cap (§6
/// check 1), which is never parsed (a caller that reads files reads at most
/// the cap and reports the size it saw).
pub fn checkpoint_too_large(source: &str, size: u64) -> Refusal {
    Refusal {
        id: "checkpoint.size",
        message: format!("checkpoint {source} is {size} bytes; the cap is {MAX_CHECKPOINT_BYTES}, and it was not read"),
    }
}

/// The `issued_at` of a checkpoint that verified.
fn issued_at(bytes: &[u8]) -> Option<String> {
    // The checkpoint verified, so its issued_at is a timestamp and no member
    // of it repeats.
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("issued_at").and_then(Value::as_str).map(str::to_string))
}

/// Verify one checkpoint's bytes under `key` (§6), named `source` in the
/// statements and in a refusal.
pub fn check_checkpoint(
    source: &str,
    bytes: &[u8],
    key: &p256::ecdsa::VerifyingKey,
) -> Result<CheckedCheckpoint, Refusal> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err(checkpoint_too_large(source, bytes.len() as u64));
    }
    match checkpoint::verify_checkpoint(bytes, key) {
        Ok(claims) => Ok(CheckedCheckpoint { source: source.to_string(), claims, issued_at: issued_at(bytes) }),
        Err(e) => Err(Refusal::of(&e, Some(&format!("checkpoint {source}")))),
    }
}

/// One line of a checkpoint history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryLine<'a> {
    /// Its bytes, without the line feed.
    Bytes(&'a [u8]),
    /// A line longer than [`MAX_CHECKPOINT_BYTES`]: its length.
    TooLong(u64),
}

/// The lines of a checkpoint history held in memory, as a reader of its file
/// reads them: split at each line feed, a last line without one is a line,
/// and no line follows a final line feed.
pub fn history_lines(bytes: &[u8]) -> impl Iterator<Item = HistoryLine<'_>> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let pieces = if bytes.is_empty() { None } else { Some(body.split(|&b| b == b'\n')) };
    pieces.into_iter().flatten().map(|line| {
        if line.len() > MAX_CHECKPOINT_BYTES {
            HistoryLine::TooLong(line.len() as u64)
        } else {
            HistoryLine::Bytes(line)
        }
    })
}

/// One checkpoint of a history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCheckpoint {
    /// Its line, from 1.
    pub line: u64,
    /// What it claims.
    pub claims: CheckpointClaims,
    /// Its `issued_at`, the writer's clock.
    pub issued_at: Option<String>,
}

/// A checkpoint history that verified line by line under the audit key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    /// What the statements call it, terminal-safe: the caller's.
    pub source: String,
    /// Its checkpoints, in order, each `tree_size` not smaller than the one
    /// before.
    pub checkpoints: Vec<HistoryCheckpoint>,
}

/// A checkpoint history, checked line by line as it is read: every line one
/// checkpoint (§6) under the audit key, each `tree_size` not smaller than
/// the line before it.
pub struct HistoryChecker<'k> {
    source: String,
    key: &'k p256::ecdsa::VerifyingKey,
    checkpoints: Vec<HistoryCheckpoint>,
    line_number: u64,
}

impl<'k> HistoryChecker<'k> {
    /// A history named `source`, checked under `key`, before its first line.
    pub fn new(source: &str, key: &'k p256::ecdsa::VerifyingKey) -> HistoryChecker<'k> {
        HistoryChecker { source: source.to_string(), key, checkpoints: Vec::new(), line_number: 0 }
    }

    /// Check the next line.
    pub fn line(&mut self, line: HistoryLine<'_>) -> Result<(), Refusal> {
        self.line_number += 1;
        let subject = format!("checkpoint {} line {}", self.source, self.line_number);
        let bytes = match line {
            HistoryLine::Bytes(bytes) => bytes,
            HistoryLine::TooLong(len) => {
                return Err(Refusal {
                    id: "checkpoint.size",
                    message: format!("{subject} is {len} bytes; the cap is {MAX_CHECKPOINT_BYTES}"),
                })
            }
        };
        let claims = checkpoint::verify_checkpoint(bytes, self.key).map_err(|e| Refusal::of(&e, Some(&subject)))?;
        if let Some(before) = self.checkpoints.last() {
            if claims.tree_size < before.claims.tree_size {
                return Err(Refusal {
                    id: CHECKPOINTS_OUT_OF_ORDER,
                    message: format!(
                        "{subject} has tree_size {}, smaller than the line before it ({})",
                        claims.tree_size, before.claims.tree_size
                    ),
                });
            }
        }
        self.checkpoints.push(HistoryCheckpoint { line: self.line_number, claims, issued_at: issued_at(bytes) });
        Ok(())
    }

    /// The history, or `None` when it held no line: an empty history is the
    /// caller's input error, not a refusal of the log.
    pub fn finish(self) -> Option<History> {
        if self.checkpoints.is_empty() {
            None
        } else {
            Some(History { source: self.source, checkpoints: self.checkpoints })
        }
    }
}

/// Why a log did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFailure {
    /// The log, or a checkpoint against it, was refused; `accepted` entries
    /// were read and accepted before it.
    Refused {
        /// The entries accepted before the refusal.
        accepted: u64,
        /// The refusal.
        refusal: Refusal,
    },
    /// A bug of this crate's (a root it should have kept): never a property
    /// of the input.
    Internal(String),
}

/// A log read as it arrives, under a profile, against checkpoints that
/// already verified under the audit key: the log is streamed through
/// [`LogReader`] (the memory of one line and the tree's frontier, plus the
/// profile's pass, within its caps, and the root at each checkpoint's size).
pub struct LogVerifier {
    row: &'static ProfileRow,
    reader: LogReader<'static>,
    sizes: BTreeSet<u64>,
    roots: BTreeMap<u64, String>,
    notes: Option<Box<dyn ProfileNotes>>,
    checkpoints: Vec<CheckedCheckpoint>,
    history: Option<History>,
    refused: Option<(u64, Refusal)>,
}

impl std::fmt::Debug for LogVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogVerifier")
            .field("profile", &self.row.name)
            .field("reader", &self.reader)
            .field("refused", &self.refused)
            .finish()
    }
}

impl LogVerifier {
    /// A verifier of a log under `row`, held to `checkpoints` and `history`,
    /// before the log's first byte.
    pub fn new(row: &'static ProfileRow, checkpoints: Vec<CheckedCheckpoint>, history: Option<History>) -> LogVerifier {
        let mut sizes: BTreeSet<u64> = checkpoints.iter().map(|cp| cp.claims.tree_size).collect();
        if let Some(history) = &history {
            sizes.extend(history.checkpoints.iter().map(|cp| cp.claims.tree_size));
        }
        LogVerifier {
            row,
            reader: LogReader::new(row.profile),
            sizes,
            roots: BTreeMap::new(),
            notes: row.notes.map(|make| make()),
            checkpoints,
            history,
            refused: None,
        }
    }

    /// The profile the log is read under.
    pub fn row(&self) -> &'static ProfileRow {
        self.row
    }

    /// Read the next bytes of the log. `false` once a line was refused: the
    /// rest of the log need not be read, and [`LogVerifier::finish`] gives
    /// the refusal.
    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        if self.refused.is_some() {
            return false;
        }
        match self.reader.feed(bytes) {
            Ok(entries) => {
                for entry in entries {
                    if let Some(notes) = self.notes.as_mut() {
                        notes.observe(&entry);
                    }
                    // Entry n's previous_root is the root over the first n
                    // entries, which the reader has just checked.
                    if self.sizes.contains(&entry.index) {
                        self.roots.insert(entry.index, entry.previous_root);
                    }
                }
                true
            }
            Err(e) => {
                self.refused = Some((self.reader.len(), Refusal::of(&e, None)));
                false
            }
        }
    }

    /// The end of the log: the log and each checkpoint against it (§6, its
    /// last paragraph), or why not.
    pub fn finish(self) -> Result<Verified, LogFailure> {
        if let Some((accepted, refusal)) = self.refused {
            return Err(LogFailure::Refused { accepted, refusal });
        }
        let accepted = self.reader.len();
        let frontier: MerkleFrontier =
            self.reader.finish().map_err(|e| LogFailure::Refused { accepted, refusal: Refusal::of(&e, None) })?;
        let size = frontier.size();
        let root = format_hash(&frontier.root());

        let given = self.checkpoints.iter().map(|cp| (cp.source.clone(), &cp.claims));
        let from_history = self.history.iter().flat_map(|h| {
            h.checkpoints.iter().map(move |cp| (format!("{} line {}", h.source, cp.line), &cp.claims))
        });
        for (source, claims) in given.chain(from_history) {
            let tree_size = claims.tree_size;
            if tree_size > size {
                return Err(LogFailure::Refused {
                    accepted: size,
                    refusal: Refusal {
                        id: CHECKPOINT_NOT_IN_LOG,
                        message: format!(
                            "checkpoint {source} covers {}; the log holds {size}",
                            plural(tree_size, "entry", "entries")
                        ),
                    },
                });
            }
            let log_root = if tree_size == size { Some(root.clone()) } else { self.roots.get(&tree_size).cloned() };
            let Some(log_root) = log_root else {
                return Err(LogFailure::Internal(format!("the root over the first {tree_size} entries was not kept")));
            };
            let same = matches!((parse_hash(&log_root), parse_hash(&claims.root_hash)), (Ok(a), Ok(b)) if a == b);
            if !same {
                return Err(LogFailure::Refused {
                    accepted: size,
                    refusal: Refusal {
                        id: CHECKPOINT_NOT_IN_LOG,
                        message: format!(
                            "checkpoint {source} covers {}, and the log's root over them, {log_root}, is not its \
                             root_hash {}",
                            plural(tree_size, "entry", "entries"),
                            display_safe(&claims.root_hash)
                        ),
                    },
                });
            }
        }
        Ok(Verified {
            row: self.row,
            entries: size,
            root,
            checkpoints: self.checkpoints,
            history: self.history,
            notes: self.notes,
        })
    }
}

/// A log that verified, with every checkpoint given.
pub struct Verified {
    /// The profile it was read under.
    pub row: &'static ProfileRow,
    /// Its entries.
    pub entries: u64,
    /// Its root over them, `sha256:` and hex.
    pub root: String,
    /// The checkpoints given one by one.
    pub checkpoints: Vec<CheckedCheckpoint>,
    /// The checkpoint history given.
    pub history: Option<History>,
    /// The profile's pass, when it has one.
    pub notes: Option<Box<dyn ProfileNotes>>,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("profile", &self.row.name)
            .field("entries", &self.entries)
            .field("root", &self.root)
            .field("checkpoints", &self.checkpoints)
            .field("history", &self.history)
            .finish()
    }
}

impl Verified {
    /// Whether any checkpoint was checked: else only the chain was.
    pub fn signed(&self) -> bool {
        !self.checkpoints.is_empty() || self.history.is_some()
    }

    fn history_checkpoints(&self) -> &[HistoryCheckpoint] {
        self.history.as_ref().map(|h| h.checkpoints.as_slice()).unwrap_or(&[])
    }

    /// How many checkpoints were checked.
    pub fn checkpoint_count(&self) -> u64 {
        (self.checkpoints.len() + self.history_checkpoints().len()) as u64
    }

    /// The entries the largest checkpoint covers (0 without one).
    pub fn covered(&self) -> u64 {
        self.checkpoints
            .iter()
            .map(|cp| cp.claims.tree_size)
            .chain(self.history_checkpoints().iter().map(|cp| cp.claims.tree_size))
            .max()
            .unwrap_or(0)
    }

    /// The first and last entry no checkpoint covers, if any: every entry
    /// when no checkpoint was given.
    pub fn uncovered(&self) -> Option<(u64, u64)> {
        let covered = self.covered();
        (covered < self.entries).then(|| (covered, self.entries - 1))
    }

    /// The result in one line, after "Audit log verified: ".
    pub fn headline(&self) -> String {
        let signatures = match self.checkpoint_count() {
            0 => "its chain only: no checkpoint was given, so no signature was checked".to_string(),
            n => format!(
                "{} signed by the pinned audit key {} {}",
                plural(n, "checkpoint", "checkpoints"),
                if n == 1 { "covers" } else { "cover" },
                entries(0, self.covered().saturating_sub(1))
            ),
        };
        format!("{}; {signatures}", plural(self.entries, "entry", "entries"))
    }

    /// The profile and what reading under it checks.
    pub fn profile_statement(&self) -> String {
        format!("{}: {}", self.row.name, self.row.checks)
    }

    /// What was checked of the lines, the chain and the signatures.
    pub fn checked_statement(&self) -> String {
        format!(
            "every line an entry of the audit-log format v0.1, canonical and in its place; the chain (each entry \
             names the root of the entries before it); {}",
            if self.signed() {
                "each checkpoint's signature under the pinned audit key, and its root against the log"
            } else {
                "no signature was checked"
            }
        )
    }

    /// The entries and their root.
    pub fn entries_statement(&self) -> String {
        format!("{}, root {}", self.entries, self.root)
    }

    /// The lines about the checkpoints, after the audit key's: none given,
    /// each one given, the history, and the entries none covers.
    pub fn checkpoint_statements(&self) -> Vec<(&'static str, String)> {
        let mut lines = Vec::new();
        if !self.signed() {
            lines.push((
                "Checkpoints",
                "none given: no signature was checked, and the chain shows only that the lines agree with one \
                 another, not who wrote them"
                    .to_string(),
            ));
        }
        for cp in &self.checkpoints {
            let tree_size = cp.claims.tree_size;
            let whole = if tree_size == self.entries { ", the whole log" } else { "" };
            let issued = cp
                .issued_at
                .as_deref()
                .map(|t| format!(", issued at {} (the writer's clock)", display_safe(t)))
                .unwrap_or_default();
            lines.push((
                "Checkpoint",
                format!(
                    "{}: tree_size {tree_size}{issued}; signed by the audit key; covers {}{whole}: the log's root \
                     over them is its root_hash",
                    cp.source,
                    entries(0, tree_size.saturating_sub(1))
                ),
            ));
        }
        if let Some(history) = &self.history {
            let first = history.checkpoints.first().map_or(0, |cp| cp.claims.tree_size);
            let last = history.checkpoints.last().map_or(0, |cp| cp.claims.tree_size);
            lines.push((
                "History",
                format!(
                    "{}: {}, in order, tree_size {first} to {last}; each signed by the audit key, and each root \
                     against the log",
                    history.source,
                    plural(history.checkpoints.len() as u64, "checkpoint", "checkpoints"),
                ),
            ));
        }
        if self.signed() {
            if let Some((first, last)) = self.uncovered() {
                let verb = if first == last { "is" } else { "are" };
                lines.push((
                    "Not covered",
                    format!(
                        "{} {verb} in no checkpoint given: the chain links them, and no signature covers them",
                        entries(first, last)
                    ),
                ));
            }
        }
        lines
    }

    /// Every checkpoint checked, as `(source, tree_size, issued_at)`: those
    /// given one by one, then the history's lines.
    pub fn all_checkpoints(&self) -> Vec<(String, u64, Option<String>)> {
        let given = self.checkpoints.iter().map(|cp| (cp.source.clone(), cp.claims.tree_size, cp.issued_at.clone()));
        let history = self.history.iter().flat_map(|h| {
            h.checkpoints
                .iter()
                .map(move |cp| (format!("{} line {}", h.source, cp.line), cp.claims.tree_size, cp.issued_at.clone()))
        });
        given.chain(history).collect()
    }
}

// ---------------------------------------------------------------------------
//  The vmr.agent profile's pass
// ---------------------------------------------------------------------------

impl ProfileNotes for vmr_agent::notes::Notes {
    fn observe(&mut self, entry: &AuditEntry) {
        vmr_agent::notes::Notes::observe(self, entry);
    }

    fn lines(&self) -> Vec<(&'static str, String)> {
        let said = self.summary();
        let refused = said.calls_refused();
        let calls = if refused == 0 {
            format!("{} proposed; none refused", said.calls)
        } else {
            // Gate names are the profile's gate type: lower case and `_` only,
            // at most 64 characters; at most GATES_SHOWN are named.
            let mut by_gate: Vec<String> =
                said.refused_by_gate.iter().take(GATES_SHOWN).map(|(gate, n)| format!("{n} by {gate}")).collect();
            let others = said
                .refused_by_gate
                .values()
                .skip(GATES_SHOWN)
                .fold(said.refused_by_other_gates, |sum, n| sum.saturating_add(*n));
            if others > 0 {
                by_gate.push(format!("and {others} by other gates"));
            }
            format!("{} proposed; {refused} refused: {}", said.calls, by_gate.join(", "))
        };
        let mut lines = vec![
            ("Sessions", said.sessions.to_string()),
            ("Calls", calls),
            (
                "Approvals",
                format!(
                    "{} granted, {} denied, {} timed out",
                    said.approvals_granted, said.approvals_denied, said.approvals_timed_out
                ),
            ),
        ];
        if said.events_dropped > 0 {
            lines.push((
                "Lost events",
                format!(
                    "{} the writer says it could not record (events.dropped): the log is incomplete",
                    said.events_dropped
                ),
            ));
        }
        if said.recoveries > 0 {
            let tails = plural(said.recoveries, "torn tail", "torn tails");
            lines.push(("Recovered", format!("{tails} the writer moved aside (log.recovered)")));
        }
        let total = self.total();
        lines.push((
            "Notes",
            if total == 0 {
                "none, of the checks made: a tool proposed by name that its session could not reach, a call \
                 proposed twice, a call's entry before its call.proposed or after its call.refused, an entry after \
                 its session's session.ended, and an approval gate's decision with no person's answer before it or \
                 against that answer"
                    .to_string()
            } else {
                format!(
                    "{total}: where the entries break the profile's rules between entries; a note does not change \
                     the result"
                )
            },
        ));
        for note in self.notes() {
            lines.push(("Note", note.message.clone()));
        }
        let shown = self.notes().len() as u64;
        if total > shown {
            lines.push(("Not shown", plural(total - shown, "more note", "more notes")));
        }
        if let Some(index) = self.untracked_from() {
            let (sessions, items) = self.bounds();
            lines.push((
                "Not tracked",
                format!(
                    "the entries from entry {index} on: past {sessions} sessions or {items} calls and tools held, \
                     the pass stopped; the counts and notes above cover the entries before it, except lost events \
                     and recoveries, counted over the whole log"
                ),
            ));
        }
        lines
    }

    fn summary_value(&self) -> Value {
        let said = self.summary();
        let by_gate: Map<String, Value> =
            said.refused_by_gate.iter().map(|(gate, n)| (gate.clone(), Value::from(*n))).collect();
        json!({
            "sessions": said.sessions,
            "calls_proposed": said.calls,
            "calls_refused": said.calls_refused(),
            "refused_by_gate": by_gate,
            "refused_by_other_gates": said.refused_by_other_gates,
            "approvals_granted": said.approvals_granted,
            "approvals_denied": said.approvals_denied,
            "approvals_timed_out": said.approvals_timed_out,
            "events_dropped": said.events_dropped,
            "recoveries": said.recoveries,
            "notes_total": self.total(),
            "notes_shown": self.notes().len(),
            "untracked_from": self.untracked_from(),
        })
    }

    fn notes_values(&self) -> Vec<Value> {
        self.notes()
            .iter()
            .map(|note| {
                json!({
                    "index": note.index,
                    "kind": note_kind(note.kind),
                    "session_id": note.session_id,
                    "call": note.call,
                    "message": note.message,
                })
            })
            .collect()
    }
}

/// A note's kind as a word.
fn note_kind(kind: vmr_agent::notes::NoteKind) -> &'static str {
    use vmr_agent::notes::NoteKind;
    match kind {
        NoteKind::UnreachableTool => "unreachable_tool",
        NoteKind::ProposedTwice => "proposed_twice",
        NoteKind::NotProposed => "not_proposed",
        NoteKind::AfterRefusal => "after_refusal",
        NoteKind::UnansweredApproval => "unanswered_approval",
        NoteKind::ApprovalAgainstAnswer => "approval_against_answer",
        NoteKind::AfterSessionEnded => "after_session_ended",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogBuilder;
    use vmr_record::jwk::key_id;
    use vmr_record::timestamp::Timestamp;

    fn key(label: &str) -> p256::ecdsa::SigningKey {
        vmr_record::sign::signing_key_from_secret(&vmr_record::hash::sha256(label.as_bytes())).unwrap()
    }

    const AUDIT: &str = "vmr-audit-log verify tests: the audit key (test-only)";
    const OTHER: &str = "vmr-audit-log verify tests: another key (test-only)";

    fn at() -> Timestamp {
        Timestamp::parse("2026-09-30T09:00:00Z").unwrap()
    }

    /// A core log of `n` entries, and its bytes.
    fn log(n: u64) -> (LogBuilder, Vec<u8>) {
        let mut log = LogBuilder::new(key_id(key(AUDIT).verifying_key()));
        let mut file = Vec::new();
        for i in 0..n {
            let entry = log.append(at(), "test.tick", json!({ "n": i }), &CORE).unwrap();
            file.extend_from_slice(entry.canonical.as_bytes());
            file.push(b'\n');
        }
        (log, file)
    }

    fn checkpoint_bytes(log: &LogBuilder, size: u64, label: &str) -> Vec<u8> {
        let signer = key(label);
        let root = log.root_at(size).unwrap();
        let doc = checkpoint::build_signed(&key_id(signer.verifying_key()), size, &root, at(), &signer).unwrap();
        vmr_record::canonical::jcs(&doc).into_bytes()
    }

    fn row(name: &str) -> &'static ProfileRow {
        profile_row(name).unwrap()
    }

    fn verify(name: &str, cps: Vec<CheckedCheckpoint>, bytes: &[u8], chunk: usize) -> Result<Verified, LogFailure> {
        let mut v = LogVerifier::new(row(name), cps, None);
        for piece in bytes.chunks(chunk.max(1)) {
            v.feed(piece);
        }
        v.finish()
    }

    #[test]
    fn the_table_holds_the_three_profiles_and_nothing_else() {
        let names: Vec<&str> = PROFILES.iter().map(|r| r.name).collect();
        assert_eq!(names, ["core", "khalm-vmr.enforcer", "vmr.agent"]);
        assert!(profile_row("acme.other").is_none());
        assert!(row("core").checks.contains("nothing about what the entries mean is checked"));
        assert!(row("vmr.agent").notes.is_some());
    }

    #[test]
    fn without_a_checkpoint_only_the_chain_is_checked_and_the_statements_say_so() {
        let (_, bytes) = log(3);
        let v = verify("core", Vec::new(), &bytes, 1).unwrap();
        assert!(!v.signed());
        assert_eq!(v.entries, 3);
        assert_eq!(v.headline(), "3 entries; its chain only: no checkpoint was given, so no signature was checked");
        assert!(v.checked_statement().ends_with("no signature was checked"));
        assert!(v.profile_statement().contains("nothing about what the entries mean is checked"));
        assert_eq!(v.uncovered(), Some((0, 2)));
        let lines = v.checkpoint_statements();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "Checkpoints");
        assert!(v.notes.is_none());
    }

    #[test]
    fn a_checkpoint_is_held_to_the_log_and_the_rest_is_uncovered() {
        let (builder, bytes) = log(5);
        let audit = key(AUDIT);
        let cp = check_checkpoint("'cp'", &checkpoint_bytes(&builder, 3, AUDIT), audit.verifying_key()).unwrap();
        assert_eq!(cp.issued_at.as_deref(), Some("2026-09-30T09:00:00Z"));
        for chunk in [1, 7, 1 << 20] {
            let v = verify("core", vec![cp.clone()], &bytes, chunk).unwrap();
            assert!(v.signed());
            assert_eq!(v.covered(), 3);
            assert_eq!(v.uncovered(), Some((3, 4)));
            assert_eq!(v.headline(), "5 entries; 1 checkpoint signed by the pinned audit key covers entries 0 to 2");
            let lines = v.checkpoint_statements();
            assert_eq!(lines.last().unwrap().0, "Not covered");
            assert_eq!(v.all_checkpoints(), vec![("'cp'".to_string(), 3, Some("2026-09-30T09:00:00Z".to_string()))]);
        }
        // A log shorter than the checkpoint, and a log whose root differs.
        let (_, short) = log(2);
        match verify("core", vec![cp.clone()], &short, 4) {
            Err(LogFailure::Refused { accepted: 2, refusal }) => assert_eq!(refusal.id, CHECKPOINT_NOT_IN_LOG),
            other => panic!("{other:?}"),
        }
        let mut other_builder = LogBuilder::new(key_id(audit.verifying_key()));
        let mut changed = Vec::new();
        for i in 0..5u64 {
            let entry = other_builder.append(at(), "test.tock", json!({ "n": i }), &CORE).unwrap();
            changed.extend_from_slice(entry.canonical.as_bytes());
            changed.push(b'\n');
        }
        match verify("core", vec![cp], &changed, 64) {
            Err(LogFailure::Refused { accepted: 5, refusal }) => {
                assert_eq!(refusal.id, CHECKPOINT_NOT_IN_LOG);
                assert!(refusal.message.contains("is not its root_hash"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_checkpoint_under_another_key_or_too_large_is_refused() {
        let (builder, _) = log(2);
        let audit = key(AUDIT);
        let refused = check_checkpoint("'cp'", &checkpoint_bytes(&builder, 2, OTHER), audit.verifying_key()).unwrap_err();
        assert_eq!(refused.id, "checkpoint.wrong_key");
        assert!(refused.message.starts_with("checkpoint 'cp': "));
        let big = vec![b' '; MAX_CHECKPOINT_BYTES + 1];
        assert_eq!(check_checkpoint("'cp'", &big, audit.verifying_key()).unwrap_err().id, "checkpoint.size");
    }

    #[test]
    fn a_refused_line_stops_the_read_and_names_what_was_accepted() {
        let (_, mut bytes) = log(4);
        // Break the third line's index.
        let third = bytes.split(|&b| b == b'\n').take(2).map(|l| l.len() + 1).sum::<usize>();
        let pos = bytes[third..].windows(9).position(|w| w == b"\"index\":2").unwrap() + third;
        bytes[pos + 8] = b'3';
        let mut v = LogVerifier::new(row("core"), Vec::new(), None);
        assert!(!v.feed(&bytes));
        assert!(!v.feed(b"anything"));
        match v.finish() {
            Err(LogFailure::Refused { accepted: 2, refusal }) => assert_eq!(refusal.id, "audit_log.index"),
            other => panic!("{other:?}"),
        }
        // A torn tail is known only at the end.
        let (_, whole) = log(2);
        let torn = &whole[..whole.len() - 1];
        match verify("core", Vec::new(), torn, 3) {
            Err(LogFailure::Refused { accepted: 1, refusal }) => assert_eq!(refusal.id, "audit_log.torn_tail"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_history_is_read_line_by_line_in_order() {
        let (builder, bytes) = log(4);
        let audit = key(AUDIT);
        let mut jsonl = Vec::new();
        for size in [1, 3] {
            jsonl.extend_from_slice(&checkpoint_bytes(&builder, size, AUDIT));
            jsonl.push(b'\n');
        }
        let mut h = HistoryChecker::new("'h'", audit.verifying_key());
        for line in history_lines(&jsonl) {
            h.line(line).unwrap();
        }
        let history = h.finish().unwrap();
        assert_eq!(history.checkpoints.iter().map(|c| c.line).collect::<Vec<_>>(), [1, 2]);
        let mut v = LogVerifier::new(row("core"), Vec::new(), Some(history));
        v.feed(&bytes);
        let v = v.finish().unwrap();
        assert_eq!(v.covered(), 3);
        let history_line = v.checkpoint_statements().into_iter().find(|(l, _)| *l == "History").unwrap();
        assert!(history_line.1.starts_with("'h': 2 checkpoints, in order, tree_size 1 to 3"));

        // Out of order.
        let mut backwards = checkpoint_bytes(&builder, 3, AUDIT);
        backwards.push(b'\n');
        backwards.extend_from_slice(&checkpoint_bytes(&builder, 1, AUDIT));
        let mut h = HistoryChecker::new("'h'", audit.verifying_key());
        let ids: Vec<_> = history_lines(&backwards).map(|line| h.line(line).err().map(|r| r.id)).collect();
        assert_eq!(ids, [None, Some(CHECKPOINTS_OUT_OF_ORDER)]);

        // Empty, and no line after a final line feed; an empty line is a line.
        assert_eq!(history_lines(b"").count(), 0);
        assert_eq!(history_lines(b"a\n").count(), 1);
        assert_eq!(history_lines(b"a\n\nb").count(), 3);
        assert!(HistoryChecker::new("'h'", audit.verifying_key()).finish().is_none());
        let long = vec![b'x'; MAX_CHECKPOINT_BYTES + 1];
        assert_eq!(history_lines(&long).next(), Some(HistoryLine::TooLong(long.len() as u64)));
    }

    #[test]
    fn the_example_agent_log_verifies_with_the_writers_statements() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/examples/agent-log");
        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        let file: Value = serde_json::from_slice(&read("audit-key.pub.json")).unwrap();
        let jwk: vmr_record::record::JwkPublicKey = serde_json::from_value(file["public_key"].clone()).unwrap();
        let audit = jwk.to_verifying_key().unwrap();
        let cp = check_checkpoint("'checkpoint.json'", &read("checkpoint.json"), &audit).unwrap();
        let v = verify("vmr.agent", vec![cp], &read("log.jsonl"), 7).unwrap();
        assert_eq!(v.headline(), "14 entries; 1 checkpoint signed by the pinned audit key covers entries 0 to 13");
        assert_eq!(v.uncovered(), None);
        let notes = v.notes.as_ref().unwrap();
        let summary = notes.summary_value();
        assert_eq!(summary["sessions"], 1);
        assert_eq!(summary["calls_proposed"], 2);
        assert_eq!(summary["calls_refused"], 1);
        assert_eq!(summary["refused_by_gate"], json!({ "guard": 1 }));
        assert_eq!(summary["approvals_granted"], 1);
        assert_eq!(summary["notes_total"], 0);
        assert!(notes.notes_values().is_empty());
        let lines = notes.lines();
        assert_eq!(lines[1], ("Calls", "2 proposed; 1 refused: 1 by guard".to_string()));
    }

    #[test]
    fn a_disclosed_item_is_found_and_checked_without_the_secret() {
        use crate::log::{EntryFinder, Found};
        use crate::profiles::vmr_agent::digest::{check_item, ItemKey};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/examples/agent-log");
        let log = std::fs::read(dir.join("log.jsonl")).unwrap();
        // The example README's disclosure.
        let hex = "11200c6264981efb8fbbdcd4e3ce185d1db9dcda617e774843dff5c578b0cd3d";
        let item_key = ItemKey::from_hex(hex).unwrap();
        assert_eq!(ItemKey::from_hex(&hex.to_uppercase()).unwrap().as_bytes(), item_key.as_bytes());
        assert!(ItemKey::from_hex("11zz").is_none());
        assert!(ItemKey::from_hex(&"g".repeat(64)).is_none());
        let find = |index: u64, chunk: usize, log: &[u8]| {
            let mut finder = EntryFinder::new(&CORE, index);
            for piece in log.chunks(chunk) {
                if finder.feed(piece) {
                    break;
                }
            }
            finder.finish()
        };
        let Found::Entry(entry) = find(4, 7, &log) else { panic!("entry 4") };
        let content = br#"{"city": "Oslo", "day": "tomorrow"}"#;
        let check = check_item(&entry, "arguments_digest", &item_key, content).unwrap();
        assert!(check.matches);
        assert_eq!(check.label, "call.proposed/arguments_digest/4");
        assert!(!check_item(&entry, "arguments_digest", &item_key, br#"{"city": "Oslo", "day": "today"}"#).unwrap().matches);
        assert!(check_item(&entry, "nope", &item_key, content).is_none());
        assert_eq!(find(99, 1 << 20, &log), Found::Missing { held: 14 });
        let mut changed = log.clone();
        let at = changed.windows(9).position(|w| w == b"\"index\":2").unwrap();
        changed[at + 8] = b'3';
        assert!(matches!(find(4, 3, &changed), Found::Refused(e) if e.id() == "audit_log.index"));
    }
}
