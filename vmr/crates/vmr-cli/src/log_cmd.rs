//! `vmr log verify` — read an audit log, and check its checkpoints under a
//! pinned audit key.
// ============================================================================
//  log_cmd.rs — the Community tool's reader of an audit log
//  (specs/audit-log-format-v0.1.md)
//
//  Orchestration, like the rest of the CLI: every rule is vmr-audit-log's.
//  The log is read with its streaming reader as it comes off the disk, one
//  piece at a time: the reader holds one line and the tree's frontier, so
//  under a profile without notes a log of any length is checked in the memory
//  of one line. A profile's notes pass holds more (vmr.agent's: its open
//  sessions' calls and tools), within caps it states; each checkpoint is verified by the format's own checks (§6) under
//  the audit key the operator pins, then held to the log (§6, its last
//  paragraph).
//
//  What it reports is what it checked, and no more (§5.1, a MUST): under the
//  core profile nothing about what an entry means is checked, and the output
//  says so; without a checkpoint no signature is checked, and the output says
//  that too. No profile makes an entry true: a log is its writer's statement,
//  and a checkpoint's signature binds the writer's key to it.
//
//  Whose log it is does not matter here. The profiles are a table: the core,
//  and each named profile the format crate carries; a later profile is one
//  row, and nothing else in this module changes.
//
//  A profile may also say what its accepted entries record across one
//  another (the vmr.agent profile's notes: specs/audit-profile-agent-v0.1.md
//  §4.6, its last paragraph). That is printed after the integrity result and
//  labelled as the writer's statements, never as a verified fact, and it
//  never changes the exit code.
// ============================================================================

use crate::cli::LogVerifyArgs;
use crate::error::{CliError, EXIT_VERIFICATION_FAILED};
use crate::files::{self, shown, ReadError};
use crate::keys;
use crate::output::Output;
use crate::render::{plural, shown_value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use vmr_audit_log::checkpoint::{self, CheckpointClaims};
use vmr_audit_log::entry::AuditEntry;
use vmr_audit_log::log::LogReader;
use vmr_audit_log::profile::{EntryProfile, CORE};
use vmr_audit_log::profiles::{khalm_enforcer, vmr_agent};
use vmr_audit_log::tree::MerkleFrontier;
use vmr_audit_log::MAX_CHECKPOINT_BYTES;
use vmr_record::hash::{format_hash, parse_hash};

/// This command's own refusal: a checkpoint that verified under the audit
/// key is not of the log given. The format asks for the check (§6, its last
/// paragraph: the log holds at least `tree_size` entries, and its root over
/// them is `root_hash`) and names no id for it; this one is the command's,
/// as `pack_sign.already_signed` is `pack sign`'s.
pub const CHECKPOINT_NOT_IN_LOG: &str = "log_verify.checkpoint_not_in_log";

/// This command's own refusal: a checkpoint history (`--checkpoints`) whose
/// checkpoints are not in order, a line's `tree_size` smaller than the line
/// before it. A writer's history only grows (§6: a checkpoint states the
/// log's size, and the log is append only).
pub const CHECKPOINTS_OUT_OF_ORDER: &str = "log_verify.checkpoints_out_of_order";

/// How much of the log is read at a time.
const READ_PIECE: usize = 1024 * 1024;

/// The longest refusal message shown, in characters.
const MESSAGE_MAX_CHARS: usize = 400;

/// A profile `log verify` reads a log under (§5).
pub struct ProfileRow {
    /// The name `--profile` takes.
    pub name: &'static str,
    /// The profile.
    pub profile: &'static dyn EntryProfile,
    /// What reading under it checks of the entries themselves, beyond the
    /// core's shape and chain: the output's words, so it never says more.
    pub checks: &'static str,
    /// The profile's pass over the accepted entries, when it has one: what
    /// they record across one another, printed after the integrity result.
    pub notes: Option<fn() -> Box<dyn ProfileNotes>>,
}

/// A profile's pass over a log's accepted entries, in order: what they
/// record across one another. The rules between entries are the writer's
/// (a reader reports where a log breaks them and never refuses it), so its
/// lines are the writer's statements, not verified facts.
pub trait ProfileNotes {
    /// Take in the next accepted entry.
    fn observe(&mut self, entry: &AuditEntry);
    /// The lines printed after the integrity result: a label and a value.
    fn lines(&self) -> Vec<(&'static str, String)>;
}

/// How many notes the output shows; the others are counted.
pub const NOTES_SHOWN: usize = 20;

/// How many gates the "Calls" line names; the refusals of the others are
/// summed.
pub const GATES_SHOWN: usize = 8;

fn agent_notes() -> Box<dyn ProfileNotes> {
    Box::new(vmr_agent::notes::Notes::with_limit(NOTES_SHOWN))
}

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
}

/// The profiles this build reads a log under: the core (the default) and each
/// named profile the format crate carries. A later profile is one row.
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

/// A refusal of the log or of a checkpoint: the format's id (or this
/// command's) and a terminal-safe message.
struct Refusal {
    id: &'static str,
    message: String,
}

impl Refusal {
    /// A refusal of the format crate's; `subject`, when given, names the file
    /// (already shown) the message is about.
    fn of(error: &vmr_audit_log::Error, subject: Option<&str>) -> Refusal {
        // The format crate made its message terminal-safe already: it is only
        // bounded here, never escaped twice.
        let (id, message) = match error {
            vmr_audit_log::Error::Refused { id, message } => (*id, message.as_str()),
            vmr_audit_log::Error::Io(message) => ("io", message.as_str()),
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

/// A checkpoint that verified under the audit key.
struct Checked {
    file: String,
    claims: CheckpointClaims,
    issued_at: Option<String>,
}

/// Run `log verify`.
pub fn verify(args: &LogVerifyArgs) -> Result<Output, CliError> {
    let row = PROFILES
        .iter()
        .find(|row| row.name == args.profile)
        .ok_or_else(|| CliError::internal(format!("--profile {} is not in the profile table", shown_value(&args.profile))))?;
    let mut report = Report::new(&args.log, row);

    // The pinned audit key: an operator's input, so a bad file is exit 1.
    let key = match &args.audit_key {
        None => None,
        Some(path) => {
            let file = keys::read_public_key_file(path)?;
            let key = file
                .public_key
                .to_verifying_key()
                .map_err(|e| CliError::internal(format!("a checked public key file does not load: {e}")))?;
            report.audit_key = Some(format!("{}, pinned from {}", shown_value(&file.key_id), shown(path)));
            Some(key)
        }
    };

    // Every checkpoint under that key first (§6): they are small, and their
    // sizes say which roots to keep while the log streams past.
    let mut checked: Vec<Checked> = Vec::new();
    for path in &args.checkpoints {
        let Some(key) = &key else {
            return Err(CliError::internal("a checkpoint was given without --audit-key"));
        };
        match check_checkpoint(path, key)? {
            Ok(cp) => checked.push(cp),
            Err(refusal) => return Ok(report.refused(&refusal, None)),
        }
    }

    // A checkpoint history: every line checked as one --checkpoint is, in
    // order, each tree_size not smaller than the one before.
    let history = match (&args.checkpoint_history, &key) {
        (None, _) => None,
        (Some(path), Some(key)) => match check_history(path, key)? {
            Ok(history) => Some(history),
            Err(refusal) => return Ok(report.refused(&refusal, None)),
        },
        (Some(_), None) => return Err(CliError::internal("--checkpoints was given without --audit-key")),
    };

    let mut sizes: BTreeSet<u64> = checked.iter().map(|cp| cp.claims.tree_size).collect();
    if let Some(history) = &history {
        sizes.extend(history.checkpoints.iter().map(|(size, _, _)| *size));
    }
    let mut notes = row.notes.map(|make| make());
    let (frontier, roots) = match read_log(&args.log, row.profile, &sizes, notes.as_deref_mut())? {
        Ok(read) => read,
        Err((accepted, refusal)) => return Ok(report.refused(&refusal, Some(accepted))),
    };
    let size = frontier.size();

    // Each checkpoint against the log (§6, its last paragraph).
    let given = checked.iter().map(|cp| (cp.file.clone(), cp.claims.tree_size, cp.claims.root_hash.as_str()));
    let from_history = history.iter().flat_map(|h| {
        h.checkpoints.iter().map(move |(tree_size, root_hash, line)| (format!("{} line {line}", h.file), *tree_size, root_hash.as_str()))
    });
    for (file, tree_size, root_hash) in given.chain(from_history) {
        if tree_size > size {
            let refusal = Refusal {
                id: CHECKPOINT_NOT_IN_LOG,
                message: format!("checkpoint {file} covers {}; the log holds {size}", plural(tree_size, "entry", "entries")),
            };
            return Ok(report.refused(&refusal, Some(size)));
        }
        let log_root = if tree_size == size { Some(format_hash(&frontier.root())) } else { roots.get(&tree_size).cloned() };
        let Some(log_root) = log_root else {
            return Err(CliError::internal(format!("the root over the first {tree_size} entries was not kept")));
        };
        let same = matches!((parse_hash(&log_root), parse_hash(root_hash)), (Ok(a), Ok(b)) if a == b);
        if !same {
            let refusal = Refusal {
                id: CHECKPOINT_NOT_IN_LOG,
                message: format!(
                    "checkpoint {file} covers {}, and the log's root over them, {log_root}, is not its root_hash {}",
                    plural(tree_size, "entry", "entries"),
                    shown_value(root_hash)
                ),
            };
            return Ok(report.refused(&refusal, Some(size)));
        }
    }

    let mut out = report.verified(size, &format_hash(&frontier.root()), &checked, history.as_ref());
    if let Some(notes) = &notes {
        Report::said(&mut out, &notes.lines());
    }
    Ok(Output::ok(out))
}

/// Read and verify one checkpoint under `key`: `Ok(Err(..))` is a refusal
/// (exit 3), `Err` a file that could not be read (exit 1).
fn check_checkpoint(path: &Path, key: &p256::ecdsa::VerifyingKey) -> Result<Result<Checked, Refusal>, CliError> {
    let file = shown(path);
    // At most the format's size is read (§6 check 1): a larger file is
    // refused for its size and never parsed.
    let bytes = match files::read_bounded(path, MAX_CHECKPOINT_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge(size)) => {
            return Ok(Err(Refusal {
                id: "checkpoint.size",
                message: format!(
                    "checkpoint {file} is {size} bytes; the cap is {MAX_CHECKPOINT_BYTES}, and it was not read"
                ),
            }))
        }
        Err(ReadError::Io(e)) => return Err(CliError::input(format!("cannot read checkpoint {file}: {e}"))),
    };
    match checkpoint::verify_checkpoint(&bytes, key) {
        Ok(claims) => {
            // The checkpoint verified, so its issued_at is a timestamp and no
            // member of it repeats.
            let issued_at = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("issued_at").and_then(serde_json::Value::as_str).map(shown_value));
            Ok(Ok(Checked { file, claims, issued_at }))
        }
        Err(e) => Ok(Err(Refusal::of(&e, Some(&format!("checkpoint {file}"))))),
    }
}

/// A checkpoint history that verified line by line under the audit key.
struct History {
    file: String,
    /// Each line's tree_size, root_hash and line number (from 1), in order.
    checkpoints: Vec<(u64, String, u64)>,
}

/// Read and verify a checkpoint history under `key`: every line one
/// checkpoint (§6), each tree_size not smaller than the line before it.
/// `Ok(Err(..))` is a refusal (exit 3), `Err` a file that could not be read or
/// that holds no checkpoint (exit 1).
fn check_history(path: &Path, key: &p256::ecdsa::VerifyingKey) -> Result<Result<History, Refusal>, CliError> {
    let file = shown(path);
    let cannot = |e: std::io::Error| CliError::input(format!("cannot read checkpoint history {file}: {e}"));
    let mut input = std::io::BufReader::new(std::fs::File::open(path).map_err(cannot)?);
    let mut checkpoints: Vec<(u64, String, u64)> = Vec::new();
    let mut line_number = 0u64;
    while let Some(line) = crate::log_seal::read_line(&mut input, MAX_CHECKPOINT_BYTES).map_err(cannot)? {
        line_number += 1;
        let subject = format!("checkpoint {file} line {line_number}");
        let bytes = match line {
            crate::log_seal::Line::Bytes(bytes) => bytes,
            crate::log_seal::Line::TooLong(len) => {
                return Ok(Err(Refusal {
                    id: "checkpoint.size",
                    message: format!("{subject} is {len} bytes; the cap is {MAX_CHECKPOINT_BYTES}"),
                }))
            }
        };
        let claims = match checkpoint::verify_checkpoint(&bytes, key) {
            Ok(claims) => claims,
            Err(e) => return Ok(Err(Refusal::of(&e, Some(&subject)))),
        };
        if let Some((before, _, _)) = checkpoints.last() {
            if claims.tree_size < *before {
                return Ok(Err(Refusal {
                    id: CHECKPOINTS_OUT_OF_ORDER,
                    message: format!(
                        "{subject} has tree_size {}, smaller than the line before it ({before})",
                        claims.tree_size
                    ),
                }));
            }
        }
        checkpoints.push((claims.tree_size, claims.root_hash, line_number));
    }
    if checkpoints.is_empty() {
        return Err(CliError::input(format!("checkpoint history {file} holds no checkpoint")));
    }
    Ok(Ok(History { file, checkpoints }))
}

/// What reading a log gives: its tree and the root over each prefix a
/// checkpoint names, or the entries accepted before a refusal and the refusal.
type LogRead = Result<(MerkleFrontier, BTreeMap<u64, String>), (u64, Refusal)>;

/// Stream the log at `path` through the format's reader, keeping the root
/// over the first `n` entries for each `n` of `sizes`: entry `n`'s
/// `previous_root`, which the reader has just checked is that root.
fn read_log(
    path: &Path,
    profile: &dyn EntryProfile,
    sizes: &BTreeSet<u64>,
    mut notes: Option<&mut (dyn ProfileNotes + 'static)>,
) -> Result<LogRead, CliError> {
    let cannot = |e: std::io::Error| CliError::input(format!("cannot read audit log {}: {e}", shown(path)));
    let mut file = std::fs::File::open(path).map_err(cannot)?;
    let mut reader = LogReader::new(profile);
    let mut roots = BTreeMap::new();
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
                for entry in entries {
                    if let Some(notes) = notes.as_mut() {
                        notes.observe(&entry);
                    }
                    if sizes.contains(&entry.index) {
                        roots.insert(entry.index, entry.previous_root);
                    }
                }
            }
            Err(e) => return Ok(Err((reader.len(), Refusal::of(&e, None)))),
        }
    }
    let accepted = reader.len();
    Ok(match reader.finish() {
        Ok(frontier) => Ok((frontier, roots)),
        Err(e) => Err((accepted, Refusal::of(&e, None))),
    })
}

/// `entry 4`, `entries 0 to 3`.
fn entries(first: u64, last: u64) -> String {
    if first == last {
        format!("entry {first}")
    } else {
        format!("entries {first} to {last}")
    }
}

/// The report's lines, built as the checks run.
struct Report {
    log: String,
    profile: String,
    audit_key: Option<String>,
}

impl Report {
    fn new(log: &Path, row: &ProfileRow) -> Report {
        Report { log: shown(log), profile: format!("{}: {}", row.name, row.checks), audit_key: None }
    }

    fn line(out: &mut String, label: &str, value: &str) {
        out.push_str(&format!("  {:<14}{value}\n", format!("{label}:")));
    }

    fn head(&self, out: &mut String) {
        Self::line(out, "Log", &self.log);
        Self::line(out, "Profile", &self.profile);
    }

    /// The output of a refusal: exit 3. `accepted` is how many entries were
    /// read and accepted, when the log was read.
    fn refused(&self, refusal: &Refusal, accepted: Option<u64>) -> Output {
        let mut out = format!("Audit log NOT verified: {}: {}\n", refusal.id, refusal.message);
        self.head(&mut out);
        let entries = match accepted {
            None => "not read: a checkpoint was refused first".to_string(),
            Some(n) => format!("{} accepted before the refusal", plural(n, "entry", "entries")),
        };
        Self::line(&mut out, "Entries", &entries);
        if let Some(key) = &self.audit_key {
            Self::line(&mut out, "Audit key", key);
        }
        Output { stdout: out, rich: None, code: EXIT_VERIFICATION_FAILED }
    }

    /// What the entries say, after the integrity result: the profile's
    /// lines, labelled as the writer's statements.
    fn said(out: &mut String, lines: &[(&'static str, String)]) {
        out.push_str("\nWhat the entries say (the writer's statements, not verified facts):\n");
        for (label, value) in lines {
            Self::line(out, label, value);
        }
    }

    /// The output of a log that verified, with every checkpoint given.
    fn verified(&self, size: u64, root: &str, checked: &[Checked], history: Option<&History>) -> String {
        let history_sizes = history.map(|h| h.checkpoints.as_slice()).unwrap_or(&[]);
        let covered = checked
            .iter()
            .map(|cp| cp.claims.tree_size)
            .chain(history_sizes.iter().map(|(size, _, _)| *size))
            .max()
            .unwrap_or(0);
        let signatures = match checked.len() + history_sizes.len() {
            0 => "its chain only: no checkpoint was given, so no signature was checked".to_string(),
            n => format!(
                "{} signed by the pinned audit key {} {}",
                plural(n as u64, "checkpoint", "checkpoints"),
                if n == 1 { "covers" } else { "cover" },
                entries(0, covered.saturating_sub(1))
            ),
        };
        let mut out = format!("Audit log verified: {}; {signatures}\n", plural(size, "entry", "entries"));
        self.head(&mut out);
        Self::line(
            &mut out,
            "Checked",
            &format!(
                "every line an entry of the audit-log format v0.1, canonical and in its place; the chain (each entry \
                 names the root of the entries before it); {}",
                if checked.is_empty() && history.is_none() {
                    "no signature was checked"
                } else {
                    "each checkpoint's signature under the pinned audit key, and its root against the log"
                }
            ),
        );
        Self::line(&mut out, "Entries", &format!("{size}, root {root}"));
        match &self.audit_key {
            Some(key) if checked.is_empty() && history.is_none() => {
                Self::line(&mut out, "Audit key", &format!("{key}; no checkpoint was checked under it"))
            }
            Some(key) => Self::line(&mut out, "Audit key", key),
            None => Self::line(&mut out, "Audit key", "none given"),
        }
        if checked.is_empty() && history.is_none() {
            Self::line(
                &mut out,
                "Checkpoints",
                "none given: no signature was checked, and the chain shows only that the lines agree with one \
                 another, not who wrote them",
            );
        }
        for cp in checked {
            let tree_size = cp.claims.tree_size;
            let whole = if tree_size == size { ", the whole log" } else { "" };
            let issued = cp.issued_at.as_deref().map(|t| format!(", issued at {t} (the writer's clock)")).unwrap_or_default();
            Self::line(
                &mut out,
                "Checkpoint",
                &format!(
                    "{}: tree_size {tree_size}{issued}; signed by the audit key; covers {}{whole}: the log's root \
                     over them is its root_hash",
                    cp.file,
                    entries(0, tree_size.saturating_sub(1))
                ),
            );
        }
        if let Some(history) = history {
            let first = history.checkpoints.first().map_or(0, |(size, _, _)| *size);
            let n = history.checkpoints.len() as u64;
            Self::line(
                &mut out,
                "History",
                &format!(
                    "{}: {}, in order, tree_size {first} to {covered_by}; each signed by the audit key, and each \
                     root against the log",
                    history.file,
                    plural(n, "checkpoint", "checkpoints"),
                    covered_by = history.checkpoints.last().map_or(0, |(size, _, _)| *size),
                ),
            );
        }
        if (!checked.is_empty() || history.is_some()) && covered < size {
            let last = size.saturating_sub(1);
            let verb = if covered == last { "is" } else { "are" };
            Self::line(
                &mut out,
                "Not covered",
                &format!(
                    "{} {verb} in no checkpoint given: the chain links them, and no signature covers them",
                    entries(covered, last)
                ),
            );
        }
        out
    }
}
