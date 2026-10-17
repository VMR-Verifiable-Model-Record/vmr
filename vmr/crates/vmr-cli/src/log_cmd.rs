//! `vmr log verify` — read an audit log, and check its checkpoints under a
//! pinned audit key.
// ============================================================================
//  log_cmd.rs — the Community tool's reader of an audit log
//  (specs/audit-log-format-v0.1.md)
//
//  Orchestration, like the rest of the CLI: every rule, and every statement
//  of what was checked, is vmr-audit-log's (`vmr_audit_log::verify`, which
//  the browser checker runs too); this module reads the files and renders.
//  The log is read as it comes off the disk, one piece at a time: the reader
//  holds one line and the tree's frontier, so under a profile without notes a
//  log of any length is checked in the memory of one line. A profile's notes
//  pass holds more (vmr.agent's: its open sessions' calls and tools), within
//  caps it states; each checkpoint is verified by the format's own checks (§6)
//  under the audit key the operator pins, then held to the log (§6, its last
//  paragraph).
//
//  What it reports is what it checked, and no more (§5.1, a MUST): under the
//  core profile nothing about what an entry means is checked, and the output
//  says so; without a checkpoint no signature is checked, and the output says
//  that too. No profile makes an entry true: a log is its writer's statement,
//  and a checkpoint's signature binds the writer's key to it.
//
//  Whose log it is does not matter here. The profiles are a table
//  (`vmr_audit_log::verify::PROFILES`): the core, and each named profile the
//  format crate carries; a later profile is one row, and nothing else in this
//  module changes.
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
use std::io::Read;
use std::path::Path;
use vmr_audit_log::verify::{
    self, check_checkpoint, checkpoint_too_large, CheckedCheckpoint, History, HistoryChecker, HistoryLine, LogFailure,
    LogVerifier, ProfileRow, Refusal, Verified,
};
use vmr_audit_log::MAX_CHECKPOINT_BYTES;

pub use vmr_audit_log::verify::{CHECKPOINTS_OUT_OF_ORDER, CHECKPOINT_NOT_IN_LOG, GATES_SHOWN, NOTES_SHOWN, PROFILES};

/// How much of the log is read at a time.
const READ_PIECE: usize = 1024 * 1024;

/// Run `log verify`.
pub fn verify(args: &LogVerifyArgs) -> Result<Output, CliError> {
    let row = verify::profile_row(&args.profile)
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
    let mut checked: Vec<CheckedCheckpoint> = Vec::new();
    for path in &args.checkpoints {
        let Some(key) = &key else {
            return Err(CliError::internal("a checkpoint was given without --audit-key"));
        };
        match read_checkpoint(path, key)? {
            Ok(cp) => checked.push(cp),
            Err(refusal) => return Ok(report.refused(&refusal, None)),
        }
    }

    // A checkpoint history: every line checked as one --checkpoint is, in
    // order, each tree_size not smaller than the one before.
    let history = match (&args.checkpoint_history, &key) {
        (None, _) => None,
        (Some(path), Some(key)) => match read_history(path, key)? {
            Ok(history) => Some(history),
            Err(refusal) => return Ok(report.refused(&refusal, None)),
        },
        (Some(_), None) => return Err(CliError::internal("--checkpoints was given without --audit-key")),
    };

    // The log, as it comes off the disk; the first refused line ends the read.
    let mut verifier = LogVerifier::new(row, checked, history);
    let cannot = |e: std::io::Error| CliError::input(format!("cannot read audit log {}: {e}", shown(&args.log)));
    let mut file = std::fs::File::open(&args.log).map_err(cannot)?;
    let mut piece = vec![0u8; READ_PIECE];
    loop {
        let n = match file.read(&mut piece) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(cannot(e)),
        };
        if !verifier.feed(piece.get(..n).unwrap_or(&[])) {
            break;
        }
    }
    match verifier.finish() {
        Ok(verified) => Ok(Output::ok(report.verified(&verified))),
        Err(LogFailure::Refused { accepted, refusal }) => Ok(report.refused(&refusal, Some(accepted))),
        Err(LogFailure::Internal(message)) => Err(CliError::internal(message)),
    }
}

/// Read and verify one checkpoint under `key`: `Ok(Err(..))` is a refusal
/// (exit 3), `Err` a file that could not be read (exit 1).
fn read_checkpoint(path: &Path, key: &p256::ecdsa::VerifyingKey) -> Result<Result<CheckedCheckpoint, Refusal>, CliError> {
    let file = shown(path);
    // At most the format's size is read (§6 check 1): a larger file is
    // refused for its size and never parsed.
    let bytes = match files::read_bounded(path, MAX_CHECKPOINT_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(ReadError::TooLarge(size)) => return Ok(Err(checkpoint_too_large(&file, size))),
        Err(ReadError::Io(e)) => return Err(CliError::input(format!("cannot read checkpoint {file}: {e}"))),
    };
    Ok(check_checkpoint(&file, &bytes, key))
}

/// Read and verify a checkpoint history under `key`, line by line as it is
/// read. `Ok(Err(..))` is a refusal (exit 3), `Err` a file that could not be
/// read or that holds no checkpoint (exit 1).
fn read_history(path: &Path, key: &p256::ecdsa::VerifyingKey) -> Result<Result<History, Refusal>, CliError> {
    let file = shown(path);
    let cannot = |e: std::io::Error| CliError::input(format!("cannot read checkpoint history {file}: {e}"));
    let mut input = std::io::BufReader::new(std::fs::File::open(path).map_err(cannot)?);
    let mut history = HistoryChecker::new(&file, key);
    while let Some(line) = crate::log_seal::read_line(&mut input, MAX_CHECKPOINT_BYTES).map_err(cannot)? {
        let checked = match &line {
            crate::log_seal::Line::Bytes(bytes) => history.line(HistoryLine::Bytes(bytes)),
            crate::log_seal::Line::TooLong(len) => history.line(HistoryLine::TooLong(*len)),
        };
        if let Err(refusal) = checked {
            return Ok(Err(refusal));
        }
    }
    history
        .finish()
        .map(Ok)
        .ok_or_else(|| CliError::input(format!("checkpoint history {file} holds no checkpoint")))
}

/// The report's lines: the library's statements, with the file names and the
/// key file this command read.
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

    /// The output of a log that verified, with every checkpoint given; then
    /// the profile's lines, labelled as the writer's statements.
    fn verified(&self, v: &Verified) -> String {
        let mut out = format!("Audit log verified: {}\n", v.headline());
        self.head(&mut out);
        Self::line(&mut out, "Checked", &v.checked_statement());
        Self::line(&mut out, "Entries", &v.entries_statement());
        match &self.audit_key {
            Some(key) if !v.signed() => {
                Self::line(&mut out, "Audit key", &format!("{key}; no checkpoint was checked under it"))
            }
            Some(key) => Self::line(&mut out, "Audit key", key),
            None => Self::line(&mut out, "Audit key", "none given"),
        }
        for (label, value) in v.checkpoint_statements() {
            Self::line(&mut out, label, &value);
        }
        if let Some(notes) = &v.notes {
            out.push_str(&format!("\n{}:\n", verify::WRITER_STATEMENTS));
            for (label, value) in notes.lines() {
                Self::line(&mut out, label, &value);
            }
        }
        out
    }
}
