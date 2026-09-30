// ============================================================================
//  vmr-audit-writer — the VMR audit log's file writer, open and general
//
//  specs/audit-log-format-v0.1.md §4.2 (the file, append only) and §4.4
//  (reading, and the recovery of a torn tail). vmr-audit-log holds the
//  format and opens nothing; this crate owns the file: one read+write handle,
//  locked for its process, replayed on open with the format's streaming
//  reader, and appended to one durable line at a time.
//
//  Whose log it is does not matter here. The entries are any profile's
//  (vmr-audit-log's `EntryProfile`): the core, `vmr.agent`, KHALM's enforcer,
//  or a vendor's own. Nothing in this crate names one.
//
//  Design invariants (as in vmr-audit-log):
//
//    * No unsafe code (`#![forbid(unsafe_code)]`).
//    * No panics in library code: every fallible path returns a typed error.
//    * No clock: every time is an input, so the same inputs give the same
//      bytes (Law 1).
//    * The log never holds an entry its reader would refuse: every entry is
//      checked as a reader checks it before a byte is written.
//    * Constant memory in the log's length: replay keeps the tree's
//      frontier and one line, never the log. A caller that needs more (a
//      proof's leaves, a set of spent tokens) keeps it from the entries it is
//      shown.
// ============================================================================

//! The VMR audit log's file writer ([`LogFile`]): open and lock one log
//! file, replay it, recover exactly a torn tail as the format allows
//! (`specs/audit-log-format-v0.1.md` §4.4), and append entries of any
//! profile, each written with one `write_all` and made durable with
//! `sync_data` before [`LogFile::append`] returns.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo
    )
)]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vmr_audit_log::entry::{validate_entry, AuditEntry};
use vmr_audit_log::log::LogReader;
use vmr_audit_log::profile::EntryProfile;
use vmr_audit_log::tree::MerkleFrontier;
use vmr_audit_log::vmr_record::hash::{format_hash, DIGEST_LEN};
use vmr_audit_log::vmr_record::merkle::hash_leaf;
use vmr_audit_log::vmr_record::timestamp::Timestamp;
use vmr_audit_log::{Error, LOG_VERSION};

pub use vmr_audit_log;

/// How much of the log is read at a time on open.
const READ_PIECE: usize = 1024 * 1024;

/// The kind a recovery is recorded as (core §4.4).
pub const RECOVERED_KIND: &str = "log.recovered";

/// A torn tail [`LogFile::open_recovering`] moved aside, or recorded for an
/// earlier start a crash cut short (core §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    /// Where the moved bytes started: the length of the log's complete lines.
    pub offset: u64,
    /// How many bytes were moved.
    pub length: u64,
    /// `sha256:` of the moved bytes.
    pub sha256: String,
    /// The file that holds them: `<log>.torn-<offset>`, or `.1`, `.2`, ...
    /// after it when an earlier file holds other bytes ([`move_torn_tail`]).
    pub sidecar: PathBuf,
    /// The `log.recovered` entry appended, when the profile has that kind.
    pub entry: Option<AuditEntry>,
}

/// One audit log file with a single writer: the file, locked for this
/// process while the value lives, and the tree's frontier (the next entry's
/// `previous_root`, in O(log n) memory).
pub struct LogFile<'p> {
    path: PathBuf,
    file: File,
    /// The lock file beside the log (`<log>.lock`), locked while this lives.
    _lock: File,
    profile: &'p (dyn EntryProfile + Sync),
    frontier: MerkleFrontier,
    /// Set when a write may have left part of a line: nothing more is
    /// appended through this value, and the next open recovers the tail.
    broken: bool,
}

impl std::fmt::Debug for LogFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogFile")
            .field("path", &self.path)
            .field("profile", &self.profile.name())
            .field("entries", &self.frontier.size())
            .field("broken", &self.broken)
            .finish()
    }
}

/// An I/O failure naming the file.
fn io(what: &str, path: &Path, e: &std::io::Error) -> Error {
    Error::io(format!("cannot {what} {}: {e}", path.display()))
}

impl<'p> LogFile<'p> {
    /// Open the log at `path` (created empty when absent), lock it for this
    /// process, and replay it under `profile`: every line is checked as a
    /// reader checks it (core §4.4), and `visit` is shown each entry in
    /// order. The first bad line is its refusal; a torn tail is
    /// `audit_log.torn_tail` ([`LogFile::open_recovering`] repairs exactly
    /// that). A log another process holds is an `io` error.
    pub fn open(
        path: &Path,
        profile: &'p (dyn EntryProfile + Sync),
        visit: &mut dyn FnMut(&AuditEntry),
    ) -> Result<LogFile<'p>, Error> {
        let (log, torn) = Self::replay(path, profile, visit)?;
        match torn {
            None => Ok(log),
            Some(torn) => Err(torn.refusal),
        }
    }

    /// [`LogFile::open`], and when the only fault is a torn tail (bytes after
    /// the last line feed, core §4.4 refusal 8), recover it as the format
    /// allows: move those bytes to a torn-bytes file ([`move_torn_tail`]:
    /// `<log>.torn-<offset>`, written and synced first, never over an earlier
    /// one), truncate the log to its last complete line, and append a
    /// `log.recovered` entry at `recorded_at` naming their offset, length and
    /// hash when `profile` has that kind (`visit` is shown it too). Any other
    /// refusal is not repaired.
    ///
    /// A start a crash cut short between the truncation and that entry is
    /// completed (QA S3): every torn-bytes file at the log's length is one no
    /// entry names yet (an entry naming it would have been appended after the
    /// truncation, and made the log longer), and each is recorded, in the
    /// order its name gives. The result lists every torn-bytes file this call
    /// moved or recorded, in that order.
    pub fn open_recovering(
        path: &Path,
        profile: &'p (dyn EntryProfile + Sync),
        recorded_at: Timestamp,
        visit: &mut dyn FnMut(&AuditEntry),
    ) -> Result<(LogFile<'p>, Vec<Recovered>), Error> {
        let (mut log, torn) = Self::replay(path, profile, visit)?;
        let moved = match torn {
            Some(torn) => Some(move_torn_tail(&mut log.file, path, torn.offset)?),
            None => None,
        };
        let offset = log.file.seek(SeekFrom::End(0)).map_err(|e| io("seek", path, &e))?;

        let mut recovered = Vec::new();
        for sidecar in torn_files_at(path, offset)? {
            let now = moved.as_ref().filter(|m| m.sidecar == sidecar);
            let (length, sha256) = match now {
                Some(m) => (m.length, m.sha256.clone()),
                None => hash_file(&sidecar)?,
            };
            let detail = json!({ "offset": offset, "length": length, "sha256": sha256 });
            // Recorded only when the profile has the kind: a profile that
            // names no `log.recovered` refuses it, and the file is the record.
            let entry = if profile.check(RECOVERED_KIND, &detail).is_ok() {
                let entry = log.append(recorded_at, RECOVERED_KIND, detail)?;
                visit(&entry);
                Some(entry)
            } else if now.is_none() {
                continue; // an earlier start's file, which this profile never records
            } else {
                None
            };
            recovered.push(Recovered { offset, length, sha256, sidecar, entry });
        }
        Ok((log, recovered))
    }

    /// Open, lock and replay; a torn tail is returned, not refused.
    fn replay(
        path: &Path,
        profile: &'p (dyn EntryProfile + Sync),
        visit: &mut dyn FnMut(&AuditEntry),
    ) -> Result<(LogFile<'p>, Option<TornTail>), Error> {
        // One writer per log: this process's exclusive OS lock on the lock
        // file beside it, taken before the log is opened and held while the
        // value lives. The OS releases it when the process ends, however it
        // ends, so it never goes stale. The lock is on that file and never on
        // the log: on Windows a lock is mandatory, and a locked log could not
        // be read by anyone else (QA S2). The lock file holds nothing and is
        // never removed (removing it while held would let a second writer
        // lock a new one).
        let lock_path = lock_path_of(path);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| io("open", &lock_path, &e))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::io(format!(
                    "{} is locked by another process (its writer holds {})",
                    path.display(),
                    lock_path.display()
                )))
            }
            Err(TryLockError::Error(e)) => return Err(io("lock", &lock_path, &e)),
        }

        // One read+write handle, through which the log is replayed and
        // appended to. Opened as std opens every file, sharing reading,
        // writing and deleting with other handles, so other processes may
        // read the log while this one writes it, on every system. Not in
        // append mode: an append seeks to the end first.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // the log is read and appended to, never overwritten
            .open(path)
            .map_err(|e| io("open", path, &e))?;
        sync_parent(path)?;

        // The reader checks every line and keeps its own frontier; this one
        // follows it, entry by entry, because a reader that meets a torn tail
        // refuses at its finish and gives no tree back.
        let mut reader = LogReader::new(profile);
        let mut frontier = MerkleFrontier::new();
        let mut piece = vec![0u8; READ_PIECE];
        let mut read = 0u64;
        let mut complete = 0u64; // the offset just past the last line feed
        loop {
            let n = match file.read(&mut piece) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io("read", path, &e)),
            };
            let bytes = piece.get(..n).unwrap_or(&[]);
            if let Some(last) = bytes.iter().rposition(|&b| b == b'\n') {
                complete = read + last as u64 + 1;
            }
            read += n as u64;
            for entry in reader.feed(bytes)? {
                frontier.push(hash_leaf(entry.canonical.as_bytes()));
                visit(&entry);
            }
        }
        // Every complete line checked. What the reader's finish refuses now
        // is bytes that no line feed ends (core §4.4 refusal 8): the one
        // fault a writer may repair.
        let torn = match reader.finish() {
            Ok(_) => None,
            Err(refusal) if refusal.id() == "audit_log.torn_tail" && read > complete => {
                Some(TornTail { offset: complete, refusal })
            }
            Err(refusal) => return Err(refusal),
        };
        file.seek(SeekFrom::End(0)).map_err(|e| io("seek", path, &e))?;
        Ok((LogFile { path: path.to_path_buf(), file, _lock: lock, profile, frontier, broken: false }, torn))
    }

    /// The log file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The profile its entries are checked under.
    pub fn profile(&self) -> &'p (dyn EntryProfile + Sync) {
        self.profile
    }

    /// The number of entries.
    pub fn len(&self) -> u64 {
        self.frontier.size()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.frontier.size() == 0
    }

    /// The Merkle root over every entry (core §4.3).
    pub fn root(&self) -> [u8; DIGEST_LEN] {
        self.frontier.root()
    }

    /// Build the next entry and check it as a reader checks it (core §4.4
    /// refusals 1 to 5), without writing it: what [`LogFile::append`] would
    /// write, or its refusal.
    pub fn prepare(&self, recorded_at: Timestamp, kind: &str, detail: Value) -> Result<AuditEntry, Error> {
        let value = json!({
            "log_version": LOG_VERSION,
            "index": self.frontier.size(),
            "previous_root": format_hash(&self.frontier.root()),
            "recorded_at": recorded_at.to_string(),
            "kind": kind,
            "detail": detail,
        });
        let line = vmr_audit_log::vmr_record::canonical::jcs(&value);
        validate_entry(&value, &line, self.profile)
    }

    /// Append `kind` and `detail` at `recorded_at`: checked as a reader
    /// checks it (a refusal writes nothing), then written as one line with
    /// one `write_all` and made durable with `sync_data` before this returns.
    /// After a write that failed, nothing more is appended through this
    /// value: reopen the log, whose recovery handles a torn tail.
    pub fn append(&mut self, recorded_at: Timestamp, kind: &str, detail: Value) -> Result<AuditEntry, Error> {
        if self.broken {
            return Err(Error::io(format!(
                "a write to {} failed earlier; reopen the log to recover it",
                self.path.display()
            )));
        }
        let entry = self.prepare(recorded_at, kind, detail)?;
        let mut bytes = Vec::with_capacity(entry.canonical.len() + 1);
        bytes.extend_from_slice(entry.canonical.as_bytes());
        bytes.push(b'\n');
        self.broken = true;
        self.file.seek(SeekFrom::End(0)).map_err(|e| io("seek", &self.path, &e))?;
        self.file.write_all(&bytes).map_err(|e| io("append to", &self.path, &e))?;
        self.file.sync_data().map_err(|e| io("sync", &self.path, &e))?;
        self.broken = false;
        self.frontier.push(hash_leaf(entry.canonical.as_bytes()));
        Ok(entry)
    }

    /// A checkpoint over the whole log (core §6), signed by `audit_key`,
    /// whose key id is the checkpoint's `log_id`. An empty log has none
    /// (`checkpoint.empty_tree`).
    pub fn checkpoint(&self, issued_at: Timestamp, audit_key: &p256::ecdsa::SigningKey) -> Result<Value, Error> {
        let log_id = vmr_audit_log::vmr_record::jwk::key_id(audit_key.verifying_key());
        vmr_audit_log::checkpoint::build_signed(&log_id, self.len(), &self.root(), issued_at, audit_key)
    }

    /// Read the whole log through the writer's handle, and leave the cursor
    /// at its end for the next append.
    pub fn read_all(&mut self) -> Result<Vec<u8>, Error> {
        self.file.seek(SeekFrom::Start(0)).map_err(|e| io("seek", &self.path, &e))?;
        let mut content = Vec::new();
        self.file.read_to_end(&mut content).map_err(|e| io("read", &self.path, &e))?;
        self.file.seek(SeekFrom::End(0)).map_err(|e| io("seek", &self.path, &e))?;
        Ok(content)
    }
}

/// A torn tail found on open: where it starts, and its refusal.
struct TornTail {
    offset: u64,
    refusal: Error,
}

/// `path` with `suffix` added to its file name, built on the OS string, so a
/// path that is not UTF-8 keeps its bytes (QA N7).
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// The lock file of the log at `path`: `<log>.lock`, beside it. Its writer
/// holds an exclusive OS lock on it (never on the log itself).
pub fn lock_path_of(path: &Path) -> PathBuf {
    with_suffix(path, ".lock")
}

/// Make the directory entries of the directory holding `path` durable: on
/// Unix a file's creation, rename or truncation is not durable until its
/// directory is synced (QA S3). Elsewhere (Windows) the file system has no
/// such step, and this does nothing.
pub fn sync_parent(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
        File::open(dir).and_then(|d| d.sync_all()).map_err(|e| io("sync the directory", dir, &e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Bytes [`move_torn_tail`] moved out of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedTail {
    /// The torn-bytes file that holds them.
    pub sidecar: PathBuf,
    /// How many bytes.
    pub length: u64,
    /// `sha256:` of the bytes.
    pub sha256: String,
}

/// The most torn-bytes files kept for one offset of one file.
const MAX_TORN_FILES: u64 = 1000;

/// The n-th torn-bytes file name for `offset` of the file at `path`:
/// `<path>.torn-<offset>`, then `<path>.torn-<offset>.1`, `.2`, ...
fn torn_name(path: &Path, offset: u64, n: u64) -> PathBuf {
    if n == 0 {
        with_suffix(path, &format!(".torn-{offset}"))
    } else {
        with_suffix(path, &format!(".torn-{offset}.{n}"))
    }
}

/// The torn-bytes files that exist for `offset` of the file at `path`, in
/// the order of their names (each is made only after the one before it).
fn torn_files_at(path: &Path, offset: u64) -> Result<Vec<PathBuf>, Error> {
    let mut found = Vec::new();
    for n in 0..MAX_TORN_FILES {
        let name = torn_name(path, offset, n);
        match std::fs::symlink_metadata(&name) {
            Ok(_) => found.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(io("read", &name, &e)),
        }
    }
    Ok(found)
}

/// Read `file` from where it stands to its end in pieces, showing each to
/// `each`: the memory of one piece, whatever the length. Returns the length.
fn stream(file: &mut File, path: &Path, each: &mut dyn FnMut(&[u8]) -> Result<(), Error>) -> Result<u64, Error> {
    let mut piece = vec![0u8; READ_PIECE];
    let mut length = 0u64;
    loop {
        let n = match file.read(&mut piece) {
            Ok(0) => return Ok(length),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io("read", path, &e)),
        };
        each(piece.get(..n).unwrap_or(&[]))?;
        length += n as u64;
    }
}

/// The length and `sha256:` of `file` from `offset` to its end.
fn hash_from(file: &mut File, path: &Path, offset: u64) -> Result<(u64, String), Error> {
    file.seek(SeekFrom::Start(offset)).map_err(|e| io("seek", path, &e))?;
    let mut hasher = Sha256::new();
    let length = stream(file, path, &mut |bytes| {
        hasher.update(bytes);
        Ok(())
    })?;
    let digest: [u8; DIGEST_LEN] = hasher.finalize().into();
    Ok((length, format_hash(&digest)))
}

/// The length and `sha256:` of the file at `path`.
fn hash_file(path: &Path) -> Result<(u64, String), Error> {
    let mut file = File::open(path).map_err(|e| io("open", path, &e))?;
    hash_from(&mut file, path, 0)
}

/// Move the bytes of `file` (the file at `path`) from `offset` to its end
/// into a torn-bytes file, then truncate `file` to `offset` (core §4.4's
/// recovery; the log sealer's checkpoint history uses it too). Everything
/// goes through `file`, in the memory of one piece whatever the length.
///
/// A torn-bytes file never overwrites an earlier one (QA S3): the bytes go
/// to the first of `<path>.torn-<offset>`, `<path>.torn-<offset>.1`, ...
/// that does not exist, created new; a file of that series that already
/// holds exactly these bytes (a crash after it was written, before the
/// truncation) is kept and named instead. The file is synced, and on Unix
/// its directory too, before the truncation, which is synced as well.
pub fn move_torn_tail(file: &mut File, path: &Path, offset: u64) -> Result<MovedTail, Error> {
    let (length, sha256) = hash_from(file, path, offset)?;
    let mut sidecar = None;
    for n in 0..MAX_TORN_FILES {
        let name = torn_name(path, offset, n);
        match OpenOptions::new().write(true).create_new(true).open(&name) {
            Ok(mut out) => {
                file.seek(SeekFrom::Start(offset)).map_err(|e| io("seek", path, &e))?;
                stream(file, path, &mut |bytes| out.write_all(bytes).map_err(|e| io("write", &name, &e)))?;
                out.sync_all().map_err(|e| io("sync", &name, &e))?;
                drop(out);
                sync_parent(&name)?;
                sidecar = Some(name);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if hash_file(&name)? == (length, sha256.clone()) {
                    sidecar = Some(name);
                    break;
                }
            }
            Err(e) => return Err(io("create", &name, &e)),
        }
    }
    let Some(sidecar) = sidecar else {
        return Err(Error::io(format!(
            "cannot move the torn tail of {}: {MAX_TORN_FILES} torn-bytes files for offset {offset} exist",
            path.display()
        )));
    };
    file.set_len(offset).map_err(|e| io("truncate", path, &e))?;
    file.sync_all().map_err(|e| io("sync", path, &e))?;
    file.seek(SeekFrom::End(0)).map_err(|e| io("seek", path, &e))?;
    Ok(MovedTail { sidecar, length, sha256 })
}
