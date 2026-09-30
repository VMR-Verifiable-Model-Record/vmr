// ============================================================================
//  log.rs — the log's file of entries, read and built
//  (`specs/audit-log-format-v0.1.md` §4.2, §4.4).
//
//  Reading is over bytes: this crate opens no file. A writer (KHALM's
//  enforcer, or another vendor's) keeps the file; what every writer shares —
//  building the next entry, checking it as a reader would, and keeping the
//  tree — is here, so no two writers disagree about a log's bytes.
// ============================================================================

//! Reading a log's bytes (§4.4), whole or as they arrive, and building one
//! entry by entry (§4.2).

use crate::entry::{validate_entry, AuditEntry};
use crate::error::Error;
use crate::json::parse_json_bounded;
use crate::profile::EntryProfile;
use crate::tree::{root_of, MerkleFrontier};
use crate::{LOG_VERSION, MAX_ENTRY_BYTES};
use serde_json::{json, Value};
use vmr_record::hash::{format_hash, DIGEST_LEN};
use vmr_record::merkle::hash_leaf;
use vmr_record::timestamp::Timestamp;

/// Read a log's bytes into its entries, refusing the first bad line (§4.4).
/// Every line must be the JCS form of a valid entry of `profile` whose `index`
/// is its position and whose `previous_root` is the root of the lines before
/// it. No file is opened and no clock is read. The whole log at once: a
/// caller that reads a large log a piece at a time uses [`LogReader`], which
/// this is.
pub fn read_log(content: &[u8], profile: &dyn EntryProfile) -> Result<Vec<AuditEntry>, Error> {
    let mut reader = LogReader::new(profile);
    let entries = reader.feed(content)?;
    reader.finish()?;
    Ok(entries)
}

/// A log's reader, fed its bytes as they arrive (§4.4): in pieces of any
/// size, cut anywhere, it accepts and refuses exactly as [`read_log`] does
/// over the whole file — the same refusal, at the same line, with the same
/// message. It holds the line in progress (at most [`MAX_ENTRY_BYTES`] of it:
/// a longer line is refused for its length, whatever its bytes) and the
/// tree's frontier, never the log, so a caller checks a log of any length in
/// the memory of one line (a pass the caller runs over the entries, such as a
/// profile's notes, holds its own state). Each entry's `previous_root` is checked against
/// the frontier's root, O(log n) node hashes.
///
/// Feed it with [`LogReader::feed`], then [`LogReader::finish`]: only the
/// finish can say that no torn tail remains (§4.4 row 8). The first refusal
/// is final: every later call returns it again.
pub struct LogReader<'p> {
    profile: &'p dyn EntryProfile,
    frontier: MerkleFrontier,
    /// The line in progress, while it is within the cap.
    partial: Vec<u8>,
    /// The line in progress's length, counted past the cap too.
    partial_len: u64,
    /// Where the line in progress starts in the log.
    line_start: u64,
    refused: Option<Error>,
}

impl std::fmt::Debug for LogReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogReader")
            .field("profile", &self.profile.name())
            .field("entries", &self.frontier.size())
            .field("line_start", &self.line_start)
            .field("partial_len", &self.partial_len)
            .field("refused", &self.refused)
            .finish()
    }
}

impl<'p> LogReader<'p> {
    /// A reader of a log whose entries are `profile`'s, before its first byte.
    pub fn new(profile: &'p dyn EntryProfile) -> LogReader<'p> {
        LogReader {
            profile,
            frontier: MerkleFrontier::new(),
            partial: Vec::new(),
            partial_len: 0,
            line_start: 0,
            refused: None,
        }
    }

    /// Read the next bytes of the log: the entries whose lines they complete,
    /// in order, or the first refusal (§4.4 rows 1 to 7). Bytes after the
    /// last line feed are kept for the next call.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<AuditEntry>, Error> {
        if let Some(refused) = &self.refused {
            return Err(refused.clone());
        }
        let mut entries = Vec::new();
        let mut rest = bytes;
        while let Some(end) = rest.iter().position(|&b| b == b'\n') {
            let (head, tail) = rest.split_at(end);
            let result = if self.partial_len == 0 {
                // The whole line is in this piece: read it where it lies.
                self.accept(head, head.len() as u64)
            } else {
                self.hold(head);
                let line = std::mem::take(&mut self.partial);
                let result = self.accept(&line, self.partial_len);
                self.partial = line;
                self.partial.clear();
                result
            };
            match result {
                Ok(entry) => entries.push(entry),
                Err(refused) => {
                    self.refused = Some(refused.clone());
                    return Err(refused);
                }
            }
            rest = tail.get(1..).unwrap_or(&[]);
        }
        self.hold(rest);
        Ok(entries)
    }

    /// The end of the log: its tree when every byte was a complete line, else
    /// `audit_log.torn_tail` (§4.4 row 8), or the refusal already made.
    pub fn finish(self) -> Result<MerkleFrontier, Error> {
        if let Some(refused) = self.refused {
            return Err(refused);
        }
        if self.partial_len > 0 {
            return Err(Error::refused(
                "audit_log.torn_tail",
                format!("bytes from offset {} are not ended by a line feed", self.line_start),
            ));
        }
        Ok(self.frontier)
    }

    /// The number of entries accepted so far.
    pub fn len(&self) -> u64 {
        self.frontier.size()
    }

    /// Whether no entry has been accepted yet.
    pub fn is_empty(&self) -> bool {
        self.frontier.size() == 0
    }

    /// The root over the entries accepted so far.
    pub fn root(&self) -> [u8; DIGEST_LEN] {
        self.frontier.root()
    }

    /// Keep `bytes` of the line in progress: its length always, its bytes
    /// only while the line is within the cap (row 1 refuses a longer line for
    /// its length, whatever its bytes are).
    fn hold(&mut self, bytes: &[u8]) {
        self.partial_len += bytes.len() as u64;
        if self.partial_len <= MAX_ENTRY_BYTES as u64 {
            self.partial.extend_from_slice(bytes);
        } else {
            self.partial = Vec::new();
        }
    }

    /// Check one complete line of `len` bytes (its bytes are `line` when
    /// `len` is within the cap) as the log's next entry.
    fn accept(&mut self, line: &[u8], len: u64) -> Result<AuditEntry, Error> {
        let start = self.line_start;
        // Row 1 before row 2: a line over the limit is refused for its length,
        // whatever its bytes are, and is never parsed.
        if len > MAX_ENTRY_BYTES as u64 {
            return Err(Error::refused(
                "audit_entry.size",
                format!("the line at offset {start} is {len} bytes; the cap is {MAX_ENTRY_BYTES}"),
            ));
        }
        let text = std::str::from_utf8(line)
            .map_err(|_| Error::refused("audit_entry.syntax", format!("line at offset {start} is not UTF-8")))?;
        let value = parse_json_bounded(text)
            .map_err(|e| Error::refused("audit_entry.syntax", format!("line at offset {start}: {e}")))?;
        let entry = validate_entry(&value, text, self.profile)?;
        let expected_index = self.frontier.size();
        if entry.index != expected_index {
            return Err(Error::refused(
                "audit_log.index",
                format!("line at offset {start} has index {}, not {expected_index}", entry.index),
            ));
        }
        if entry.previous_root != format_hash(&self.frontier.root()) {
            return Err(Error::refused(
                "audit_log.previous_root",
                format!("line {expected_index}'s previous_root is not the root of the lines before it"),
            ));
        }
        self.frontier.push(hash_leaf(text.as_bytes()));
        self.line_start = start + len + 1;
        self.partial_len = 0;
        Ok(entry)
    }
}

/// The leaf hashes of entries a reader accepted, in index order.
pub fn leaves_of(entries: &[AuditEntry]) -> Vec<[u8; DIGEST_LEN]> {
    entries.iter().map(|e| hash_leaf(e.canonical.as_bytes())).collect()
}

/// A log kept in memory: its id, its entries' leaves (for the proofs) and
/// the tree's frontier (for the next entry's `previous_root`, O(log n)). A
/// writer that owns a file (this crate opens none) uses
/// [`LogBuilder::prepare`] to build and check an entry, writes the line, then
/// [`LogBuilder::commit`]s it, so its file and its tree never disagree.
#[derive(Debug, Clone)]
pub struct LogBuilder {
    log_id: String,
    leaves: Vec<[u8; DIGEST_LEN]>,
    frontier: MerkleFrontier,
}

impl LogBuilder {
    /// An empty log whose `log_id` is the audit key's id.
    pub fn new(log_id: impl Into<String>) -> LogBuilder {
        LogBuilder { log_id: log_id.into(), leaves: Vec::new(), frontier: MerkleFrontier::new() }
    }

    /// A log already holding the entries a reader accepted.
    pub fn with_entries(log_id: impl Into<String>, entries: &[AuditEntry]) -> LogBuilder {
        let leaves = leaves_of(entries);
        let frontier = MerkleFrontier::from_leaves(&leaves);
        LogBuilder { log_id: log_id.into(), leaves, frontier }
    }

    /// The audit key's id, which every checkpoint's `log_id` names.
    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// The number of entries.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The Merkle root over every entry.
    pub fn root(&self) -> [u8; DIGEST_LEN] {
        self.frontier.root()
    }

    /// The root over the first `n` entries, or `None` when `n` exceeds the log.
    pub fn root_at(&self, n: u64) -> Option<[u8; DIGEST_LEN]> {
        let n = usize::try_from(n).ok()?;
        self.leaves.get(..n).map(root_of)
    }

    /// The leaf hashes, in index order.
    pub fn leaves(&self) -> &[[u8; DIGEST_LEN]] {
        &self.leaves
    }

    /// Build the next entry and check it as a reader checks it (§4.4 refusals
    /// 1 to 5), without adding it: the caller writes its line, then commits.
    pub fn prepare(
        &self,
        recorded_at: Timestamp,
        kind: &str,
        detail: Value,
        profile: &dyn EntryProfile,
    ) -> Result<AuditEntry, Error> {
        let value = json!({
            "log_version": LOG_VERSION,
            "index": self.leaves.len() as u64,
            "previous_root": format_hash(&self.root()),
            "recorded_at": recorded_at.to_string(),
            "kind": kind,
            "detail": detail,
        });
        let line = vmr_record::canonical::jcs(&value);
        validate_entry(&value, &line, profile)
    }

    /// Add an entry [`LogBuilder::prepare`] built and the caller wrote.
    pub fn commit(&mut self, entry: &AuditEntry) {
        let leaf = hash_leaf(entry.canonical.as_bytes());
        self.leaves.push(leaf);
        self.frontier.push(leaf);
    }

    /// Prepare and commit in one step, for a log kept only in memory (a test,
    /// a vector generator, a tool that writes its file afterwards).
    pub fn append(
        &mut self,
        recorded_at: Timestamp,
        kind: &str,
        detail: Value,
        profile: &dyn EntryProfile,
    ) -> Result<AuditEntry, Error> {
        let entry = self.prepare(recorded_at, kind, detail, profile)?;
        self.commit(&entry);
        Ok(entry)
    }
}
