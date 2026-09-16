// ============================================================================
//  log.rs — the log's file of entries, read and built
//  (`specs/audit-log-format-v0.1.md` §4.2, §4.4).
//
//  Reading is over bytes: this crate opens no file. A writer (KHALM's
//  enforcer, or another vendor's) keeps the file; what every writer shares —
//  building the next entry, checking it as a reader would, and keeping the
//  tree — is here, so no two writers disagree about a log's bytes.
// ============================================================================

//! Reading a log's bytes (§4.4), and building one entry by entry (§4.2).

use crate::entry::{validate_entry, AuditEntry};
use crate::error::Error;
use crate::json::parse_json_bounded;
use crate::profile::EntryProfile;
use crate::tree::root_of;
use crate::{LOG_VERSION, MAX_ENTRY_BYTES};
use serde_json::{json, Value};
use vmr_record::hash::{format_hash, DIGEST_LEN};
use vmr_record::merkle::hash_leaf;
use vmr_record::timestamp::Timestamp;

/// Read a log's bytes into its entries, refusing the first bad line (§4.4).
/// Every line must be the JCS form of a valid entry of `profile` whose `index`
/// is its position and whose `previous_root` is the root of the lines before
/// it. No file is opened and no clock is read.
pub fn read_log(content: &[u8], profile: &dyn EntryProfile) -> Result<Vec<AuditEntry>, Error> {
    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut leaves: Vec<[u8; DIGEST_LEN]> = Vec::new();
    let mut start = 0usize;
    while start < content.len() {
        let rel = content.get(start..).and_then(|s| s.iter().position(|&b| b == b'\n'));
        let Some(rel) = rel else {
            return Err(Error::refused(
                "audit_log.torn_tail",
                format!("bytes from offset {start} are not ended by a line feed"),
            ));
        };
        let end = start + rel;
        let line = content.get(start..end).unwrap_or(&[]);
        // Row 1 before row 2: a line over the limit is refused for its length,
        // whatever its bytes are, and is never parsed.
        if line.len() > MAX_ENTRY_BYTES {
            return Err(Error::refused(
                "audit_entry.size",
                format!("the line at offset {start} is {} bytes; the cap is {MAX_ENTRY_BYTES}", line.len()),
            ));
        }
        let text = std::str::from_utf8(line)
            .map_err(|_| Error::refused("audit_entry.syntax", format!("line at offset {start} is not UTF-8")))?;
        let value = parse_json_bounded(text)
            .map_err(|e| Error::refused("audit_entry.syntax", format!("line at offset {start}: {e}")))?;
        let entry = validate_entry(&value, text, profile)?;
        let expected_index = leaves.len() as u64;
        if entry.index != expected_index {
            return Err(Error::refused(
                "audit_log.index",
                format!("line at offset {start} has index {}, not {expected_index}", entry.index),
            ));
        }
        if entry.previous_root != format_hash(&root_of(&leaves)) {
            return Err(Error::refused(
                "audit_log.previous_root",
                format!("line {expected_index}'s previous_root is not the root of the lines before it"),
            ));
        }
        leaves.push(hash_leaf(text.as_bytes()));
        entries.push(entry);
        start = end + 1;
    }
    Ok(entries)
}

/// The leaf hashes of entries a reader accepted, in index order.
pub fn leaves_of(entries: &[AuditEntry]) -> Vec<[u8; DIGEST_LEN]> {
    entries.iter().map(|e| hash_leaf(e.canonical.as_bytes())).collect()
}

/// A log kept in memory: its id and its entries' leaves. A writer that owns a
/// file (this crate opens none) uses [`LogBuilder::prepare`] to build and
/// check an entry, writes the line, then [`LogBuilder::commit`]s it, so its
/// file and its tree never disagree.
#[derive(Debug, Clone)]
pub struct LogBuilder {
    log_id: String,
    leaves: Vec<[u8; DIGEST_LEN]>,
}

impl LogBuilder {
    /// An empty log whose `log_id` is the audit key's id.
    pub fn new(log_id: impl Into<String>) -> LogBuilder {
        LogBuilder { log_id: log_id.into(), leaves: Vec::new() }
    }

    /// A log already holding the entries a reader accepted.
    pub fn with_entries(log_id: impl Into<String>, entries: &[AuditEntry]) -> LogBuilder {
        LogBuilder { log_id: log_id.into(), leaves: leaves_of(entries) }
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
        root_of(&self.leaves)
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
        self.leaves.push(hash_leaf(entry.canonical.as_bytes()));
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
