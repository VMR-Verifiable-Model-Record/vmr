// tests/log_file.rs — the audit log's file writer (specs/audit-log-format-v0.1.md
// §4.2, §4.4): what it writes is what a reader accepts, a torn tail is
// recovered exactly as the format allows, and one log has one writer.

use serde_json::json;
use std::path::{Path, PathBuf};
use vmr_audit_log::checkpoint::verify_checkpoint_value;
use vmr_audit_log::log::read_log;
use vmr_audit_log::profile::CORE;
use vmr_audit_log::profiles::vmr_agent;
use vmr_audit_log::vmr_record::hash::{format_hash, sha256};
use vmr_audit_log::vmr_record::timestamp::Timestamp;
use vmr_audit_writer::LogFile;

fn t() -> Timestamp {
    Timestamp::parse("2026-09-30T10:00:00Z").unwrap()
}

fn scratch(label: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("vmr-audit-writer").join(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn key() -> p256::ecdsa::SigningKey {
    vmr_audit_log::vmr_record::sign::signing_key_from_secret(&sha256(b"vmr-audit-writer tests: the audit key (test-only)")).unwrap()
}

const SESSION: &str = "urn:uuid:0f3c6a2e-8d4b-4c1e-9a7f-2b5d8e1c4a90";

fn seed(log: &mut LogFile<'_>, n: u64) {
    for i in 0..n {
        log.append(t(), "session.ended", json!({ "session_id": SESSION, "outcome": if i % 2 == 0 { "completed" } else { "failed" } }))
            .unwrap();
    }
}

#[test]
fn what_it_writes_a_reader_accepts_and_a_reopen_replays() {
    let dir = scratch("roundtrip");
    let path = dir.join("log.jsonl");
    let root = {
        let mut log = LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap();
        seed(&mut log, 5);
        assert_eq!(log.len(), 5);
        let cp = log.checkpoint(t(), &key()).unwrap();
        let claims = verify_checkpoint_value(&cp, key().verifying_key()).unwrap();
        assert_eq!((claims.tree_size, claims.root_hash), (5, format_hash(&log.root())));
        log.root()
    };
    let entries = read_log(&std::fs::read(&path).unwrap(), &vmr_agent::PROFILE).unwrap();
    assert_eq!(entries.len(), 5);
    let mut seen = 0;
    let log = LogFile::open(&path, &vmr_agent::PROFILE, &mut |e| {
        assert_eq!(e.index, seen);
        seen += 1;
    })
    .unwrap();
    assert_eq!((seen, log.len(), log.root()), (5, 5, root));
}

#[test]
fn a_refused_entry_writes_nothing() {
    let dir = scratch("refused");
    let path = dir.join("log.jsonl");
    let mut log = LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap();
    seed(&mut log, 1);
    let before = log.read_all().unwrap();
    let e = log.append(t(), "session.ended", json!({ "session_id": SESSION, "outcome": "maybe" })).unwrap_err();
    assert_eq!(e.id(), "audit_entry.structure");
    assert_eq!(log.read_all().unwrap(), before);
    assert_eq!(log.len(), 1);
    // The log still takes the next good entry.
    seed(&mut log, 1);
    assert_eq!(log.len(), 2);
}

#[test]
fn a_torn_tail_is_refused_then_recovered_and_recorded() {
    let dir = scratch("torn");
    let path = dir.join("log.jsonl");
    {
        let mut log = LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap();
        seed(&mut log, 3);
    }
    let complete = std::fs::read(&path).unwrap();
    let torn = b"{\"log_version\":\"0.1\",\"index\":3,\"part";
    let mut damaged = complete.clone();
    damaged.extend_from_slice(torn);
    std::fs::write(&path, &damaged).unwrap();

    assert_eq!(LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap_err().id(), "audit_log.torn_tail");

    let mut shown = Vec::new();
    let (log, recovered) =
        LogFile::open_recovering(&path, &vmr_agent::PROFILE, t(), &mut |e| shown.push(e.kind.clone())).unwrap();
    let [recovered] = <[_; 1]>::try_from(recovered).expect("one tail to recover");
    assert_eq!((recovered.offset, recovered.length), (complete.len() as u64, torn.len() as u64));
    assert_eq!(recovered.sha256, format_hash(&sha256(torn)));
    assert_eq!(std::fs::read(&recovered.sidecar).unwrap(), torn);
    assert_eq!(recovered.sidecar, PathBuf::from(format!("{}.torn-{}", path.display(), complete.len())));
    let entry = recovered.entry.expect("vmr.agent has log.recovered");
    assert_eq!((entry.index, entry.kind.as_str()), (3, "log.recovered"));
    assert_eq!(shown.last().map(String::as_str), Some("log.recovered"));
    assert_eq!(log.len(), 4);
    drop(log);

    // The log now reads whole, and a clean log needs no recovery.
    assert_eq!(read_log(&std::fs::read(&path).unwrap(), &vmr_agent::PROFILE).unwrap().len(), 4);
    let (_, again) = LogFile::open_recovering(&path, &vmr_agent::PROFILE, t(), &mut |_| {}).unwrap();
    assert!(again.is_empty());
}

/// Append `bytes` to the file at `path`, as a crash mid-write leaves them.
fn tear(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    std::fs::OpenOptions::new().append(true).open(path).unwrap().write_all(bytes).unwrap();
}

/// A writer's profile with one kind, `test.tick`, and no `log.recovered`.
struct TicksOnly;

impl vmr_audit_log::profile::EntryProfile for TicksOnly {
    fn name(&self) -> &str {
        "test.ticks-only"
    }

    fn check(&self, kind: &str, _detail: &serde_json::Value) -> Result<(), vmr_audit_log::Error> {
        if kind == "test.tick" {
            Ok(())
        } else {
            Err(vmr_audit_log::Error::refused("audit_entry.structure", format!("{kind} is not a kind of test.ticks-only")))
        }
    }
}

#[test]
fn a_torn_bytes_file_never_overwrites_an_earlier_one() {
    // QA S3 (a): under a profile with no log.recovered, the torn-bytes file
    // is the only record of the moved bytes. A second crash at the same
    // offset keeps the first file and moves its bytes to a new one; the same
    // bytes again reuse the file that already holds them.
    let dir = scratch("torn-twice");
    let path = dir.join("log.jsonl");
    {
        let mut log = LogFile::open(&path, &TicksOnly, &mut |_| {}).unwrap();
        log.append(t(), "test.tick", json!({ "n": 0 })).unwrap();
    }
    let offset = std::fs::metadata(&path).unwrap().len();
    let base = PathBuf::from(format!("{}.torn-{offset}", path.display()));
    let next = PathBuf::from(format!("{}.torn-{offset}.1", path.display()));
    let recover = || {
        let (_, recovered) = LogFile::open_recovering(&path, &TicksOnly, t(), &mut |_| {}).unwrap();
        let [recovered] = <[_; 1]>::try_from(recovered).expect("one tail");
        assert!(recovered.entry.is_none(), "the profile has no log.recovered");
        recovered
    };

    tear(&path, b"{\"first");
    assert_eq!(recover().sidecar, base);
    tear(&path, b"{\"second crash");
    let second = recover();
    assert_eq!((second.sidecar.clone(), second.length), (next.clone(), 14));
    assert_eq!(std::fs::read(&base).unwrap(), b"{\"first", "the first file is kept");
    assert_eq!(std::fs::read(&next).unwrap(), b"{\"second crash");
    tear(&path, b"{\"first");
    assert_eq!(recover().sidecar, base, "the same bytes reuse the file that holds them");
    assert!(!PathBuf::from(format!("{}.torn-{offset}.2", path.display())).exists());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), offset);
}

#[test]
fn a_recovery_a_crash_cut_short_is_recorded_on_the_next_start() {
    // QA S3 (b): a crash after the truncation and before the log.recovered
    // append leaves a torn-bytes file at the log's length that no entry
    // names. The next start records it (only an entry appended after the
    // truncation could have named it, and it would have made the log longer).
    let dir = scratch("torn-unrecorded");
    let path = dir.join("log.jsonl");
    {
        let mut log = LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap();
        seed(&mut log, 2);
    }
    let offset = std::fs::metadata(&path).unwrap().len();
    let moved = b"{\"log_version\":\"0.1\",\"index\":2,";
    std::fs::write(format!("{}.torn-{offset}", path.display()), moved).unwrap();
    // The crash may also have torn the log.recovered line itself.
    let partial = b"{\"log_version\":\"0.1\",\"index\":2,\"previous";
    tear(&path, partial);

    let (log, recovered) = LogFile::open_recovering(&path, &vmr_agent::PROFILE, t(), &mut |_| {}).unwrap();
    let details: Vec<_> = recovered.iter().map(|r| (r.offset, r.length, r.sha256.clone(), r.entry.as_ref().map(|e| e.index))).collect();
    assert_eq!(
        details,
        [
            (offset, moved.len() as u64, format_hash(&sha256(moved)), Some(2)),
            (offset, partial.len() as u64, format_hash(&sha256(partial)), Some(3)),
        ]
    );
    assert_eq!(recovered[1].sidecar, PathBuf::from(format!("{}.torn-{offset}.1", path.display())));
    assert_eq!(log.len(), 4);
    drop(log);
    let entries = read_log(&std::fs::read(&path).unwrap(), &vmr_agent::PROFILE).unwrap();
    assert_eq!(entries[2].detail, json!({ "offset": offset, "length": moved.len(), "sha256": format_hash(&sha256(moved)) }));
    let (_, again) = LogFile::open_recovering(&path, &vmr_agent::PROFILE, t(), &mut |_| {}).unwrap();
    assert!(again.is_empty(), "each is recorded once");
}

#[cfg(windows)]
#[test]
fn the_torn_bytes_file_is_named_from_the_log_path_without_loss() {
    // QA N7: the name is the log's own OS string with `.torn-<offset>`
    // added, so a name that is not valid Unicode (here an unpaired UTF-16
    // surrogate) keeps its exact units.
    use std::os::windows::ffi::OsStringExt;
    let dir = scratch("torn-name");
    let name: Vec<u16> = "log-".encode_utf16().chain([0xD800]).chain(".jsonl".encode_utf16()).collect();
    let path = dir.join(std::ffi::OsString::from_wide(&name));
    {
        let mut log = LogFile::open(&path, &CORE, &mut |_| {}).unwrap();
        log.append(t(), "test.tick", json!({ "n": 0 })).unwrap();
    }
    let offset = std::fs::metadata(&path).unwrap().len();
    tear(&path, b"{\"x");
    let (_, recovered) = LogFile::open_recovering(&path, &CORE, t(), &mut |_| {}).unwrap();
    let mut expected = path.clone().into_os_string();
    expected.push(format!(".torn-{offset}"));
    assert_eq!(recovered[0].sidecar, PathBuf::from(expected.clone()));
    assert_eq!(std::fs::read(&expected).unwrap(), b"{\"x");
}

#[test]
fn any_other_refusal_is_not_repaired() {
    let dir = scratch("other");
    let path = dir.join("log.jsonl");
    {
        let mut log = LogFile::open(&path, &CORE, &mut |_| {}).unwrap();
        for i in 0..3 {
            log.append(t(), "test.tick", json!({ "n": i })).unwrap();
        }
    }
    let mut content = std::fs::read(&path).unwrap();
    content[30] ^= 0x01; // inside the first line
    content.extend_from_slice(b"{\"torn");
    std::fs::write(&path, &content).unwrap();
    let e = LogFile::open_recovering(&path, &CORE, t(), &mut |_| {}).unwrap_err();
    assert_ne!(e.id(), "audit_log.torn_tail");
    assert_eq!(std::fs::read(&path).unwrap(), content, "nothing moved, nothing truncated");
}

#[test]
fn others_may_read_the_log_while_its_writer_holds_it() {
    // QA S2: the lock is on a lock file beside the log, not on the log, so a
    // reader's handle reads the log on every system, Windows included, while
    // a second writer is still refused.
    let dir = scratch("readable");
    let path = dir.join("log.jsonl");
    let mut log = LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap();
    seed(&mut log, 2);
    let bytes = std::fs::read(&path).expect("another handle reads the log while it is held");
    assert_eq!(read_log(&bytes, &vmr_agent::PROFILE).unwrap().len(), 2);
    assert!(dir.join("log.jsonl.lock").is_file(), "the writer's lock file");
    assert_eq!(LogFile::open(&path, &vmr_agent::PROFILE, &mut |_| {}).unwrap_err().id(), "io");
    seed(&mut log, 1);
    assert_eq!(read_log(&std::fs::read(&path).unwrap(), &vmr_agent::PROFILE).unwrap().len(), 3);
}

#[test]
fn a_second_writer_is_refused_while_the_first_holds_the_lock() {
    let dir = scratch("lock");
    let path = dir.join("log.jsonl");
    let first = LogFile::open(&path, &CORE, &mut |_| {}).unwrap();
    assert_eq!(LogFile::open(&path, &CORE, &mut |_| {}).unwrap_err().id(), "io");
    drop(first);
    assert!(LogFile::open(&path, &CORE, &mut |_| {}).is_ok());
}
