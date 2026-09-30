// tests/scale.rs — a long log written and read, and the time it takes.
//
// Every entry names the root of the entries before it (§4.1), so a writer and
// a reader compute a root once per entry. Computed from every earlier leaf,
// that is quadratic in the log's length; kept as a Merkle frontier, each root
// is O(log n) and each append amortised O(1) node hashes. This test writes a
// log of small entries with `LogBuilder`, reads it back with `read_log`, and
// prints both times. It is a measurement, not a gate: run it in release,
//
//     cargo test --release -p vmr-audit-log --test scale -- --ignored --nocapture
//
// with VMR_SCALE_ENTRIES to choose another length (default 1 000 000).

use serde_json::json;
use vmr_audit_log::log::{read_log, LogBuilder};
use vmr_audit_log::profile::CORE;
use vmr_audit_log::vmr_record::hash::format_hash;
use vmr_audit_log::vmr_record::timestamp::Timestamp;

/// The log's length: VMR_SCALE_ENTRIES, else one million.
#[allow(clippy::disallowed_methods)] // a measurement's size, chosen by whoever runs it; no document depends on it
fn entries() -> u64 {
    std::env::var("VMR_SCALE_ENTRIES").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000)
}

#[test]
#[ignore = "a measurement: run with --release -- --ignored --nocapture"]
#[allow(clippy::disallowed_methods)] // Instant::now: this test measures time; nothing it measures reaches a document
fn a_long_log_is_written_and_read_in_time_linear_in_its_length() {
    let n = entries();
    let at = Timestamp::parse("2026-09-30T12:00:00Z").unwrap();

    let started = std::time::Instant::now();
    let mut log = LogBuilder::new("urn:ietf:params:oauth:jwk-thumbprint:sha-256:scale-test");
    let mut file: Vec<u8> = Vec::new();
    for i in 0..n {
        let entry = log.append(at, "test.tick", json!({ "n": i }), &CORE).unwrap();
        file.extend_from_slice(entry.canonical.as_bytes());
        file.push(b'\n');
    }
    let written = started.elapsed();

    let started = std::time::Instant::now();
    let entries = read_log(&file, &CORE).unwrap();
    let read = started.elapsed();

    assert_eq!(entries.len() as u64, n);
    assert_eq!(entries.last().map(|e| e.index), n.checked_sub(1));
    // The reader and the writer agree on every root: the last entry names the
    // root of all before it, and the writer's root covers them all.
    let rebuilt = LogBuilder::with_entries(log.log_id(), &entries);
    assert_eq!(format_hash(&rebuilt.root()), format_hash(&log.root()));
    eprintln!(
        "scale: {n} entries, {} bytes: written in {:.3} s, read in {:.3} s",
        file.len(),
        written.as_secs_f64(),
        read.as_secs_f64()
    );
}
