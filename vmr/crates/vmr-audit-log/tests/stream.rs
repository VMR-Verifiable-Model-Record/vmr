// tests/stream.rs — the Merkle frontier and the streaming reader.
//
// A writer and a reader compute one root per entry (§4.1: every entry names
// the root of the entries before it). The frontier gives that root in
// O(log n) instead of O(n); the streaming reader checks a log fed to it in
// pieces, so a caller never holds the whole file. Neither may change a single
// answer: the frontier's root is `root_of`'s for every size, and the reader
// accepts what the whole-file reader accepted and refuses with the same id,
// the same message and at the same line, however its input is cut.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use vmr_audit_log::entry::{validate_entry, AuditEntry};
use vmr_audit_log::json::parse_json_bounded;
use vmr_audit_log::log::{read_log, LogBuilder, LogReader};
use vmr_audit_log::profile::{EntryProfile, CORE};
use vmr_audit_log::profiles::khalm_enforcer::PROFILE;
use vmr_audit_log::tree::{root_of, MerkleFrontier};
use vmr_audit_log::vmr_record::hash::{format_hash, DIGEST_LEN};
use vmr_audit_log::vmr_record::merkle::{empty_root, hash_leaf, MerkleStream};
use vmr_audit_log::{Error, MAX_ENTRY_BYTES};

// ---------------------------------------------------------------------------
//  The frontier
// ---------------------------------------------------------------------------

fn leaf(i: u64) -> [u8; DIGEST_LEN] {
    hash_leaf(format!("entry-{i}").as_bytes())
}

#[test]
fn the_frontier_root_is_root_of_for_every_size_0_to_1100() {
    let mut frontier = MerkleFrontier::new();
    let mut leaves: Vec<[u8; DIGEST_LEN]> = Vec::new();
    assert_eq!(frontier.root(), empty_root(), "the empty tree's root is SHA-256(0x02)");
    assert_eq!(frontier.size(), 0);
    for i in 0..=1100u64 {
        assert_eq!(frontier.root(), root_of(&leaves), "size {}", leaves.len());
        assert_eq!(frontier.size(), leaves.len() as u64);
        assert_eq!(MerkleFrontier::from_leaves(&leaves), frontier, "from_leaves at size {}", leaves.len());
        leaves.push(leaf(i));
        frontier.push(leaf(i));
    }
}

#[test]
fn the_frontier_root_is_root_of_at_larger_sizes() {
    let checked = [2047u64, 2048, 2049, 4095, 4096, 4097, 65_535, 65_536, 65_537, 100_003];
    let mut frontier = MerkleFrontier::new();
    let mut leaves: Vec<[u8; DIGEST_LEN]> = Vec::new();
    let mut stream = MerkleStream::new();
    for i in 0..=*checked.last().unwrap() {
        if checked.contains(&i) {
            assert_eq!(frontier.root(), root_of(&leaves), "size {i}");
            // The record format's streaming tree holds the same nodes (§4.3).
            assert_eq!(frontier.root(), stream.clone().finish(), "size {i}");
        }
        leaves.push(leaf(i));
        frontier.push(leaf(i));
        stream.push(format!("entry-{i}").as_bytes());
    }
}

// ---------------------------------------------------------------------------
//  The reference: the whole-file reader as it was before the frontier
// ---------------------------------------------------------------------------

/// `read_log` as it read before the frontier and the streaming reader,
/// computing every entry's `previous_root` from all earlier leaves. Quadratic,
/// and the reference every refusal of the new reader is held to: its id, its
/// message and so its line.
fn reference_read_log(content: &[u8], profile: &dyn EntryProfile) -> Result<Vec<AuditEntry>, Error> {
    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut leaves: Vec<[u8; DIGEST_LEN]> = Vec::new();
    let mut start = 0usize;
    while start < content.len() {
        let Some(rel) = content[start..].iter().position(|&b| b == b'\n') else {
            return Err(Error::refused(
                "audit_log.torn_tail",
                format!("bytes from offset {start} are not ended by a line feed"),
            ));
        };
        let end = start + rel;
        let line = &content[start..end];
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

/// Read `content` through a `LogReader` fed pieces of the given sizes in
/// turn (cycled), then finished. Returns what the whole-file reader returns,
/// and the frontier's size and root on success.
fn read_in_pieces(
    content: &[u8],
    profile: &dyn EntryProfile,
    sizes: &[usize],
) -> Result<(Vec<AuditEntry>, u64, [u8; DIGEST_LEN]), Error> {
    let mut reader = LogReader::new(profile);
    let mut entries = Vec::new();
    let mut at = 0usize;
    let mut turn = 0usize;
    while at < content.len() {
        let n = sizes[turn % sizes.len()].max(1).min(content.len() - at);
        turn += 1;
        entries.extend(reader.feed(&content[at..at + n])?);
        assert_eq!(reader.len(), entries.len() as u64);
        at += n;
    }
    let frontier = reader.finish()?;
    Ok((entries, frontier.size(), frontier.root()))
}

/// The reader, fed in pieces, answers exactly as the reference does.
fn assert_same_answer(content: &[u8], profile: &dyn EntryProfile, sizes: &[usize], what: &str) {
    let want = reference_read_log(content, profile);
    let got = read_in_pieces(content, profile, sizes);
    match (&want, &got) {
        (Ok(entries), Ok((read, size, root))) => {
            assert_eq!(read, entries, "{what}: pieces {sizes:?}");
            assert_eq!(*size, entries.len() as u64, "{what}");
            assert_eq!(*root, root_of(&vmr_audit_log::log::leaves_of(entries)), "{what}");
        }
        (Err(w), Err(g)) => assert_eq!(g, w, "{what}: pieces {sizes:?}"),
        _ => panic!("{what}: pieces {sizes:?}: the reference gave {want:?}, the reader {:?}", got.map(|g| g.0.len())),
    }
    // And the whole-file reader, now a wrapper over the streaming one.
    assert_eq!(read_log(content, profile), want, "{what}: read_log");
}

const PIECES: [&[usize]; 7] = [&[1], &[2], &[3], &[7], &[64], &[1, 1000, 5, 65_537], &[usize::MAX]];

fn vector_doc() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../specs/test-vectors/audit-log/cases.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn profile_of(case: &Value) -> &'static dyn EntryProfile {
    match case.get("profile").and_then(Value::as_str) {
        None => &CORE,
        Some("khalm-vmr.enforcer") => &PROFILE,
        Some(other) => panic!("unknown profile {other}"),
    }
}

#[test]
fn every_log_and_entry_vector_reads_the_same_in_any_pieces() {
    let doc = vector_doc();
    for case in doc["logs"].as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap().as_bytes();
        for sizes in PIECES {
            assert_same_answer(raw, profile_of(case), sizes, case["id"].as_str().unwrap());
        }
    }
    for case in doc["entries"].as_array().unwrap() {
        let line = format!("{}\n", case["raw"].as_str().unwrap());
        for sizes in PIECES {
            assert_same_answer(line.as_bytes(), profile_of(case), sizes, case["id"].as_str().unwrap());
        }
    }
}

/// A log of `n` entries under the core profile, as a file's bytes.
fn core_log(n: u64) -> (LogBuilder, Vec<u8>) {
    let mut log = LogBuilder::new(key_id(AUDIT_KEY));
    let mut file = Vec::new();
    for i in 0..n {
        let entry = log.append(t("2026-09-30T12:00:00Z"), "test.tick", json!({ "n": i }), &CORE).unwrap();
        file.extend_from_slice(entry.canonical.as_bytes());
        file.push(b'\n');
    }
    (log, file)
}

#[test]
fn a_log_read_in_pieces_ends_at_the_writers_root() {
    for n in [0u64, 1, 2, 3, 31, 32, 33, 200] {
        let (log, file) = core_log(n);
        for sizes in PIECES {
            let (entries, size, root) = read_in_pieces(&file, &CORE, sizes).unwrap();
            assert_eq!((entries.len() as u64, size), (n, n));
            assert_eq!(root, log.root(), "size {n}, pieces {sizes:?}");
        }
        // Every root the writer names is the reference's.
        assert_same_answer(&file, &CORE, &[13], &format!("core log of {n}"));
    }
}

#[test]
fn an_oversized_line_is_refused_for_its_length_across_pieces_and_a_torn_one_as_torn() {
    let (_, mut file) = core_log(3);
    let offset = file.len();
    // A line far over the cap, fed in pieces: refused for its whole length
    // once its line feed arrives, whatever its bytes are (§4.4 row 1).
    file.extend(vec![b'x'; MAX_ENTRY_BYTES * 3 + 5]);
    let mut ended = file.clone();
    ended.push(b'\n');
    for sizes in [&[1000usize][..], &[MAX_ENTRY_BYTES + 1], &[usize::MAX]] {
        let err = read_in_pieces(&ended, &CORE, sizes).unwrap_err();
        assert_eq!(err.id(), "audit_entry.size");
        assert!(err.to_string().contains(&format!("offset {offset} is {} bytes", MAX_ENTRY_BYTES * 3 + 5)), "{err}");
        assert_same_answer(&ended, &CORE, sizes, "oversized line");
        // Without its line feed it is a torn tail, as the whole-file reader
        // says (§4.4 row 8): the length rule reads a line, and this is none.
        let err = read_in_pieces(&file, &CORE, sizes).unwrap_err();
        assert_eq!(err.id(), "audit_log.torn_tail");
        assert_same_answer(&file, &CORE, sizes, "oversized torn tail");
    }
}

#[test]
fn a_refused_reader_stays_refused() {
    let (_, file) = core_log(4);
    let mut bad = file.clone();
    // Lines 1 and 2 swapped: line 1 is out of place (§4.4 row 6).
    let lines: Vec<&[u8]> = file.split(|&b| b == b'\n').filter(|l| !l.is_empty()).collect();
    bad.clear();
    for l in [lines[0], lines[2], lines[1], lines[3]] {
        bad.extend_from_slice(l);
        bad.push(b'\n');
    }
    let mut reader = LogReader::new(&CORE);
    let first = reader.feed(&bad).unwrap_err();
    assert_eq!(first.id(), "audit_log.index");
    assert_eq!(reader.feed(&file).unwrap_err(), first, "more bytes never clear a refusal");
    assert_eq!(reader.finish().unwrap_err(), first);
}

// ---------------------------------------------------------------------------
//  Mutants: the reader in pieces against the reference
// ---------------------------------------------------------------------------

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 11
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

const INTERESTING: [u8; 8] = [b'\n', b'"', b'{', b'}', b'0', b'\\', 0x80, b' '];

fn mutate(rng: &mut Lcg, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(3) {
        let len = b.len();
        match rng.below(6) {
            0 if len > 0 => {
                let i = rng.below(len);
                b[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                b[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => b.truncate(rng.below(len + 1)),
            3 => {
                let i = rng.below(len + 1);
                b.insert(i, INTERESTING[rng.below(INTERESTING.len())]);
            }
            4 if len > 0 => {
                // A run of the file copied elsewhere: a line repeated or split.
                let (i, n) = (rng.below(len), 1 + rng.below(400));
                let run: Vec<u8> = b[i..(i + n).min(len)].to_vec();
                let at = rng.below(len + 1);
                b.splice(at..at, run);
            }
            _ if len > 0 => {
                let (i, n) = (rng.below(len), 1 + rng.below(400));
                b.drain(i..(i + n).min(len));
            }
            _ => {}
        }
    }
    b
}

#[test]
fn mutated_logs_read_in_random_pieces_answer_as_the_reference_does() {
    let (_, seeded) = {
        let (log, lines) = seeded_log();
        (log, file_of(&lines).into_bytes())
    };
    let (_, core) = core_log(12);
    let seeds: [(&[u8], &dyn EntryProfile); 3] =
        [(seeded.as_slice(), &PROFILE), (core.as_slice(), &CORE), (seeded.as_slice(), &CORE)];
    let mut rng = Lcg(0x5357_0001);
    let mut accepted = 0;
    for i in 0..3_000 {
        let (seed, profile) = seeds[rng.below(seeds.len())];
        let mutant = mutate(&mut rng, seed);
        let sizes: Vec<usize> = (0..4).map(|_| 1 + rng.below(300)).collect();
        if reference_read_log(&mutant, profile).is_ok() {
            accepted += 1;
        }
        assert_same_answer(&mutant, profile, &sizes, &format!("mutant {i}"));
    }
    eprintln!("stream: {accepted} of 3000 mutated logs accepted; every answer the reference's");
}
