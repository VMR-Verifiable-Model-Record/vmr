// tests/portable.rs — task 10.13a, commit B10 (docs/dev/task-10.13a.md §4.1,
// §4.2, §12): the same folder gives the same model_hash on every system.
//
// The portable rows of §4.2 are generated here, in a scratch directory, from
// names and patterned bytes. The walk's model_hash must equal a constant that
// an independent recomputation, sharing no code with this crate, computed
// over the folder `write_portable_fixture` writes. Both CI lanes run this
// test with no workflow change (Linux on every push, Windows weekly), so both
// pass only if both systems give that constant.
//
// The rows, as §4.2 numbers them:
//   P1  a five-level path, `a/b/c/d/e/weights.bin`;
//   P2  order traps: `B`, `_`, `a b`, `a-b`, `a.b`, a file in `a/` (P1's),
//       `a0`, `~` (`B`, not `A`: on a case-insensitive folder a file `A` is
//       the directory `a`);
//   P3  non-ASCII names, U+FF5E and U+1F600 among them;
//   P4  `é.bin` composed and decomposed: two members;
//   P5  an empty file and an empty directory (the directory is no member);
//   P6  `.hidden`, `.gitattributes`, `.git/config`, `.cache/...`: all members;
//   P7  `a..b` (not `...`: Windows cannot hold a name that ends in a dot);
//   P8  a name over 260 UTF-16 units;
//   P9  5,000 files in 50 directories;
//   P10 a hard link: two members, one content;
//   P11 spaces and brackets;
//   P12 sizes 1 MiB - 1, 1 MiB and 1 MiB + 1 around the read buffer.
//   S1  P1's file given alone is named by its own name.
// Rows only one system can create (links without Windows' privilege, names
// that are not Unicode, `\` and `:` in a name, case twins, pipes) are in
// tests/walk.rs; they are not portable, so they are not pinned here.

use std::path::{Path, PathBuf};
use vmr_builder::files::read_model;
use vmr_record::hash::{format_hash, sha256};

/// The independent recomputation's model_hash of the portable fixture, computed
/// on 2026-09-15 over the folder `write_portable_fixture` wrote: on Windows (NTFS,
/// Python 3.12.10) and on Linux (a tmpfs copy and drvfs, Python 3.12.3), the
/// same value.
const PORTABLE_MODEL_HASH: &str = "sha256:0fa4271b0b7b71fddb65164751c83974ee11c6724002829399f79a98403b2c67";
/// The fixture's files: 21 small, the empty file, 5,000, the hard link, 3 sizes.
const PORTABLE_FILES: usize = 5026;
/// The fixture's bytes: 22 files of 97, 5,000 of 16, and 3 MiB (3,227,862).
const PORTABLE_BYTES: u64 = 22 * 97 + 5000 * 16 + 3 * (1 << 20);
/// The same recomputation's model_hash of P1's file given alone (S1), on the
/// same systems.
const ONE_FILE_MODEL_HASH: &str = "sha256:fd3c4c142e0268c585fd0285033849002baf5c173508996a02a2107c9043cc11";

const MIB: usize = 1 << 20;
const P1: &str = "a/b/c/d/e/weights.bin";

/// A fresh scratch directory for one test, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Scratch {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("vmr-builder-portable").join(format!("{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `len` bytes derived from `name` (tests/walk.rs's pattern): no two files
/// share their bytes by accident.
fn pattern(name: &str, len: usize) -> Vec<u8> {
    let seed = sha256(name.as_bytes());
    let mut state = u64::from_le_bytes(seed[..8].try_into().unwrap()) | 1;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u8
        })
        .collect()
}

/// Write `name` (a `/`-separated path) under `root` with `bytes`.
fn put(root: &Path, name: &str, bytes: &[u8]) {
    let path = name.split('/').fold(root.to_path_buf(), |p, s| p.join(s));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// P8: a name of 360 UTF-16 units in ten segments, each under NTFS's 255.
fn long_name() -> String {
    let segments: Vec<String> = (0..8).map(|i| format!("segment-{i}-{}", "x".repeat(32))).collect();
    format!("long/{}/weights.bin", segments.join("/"))
}

/// Write the portable fixture under `root`; the number of files and bytes.
fn write_fixture(root: &Path) -> (usize, u64) {
    let mut small: Vec<String> = [
        P1,                                                         // P1; P2's file in `a/`
        "B", "_", "a b", "a-b", "a.b", "a0", "~",                   // P2
        "donn\u{e9}es/mod\u{e8}le.bin", "\u{6a21}\u{578b}/\u{6743}\u{91cd}.bin", "\u{ff5e}", "\u{1f600}", // P3
        "\u{e9}.bin", "e\u{301}.bin",                               // P4
        ".hidden", ".gitattributes", ".git/config", ".cache/huggingface/download/x.metadata", // P6
        "a..b",                                                     // P7
        "training/A mushroom in [V] style.png",                     // P11
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    small.push(long_name()); // P8
    let (mut files, mut bytes) = (0usize, 0u64);
    for name in &small {
        put(root, name, &pattern(name, 97));
        (files, bytes) = (files + 1, bytes + 97);
    }
    put(root, "empty.bin", b""); // P5
    std::fs::create_dir_all(root.join("empty-dir").join("nested")).unwrap();
    files += 1;
    for i in 0..5000 {
        let name = format!("shard-{:02}/part-{i:05}.bin", i % 50); // P9
        put(root, &name, &pattern(&name, 16));
        (files, bytes) = (files + 1, bytes + 16);
    }
    std::fs::hard_link(root.join("B"), root.join("B-hard-link")).unwrap(); // P10
    (files, bytes) = (files + 1, bytes + 97);
    for size in [MIB - 1, MIB, MIB + 1] {
        let name = format!("size-{size}.bin"); // P12
        put(root, &name, &pattern(&name, size));
        (files, bytes) = (files + 1, bytes + size as u64);
    }
    (files, bytes)
}

#[test]
fn the_portable_fixture_digest_is_pinned() {
    let s = Scratch::new("pinned");
    let root = s.0.join("fixture");
    let written = write_fixture(&root);
    assert_eq!(written, (PORTABLE_FILES, PORTABLE_BYTES), "the generator writes what the constants count");
    let set = read_model(&root).unwrap();
    assert_eq!((set.len(), set.total_bytes()), (PORTABLE_FILES, PORTABLE_BYTES), "every file, hidden ones included");
    assert_eq!(
        format_hash(&set.named_set_digest()),
        PORTABLE_MODEL_HASH,
        "the walk's model_hash of the portable fixture is the independent recomputation's"
    );
    let one = read_model(&P1.split('/').fold(root.clone(), |p, s| p.join(s))).unwrap();
    assert_eq!(one.entries().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["weights.bin"]);
    assert_eq!(format_hash(&one.named_set_digest()), ONE_FILE_MODEL_HASH, "S1: one file, named by its own name");
}

/// Writes the fixture where an independent recomputation can read it: the
/// constants above come from that folder, never from this crate's walk.
#[test]
#[ignore = "writes the portable fixture; run with VMR_BUILDER_FIXTURE_DIR=<a directory that does not exist yet>"]
#[allow(clippy::disallowed_methods)] // the opt-in directory is this test's input
fn write_portable_fixture() {
    let Some(dir) = std::env::var_os("VMR_BUILDER_FIXTURE_DIR") else {
        eprintln!("VMR_BUILDER_FIXTURE_DIR is not set: nothing written");
        return;
    };
    let root = PathBuf::from(dir);
    assert!(!root.exists(), "{} exists: the fixture is written into a new directory", root.display());
    let (files, bytes) = write_fixture(&root);
    eprintln!("wrote the portable fixture: {files} files, {bytes} bytes, in {}", root.display());
}
