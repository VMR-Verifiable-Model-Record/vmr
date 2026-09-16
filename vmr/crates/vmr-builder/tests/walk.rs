// tests/walk.rs — task 10.13a, commits B4/B5 (docs/dev/task-10.13a.md §4.2,
// §12): naming and hashing a model's files from a folder or one file, by spec
// §7.2 as settled on main.
//
// Every folder is made here, in a scratch directory under
// CARGO_TARGET_TMPDIR, from names and patterned bytes; every expected digest
// is computed here from those names and bytes with the format crate's own
// named-set digest, never read back from the walk under test. A case the
// operating system cannot create (a symbolic link without Windows' privilege,
// two names differing only in case on a case-insensitive folder) prints
// "not run" and makes no claim.

use std::path::{Path, PathBuf};
use vmr_builder::files::{read_folder, read_folder_observed, read_model, read_model_observed, WalkError, WalkObserver};
use vmr_builder::general::DigestSource;
use vmr_record::hash::{format_hash, sha256, DIGEST_LEN};
use vmr_record::named_set::named_set_digest;

/// A fresh scratch directory for one test, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Scratch {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("vmr-builder-walk").join(format!("{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn dir(&self, rel: &str) -> PathBuf {
        let p = self.0.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `len` bytes derived from `name`: no two files share their bytes by accident.
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

/// What an observer of the walk was told, in order.
#[derive(Default)]
struct Seen {
    listed: Vec<(u64, Option<u64>)>,
    started: Vec<(u64, String, u64)>,
    bytes: u64,
    /// The bytes told after each file's start and before the next one's.
    per_file: Vec<u64>,
}

impl WalkObserver for Seen {
    fn listed(&mut self, files: u64, total_bytes: Option<u64>) {
        self.listed.push((files, total_bytes));
    }

    fn file_started(&mut self, index: u64, name: &str, size: u64) {
        self.started.push((index, name.to_string(), size));
        self.per_file.push(0);
    }

    fn bytes_read(&mut self, n: u64) {
        self.bytes += n;
        if let Some(current) = self.per_file.last_mut() {
            *current += n;
        }
    }

    fn wants_total(&self) -> bool {
        true
    }
}

#[test]
fn an_observer_sees_the_walk_and_changes_nothing() {
    // docs/dev/cli-polish.md CP-6: the walk tells an observer its file count
    // and total size, each file as it starts and every byte it reads, and
    // nothing else; the file set, its order and model_hash are the same with
    // and without one.
    let s = Scratch::new("observer");
    let root = s.dir("model");
    let names = ["b.bin", "a/one.json", "a/two.safetensors", "z"];
    let sizes = [3000usize, 10, (1 << 20) + 7, 0];
    for (name, size) in names.iter().zip(sizes) {
        put(&root, name, &pattern(name, size));
    }
    let plain = read_model(&root).unwrap();
    let mut seen = Seen::default();
    let observed = read_model_observed(&root, &mut seen).unwrap();
    assert_eq!(observed.named_set_digest(), plain.named_set_digest());
    let listing = |set: &vmr_builder::general::FileSet| -> Vec<(String, u64)> {
        set.entries().iter().map(|e| (e.name.clone(), e.size_bytes)).collect()
    };
    assert_eq!(listing(&observed), listing(&plain));
    let total: u64 = sizes.iter().map(|size| *size as u64).sum();
    assert_eq!(seen.listed, [(4, Some(total))]);
    let started: Vec<(u64, String, u64)> =
        listing(&plain).into_iter().enumerate().map(|(i, (name, size))| (i as u64, name, size)).collect();
    assert_eq!(seen.started, started);
    assert_eq!(seen.bytes, total);
    // QA QPB-01 (MB7): each file's bytes are told while that file is read,
    // between its start and the next file's.
    let sizes: Vec<u64> = listing(&plain).into_iter().map(|(_, size)| size).collect();
    assert_eq!(seen.per_file, sizes);

    // QA QPB-03: an observer that does not ask for the total is told none, and
    // the walk reads no size for it.
    #[derive(Default)]
    struct Uncounted {
        listed: Vec<(u64, Option<u64>)>,
    }
    impl WalkObserver for Uncounted {
        fn listed(&mut self, files: u64, total_bytes: Option<u64>) {
            self.listed.push((files, total_bytes));
        }
    }
    let mut uncounted = Uncounted::default();
    assert_eq!(read_model_observed(&root, &mut uncounted).unwrap().named_set_digest(), plain.named_set_digest());
    assert_eq!(uncounted.listed, [(4, None)]);

    // One file given, and a folder read as training records, are observed
    // the same way.
    let mut one = Seen::default();
    let file = read_model_observed(&root.join("b.bin"), &mut one).unwrap();
    assert_eq!(file.named_set_digest(), read_model(&root.join("b.bin")).unwrap().named_set_digest());
    assert_eq!(one.listed, [(1, Some(3000))]);
    assert_eq!((one.started.len(), one.bytes), (1, 3000));
    let mut folder = Seen::default();
    assert_eq!(read_folder_observed(&root, &mut folder).unwrap().named_set_digest(), plain.named_set_digest());
    assert_eq!(folder.bytes, total);
}

/// The named-set digest of `(name, bytes)` members, computed here.
fn expected_digest(members: &[(&str, Vec<u8>)]) -> String {
    let mut sorted: Vec<(&str, [u8; DIGEST_LEN])> = members.iter().map(|(n, b)| (*n, sha256(b))).collect();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    format_hash(&named_set_digest(&sorted).unwrap())
}

fn names(set: &vmr_builder::general::FileSet) -> Vec<String> {
    set.entries().iter().map(|e| e.name.clone()).collect()
}

#[test]
fn a_folder_names_every_file_by_its_path_with_slashes_in_utf8_order() {
    let s = Scratch::new("naming");
    let root = s.dir("model");
    // `B`, not `A`: on a case-insensitive folder a file `A` is the directory
    // `a` below. Upper case still sorts before `_` and lower case.
    let mut listed = vec![
        "a/b/c/d/e/weights.bin",
        "B",
        "_",
        "a b",
        "a-b",
        "a.b",
        "a0",
        "~",
        "config.json",
        "donn\u{e9}es/mod\u{e8}le.bin",
        "\u{6a21}\u{578b}/\u{6743}\u{91cd}.bin",
        "\u{ff5e}.txt",
        "\u{1f600}.txt",
        ".hidden",
        ".gitattributes",
        ".git/config",
        ".cache/huggingface/download/x.metadata",
        "a..b",
        "training/A mushroom in [V] style.png",
    ];
    // `...` is a name Windows cannot hold (it drops a name's trailing dots):
    // a Unix-only member.
    if cfg!(unix) {
        listed.push("...");
    }
    let members: Vec<(&str, Vec<u8>)> = listed.iter().map(|n| (*n, pattern(n, 97))).collect();
    for (n, b) in &members {
        put(&root, n, b);
    }
    put(&root, "empty.bin", b"");
    std::fs::create_dir_all(root.join("empty-dir/nested")).unwrap();
    let mut all = members.clone();
    all.push(("empty.bin", Vec::new()));

    let set = read_model(&root).unwrap();
    let mut want: Vec<String> = all.iter().map(|(n, _)| n.to_string()).collect();
    want.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(names(&set), want, "every regular file, hidden ones included, no directory, by UTF-8 bytes");
    assert_eq!(format_hash(&set.named_set_digest()), expected_digest(&all));
    for (n, b) in &all {
        let e = set.get(n).unwrap();
        assert_eq!((e.digest, e.size_bytes), (sha256(b), b.len() as u64), "{n}");
        assert_eq!(e.source, DigestSource::Read { through_link: false });
    }
    // U+FF5E before U+1F600 (spec §7.2), `a b` < `a-b` < `a.b` < `a/b/...` < `a0`.
    let pos = |n: &str| want.iter().position(|w| w == n).unwrap();
    assert!(pos("\u{ff5e}.txt") < pos("\u{1f600}.txt"));
    assert!(pos("a b") < pos("a-b") && pos("a-b") < pos("a.b") && pos("a.b") < pos("a/b/c/d/e/weights.bin") && pos("a/b/c/d/e/weights.bin") < pos("a0"));
}

#[test]
fn a_model_given_as_one_file_is_named_by_its_own_name_and_a_folder_by_paths() {
    let s = Scratch::new("one-file");
    let root = s.dir("downloads/deep");
    let bytes = pattern("model.gguf", 1000);
    put(&root, "model.gguf", &bytes);
    let one = read_model(&root.join("model.gguf")).unwrap();
    assert_eq!(names(&one), ["model.gguf"]);
    assert_eq!(format_hash(&one.named_set_digest()), expected_digest(&[("model.gguf", bytes.clone())]));
    // A folder that holds one file names it by its path in the folder.
    let folder = s.dir("wrapped");
    put(&folder, "sub/model.gguf", &bytes);
    assert_eq!(names(&read_model(&folder).unwrap()), ["sub/model.gguf"]);
    // Training records are always a folder.
    assert!(matches!(read_folder(&root.join("model.gguf")), Err(WalkError::NotAFolder { .. })));
}

#[test]
fn the_order_a_directory_lists_its_entries_never_changes_anything() {
    let s = Scratch::new("order");
    let files: Vec<String> = (0..40).map(|i| format!("d{}/f{:02}.bin", i % 4, (i * 7) % 40)).collect();
    let forward = s.dir("forward");
    let reverse = s.dir("reverse");
    for f in &files {
        put(&forward, f, &pattern(f, 33));
    }
    for f in files.iter().rev() {
        put(&reverse, f, &pattern(f, 33));
    }
    assert_eq!(read_model(&forward).unwrap(), read_model(&reverse).unwrap());
}

#[test]
fn a_file_set_keeps_nfc_and_nfd_names_apart_and_case_twins_where_they_can_exist() {
    let s = Scratch::new("unicode");
    let root = s.dir("m");
    put(&root, "\u{e9}.bin", b"nfc");
    put(&root, "e\u{301}.bin", b"nfd");
    let set = read_model(&root).unwrap();
    assert_eq!(set.len(), 2, "names are taken as stored, never normalised: {:?}", names(&set));
    let twins = s.dir("twins");
    put(&twins, "README.md", b"upper");
    std::fs::write(twins.join("readme.md"), b"lower").unwrap();
    let entries = std::fs::read_dir(&twins).unwrap().count();
    if entries == 2 {
        let set = read_model(&twins).unwrap();
        assert_eq!(names(&set), ["README.md", "readme.md"], "no case folding");
    } else {
        eprintln!("not run: this folder is case-insensitive, so README.md and readme.md are one file");
    }
}

#[test]
fn a_hard_link_is_two_members_and_an_empty_folder_is_an_empty_set() {
    let s = Scratch::new("hardlink");
    let root = s.dir("m");
    put(&root, "a.bin", b"shared bytes");
    std::fs::hard_link(root.join("a.bin"), root.join("b.bin")).unwrap();
    let set = read_model(&root).unwrap();
    assert_eq!(names(&set), ["a.bin", "b.bin"]);
    assert_eq!(set.entries()[0].digest, set.entries()[1].digest);
    let empty = s.dir("empty/only-dirs/deeper");
    let _ = empty;
    assert!(read_model(&s.0.join("empty")).unwrap().is_empty());
}

#[test]
fn sizes_around_the_read_buffer_hash_exactly() {
    let s = Scratch::new("sizes");
    let root = s.dir("m");
    let mib = 1 << 20;
    let members: Vec<(String, Vec<u8>)> = [0, 1, mib - 1, mib, mib + 1, 3 * mib + 17]
        .iter()
        .map(|&n| (format!("size-{n}.bin"), pattern(&format!("size-{n}"), n)))
        .collect();
    for (n, b) in &members {
        put(&root, n, b);
    }
    let set = read_model(&root).unwrap();
    for (n, b) in &members {
        let e = set.get(n).unwrap();
        assert_eq!((e.digest, e.size_bytes), (sha256(b), b.len() as u64), "{n}");
    }
}

#[test]
fn thousands_of_files_in_many_folders() {
    let s = Scratch::new("thousands");
    let root = s.dir("m");
    let members: Vec<(String, Vec<u8>)> = (0..5000).map(|i| (format!("shard-{:02}/part-{i:05}.bin", i % 50), pattern(&i.to_string(), 16))).collect();
    for (n, b) in &members {
        put(&root, n, b);
    }
    let set = read_model(&root).unwrap();
    assert_eq!(set.len(), 5000);
    let refs: Vec<(&str, Vec<u8>)> = members.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    assert_eq!(format_hash(&set.named_set_digest()), expected_digest(&refs));
}

#[test]
fn a_folder_that_is_not_there_or_not_a_folder_is_refused() {
    let s = Scratch::new("missing");
    assert!(matches!(read_model(&s.0.join("no-such-model")), Err(WalkError::Unreadable { .. })));
    assert!(matches!(read_folder(&s.0.join("no-such-records")), Err(WalkError::Unreadable { .. })));
}

// --- links ------------------------------------------------------------------

/// Make a symbolic link to a file; `false` if this system does not let us.
fn file_link(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, link);
    match made {
        Ok(()) => true,
        Err(e) => {
            eprintln!("not run: cannot create a symbolic link here ({e})");
            false
        }
    }
}

#[test]
fn a_link_to_a_regular_file_is_hashed_as_that_file_under_the_links_own_name() {
    let s = Scratch::new("file-links");
    let blobs = s.dir("blobs");
    put(&blobs, "0a1b2c", &pattern("weights", 4096));
    put(&blobs, "3d4e5f", &pattern("config", 64));
    // A hub-cache layout: the snapshot's names are links to blobs outside it.
    let snapshot = s.dir("snapshots/rev");
    std::fs::create_dir_all(snapshot.join("sub")).unwrap();
    if !file_link(&blobs.join("0a1b2c"), &snapshot.join("sub/model.safetensors")) {
        return;
    }
    assert!(file_link(&blobs.join("3d4e5f"), &snapshot.join("config.json")));
    let set = read_model(&snapshot).unwrap();
    assert_eq!(names(&set), ["config.json", "sub/model.safetensors"]);
    assert!(set.entries().iter().all(|e| e.source == DigestSource::Read { through_link: true }));
    // The same names over plain copies: the same model_hash.
    let plain = s.dir("plain");
    put(&plain, "sub/model.safetensors", &pattern("weights", 4096));
    put(&plain, "config.json", &pattern("config", 64));
    assert_eq!(read_model(&snapshot).unwrap().named_set_digest(), read_model(&plain).unwrap().named_set_digest());
    // A model given as one link is named by the link's own name.
    let one = read_model(&snapshot.join("config.json")).unwrap();
    assert_eq!(names(&one), ["config.json"]);
}

#[cfg(unix)]
#[test]
fn a_link_to_a_directory_to_nothing_or_through_a_loop_refuses_the_folder() {
    use std::os::unix::fs::symlink;
    let s = Scratch::new("bad-links");
    let to_dir = s.dir("to-dir");
    put(&to_dir, "real.bin", b"x");
    std::fs::create_dir_all(s.0.join("elsewhere")).unwrap();
    symlink(s.0.join("elsewhere"), to_dir.join("linked-dir")).unwrap();
    assert!(matches!(read_model(&to_dir), Err(WalkError::LinkToDirectory { .. })));

    let dangling = s.dir("dangling");
    put(&dangling, "real.bin", b"x");
    symlink(s.0.join("no-such-target"), dangling.join("gone.bin")).unwrap();
    assert!(matches!(read_model(&dangling), Err(WalkError::LinkToNothing { .. })));

    let looped = s.dir("loop");
    symlink(looped.join("b"), looped.join("a")).unwrap();
    symlink(looped.join("a"), looped.join("b")).unwrap();
    let err = read_model(&looped).unwrap_err();
    assert!(matches!(err, WalkError::LinkUnresolved { .. }), "{err}");
    assert!(err.to_string().contains("loop"), "{err}");
}

#[cfg(windows)]
#[test]
fn a_directory_junction_is_a_link_and_refuses_the_folder() {
    let s = Scratch::new("junction");
    let root = s.dir("m");
    put(&root, "real.bin", b"x");
    let target = s.dir("elsewhere");
    put(&target, "inside.bin", b"y");
    // cmd reads a `/` in a path as a switch, and CARGO_TARGET_TMPDIR may be
    // spelled with `/` (a target directory given from Git Bash): mklink is
    // given `\` only.
    let native = |p: &Path| p.to_string_lossy().replace('/', "\\");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(native(&root.join("junction")))
        .arg(native(&target))
        .output()
        .unwrap();
    assert!(status.status.success(), "mklink /J needs no privilege: {}", String::from_utf8_lossy(&status.stderr));
    let err = read_model(&root).unwrap_err();
    assert!(matches!(err, WalkError::LinkToDirectory { .. }), "a junction is a link (spec §7.2): {err}");
    // A junction whose target is gone resolves to nothing.
    std::fs::remove_dir_all(&target).unwrap();
    let err = read_model(&root).unwrap_err();
    assert!(matches!(err, WalkError::LinkToNothing { .. } | WalkError::LinkUnresolved { .. }), "{err}");
}

#[cfg(windows)]
#[test]
fn an_ntfs_alternate_data_stream_is_not_a_file_of_the_model() {
    let s = Scratch::new("ads");
    let root = s.dir("m");
    put(&root, "weights.bin", b"main stream");
    let before = read_model(&root).unwrap();
    std::fs::write(root.join("weights.bin:Zone.Identifier"), b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
    assert_eq!(read_model(&root).unwrap(), before, "a stream is not a directory entry");
}

// --- what is not a regular file, and names that are not Unicode -------------

#[cfg(unix)]
#[test]
fn a_pipe_or_a_socket_is_not_a_regular_file() {
    let s = Scratch::new("special");
    let root = s.dir("fifo");
    put(&root, "real.bin", b"x");
    let made = std::process::Command::new("mkfifo").arg(root.join("pipe")).status().unwrap();
    assert!(made.success());
    assert!(matches!(read_model(&root), Err(WalkError::NotRegular { .. })));
    let sock_root = s.dir("sock");
    let _listener = std::os::unix::net::UnixListener::bind(sock_root.join("s.sock")).unwrap();
    assert!(matches!(read_model(&sock_root), Err(WalkError::NotRegular { .. })));
    // A link to a pipe resolves to something that is not a regular file.
    let link_root = s.dir("link-to-pipe");
    std::os::unix::fs::symlink(root.join("pipe"), link_root.join("p")).unwrap();
    assert!(matches!(read_model(&link_root), Err(WalkError::NotRegular { .. })));
}

#[cfg(unix)]
#[test]
fn a_name_that_is_not_utf8_refuses_the_folder() {
    use std::os::unix::ffi::OsStrExt;
    let s = Scratch::new("not-utf8");
    let root = s.dir("m");
    put(&root, "fine.bin", b"x");
    std::fs::write(root.join(std::ffi::OsStr::from_bytes(b"bad-\xff.bin")), b"y").unwrap();
    assert!(matches!(read_model(&root), Err(WalkError::NameNotUnicode { .. })));
}

#[cfg(windows)]
#[test]
fn a_name_with_an_unpaired_surrogate_refuses_the_folder() {
    use std::os::windows::ffi::OsStringExt;
    let s = Scratch::new("surrogate");
    let root = s.dir("m");
    put(&root, "fine.bin", b"x");
    let name = std::ffi::OsString::from_wide(&[0x62, 0xD800, 0x2E, 0x62]);
    std::fs::write(root.join(name), b"y").unwrap();
    assert!(matches!(read_model(&root), Err(WalkError::NameNotUnicode { .. })));
}

// QA QM-03: spec §7.2 refuses a folder that holds a FILE whose name is not a
// sequence of Unicode scalar values. A directory with such a name that holds
// no file contributes no member and refuses nothing; a file below it has such
// a name (its path in the folder), and refuses the folder.

#[cfg(unix)]
#[test]
fn a_directory_whose_name_is_not_utf8_contributes_nothing_until_it_holds_a_file() {
    use std::os::unix::ffi::OsStrExt;
    let s = Scratch::new("not-utf8-dir");
    let root = s.dir("m");
    put(&root, "fine.bin", b"x");
    let bad = root.join(std::ffi::OsStr::from_bytes(b"dir-\xfe"));
    std::fs::create_dir_all(bad.join("empty-below")).unwrap();
    let set = read_model(&root).unwrap();
    assert_eq!(names(&set), ["fine.bin"], "an empty directory is not a member, whatever its name");
    assert_eq!(format_hash(&set.named_set_digest()), expected_digest(&[("fine.bin", b"x".to_vec())]));
    std::fs::write(bad.join("empty-below").join("inside.bin"), b"y").unwrap();
    assert!(matches!(read_model(&root), Err(WalkError::NameNotUnicode { .. })), "a file whose name is not Unicode");
}

#[cfg(windows)]
#[test]
fn a_directory_whose_name_has_an_unpaired_surrogate_contributes_nothing_until_it_holds_a_file() {
    use std::os::windows::ffi::OsStringExt;
    let s = Scratch::new("surrogate-dir");
    let root = s.dir("m");
    put(&root, "fine.bin", b"x");
    let bad = root.join(std::ffi::OsString::from_wide(&[0x64, 0x69, 0x72, 0x2D, 0xDC00]));
    std::fs::create_dir_all(bad.join("empty-below")).unwrap();
    let set = read_model(&root).unwrap();
    assert_eq!(names(&set), ["fine.bin"], "an empty directory is not a member, whatever its name");
    assert_eq!(format_hash(&set.named_set_digest()), expected_digest(&[("fine.bin", b"x".to_vec())]));
    std::fs::write(bad.join("empty-below").join("inside.bin"), b"y").unwrap();
    assert!(matches!(read_model(&root), Err(WalkError::NameNotUnicode { .. })), "a file whose name is not Unicode");
}

// --- one file given by a path spelled otherwise than its folder lists it -----

/// Spec §7.2's example of a model of one file: `weights.bin`, four zero bytes.
const ONE_FILE_EXAMPLE: &str = "sha256:c32b0039edc7ed971446e62f8701b5a835f9c15b3fbac208f318e2626b9650ea";

#[test]
fn a_one_file_model_given_by_another_spelling_is_named_as_its_folder_stores_it() {
    // QA QM-01: on a case-insensitive file system (NTFS, and drvfs from WSL) a
    // path typed WEIGHTS.BIN opens the file stored as weights.bin. Spec §7.2
    // takes each name as the file system stores it, so the model is the one the
    // stored name gives on every system.
    let s = Scratch::new("typed-spelling");
    let root = s.dir("m");
    put(&root, "weights.bin", &[0u8; 4]);
    let stored = read_model(&root.join("weights.bin")).unwrap();
    assert_eq!(names(&stored), ["weights.bin"]);
    assert_eq!(format_hash(&stored.named_set_digest()), ONE_FILE_EXAMPLE);
    let typed = root.join("WEIGHTS.BIN");
    if !typed.exists() {
        eprintln!("not run: this folder is case-sensitive, so WEIGHTS.BIN does not open weights.bin");
        return;
    }
    let set = read_model(&typed).unwrap();
    assert_eq!(names(&set), ["weights.bin"], "the name its folder lists, not the one typed");
    assert_eq!(format_hash(&set.named_set_digest()), ONE_FILE_EXAMPLE, "the model_hash the stored name gives");
}

#[cfg(unix)]
#[test]
fn an_unreadable_file_refuses_the_folder() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new("unreadable");
    let root = s.dir("m");
    put(&root, "locked.bin", b"secret");
    std::fs::set_permissions(root.join("locked.bin"), std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(root.join("locked.bin")).is_ok() {
        eprintln!("not run: this user reads a mode-000 file (root)");
        return;
    }
    assert!(matches!(read_model(&root), Err(WalkError::Unreadable { .. })));
    std::fs::set_permissions(root.join("locked.bin"), std::fs::Permissions::from_mode(0o600)).unwrap();
}

// --- size -------------------------------------------------------------------

/// X1 (plan §4.2): one file of 4 GiB + 1 bytes, patterned, hashed by
/// streaming. Written into the directory named by VMR_BUILDER_BIG_DIR (on D:
/// for this project), then removed; the expected digest is computed here, as
/// the bytes are written, with the sha2 crate's own streaming SHA-256.
#[test]
#[ignore = "writes a file of 4 GiB + 1 bytes; run with VMR_BUILDER_BIG_DIR=<a directory with 5 GB free>"]
#[allow(clippy::disallowed_methods)] // the opt-in directory is this test's input
fn a_file_over_4_gib_streams() {
    use sha2::{Digest, Sha256};
    let Some(dir) = std::env::var_os("VMR_BUILDER_BIG_DIR") else {
        eprintln!("VMR_BUILDER_BIG_DIR is not set: nothing written");
        return;
    };
    let root = PathBuf::from(dir).join(format!("vmr-builder-x1-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("weights.bin");
    let size: u64 = (4u64 << 30) + 1;
    let mut hasher = Sha256::new();
    {
        use std::io::Write;
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let block = pattern("x1-block", 1 << 20);
        let mut left = size;
        let mut i: u64 = 0;
        while left > 0 {
            let n = left.min(block.len() as u64) as usize;
            let mut chunk = block[..n].to_vec();
            chunk[0] = (i % 251) as u8;
            f.write_all(&chunk).unwrap();
            hasher.update(&chunk);
            left -= n as u64;
            i += 1;
        }
    }
    let set = read_model(&root).unwrap();
    let e = set.get("weights.bin").unwrap();
    assert_eq!(e.size_bytes, size);
    let want: [u8; 32] = hasher.finalize().into();
    assert_eq!(e.digest, want);
    std::fs::remove_dir_all(&root).unwrap();
}
